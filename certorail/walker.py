"""Entry point: run the lexical checks and then the dataflow walker over one program.

    python -m certorail.walker program.py

The pipeline, each stage running only if the previous one found nothing:

1. ``_ImportAnalysis``    -- collects the program's imports; rejects ``from``/``as`` imports and
                             forbidden modules.
2. ``ValidationAnalysis`` -- the lexical rules: escaping imported names, dunders, dangerous members,
                             rebinding builtins, ...
3. ``ValidationWalker``   -- the dataflow: a fact per variable, seeded from parameter annotations,
                             updated by assignments, refined by guards, and checked at sinks
                             (``open``).

Kept apart from ``analysis`` (the domain and the expression semantics) so that this module can
import ``guards``, ``annotations`` and ``safepy`` -- which themselves import ``analysis`` -- without
a cycle:

    analysis  <-  terms, guards, annotations, safepy  <-  walker
"""
import argparse
import ast
import pathlib
import sys
from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from .analysis import (
    InvalidConstantForm,
    InvalidProgram,
    Located,
    PathFact,
    PyOpenCall,
    StaticPath,
    StrFact,
    ValidationFact,
    as_const_or_default,
    bind_call_args,
    interpret_expr,
    is_path_typed,
    iteration_bindings,
    location_to_regex,
    resolve_callee,
)
from .dangerous import PATH_SINK_FUNCTIONS, PATH_SINK_METHODS
from .annotations import parse_function
from .guards import apply, recognize
from .markers import NAMESPACE
from .safepy import ClassAnalysis, InheritanceAnalysis, ValidationAnalysis, ImportAnalysis
from .terms import Call, Method, lower

type State = dict[str, ValidationFact]


@dataclass(frozen=True)
class SinkSite:
    """A filesystem operation (``open``, ``os.listdir``, ``p.read_text()``, ...) and what the
    analysis knew about the path it touches."""

    node: ast.Call
    what: str
    fact: ValidationFact | None

    @property
    def confined(self) -> bool:
        return isinstance(self.fact, Located)


@dataclass
class Report:
    violations: list[tuple[ast.AST, str]] = field(default_factory=list)
    sinks: list[SinkSite] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations and all(s.confined for s in self.sinks)


# ---------------------------------------------------------------------------
# block structure helpers
# ---------------------------------------------------------------------------


def _pattern_names(pattern: ast.pattern) -> set[str]:
    """Names a match pattern binds. They are bare identifiers on the pattern nodes, not ``Name``
    stores, so the usual ``visit_Name`` kill never sees them."""
    out: set[str] = set()
    for n in ast.walk(pattern):
        match n:
            case ast.MatchAs(name=str() as name) | ast.MatchStar(name=str() as name):
                out.add(name)
            case ast.MatchMapping(rest=str() as name):
                out.add(name)
            case _:
                pass
    return out


def _assigned_names(nodes: Iterable[ast.AST]) -> set[str]:
    """Every name bound anywhere inside *nodes* (over-approximate: nested scopes count too)."""
    out: set[str] = set()
    for root in nodes:
        for n in ast.walk(root):
            match n:
                case ast.Name(id=name, ctx=ast.Store() | ast.Del()):
                    out.add(name)
                case ast.ExceptHandler(name=str() as name):
                    out.add(name)
                case ast.FunctionDef(name=name) | ast.ClassDef(name=name):
                    out.add(name)
                case ast.match_case(pattern=pattern):
                    out |= _pattern_names(pattern)
                case _:
                    pass
    return out


def _kill(st: State, names: set[str]) -> State:
    return {k: v for k, v in st.items() if k not in names}


def _join(a: State, b: State) -> State:
    """Facts that hold on both paths. Equality for now; the lattice join (``join_loc`` &c.) slots
    in here once it lands."""
    return {k: v for k, v in a.items() if b.get(k) == v}


def _join_all(states: Sequence[State]) -> State:
    if not states:
        return {}  # no path reaches here
    joined = states[0]
    for s in states[1:]:
        joined = _join(joined, s)
    return joined


def _falls_through(stmts: Sequence[ast.stmt]) -> bool:
    """Can control reach the end of this block? Conservative: only definite exits say no."""
    if not stmts:
        return True
    match stmts[-1]:
        case ast.Raise() | ast.Return() | ast.Continue() | ast.Break():
            return False
        case ast.If(body=body, orelse=orelse):
            return _falls_through(body) or _falls_through(orelse)
        case _:
            return True


def _may_break(stmts: Sequence[ast.stmt]) -> bool:
    # over-approximate: a break in a nested loop counts too
    return any(isinstance(n, ast.Break) for s in stmts for n in ast.walk(s))


def _negated(cond: ast.expr) -> ast.expr:
    return ast.copy_location(ast.UnaryOp(op=ast.Not(), operand=cond), cond)


# ---------------------------------------------------------------------------
# the dataflow walker
# ---------------------------------------------------------------------------


class ValidationWalker(ast.NodeVisitor):
    """Flow-sensitive facts per variable, along the block structure.

    A fact established by a guard holds for the remaining statements of the enclosing block and
    inside nested blocks; branches are joined, loop bodies see their assigned names killed, and
    exceptional exits leave a ``try`` body's facts behind. That is the syntactic under-approximation
    of the dominance region we settled on: exception edges only ever *leave* a block.

    Every walk of a nested block happens under ``state_snapshot``; what survives the block is
    assigned explicitly afterwards.
    """

    def __init__(self, imports: frozenset[tuple[str, ...]]):
        self.state: State = {}
        self.violations: list[tuple[ast.AST, str]] = []
        self.sinks: list[SinkSite] = []
        # the names that denote modules, for lowering: only what the program actually imported,
        # plus the marker namespace the sandbox injects
        self.modules: frozenset[str] = frozenset(root for (root, *_) in imports) | {NAMESPACE}

    def _violation(self, node: ast.AST, what: str) -> None:
        self.violations.append((node, what))

    @contextmanager
    def state_snapshot(self):
        saved = self.state.copy()
        try:
            yield
        finally:
            self.state = saved

    def _block(self, stmts: Sequence[ast.stmt]) -> None:
        for s in stmts:
            self.visit(s)

    def _refine(self, st: State, cond: ast.expr) -> State:
        """*st* with everything *cond* being true establishes."""
        out = dict(st)
        for g in recognize(lower(cond, self.modules), out):
            refined = apply(out.get(g.subject), g.refinement)
            if refined is not None:
                out[g.subject] = refined
        return out

    # -- simple statements --------------------------------------------------------------------

    def visit_Name(self, node: ast.Name) -> Any:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.state.pop(node.id, None)

    def _assign(self, target: ast.expr, value: ast.expr) -> None:
        self.visit(value)  # for sinks inside the value, e.g. ``x = open(...)``
        if isinstance(target, ast.Name):
            fact = interpret_expr(value, self.state)
            if fact is None:
                self.state.pop(target.id, None)
            else:
                self.state[target.id] = fact
        else:
            self.visit(target)  # tuple/attribute/subscript targets: kill the names involved

    def visit_Assign(self, node: ast.Assign) -> Any:
        if len(node.targets) == 1:
            self._assign(node.targets[0], node.value)
            return
        self.visit(node.value)
        for t in node.targets:
            self.visit(t)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        # a local's annotation is unchecked at runtime, so it establishes nothing; the value does
        if node.value is None:
            self.visit(node.target)
        else:
            self._assign(node.target, node.value)

    def visit_Assert(self, node: ast.Assert) -> Any:
        self.state = self._refine(self.state, node.test)

    def visit_Call(self, node: ast.Call) -> Any:
        if resolve_callee(node.func) is None:
            raise InvalidProgram(node.func, "computed callee")  # f()(): no name to reason about
        self._audit_sink(node)
        self.generic_visit(node)

    def _audit_sink(self, node: ast.Call) -> None:
        """Record a filesystem operation with what is known about the path it touches. The path's
        provenance is not a violation here; ``Report.ok`` decides on ``confined``."""
        match lower(node, self.modules):
            case Call(("open",), _, _):
                bound = bind_call_args(node, PyOpenCall)
                if bound is None:
                    self._violation(node, "open(): arguments cannot be bound statically")
                    return
                try:
                    mode = as_const_or_default(str, bound.mode)
                except InvalidConstantForm:
                    mode = "?"
                    self._violation(node, "open(): mode must be a string literal")
                fact = interpret_expr(bound.file, self.state)
                what = f"open(mode={mode!r})"
            case Call(callee, args, _) if callee in PATH_SINK_FUNCTIONS:
                index = PATH_SINK_FUNCTIONS[callee]
                if index < len(args):
                    fact = interpret_expr(args[index].node, self.state)
                else:
                    fact = Located(StaticPath(()), "str")  # the current directory: the sandbox root
                what = ".".join(callee)
            case Method(recv, name, _, _) if name in PATH_SINK_METHODS:
                # an unknown receiver is unproven, not "probably not a Path"
                fact = interpret_expr(recv.node, self.state)
                what = f"<path>.{name}"
            case _:
                return
        self.sinks.append(SinkSite(node, what, fact))

    # -- compound statements ------------------------------------------------------------------

    def visit_If(self, node: ast.If) -> Any:
        self.visit(node.test)
        with self.state_snapshot():
            self.state = self._refine(self.state, node.test)
            self._block(node.body)
            then_end = self.state
        with self.state_snapshot():
            self.state = self._refine(self.state, _negated(node.test))
            self._block(node.orelse)
            else_end = self.state
        match _falls_through(node.body), _falls_through(node.orelse):
            case True, True:
                self.state = _join(then_end, else_end)
            case True, False:
                self.state = then_end
            case False, True:
                self.state = else_end  # ``if not C: raise`` -> C for the rest of the block
            case False, False:
                self.state = {}  # unreachable

    def _loop(
        self, node: ast.For | ast.While, test: ast.expr | None, bindings: State | None = None
    ) -> None:
        # names assigned in the loop are unknown at every iteration boundary; one pass over the body
        # in that state covers all iterations, and nothing the body established survives the loop.
        # A ``for`` header rebinds its target on every iteration, so *bindings* is applied after the
        # kill and holds at every iteration start.
        killed = _kill(self.state, _assigned_names([node]))
        with self.state_snapshot():
            entry = killed if test is None else self._refine(killed, test)
            self.state = {**entry, **(bindings or {})}
            self._block(node.body)
        with self.state_snapshot():
            self.state = dict(killed)
            self._block(node.orelse)  # runs only when the loop was not left by ``break``
            orelse_end = self.state
        self.state = _join(orelse_end, killed) if _may_break(node.body) else orelse_end

    def visit_For(self, node: ast.For) -> Any:
        self.visit(node.iter)
        # the iterable is evaluated once, before the loop, in the pre-loop state
        self._loop(node, None, iteration_bindings(node.target, node.iter, self.state))

    def visit_While(self, node: ast.While) -> Any:
        self.visit(node.test)
        self._loop(node, node.test)

    def _cannot_suppress(self, context_expr: ast.expr) -> bool:
        """Is this a context manager known not to swallow exceptions? Anything else -- including
        a user-defined one, which ``contextlib.contextmanager`` lets a program write without any
        dunder -- is assumed able to."""
        match lower(context_expr, self.modules):
            case Call(("open",), _, _):
                return True
            case Call(("tempfile", "TemporaryDirectory" | "NamedTemporaryFile" | "TemporaryFile"), _, _):
                return True
            case Call(("zipfile", "ZipFile"), _, _) | Call(("tarfile", "open" | "TarFile"), _, _):
                return True
            case Call(("contextlib", "redirect_stdout" | "redirect_stderr" | "nullcontext" | "closing"), _, _):
                return True
            case Method(recv, "open", _, _):
                return is_path_typed(interpret_expr(recv.node, self.state))  # Path.open
            case _:
                return False

    def visit_With(self, node: ast.With) -> Any:
        for item in node.items:
            self.visit(item.context_expr)
        straight_line = all(self._cannot_suppress(item.context_expr) for item in node.items)

        def bind_and_walk() -> None:
            for item in node.items:
                if item.optional_vars is not None:
                    self.visit(item.optional_vars)  # kills the bound names
            self._block(node.body)

        if straight_line:
            bind_and_walk()
            return
        # a manager that may swallow an exception makes the body a ``try`` with a catch-all
        # handler that falls through: whatever the body established may not have happened
        escaped = _kill(self.state, _assigned_names([node]))
        with self.state_snapshot():
            bind_and_walk()
            body_end = self.state
        self.state = _join(body_end, escaped)

    def _try(self, node: ast.Try | ast.TryStar, *, handlers_chain: bool) -> None:
        # an exception may leave the body at any point: a handler sees the pre-state minus whatever
        # the body may have assigned, and none of the facts the body established
        killed_by: list[ast.stmt] = list(node.body)
        if handlers_chain:
            # ``except*``: several handlers may run for one raise, one after another, so each also
            # loses whatever the others assign
            killed_by += [s for h in node.handlers for s in h.body]
        handler_entry = _kill(self.state, _assigned_names(killed_by))
        ends: list[State] = []
        with self.state_snapshot():
            self._block(node.body)
            self._block(node.orelse)  # runs only after the body completed normally
            ends.append(self.state)
        for h in node.handlers:
            with self.state_snapshot():
                self.state = dict(handler_entry)
                if h.name is not None:
                    self.state.pop(h.name, None)
                self._block(h.body)
                if _falls_through(h.body):
                    ends.append(self.state)
        self.state = _join_all(ends)
        self._block(node.finalbody)

    def visit_Try(self, node: ast.Try) -> Any:
        self._try(node, handlers_chain=False)

    def visit_TryStar(self, node: ast.TryStar) -> Any:
        self._try(node, handlers_chain=True)

    def visit_Match(self, node: ast.Match) -> Any:
        self.visit(node.subject)
        ends: list[State] = []
        for case in node.cases:
            with self.state_snapshot():
                self.state = _kill(self.state, _pattern_names(case.pattern))
                if case.guard is not None:
                    self.state = self._refine(self.state, case.guard)
                self._block(case.body)
                if _falls_through(case.body):
                    ends.append(self.state)
        irrefutable = any(
            isinstance(c.pattern, ast.MatchAs) and c.pattern.pattern is None and c.guard is None
            for c in node.cases
        )
        if not irrefutable:
            ends.append(self.state)  # the subject may match no case at all
        self.state = _join_all(ends)

    # -- scopes -------------------------------------------------------------------------------

    def _params(self, node: ast.FunctionDef) -> State:
        # the rely: only scalar facts fit the state for now; container facts (list[...], dict[...])
        # wait on element-level tracking
        return {
            name: f
            for name, f in parse_function(node).params.items()
            if isinstance(f, (StrFact, PathFact, Located))
        }

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        for d in [*node.args.defaults, *node.args.kw_defaults]:
            if d is not None:
                self.visit(d)
        with self.state_snapshot():
            self.state = self._params(node)
            self._block(node.body)
        self.state.pop(node.name, None)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        for b in node.bases:
            self.visit(b)
        with self.state_snapshot():
            self._block(node.body)
        self.state.pop(node.name, None)


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------


def analyze(source: str, filename: str = "<program>") -> Report:
    """Run the whole pipeline over *source*. Raises ``SyntaxError`` for unparsable input."""
    tree = ast.parse(source, filename)

    imports = ImportAnalysis()
    imports.visit(tree)
    if imports.violations:
        return Report(violations=list(imports.violations))

    classes = ClassAnalysis()
    classes.visit(tree)
    if classes.violations:
        return Report(violations=list(classes.violations))

    inheritance = InheritanceAnalysis(known_classes=classes.known_classes, module_roots=imports.import_roots)
    inheritance.visit(tree)
    if inheritance.violations:
        return Report(violations=list(inheritance.violations))

    lexical = ValidationAnalysis(known_classes=classes.known_classes, module_roots=imports.import_roots)
    lexical.visit(tree)
    if lexical.violations:
        return Report(violations=list(lexical.violations))

    walker = ValidationWalker(imports.imports)
    try:
        walker.visit(tree)
    except InvalidProgram as e:
        return Report(violations=[*walker.violations, (e.node, str(e))], sinks=walker.sinks)
    return Report(violations=walker.violations, sinks=walker.sinks)


def _where(filename: str, node: ast.AST) -> str:
    line = getattr(node, "lineno", None)
    col = getattr(node, "col_offset", None)
    if line is None:
        return filename
    return f"{filename}:{line}" if col is None else f"{filename}:{line}:{col + 1}"


def _describe_sink(site: SinkSite) -> str:
    match site.fact:
        case None:
            return "nothing is known about the path"
        case Located(location=loc):
            return f"confined to {location_to_regex(loc)}"
        case _:
            return "the path is read as text; it is not confined"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="certorail",
        description="Check a program against the certorail rules and report where it touches the filesystem.",
    )
    parser.add_argument("program", type=pathlib.Path, help="the Python source file to analyse")
    args = parser.parse_args(argv)

    filename = str(args.program)
    try:
        report = analyze(args.program.read_text(), filename)
    except SyntaxError as e:
        print(f"{filename}:{e.lineno}: syntax error: {e.msg}", file=sys.stderr)
        return 1

    for node, what in report.violations:
        print(f"{_where(filename, node)}: violation: {what}")
    for site in report.sinks:
        status = "ok" if site.confined else "UNCONFINED"
        print(f"{_where(filename, site.node)}: {site.what}: {status} -- {_describe_sink(site)}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
