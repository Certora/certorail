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
    ANY_STR,
    Exact,
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
    entails,
    interpret_expr,
    is_path_typed,
    iteration_bindings,
    locate,
    operand_value,
    pretty_location,
    pretty_regex,
    resolve_callee,
)
from .dangerous import (
    EXEC_ALLOWED_KEYWORDS,
    EXEC_CALLEE,
    EXEC_REQUIRED_KEYWORDS,
    PATH_SINK_FUNCTIONS,
    PATH_SINK_METHODS,
    AccessKind,
)
from .annotations import Contract, bind_arguments, default_of, is_plain_type
from .guards import apply, recognize
from .markers import NAMESPACE
from .safepy import (
    ClassAnalysis,
    FunctionAnalysis,
    ImportAnalysis,
    InheritanceAnalysis,
    ValidationAnalysis,
)
from .terms import Call, Method, lower

type State = dict[str, ValidationFact]


@dataclass(frozen=True)
class SinkSite:
    """A filesystem operation (``open``, ``os.listdir``, ``p.read_text()``, ...) and what the
    analysis knew about the path it touches."""

    node: ast.Call
    what: str
    fact: ValidationFact | None
    kind: AccessKind

    @property
    def confined(self) -> bool:
        return isinstance(self.fact, Located)


@dataclass(frozen=True)
class ExecSite:
    """A ``certora.exec(program, *args, cwd=...)`` call: the controlled shell-out."""

    node: ast.Call
    program: str
    arguments: tuple[str | ValidationFact | None, ...]
    cwd: ValidationFact | None

    @property
    def what(self) -> str:
        return f"exec({self.program!r})"

    @property
    def confined(self) -> bool:
        return isinstance(self.cwd, Located)


type Site = SinkSite | ExecSite


@dataclass
class Report:
    violations: list[tuple[ast.AST, str]] = field(default_factory=list)
    sinks: list[Site] = field(default_factory=list)

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


_OPAQUE_SCOPES = (
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
    ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
)


def _module_scope_binds(body: Sequence[ast.stmt]) -> dict[str, int]:
    """How many times each name is bound at module scope, not descending into function/class
    bodies or comprehensions (each a fresh scope). Over-approximate is safe: it only makes the
    single-assignment test for a constant stricter, never looser."""
    counts: dict[str, int] = {}
    stack: list[ast.AST] = list(body)
    while stack:
        node = stack.pop()
        match node:
            case ast.FunctionDef(name=name) | ast.AsyncFunctionDef(name=name) | ast.ClassDef(name=name):
                counts[name] = counts.get(name, 0) + 1  # binds its own name; body is a separate scope
                continue
            case ast.Lambda() | ast.ListComp() | ast.SetComp() | ast.DictComp() | ast.GeneratorExp():
                continue  # a separate scope: binds nothing at module level
            case ast.Name(id=name, ctx=ast.Store() | ast.Del()):
                counts[name] = counts.get(name, 0) + 1
            case ast.ExceptHandler(name=str() as name):
                counts[name] = counts.get(name, 0) + 1
            case _:
                pass
        stack.extend(ast.iter_child_nodes(node))
    return counts


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


def _open_kind(mode: str | None) -> AccessKind:
    """What an ``open`` does, from its mode; an unknown mode is taken as a write."""
    if mode is None:
        return "write"
    return "write" if any(c in mode for c in "wax+") else "read"


def _at_sink(fact: ValidationFact | None) -> ValidationFact | None:
    """What a sink records about its path: the path reading when the value has one (a literal
    ``"./out.txt"``, a validated name), otherwise the value as it was, for the report."""
    located = locate(fact)
    return fact if located is None else located


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

    def __init__(
        self,
        imports: frozenset[tuple[str, ...]],
        contracts: dict[str, tuple[ast.FunctionDef, Contract]],
    ):
        self.state: State = {}
        self.violations: list[tuple[ast.AST, str]] = []
        self.sinks: list[Site] = []
        # rely/guarantee: the module-level functions' contracts (collected and validated by
        # FunctionAnalysis) and the guarantee of the function being walked, if it has one
        self.contracts = contracts
        self._guarantee: ValidationFact | None = None
        # the names that denote modules, for lowering: only what the program actually imported,
        # plus the marker namespace the sandbox injects
        self.modules: frozenset[str] = frozenset(root for (root, *_) in imports) | {NAMESPACE}
        # facts for module-level constants, computed by visit_Module and seeded into function bodies
        self.module_constants: State = {}

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

    def _guaranteed(self, value: ast.expr) -> ValidationFact | None:
        """The guarantee of ``f(...)`` for a module-level ``f`` with a return contract."""
        match value:
            case ast.Call(func=ast.Name(id=name)) if name in self.contracts:
                returns = self.contracts[name][1].returns
                return returns if isinstance(returns, (StrFact, PathFact, Located)) else None
            case _:
                return None

    def _assign(self, target: ast.expr, value: ast.expr) -> None:
        self.visit(value)  # for sinks inside the value, e.g. ``x = open(...)``
        if isinstance(target, ast.Name):
            fact = interpret_expr(value, self.state)
            if fact is None:
                fact = self._guaranteed(value)
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
        if isinstance(node.func, ast.Name) and node.func.id in self.contracts:
            self._check_rely(node, node.func.id)
        self.generic_visit(node)

    def _check_rely(self, node: ast.Call, name: str) -> None:
        """Every argument to a contracted parameter must establish its rely; a parameter left to
        its default is checked against the default."""
        fdef, contract = self.contracts[name]
        if not contract.params:
            return
        bound = bind_arguments(node, fdef)
        if bound is None:
            self._violation(node, f"call to {name}: arguments cannot be bound statically, so its rely cannot be discharged")
            return
        for param, rely in contract.params.items():
            if is_plain_type(rely):
                continue  # a type rely: the injected runtime guard's job, not ours
            supplied = bound.get(param)
            if supplied is None:
                default = default_of(fdef, param)
                if default is None:
                    continue  # unbound without a default: bind() would have failed
                if not entails(operand_value(default, {}), rely):
                    self._violation(node, f"call to {name}: the default for {param} does not establish {_describe_value(rely)}")
                continue
            if not isinstance(supplied, ast.expr):
                self._violation(node, f"call to {name}: arguments to *{param} cannot be checked against its rely")
                continue
            if not entails(operand_value(supplied, self.state), rely):
                self._violation(supplied, f"call to {name}: the argument for {param} does not establish {_describe_value(rely)}")

    def _audit_exec(self, node: ast.Call) -> None:
        """``certora.exec(program, *args, cwd=...)``: the shape is checked here (violations), the
        cwd's provenance is a sink question (``confined``), and the arguments are reported."""
        if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
            self._violation(node, "exec: *args / **kwargs are not admissible; spell the command out")
            return
        keywords = {k.arg: k.value for k in node.keywords if k.arg is not None}
        for name in sorted(keywords.keys() - EXEC_ALLOWED_KEYWORDS):
            self._violation(node, f"exec: keyword {name!r} is not part of the API")
        for name in sorted(EXEC_REQUIRED_KEYWORDS - keywords.keys()):
            self._violation(node, f"exec: {name}= is required")
        if not node.args:
            self._violation(node, "exec: no program given")
            return
        match interpret_expr(node.args[0], self.state):
            case StrFact(regex=Exact(exact_str=program)):
                pass
            case _:
                program = "?"
                self._violation(
                    node.args[0], "exec: the program must be a string literal (or a name bound to one)"
                )
        cwd_expr = keywords.get("cwd")
        self.sinks.append(
            ExecSite(
                node,
                program,
                tuple(operand_value(a, self.state) for a in node.args[1:]),
                None if cwd_expr is None else _at_sink(interpret_expr(cwd_expr, self.state)),
            )
        )

    def _audit_sink(self, node: ast.Call) -> None:
        """Record a filesystem operation with what is known about the path it touches. The path's
        provenance is not a violation here; ``Report.ok`` decides on ``confined``."""
        callee = resolve_callee(node.func)
        if callee is not None and callee.matches(*EXEC_CALLEE):
            self._audit_exec(node)
            return
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
                kind = _open_kind(mode)
            case Call(callee, args, _) if callee in PATH_SINK_FUNCTIONS:
                index, kind = PATH_SINK_FUNCTIONS[callee]
                if index < len(args):
                    fact = interpret_expr(args[index].node, self.state)
                else:
                    fact = Located(StaticPath(()), "str")  # the current directory: the sandbox root
                what = ".".join(callee)
            case Method(recv, name, args, kwargs) if name in PATH_SINK_METHODS:
                # an unknown receiver is unproven, not "probably not a Path"
                fact = interpret_expr(recv.node, self.state)
                what = f"<path>.{name}"
                kind = PATH_SINK_METHODS[name]
                if name == "open":  # Path.open(mode=...) / Path.open("w")
                    mode_term = next((v for k, v in kwargs if k == "mode"), args[0] if args else None)
                    kind = _open_kind("r" if mode_term is None else mode_term.as_str())
            case _:
                return
        self.sinks.append(SinkSite(node, what, _at_sink(fact), kind))

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

    # -- scopes and contracts -----------------------------------------------------------------

    def visit_Module(self, node: ast.Module) -> Any:
        # a module-level constant (a name bound by exactly one unconditional top-level assignment)
        # is immutable: module-level reassignment is forbidden and `global` is banned, so no code
        # can rebind it. Its fact therefore holds in every function body and may seed it.
        self.module_constants = self._module_constants(node)
        self.generic_visit(node)

    def _module_constants(self, module: ast.Module) -> State:
        counts = _module_scope_binds(module.body)
        state: State = {}
        for s in module.body:
            if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                name, value = s.targets[0].id, s.value
            elif isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name) and s.value is not None:
                name, value = s.target.id, s.value
            else:
                continue
            if counts.get(name, 0) != 1:
                continue  # bound more than once at module scope: not a constant
            try:
                fact = interpret_expr(value, state)  # earlier constants are in scope for later ones
            except InvalidProgram:
                continue  # a malformed value; the main walk reports it
            if fact is None:
                fact = self._guaranteed(value)
            if isinstance(fact, (StrFact, PathFact, Located)):
                state[name] = fact
        return state

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        # decorators and defaults are evaluated at definition time, in the enclosing scope: audited
        # like any other expression there (a call inside a decorator is still a call)
        for d in node.decorator_list:
            self.visit(d)
        for d in [*node.args.defaults, *node.args.kw_defaults]:
            if d is not None:
                self.visit(d)
        # the contract belongs to one specific module-level node (FunctionAnalysis saw to that); a
        # nested function or method -- even one sharing the name -- starts from nothing
        entry = self.contracts.get(node.name)
        contract = entry[1] if entry is not None and entry[0] is node else None
        rely: State = {} if contract is None else dict(contract.params)
        # seed the module constants the body may read. Exclude any name the function binds itself:
        # in Python such a name is local throughout the body (it shadows the module name), and the
        # rely then supplies the facts for the parameters.
        a = node.args
        local = {p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)}
        for extra in (a.vararg, a.kwarg):
            if extra is not None:
                local.add(extra.arg)
        local |= _assigned_names(node.body)
        seed: State = {k: v for k, v in self.module_constants.items() if k not in local}
        seed.update(rely)
        guarantee = None if contract is None else contract.returns
        outer = self._guarantee
        self._guarantee = guarantee
        try:
            with self.state_snapshot():
                self.state = seed
                self._block(node.body)
                if guarantee is not None and not is_plain_type(guarantee) and _falls_through(node.body):
                    self._violation(node, f"{node.name} may fall off its end without establishing its guarantee")
        finally:
            self._guarantee = outer
        self.state.pop(node.name, None)

    def visit_Return(self, node: ast.Return) -> Any:
        if node.value is not None:
            self.visit(node.value)
        guarantee = self._guarantee
        if guarantee is None or is_plain_type(guarantee):
            return  # a plain return type is the type checker's business
        if node.value is None or not entails(operand_value(node.value, self.state), guarantee):
            self._violation(node, f"return does not establish the guarantee {_describe_value(guarantee)}")

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        for d in node.decorator_list:
            self.visit(d)
        for b in node.bases:
            self.visit(b)
        for kw in node.keywords:
            self.visit(kw.value)
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

    functions = FunctionAnalysis()
    functions.visit(tree)
    if functions.violations:
        return Report(violations=list(functions.violations))

    # the injected namespace is a module root like any import: its members may only be applied
    module_roots = imports.import_roots | {NAMESPACE}

    inheritance = InheritanceAnalysis(known_classes=classes.known_classes, module_roots=module_roots)
    inheritance.visit(tree)
    if inheritance.violations:
        return Report(violations=list(inheritance.violations))

    lexical = ValidationAnalysis(
        known_classes=classes.known_classes,
        contracts=functions.contracts,
        module_roots=module_roots,
    )
    lexical.visit(tree)
    if lexical.violations:
        return Report(violations=list(lexical.violations))

    walker = ValidationWalker(imports.imports, functions.contracts)
    try:
        walker.visit(tree)
    except InvalidProgram as e:
        return Report(violations=[*walker.violations, (e.node, str(e))], sinks=walker.sinks)
    return Report(violations=walker.violations, sinks=walker.sinks)


def where(filename: str, node: ast.AST) -> str:
    line = getattr(node, "lineno", None)
    col = getattr(node, "col_offset", None)
    if line is None:
        return filename
    return f"{filename}:{line}" if col is None else f"{filename}:{line}:{col + 1}"


def _describe_value(v: str | ValidationFact | None) -> str:
    match v:
        case None:
            return "unknown"
        case str():
            return repr(v)
        case Located(location=loc, repr=rp):
            return f"{rp} at {pretty_location(loc)}"
        case StrFact(regex=regex, atoms=atoms):
            text = "text" if regex == ANY_STR else f"text matching {pretty_regex(regex)}"
            return text + (f" [{', '.join(sorted(atoms))}]" if atoms else "")
        case PathFact(atoms=atoms):
            return "path of unknown location" + (f" [{', '.join(sorted(atoms))}]" if atoms else "")


def describe_sink(site: Site) -> str:
    match site:
        case SinkSite(fact=None):
            return "nothing is known about the path"
        case SinkSite(fact=Located(location=loc)):
            return f"confined to {pretty_location(loc)}"
        case SinkSite():
            return "the path is read as text; it is not confined"
        case ExecSite(arguments=arguments, cwd=cwd):
            args = ", ".join(_describe_value(a) for a in arguments) or "none"
            return f"cwd {_describe_value(cwd)}; arguments: {args}"


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
        print(f"{where(filename, node)}: violation: {what}")
    for site in report.sinks:
        status = "ok" if site.confined else "UNCONFINED"
        print(f"{where(filename, site.node)}: {site.what}: {status} -- {describe_sink(site)}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
