"""Entry point: run the lexical checks and then the dataflow walker over one program.

    python -m certorail.walker program.py

The pipeline, each stage running only if the previous one found nothing:

1. ``_ImportAnalysis``    -- collects the program's imports; rejects ``from``/``as`` imports and
                             forbidden modules.
2. ``ValidationAnalysis`` -- the lexical rules: escaping imported names, dunders, dangerous members,
                             rebinding builtins, ...
3. ``ValidationWalker``   -- the dataflow: a fact per variable, seeded from parameter annotations,
                             updated by assignments, refined by guards, joined at branches, killed
                             at assignments and at effects.

The walker owns the program: its syntax, its state and its control flow. What the policy has to
say about a call -- is it a site, what does it write, what does it yield, does a value establish
what is demanded -- is ``enforcement.Enforcement``'s. The walker digests each call into a
``Callsite`` (values, not syntax) and applies what comes back: sites and violations into the
report, the kill onto the state, a check's atoms onto the variables it named.

Kept apart from ``analysis`` (the domain and the expression semantics) so that this module can
import ``guards``, ``annotations`` and ``safepy`` -- which themselves import ``analysis`` -- without
a cycle:

    analysis  <-  terms, guards, annotations, safepy, enforcement  <-  walker
"""
import argparse
import ast
import pathlib
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from typing import Any

from .analysis import (
    Container,
    Data,
    InvalidProgram,
    Located,
    PathFact,
    StrFact,
    UrlString,
    ValidationFact,
    as_const_or_null,
    interpret_expr,
    is_path_typed,
    iteration_bindings,
    operand_value,
    resolve_callee,
)
from .annotations import Contract, bind_arguments, default_of, is_plain_type, parse_annotation
from .dangerous import CHECK_CALLEE, EXEC_CALLEE, EXTRACT_ALL_CALLEE, LINES_CALLEE
from .effects import EVERYTHING, NOTHING, Effects
from .enforcement import (
    CONTAINER_METHODS,
    CONTAINER_READ_CALLS,
    METHOD_KINDS,
    Argument,
    Audit,
    Callsite,
    CheckSignature,
    CheckSite,
    Discharge,
    Enforcement,
    ExecSite,
    NetworkSite,
    SinkSite,
    Site,
    SourceTable,
    Vocabulary,
    WriteTable,
    describe_sink,
    describe_value,
    host_matches,
)
from .guards import apply, recognize
from .markers import NAMESPACE
from .safepy import (
    ClassAnalysis,
    FunctionAnalysis,
    ImportAnalysis,
    InheritanceAnalysis,
    ValidationAnalysis,
)
from .templates import Binding, Elements, Many
from .terms import Call, Method, lower

__all__ = [
    "Argument", "Audit", "Callsite", "CheckSignature", "CheckSite", "Enforcement", "ExecSite",
    "NetworkSite", "Report", "SinkSite", "Site", "SourceTable", "State", "ValidationWalker",
    "Vocabulary", "WriteTable", "analyze", "describe_sink", "describe_value", "host_matches",
    "where",
]

type State = dict[str, ValidationFact | Container | Data]


def _roster_blessings(
    root: ast.AST, contracts: dict[str, tuple[ast.FunctionDef, Contract]]
) -> set[int]:
    """The ``ast.Name`` occurrences (by ``id``) in container-roster positions: the blessed
    shapes of CONTAINERS.md, computed syntactically in one pass over the whole tree.
    ``visit_Name`` treats any other Load of a tracked container as its escape -- a
    violation, always, so no escaped-set ever needs propagating to block boundaries: for
    any program that survives, that set is empty.

    A call to a contracted function blesses only the arguments bound to *container*
    parameters -- handing a tracked container to a scalar or unannotated parameter is an
    escape (the callee would hold an unobligated alias)."""
    blessed: set[int] = set()

    def bless(e: object) -> None:
        if isinstance(e, ast.Name):
            blessed.add(id(e))

    for n in ast.walk(root):
        match n:
            case ast.Call(func=ast.Attribute(value=recv, attr=method), args=args, keywords=kws):
                if method in CONTAINER_METHODS:
                    bless(recv)
                if method == "extend" and args:
                    bless(args[0])
                if method == EXEC_CALLEE[1] and isinstance(recv, ast.Name) and recv.id == EXEC_CALLEE[0]:
                    # a container bound to a hole of certora.exec is a roster read (the splat of
                    # TEMPLATES.md); the exec audit records its element fact for the policy
                    for k in kws:
                        if k.arg is not None and k.arg != "cwd":
                            bless(k.value)
            case ast.Call(func=ast.Name(id=f), args=args):
                if f in CONTAINER_READ_CALLS:
                    for a in args:
                        bless(a)
                elif f in contracts:
                    fdef, contract = contracts[f]
                    bound = bind_arguments(n, fdef)
                    for param, rely in contract.params.items():
                        if isinstance(rely, Container) and bound is not None:
                            bless(bound.get(param))
            case ast.For(iter=it):
                bless(it)  # a wrapper call in iter position is covered by the Call case
            case (
                ast.ListComp(generators=gens)
                | ast.SetComp(generators=gens)
                | ast.GeneratorExp(generators=gens)
                | ast.DictComp(generators=gens)
            ):
                for g in gens:
                    bless(g.iter)  # iterating a tracked container in a comprehension reads it
            case ast.Subscript(value=v, ctx=ast.Load()):
                bless(v)  # an index reads an element; a slice-load is a copy
            case ast.Assign(targets=[ast.Subscript(value=v, slice=s)]) if not isinstance(
                s, ast.Slice
            ):
                # the ONE store shape the semantics handle (_container_store imposes the
                # obligation): a direct, single-target element store. Every other spelling
                # -- tuple targets, x[0] = y[0] = v, x[i] += v, for x[i] in ... -- is
                # unblessed and therefore an escape, never a silently unobligated write.
                bless(v)
            case ast.AnnAssign(target=ast.Subscript(value=v, slice=s)) if not isinstance(
                s, ast.Slice
            ):
                bless(v)
            case ast.Compare(ops=ops, comparators=comparators):
                for op, comp in zip(ops, comparators):
                    if isinstance(op, (ast.In, ast.NotIn)):
                        bless(comp)
            case ast.If(test=t) | ast.While(test=t) | ast.Assert(test=t):
                bless(t)  # bare-name truthiness
            case ast.UnaryOp(op=ast.Not(), operand=operand):
                bless(operand)
            case ast.BoolOp(values=values):
                for v in values:
                    bless(v)
            case ast.Return(value=v):
                bless(v)  # move or alias: visit_Return decides which
            case ast.AugAssign(value=v):
                bless(v)  # x += y reads y; the extend semantics check it
            case _:
                pass
    return blessed


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
        vocabulary: Vocabulary | None = None,
        discharge: Discharge | None = None,
    ):
        self.state: State = {}
        self.violations: list[tuple[ast.AST, str]] = []
        self.sinks: list[Site] = []
        # rely/guarantee: the module-level functions' contracts (collected and validated by
        # FunctionAnalysis) and the guarantee of the function being walked, if it has one
        self.contracts = contracts
        self._guarantee: ValidationFact | Container | None = None
        # the names that denote modules, for lowering: only what the program actually imported,
        # plus the marker namespace the sandbox injects
        self.modules: frozenset[str] = frozenset(root for (root, *_) in imports) | {NAMESPACE}
        # the policy's side: the validations as the analysis sees them (Policy.vocabulary), the
        # literal-checker runner (Policy.discharger), and every verdict about a call
        self.enforcement = Enforcement(
            vocabulary if vocabulary is not None else Vocabulary(), discharge, self.modules
        )
        # facts for module-level constants, computed by visit_Module and seeded into function
        # bodies. Scalars only: containers are never module constants.
        self.module_constants: dict[str, ValidationFact] = {}
        # ast.Name occurrences (by id) in container-roster positions; any other Load of a
        # tracked container is its escape. Filled once per module by visit_Module.
        self._blessed: set[int] = set()

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
            current = out.get(g.subject)
            if isinstance(current, (Container, Data)):
                continue  # guards speak about scalars; containers and handles have their own rules
            refined = apply(current, g.refinement)
            if refined is not None:
                out[g.subject] = refined
        return out

    # -- the seam to the enforcement ----------------------------------------------------------

    @staticmethod
    def _maybe_call[F](e: ast.expr, f: Callable[[ast.Call], F]) -> F | None:
        """*f* of *e* when it is a call with a name to reason about -- a computed callee is
        refused by ``visit_Call`` before anything else asks about it -- and None otherwise."""
        if isinstance(e, ast.Call) and resolve_callee(e.func) is not None:
            return f(e)
        return None

    def _digest(self, call: ast.Call, st: State, *, interpret: bool = True) -> Callsite:
        """*call* as the enforcement sees it, against *st*. Without *interpret* only literals are
        read -- the state-free digest for code the walk does not pass through (a loop's other
        iterations, a handler's entry), where every exemption that needs a fact is unavailable
        and the answer is conservative by construction."""
        callee = resolve_callee(call.func)
        assert callee is not None, "visit_Call refuses computed callees before digesting"

        def value(e: ast.expr) -> Binding:
            if isinstance(e, ast.Starred):
                return None
            if not interpret:
                return as_const_or_null(str, e)
            return self._binding(e, st)

        receiver: ValidationFact | Container | Data | None = None
        if interpret and isinstance(call.func, ast.Attribute):
            recv = call.func.value
            receiver = st.get(recv.id) if isinstance(recv, ast.Name) else interpret_expr(recv, st)

        def handle_of(which: int | str) -> Data | None:
            if not interpret:
                return None
            if isinstance(which, int):
                if which >= len(call.args):
                    return None
                e: ast.expr = call.args[which]
            else:
                found = next((k.value for k in call.keywords if k.arg == which), None)
                if found is None:
                    return None
                e = found
            if isinstance(e, ast.Name):
                bound = st.get(e.id)
                return bound if isinstance(bound, Data) else None
            # a source call inline: its handle needs the state, so this is only reached when
            # interpreting, and the nested record interprets as well
            return self._maybe_call(
                e, lambda c: self.enforcement.handle(self._digest(c, st, interpret=True))
            )

        keywords = {k.arg: value(k.value) for k in call.keywords if k.arg is not None}
        return Callsite(
            node=call,
            callee=callee,
            args=tuple(
                v if not isinstance(v, (Many, Elements)) else None
                for v in (value(a) for a in call.args)
            ),
            arg_nodes=tuple(call.args),
            keywords=keywords,
            keyword_nodes={k.arg: k.value for k in call.keywords if k.arg is not None},
            keyword_names={
                k.arg: (k.value.id if isinstance(k.value, ast.Name) else None)
                for k in call.keywords
                if k.arg is not None
            },
            splat=any(isinstance(a, ast.Starred) for a in call.args)
            or any(k.arg is None for k in call.keywords),
            receiver=receiver,
            handle_of=handle_of,
        )

    def _binding(self, expr: ast.expr, st: State) -> Binding:
        """An argument as the policy will bind it: a display is the sequence of its elements, a
        tracked container its element fact, anything else a value."""
        match expr:
            case ast.List(elts=elts) | ast.Tuple(elts=elts):
                return Many(tuple(operand_value(e, st) for e in elts))
            case ast.Name(id=name) if isinstance(container := st.get(name), Container):
                return Elements(container.elem)
            case _:
                return operand_value(expr, st)

    def _sources_of(self, expr: ast.expr) -> frozenset[str] | None:
        """The sources behind an extractor's argument: a name bound to a handle, or a source call
        inline. None: not a source."""
        if isinstance(expr, ast.Name):
            bound = self.state.get(expr.id)
            return bound.sources if isinstance(bound, Data) else None
        handle = self._maybe_call(
            expr, lambda c: self.enforcement.handle(self._digest(c, self.state))
        )
        return None if handle is None else handle.sources

    def _record(self, audit: Audit) -> None:
        self.sinks.extend(audit.sites)
        self.violations.extend(audit.violations)

    def _establish(self, atoms_by_name: Mapping[str, frozenset[str]]) -> None:
        """A check's success, on the variables it named: a fact needs a variable to live on."""
        for name, atoms in atoms_by_name.items():
            fact = self.state.get(name)
            if fact is not None and not isinstance(fact, (Container, Data)):
                self.state[name] = replace(fact, checks=fact.checks | atoms)

    def _killed(self, st: State, writes: Effects) -> State:
        """*st* after an effect writing *writes*: every atom the write set reaches dies, on every
        variable and on every container's element fact (the annotation is only the birth
        invariant; reads yield the current, possibly degraded fact). A handle carries only
        source atoms, which are pure."""
        if writes.empty:
            return st
        forget = self.enforcement.forget
        return {
            k: (
                replace(v, elem=forget(v.elem, writes))
                if isinstance(v, Container)
                else v if isinstance(v, Data)
                else forget(v, writes)
            )
            for k, v in st.items()
        }

    def _writes_in(self, nodes: Iterable[ast.AST]) -> Effects:
        """What the calls inside *nodes* may write, for the states the walk does *not* pass
        through -- a loop's iteration boundary, a try's handler entry, a with's escape path.
        State-free, so over-approximate: it only costs checks, never soundness."""
        total = NOTHING
        for root in nodes:
            for n in ast.walk(root):
                if not isinstance(n, ast.Call):
                    continue
                if resolve_callee(n.func) is None:
                    return EVERYTHING
                total = total | self.enforcement.writes_of(self._digest(n, {}, interpret=False))
                if total == EVERYTHING:
                    return total
        return total

    # -- simple statements --------------------------------------------------------------------

    def visit_Name(self, node: ast.Name) -> Any:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.state.pop(node.id, None)
            return
        tracked = self.state.get(node.id)
        if isinstance(tracked, Container) and id(node) not in self._blessed:
            self._escape(node, node.id, tracked)

    def _escape(self, node: ast.AST, name: str, container: Container) -> None:
        """Any use outside the roster: an error, always (CONTAINERS.md). A typed container
        is an opt-in assertion by code written de novo to be analyzable; silently dropping
        the state and complaining later -- if the thrown-away fact even turns out to matter
        -- serves nobody here. Provenance still decides *returns* (a local moves out, a
        parameter would alias), not the loudness of an escape."""
        self._violation(
            node,
            f"container {name!r} escapes: a typed container may only be used through "
            "the container operations",
        )
        self.state.pop(name, None)

    def _guaranteed(self, value: ast.expr) -> ValidationFact | Container | None:
        """The guarantee of ``f(...)`` for a module-level ``f`` with a return contract. A
        container guarantee is a move in: the caller receives fresh ownership."""
        match value:
            case ast.Call(func=ast.Name(id=name)) if name in self.contracts:
                returns = self.contracts[name][1].returns
                if isinstance(returns, Container):
                    # a contract container is always param=False (the annotations
                    # constructor never sets it): the caller receives fresh ownership as-is
                    return returns
                return (
                    returns
                    if isinstance(returns, (StrFact, PathFact, Located, UrlString))
                    else None
                )
            case _:
                return None

    def _assign(self, target: ast.expr, value: ast.expr) -> None:
        self.visit(value)  # for sinks inside the value, e.g. ``x = open(...)``
        if isinstance(target, ast.Name):
            # a source handle or an extraction first (PROVENANCE.md): those right-hand sides
            # have no scalar reading worth keeping, and must not be shadowed by one
            site = self._maybe_call(value, lambda c: self._digest(c, self.state))
            fact: ValidationFact | Container | Data | None = None
            if site is not None:
                fact = self.enforcement.handle(site)
                if fact is None:
                    fact = self.enforcement.extract_fact(site)
            if fact is None:
                fact = interpret_expr(value, self.state)
            if fact is None:
                fact = self._guaranteed(value)
            if fact is None and site is not None:
                fact = self.enforcement.check_single_fact(site)
            if fact is None:
                self.state.pop(target.id, None)
            else:
                self.state[target.id] = fact
        elif (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and isinstance((c := self.state.get(target.value.id)), Container)
        ):
            self._container_store(target.value.id, target, value, c)
        else:
            assert isinstance(target, ast.Tuple)
            self.visit(target)  # tuple/attribute/subscript targets: kill the names involved

    def _container_store(
        self, name: str, target: ast.Subscript, value: ast.expr, c: Container
    ) -> None:
        """``x[i] = v``: an element write, with the usual obligation. A slice store is the
        punted escape; a set is unsubscriptable; a Sequence parameter is read-only."""
        if c.kind == "sequence":
            self._violation(target, f"{name!r} is a Sequence parameter: read-only")
            return
        if c.kind == "set" or isinstance(target.slice, ast.Slice):
            self._escape(target, name, c)
            return
        self.visit(target.slice)
        if not self.enforcement.establishes(operand_value(value, self.state), c.elem):
            self._unvouched_write(value, name, c, "the assigned element does not establish")

    def visit_Assign(self, node: ast.Assign) -> Any:
        if len(node.targets) == 1:
            self._assign(node.targets[0], node.value)
            return
        self.visit(node.value)
        for t in node.targets:
            self.visit(t)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        declared = self._container_annotation(node.annotation)
        if declared is not None:
            self._construct_container(node, declared)
            return
        # a local's annotation is unchecked at runtime, so it establishes nothing; the value does
        if node.value is None:
            self.visit(node.target)
        else:
            self._assign(node.target, node.value)

    def _container_annotation(self, annotation: ast.expr) -> Container | None:
        try:
            fact = parse_annotation(annotation)
        except InvalidProgram:
            return None  # malformed annotations are FunctionAnalysis' report, not ours
        return fact if isinstance(fact, Container) else None

    def _construct_container(self, node: ast.AnnAssign, declared: Container) -> None:
        """The opt-in construction site (CONTAINERS.md): an annotated assignment whose value
        is a known constructor, every element establishing the declared element fact."""
        if not isinstance(node.target, ast.Name):
            self._violation(node, "container: the target must be a bare name")
            self.visit(node.target)
            return
        target = node.target.id
        if declared.kind == "sequence":
            self._violation(node, "Sequence is a borrowed view; construct a list or a set")
            self.state.pop(target, None)
            return
        if node.value is None:
            self._violation(node, "container: the annotation opts in at a construction site; assign a constructor")
            self.state.pop(target, None)
            return
        self.visit(node.value)  # sinks inside elements; a nested tracked container escapes
        if self._constructed(node.value, declared):
            self.state[target] = Container(declared.kind, declared.elem)
        else:
            self.state.pop(target, None)

    def _constructed(self, value: ast.expr, declared: Container) -> bool:
        match value:
            case ast.List(elts=elts) if declared.kind == "list":
                return self._elements_establish(elts, declared.elem)
            case ast.Set(elts=elts) if declared.kind == "set":
                return self._elements_establish(elts, declared.elem)
            case ast.Call(func=ast.Name(id=ctor), args=[], keywords=[]) if ctor == declared.kind:
                return True  # list() / set(): empty, trivially conforming
            case ast.Call(func=ast.Name(id=ctor), args=[ast.Name(id=src)], keywords=[]) if (
                ctor == declared.kind
                and isinstance((source := self.state.get(src)), Container)
            ):
                # the copy constructor: the blessed "alias" -- a fresh container whose
                # elements come vouched-for by the source's current element fact
                if not self.enforcement.establishes(source.elem, declared.elem):
                    self._violation(
                        value,
                        f"the copied elements do not establish {describe_value(declared.elem)}",
                    )
                    return False
                return True
            case ast.ListComp(elt=elt, generators=[gen]) if (
                declared.kind == "list" and not gen.is_async
            ):
                return self._comprehension_conforms(value, elt, gen, declared)
            case ast.SetComp(elt=elt, generators=[gen]) if (
                declared.kind == "set" and not gen.is_async
            ):
                return self._comprehension_conforms(value, elt, gen, declared)
            # the extractors (PROVENANCE.md): every element is something the source produced
            case ast.Call(func=func, args=[source_expr, _], keywords=[]) if (
                declared.kind == "list"
                and (callee := resolve_callee(func)) is not None
                and callee.matches(*EXTRACT_ALL_CALLEE)
            ):
                return self._extracted_conforms(value, self._sources_of(source_expr), declared)
            case ast.Call(func=func, args=[source_expr], keywords=[]) if (
                declared.kind == "list"
                and (callee := resolve_callee(func)) is not None
                and callee.matches(*LINES_CALLEE)
            ):
                return self._extracted_conforms(value, self._sources_of(source_expr), declared)
            case ast.Call(
                func=ast.Attribute(value=ast.Name(id=handle_name), attr="readlines"), args=[], keywords=[]
            ) if declared.kind == "list" and isinstance((handle := self.state.get(handle_name)), Data):
                return self._extracted_conforms(value, handle.sources, declared)  # certora.lines, stdlib-spelled
            case _:
                self._violation(
                    value,
                    f"container: not a recognized {declared.kind} constructor "
                    f"(a display, a comprehension, {declared.kind}(), {declared.kind}(tracked), "
                    "or an extractor)",
                )
                return False

    def _extracted_conforms(
        self, node: ast.expr, sources: frozenset[str] | None, declared: Container
    ) -> bool:
        if sources is None:
            return False  # the extractor's audit reported the non-source
        if not self.enforcement.establishes(StrFact(checks=sources), declared.elem):
            self._violation(
                node, f"the extracted elements do not establish {describe_value(declared.elem)}"
            )
            return False
        return True

    def _comprehension_conforms(
        self, comp: ast.expr, elt: ast.expr, gen: ast.comprehension, declared: Container
    ) -> bool:
        """A single-generator comprehension as a constructor: the element expression,
        evaluated under the iteration bindings and the ``if`` refinements, must establish the
        declared element fact. When any iteration may run an effectful call, environmental
        checks cannot accumulate across iterations -- iteration i+1's effects kill what
        iteration i established -- so only what survives those effects enters the container
        fact (CONTAINERS.md: an effectful check_single usefully establishes only its pure atoms
        here)."""
        targets = {
            n.id for n in ast.walk(gen.target) if isinstance(n, ast.Name)
        }
        inner: State = {k: v for k, v in self.state.items() if k not in targets}
        inner.update(iteration_bindings(gen.target, gen.iter, self.state))
        for cond in gen.ifs:
            inner = self._refine(inner, cond)
        fact = self._maybe_call(
            elt, lambda c: self.enforcement.check_single_fact(self._digest(c, inner))
        )
        if fact is None:
            fact = operand_value(elt, inner)
        if fact is not None and not isinstance(fact, str):
            fact = self.enforcement.forget(fact, self._writes_in([comp]))
        if not self.enforcement.establishes(fact, declared.elem):
            self._violation(
                elt,
                f"the comprehension element does not establish {describe_value(declared.elem)}",
            )
            return False
        return True

    def _elements_establish(self, elts: Sequence[ast.expr], elem: ValidationFact) -> bool:
        ok = True
        for i, e in enumerate(elts):
            if isinstance(e, ast.Starred) or not self.enforcement.establishes(
                operand_value(e, self.state), elem
            ):
                self._violation(e, f"element {i + 1} does not establish {describe_value(elem)}")
                ok = False
        return ok

    def visit_AugAssign(self, node: ast.AugAssign) -> Any:
        if isinstance(node.target, ast.Name) and isinstance(
            (c := self.state.get(node.target.id)), Container
        ):
            self.visit(node.value)
            if c.kind == "list" and isinstance(node.op, ast.Add):
                self._extend(node, node.target.id, c, node.value)
            else:
                self._escape(node, node.target.id, c)
            return
        self.generic_visit(node)

    def _extend(self, node: ast.AST, name: str, c: Container, source: ast.expr) -> None:
        if c.kind == "sequence":
            self._violation(node, f"{name!r} is a Sequence parameter: read-only")
            return
        match source:
            case ast.Name(id=src) if isinstance((other := self.state.get(src)), Container):
                if not self.enforcement.establishes(other.elem, c.elem):
                    self._unvouched_write(
                        source, name, c, "the extended elements do not establish"
                    )
            case ast.List(elts=elts) | ast.Set(elts=elts) | ast.Tuple(elts=elts):
                if not self._elements_ok(elts, c.elem):
                    self._unvouched_write(
                        source, name, c, "the extended elements do not establish"
                    )
            case _:
                # an unvouched iterable: nothing speaks for its elements
                self._unvouched_write(
                    source, name, c, "the extended elements do not establish"
                )

    def _elements_ok(self, elts: Sequence[ast.expr], elem: ValidationFact) -> bool:
        return all(
            not isinstance(e, ast.Starred)
            and self.enforcement.establishes(operand_value(e, self.state), elem)
            for e in elts
        )

    def _unvouched_write(
        self, node: ast.AST, name: str, container: Container, what: str
    ) -> None:
        """A write that does not establish the element fact: a violation like any other
        escape. The container is dropped afterwards only to keep the (already rejected)
        remainder of the walk from cascading."""
        self._violation(node, f"{what} {describe_value(container.elem)}")
        self.state.pop(name, None)

    def visit_Assert(self, node: ast.Assert) -> Any:
        self.generic_visit(node)  # sinks (and check-killing calls) inside the test are real
        self.state = self._refine(self.state, node.test)

    def visit_Expr(self, node: ast.Expr) -> Any:
        match node.value:
            case ast.Call(func=func) as call if (
                (callee := resolve_callee(func)) is not None and callee.matches(*CHECK_CALLEE)
            ):
                # the statement form of certora.check: the gen postdominates the statement, so
                # falling through it is what the established atoms speak for
                self.generic_visit(call)  # arguments first; the callee attribute itself is inert
                site = self._digest(call, self.state)
                audit = self.enforcement.audit(site)
                self._record(audit)
                # the evaluator is a subprocess like any other call: it kills first ...
                self.state = self._killed(self.state, self.enforcement.writes_of(site))
                # ... and its success -- the only way past this statement -- establishes
                self._establish(audit.establishes)
            case _:
                self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> Any:
        callee = resolve_callee(node.func)
        if callee is None:
            raise InvalidProgram(node.func, "computed callee")  # f()(): no name to reason about
        self._container_call(node)
        self.generic_visit(node)  # children first: an inner call's effects precede the outer one
        site = self._digest(node, self.state)
        if callee.matches(*CHECK_CALLEE):
            # only the statement form (visit_Expr) has a program point whose fall-through the
            # success can speak for
            self._violation(node, "check: certora.check(...) must be a bare statement")
        else:
            self._record(self.enforcement.audit(site))
        if isinstance(node.func, ast.Name) and node.func.id in self.contracts:
            self._check_rely(node, node.func.id)
        # the kill: the site's facts were read above, so check-then-use survives;
        # check-call-then-use does not
        self.state = self._killed(self.state, self.enforcement.writes_of(site))

    def _container_call(self, node: ast.Call) -> None:
        """The roster methods on a tracked container: obligations for the writes, kind
        conformance, and the Sequence read-only rule. Pure reads need nothing here --
        ``interpret_expr`` knows ``pop`` and subscripts -- and an off-roster method is an
        escape, via ``visit_Name`` and the blessing pass."""
        match node.func:
            case ast.Attribute(value=ast.Name(id=name), attr=method):
                pass
            case _:
                return  # a method on a computed receiver, or a bare call: no roster here
        c = self.state.get(name)
        if not isinstance(c, Container) or method not in CONTAINER_METHODS:
            return
        if c.kind == "sequence":
            self._violation(node, f"{name!r} is a Sequence parameter: read-only")
            return
        if c.kind not in METHOD_KINDS[method]:
            self._violation(node, f"a {c.kind} has no {method}()")
            return
        if method in ("append", "add") and len(node.args) == 1:
            if not self.enforcement.establishes(operand_value(node.args[0], self.state), c.elem):
                self._unvouched_write(
                    node.args[0], name, c, "the appended element does not establish"
                )
        elif method == "insert" and len(node.args) == 2:
            if not self.enforcement.establishes(operand_value(node.args[1], self.state), c.elem):
                self._unvouched_write(
                    node.args[1], name, c, "the inserted element does not establish"
                )
        elif method == "extend" and len(node.args) == 1:
            self._extend(node, name, c, node.args[0])

    def _check_rely(self, node: ast.Call, name: str) -> None:
        """Bind the call to the contracted function's signature and hand each argument to the
        enforcement: every argument to a contracted parameter must establish its rely; a
        parameter left to its default is checked against the default."""
        fdef, contract = self.contracts[name]
        if not contract.params:
            return
        bound = bind_arguments(node, fdef)
        if bound is None:
            self._violation(node, f"call to {name}: arguments cannot be bound statically, so its rely cannot be discharged")
            return
        arguments: dict[str, Argument] = {}
        for param in contract.params:
            supplied = bound.get(param)
            if supplied is None:
                default = default_of(fdef, param)
                if default is None:
                    continue  # unbound without a default: bind() would have failed
                arguments[param] = Argument(node, operand_value(default, {}), defaulted=True)
            elif not isinstance(supplied, ast.expr):
                arguments[param] = Argument(node, None, starred=True)
            else:
                var = supplied.id if isinstance(supplied, ast.Name) else None
                entry = self.state.get(var) if var is not None else None
                arguments[param] = Argument(
                    supplied,
                    operand_value(supplied, self.state),
                    entry if isinstance(entry, Container) else None,
                    var,
                )
        for where_, what in self.enforcement.rely_failures(name, contract, arguments):
            self._violation(where_, what)

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
                self.state = else_end
            case False, False:
                self.state = {}  # unreachable

    def _loop(
        self,
        node: ast.For | ast.While,
        test: ast.expr | None,
        bindings: Mapping[str, ValidationFact] | None = None,
    ) -> None:
        # names assigned in the loop are unknown at every iteration boundary; one pass over the body
        # in that state covers all iterations, and nothing the body established survives the loop.
        # A ``for`` header rebinds its target on every iteration, so *bindings* is applied after the
        # kill and holds at every iteration start.
        # a container escaping anywhere in the body is a violation reported by the walked
        # pass itself: no escaped-set propagates to the boundary, because for any program
        # that survives, that set is empty (CONTAINERS.md)
        killed = _kill(self.state, _assigned_names([node]))
        # some iteration (or the header itself) may run an effectful call: nothing it reaches
        # survives an iteration boundary, so it neither enters the body nor survives the loop
        killed = self._killed(killed, self._writes_in([node]))
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
        # a Name target is a rebinding kill; a subscript target reaches visit_Name, so
        # ``for x[0] in ...`` is the container escape it deserves to be
        self.visit(node.target)
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
                    if isinstance(item.optional_vars, ast.Name):
                        # ``with open(p) as f`` on a proven path: f is a source handle
                        handle = self._maybe_call(
                            item.context_expr,
                            lambda c: self.enforcement.with_handle(self._digest(c, self.state)),
                        )
                        if handle is not None:
                            self.state[item.optional_vars.id] = handle
            self._block(node.body)

        if straight_line:
            bind_and_walk()
            return
        # a manager that may swallow an exception makes the body a ``try`` with a catch-all
        # handler that falls through: whatever the body established may not have happened
        escaped = _kill(self.state, _assigned_names([node]))
        # the body may have called before the escape
        escaped = self._killed(escaped, self._writes_in([node]))
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
        # the body may have called before raising
        handler_entry = self._killed(handler_entry, self._writes_in(killed_by))
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
        # ``finally`` runs on every path, in the joined state
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
        # container-roster positions, classified once, syntactically, for the whole tree
        self._blessed = _roster_blessings(node, self.contracts)
        # a module-level constant (a name bound by exactly one unconditional top-level assignment)
        # is immutable: module-level reassignment is forbidden and `global` is banned, so no code
        # can rebind it. Its fact therefore holds in every function body and may seed it.
        self.module_constants = self._module_constants(node)
        self.generic_visit(node)

    def _module_constants(self, module: ast.Module) -> dict[str, ValidationFact]:
        counts = _module_scope_binds(module.body)
        state: dict[str, ValidationFact] = {}
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
        rely: State = {}
        if contract is not None:
            for k, v in contract.params.items():
                # a container parameter arrives with param provenance: its escape is an error
                rely[k] = replace(v, param=True) if isinstance(v, Container) else v
        # seed the module constants the body may read. Exclude any name the function binds itself:
        # in Python such a name is local throughout the body (it shadows the module name), and the
        # rely then supplies the facts for the parameters.
        a = node.args
        local = {p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)}
        for extra in (a.vararg, a.kwarg):
            if extra is not None:
                local.add(extra.arg)
        local |= _assigned_names(node.body)
        # a constant's location (and any pure atom: the value is immutable) holds everywhere; an
        # environment check is anchored to a program point and does not survive into an arbitrary
        # call of the function
        seed: State = {
            k: self.enforcement.forget(v, EVERYTHING)
            for k, v in self.module_constants.items()
            if k not in local
        }
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
        value = node.value
        if isinstance(value, ast.Name) and isinstance(
            (c := self.state.get(value.id)), Container
        ):
            self._return_container(node, value.id, c)
            return
        if value is not None:
            self.visit(value)
        guarantee = self._guarantee
        if guarantee is None or is_plain_type(guarantee):
            return  # a plain return type is the type checker's business
        if isinstance(guarantee, Container):
            self._violation(
                node,
                "return does not establish the container guarantee (return a tracked local)",
            )
            return
        if value is None or not self.enforcement.establishes(operand_value(value, self.state), guarantee):
            self._violation(node, f"return does not establish the guarantee {describe_value(guarantee)}")

    def _return_container(self, node: ast.Return, name: str, c: Container) -> None:
        """Returning a tracked container: a *move* for a local -- the name dies, no alias
        survives, the return annotation is the guarantee -- and an aliasing error for a
        parameter, which would hand the caller a second name for its own container."""
        if c.param:
            self._violation(
                node,
                f"returning {name!r} aliases the caller's container: a parameter container "
                "may not be returned",
            )
            self.state.pop(name, None)
            return
        guarantee = self._guarantee
        establishes = self.enforcement.establishes
        if not isinstance(guarantee, Container):
            self._violation(
                node,
                f"returning container {name!r} needs a container return annotation "
                "(the move's guarantee)",
            )
        elif guarantee.kind == "sequence":
            if not establishes(c.elem, guarantee.elem):
                self._violation(node, "return does not establish the Sequence guarantee")
        elif guarantee.kind != c.kind or not (
            establishes(c.elem, guarantee.elem) and establishes(guarantee.elem, c.elem)
        ):
            self._violation(
                node,
                f"return does not establish the container guarantee (a {guarantee.kind} of "
                f"exactly {describe_value(guarantee.elem)})",
            )
        self.state.pop(name, None)  # moved out

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


def analyze(
    source: str,
    filename: str = "<program>",
    vocabulary: Vocabulary | None = None,
    discharge: Discharge | None = None,
) -> Report:
    """Run the whole pipeline over *source*. Raises ``SyntaxError`` for unparsable input.

    *vocabulary* is the policy's validation vocabulary (``Policy.vocabulary``); without it every
    ``certora.check`` is a violation, since no validation is declared. *discharge*
    (``Policy.discharger``) lets the walker run literal checkers while discharging relies and
    guarantees; without it only regex-defined atoms are established on known text."""
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

    walker = ValidationWalker(imports.imports, functions.contracts, vocabulary, discharge)
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
