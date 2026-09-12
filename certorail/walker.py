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
report, the kill onto the state, a check's atoms onto the variables it named. What a call to one
of the program's own module-level functions does is a ``summaries.Summary``, computed by the
walker as a fixpoint before the walk (EFFECTS.md, the callee analysis).

Kept apart from ``analysis`` (the domain and the expression semantics) so that this module can
import ``guards``, ``annotations`` and ``safepy`` -- which themselves import ``analysis`` -- without
a cycle:

    analysis  <-  terms, guards, annotations, safepy, enforcement  <-  summaries  <-  walker
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
    Std,
    StrFact,
    UrlString,
    Interpreter,
    LocationFact,
    StateMap,
    ValidationFact,
    destructure,
    inert,
    is_path_typed,
    resolve_callee,
)
from .annotations import Contract, bind_arguments, default_of, is_plain_type, parse_annotation
from .ids import Atom, SourceId
from .dangerous import CHECK_CALLEE, EXEC_CALLEE, EXTRACT_ALL_CALLEE, LINES_CALLEE
from .enforcement import (
    CONTAINER_METHODS,
    CONTAINER_READ_CALLS,
    METHOD_KINDS,
    NO_KILL,
    OPAQUE,
    OPENING,
    Argument,
    Audit,
    Callsite,
    CheckSignature,
    CheckSite,
    Discharge,
    Enforcement,
    ExecSite,
    Kill,
    NetworkSite,
    ProgramCall,
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
    ContainerClosureAnalysis,
    FunctionAnalysis,
    ImportAnalysis,
    InheritanceAnalysis,
    ValidationAnalysis,
)
from .summaries import (
    BOTTOM,
    HAVOC,
    NEVER,
    Result,
    Summary,
    is_generator,
    join_result,
    module_functions,
    property_names,
)
from .templates import Binding, Elements, Many
from .terms import Call, Method, lower

__all__ = [
    "Argument", "Audit", "Callsite", "CheckSignature", "CheckSite", "Enforcement", "ExecSite",
    "NetworkSite", "Report", "SinkSite", "Site", "SourceTable", "State", "ValidationWalker",
    "Vocabulary", "WriteTable", "analyze", "describe_sink", "describe_value", "host_matches",
    "where",
]

type State = dict[str, ValidationFact | Container | Data | Std]


@dataclass
class _Frame:
    """What a scoped block did, read after its scope closes: the kill it applied, and -- for a
    function body -- what it returned."""

    kill: Kill = NO_KILL
    result: Result = NEVER


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
    """Facts that hold on both paths: equal entries as they are; two standard values as one of
    the common kind, closed when both are; two handles as one with the sources both have, the
    locations either may write, closed when both are; two inert scalars that differ -- text on
    one path, a number on the other -- as a standard value of unknown kind. A container or a
    handle against anything else is dropped: a write handle must never become a mere inert
    value, or a write through it would go unkilled. Equality otherwise; the lattice join for
    facts (``join_loc`` &c.) slots in here once it lands."""
    out: State = {}
    for k, v in a.items():
        other = b.get(k)
        if other is None:
            continue
        if other == v:
            out[k] = v
        elif isinstance(v, Std) and isinstance(other, Std):
            out[k] = Std(v.kind if v.kind == other.kind else None, v.closed and other.closed)
        elif isinstance(v, Data) and isinstance(other, Data):
            writes: tuple[LocationFact, ...] | None
            if v.writes is None and other.writes is None:
                writes = None
            else:
                writes = tuple(v.writes or ()) + tuple(w for w in other.writes or () if w not in (v.writes or ()))
            out[k] = Data(v.sources & other.sources, v.closed and other.closed, writes)
        elif isinstance(v, (Container, Data)) or isinstance(other, (Container, Data)):
            continue
        elif isinstance(v, Std) or isinstance(other, Std):
            out[k] = Std(None, inert(v) and inert(other))
        elif replace(v, atoms=frozenset()) == replace(other, atoms=frozenset()):
            # the same fact, differently attested: an atom died on one path (an effect there),
            # or was established on one path only -- what both paths carry survives
            out[k] = replace(v, atoms=v.atoms & other.atoms)
        else:
            out[k] = Std(None, True)  # two facts of different shape: text or a path either way
    return out


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
        # bodies. Scalars only: containers are never module constants (and may not be closed
        # over), and a standard value only when nothing can open it.
        self.module_constants: dict[str, ValidationFact | Std] = {}
        # ast.Name occurrences (by id) in container-roster positions; any other Load of a
        # tracked container is its escape. Filled once per module by visit_Module.
        self._blessed: set[int] = set()
        # what the walk has done to the state since the innermost ``_measuring`` began: the kills
        # of one loop iteration, one comprehension, one try body, one function body -- the
        # boundaries the walk does not pass through, and the summaries, are computed from it
        self._seen: Kill = NO_KILL
        # the callee analysis' second half (summaries.py): the module-level functions and what
        # one call of each does, computed by visit_Module before the walk; the names defined
        # as properties anywhere, whose read is an unknown call
        self.functions: dict[str, ast.FunctionDef] = {}
        self.summaries: dict[str, Summary] = {}
        self.property_names: frozenset[str] = frozenset()
        # what the function body being walked has been seen to return (joined over its returns)
        self._result: Result = NEVER

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

    def _interpreter(self, st: StateMap | None = None) -> Interpreter:
        """The expression semantics against *st* -- the current state unless another is given
        (a comprehension's scope, a seed) -- under this program's module names. The current
        state is copied: the interpreter answers for it as it was when asked for, however the
        walk mutates the live one afterwards. An explicitly passed *st* is the caller's own."""
        return Interpreter(dict(self.state) if st is None else st, self.modules)

    def _refine(self, st: State, cond: ast.expr) -> State:
        """*st* with everything *cond* being true establishes."""
        out = dict(st)
        for g in recognize(lower(cond, self.modules), out):
            current = out.get(g.subject)
            if isinstance(current, (Container, Data)):
                continue  # guards speak about scalars; containers and handles have their own rules
            # a standard value refined by a guard (``isinstance(x, str)``) becomes the fact the
            # guard establishes, from nothing; otherwise it stays what it was
            refined = apply(None if isinstance(current, Std) else current, g.refinement)
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

    def _digest(self, call: ast.Call, st: State) -> Callsite:
        """*call* as the enforcement sees it, against *st*."""
        callee = resolve_callee(call.func)
        assert callee is not None, "visit_Call refuses computed callees before digesting"

        semantics = self._interpreter(st)

        def value(e: ast.expr) -> Binding:
            return None if isinstance(e, ast.Starred) else self._binding(e, st)

        receiver: ValidationFact | Container | Data | Std | None = None
        if isinstance(call.func, ast.Attribute):
            receiver = semantics.interpret(call.func.value)

        # the argument conditions of the callee analysis: plain positionals, ``*xs`` (the
        # inertness of xs), ``name=value``, ``**m`` (the inertness of m)
        plain = [semantics.is_inert(a) for a in call.args if not isinstance(a, ast.Starred)]
        starred = [semantics.is_inert(a) for a in call.args if isinstance(a, ast.Starred)]
        named = [semantics.is_inert(k.value) for k in call.keywords if k.arg is not None]
        double = [semantics.is_inert(k.value) for k in call.keywords if k.arg is None]
        inert_keywords = all(named)
        inert_splats = all(starred) and all(double)

        def handle_of(which: int | str) -> Data | None:
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
            # a source call inline
            return self._maybe_call(e, lambda c: self.enforcement.handle(self._digest(c, st)))

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
            inert_arguments=all(plain) and inert_keywords and inert_splats,
            inert_keywords=inert_keywords,
            inert_splats=inert_splats,
        )

    def _binding(self, expr: ast.expr, st: State) -> Binding:
        """An argument as the policy will bind it: a display is the sequence of its elements, a
        tracked container its element fact, anything else a value."""
        semantics = self._interpreter(st)
        match expr:
            case ast.List(elts=elts) | ast.Tuple(elts=elts):
                return Many(tuple(semantics.operand(e) for e in elts))
            case ast.Name(id=name) if isinstance(container := st.get(name), Container):
                return Elements(container.elem)
            case _:
                return semantics.operand(expr)

    def _sources_of(self, expr: ast.expr) -> frozenset[SourceId] | None:
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

    def _establish(self, atoms_by_name: Mapping[str, frozenset[Atom]]) -> None:
        """A check's success, on the variables it named: a fact needs a variable to live on."""
        for name, atoms in atoms_by_name.items():
            fact = self.state.get(name)
            if fact is not None and not isinstance(fact, (Container, Data, Std)):
                self.state[name] = replace(fact, atoms=fact.atoms | atoms)

    def _killed(self, st: State, kill: Kill) -> State:
        """*st* after a call: every atom the write set reaches dies, on every variable and on
        every container's element fact (the annotation is only the birth invariant; reads yield
        the current, possibly degraded fact); a handle carries only source atoms, which are pure.
        When the call opens the state -- program code may have run, or a program object was
        stored -- every standard value and handle that can hold one is opened."""
        if kill.nothing:
            return st
        forget = self.enforcement.forget
        out: State = {}
        for k, v in st.items():
            match v:
                case Container(elem=elem):
                    out[k] = replace(v, elem=forget(elem, kill))
                case Data() | Std():
                    out[k] = v.opened() if kill.opens else v
                case _:
                    out[k] = forget(v, kill)
        return out

    def _kill_state(self, kill: Kill) -> None:
        """Apply a call's or a store's kill to the state, and count it for the enclosing measure."""
        self.state = self._killed(self.state, kill)
        self._seen = self._seen | kill

    # -- scopes: the walk's registers, saved and restored as blocks ----------------------------
    #
    # Beside the state, the walk keeps three registers: what has been done to the state since
    # the innermost measure began (``_seen``), and -- for the function body being walked -- its
    # guarantee and what it has been seen to return. Each is scoped by a context manager below;
    # nothing saves or restores one by hand.

    @contextmanager
    def _measuring(self, *, counted: bool = True):
        """Measure what the block does to the state. The frame's ``kill`` is filled on exit.
        *counted*: the enclosing measure keeps counting it -- not for a rehearsal or a function
        body, which do not run here."""
        outer, self._seen = self._seen, NO_KILL
        frame = _Frame()
        try:
            yield frame
        finally:
            frame.kill = self._seen
            self._seen = outer | frame.kill if counted else outer

    @contextmanager
    def _unrecorded(self):
        """Walk for the verdicts alone: no site and no violation the block reports is kept."""
        sinks, violations = list(self.sinks), list(self.violations)
        try:
            yield
        finally:
            self.sinks, self.violations = sinks, violations

    @contextmanager
    def _function_scope(self, guarantee: ValidationFact | Container | None, seed: State):
        """A function body's own scope: it starts from *seed*, its returns are checked against
        *guarantee*, and what it does and returns is its own -- the frame's ``kill`` and
        ``result`` on exit -- not the enclosing walk's, which did not run it."""
        saved = self._guarantee, self._result
        self._guarantee, self._result = guarantee, NEVER
        try:
            with self.state_snapshot(), self._measuring(counted=False) as frame:
                self.state = seed
                yield frame
                frame.result = self._result
        finally:
            self._guarantee, self._result = saved

    def _measure(self, walk: Callable[[], None]) -> Kill:
        """Run *walk* and answer what it did to the state; the enclosing measure keeps counting."""
        with self._measuring() as frame:
            walk()
        return frame.kill

    def _rehearse(self, walk: Callable[[], None], state: State) -> Kill:
        """Walk once from *state* for the verdicts alone -- what the calls and stores of *walk*
        do to the state -- recording nothing and leaving the state as it was. For the states the
        walk does not otherwise pass through: a loop's later iterations."""
        with self._unrecorded(), self.state_snapshot(), self._measuring(counted=False) as frame:
            self.state = dict(state)
            walk()
        return frame.kill

    def _every_iteration(self, iteration: Callable[[], None], boundary: State) -> Kill:
        """What every iteration of a body may do, from the state at the iteration boundary. A
        verdict depends on what the receiver and the arguments *are* -- their types and
        closedness -- never on the atoms they carry, and the names an iteration assigns are
        already unknown at the boundary, so one rehearsal answers for every iteration of a body
        that opens nothing. A body that opens something may find, next time round, an opened
        value where it found a closed one; a second rehearsal from the opened boundary answers
        for those iterations, and no third can differ: closedness has two points and opening is
        state-wide."""
        once = self._rehearse(iteration, boundary)
        if once.opens:
            once = once | self._rehearse(iteration, self._killed(boundary, once))
        return once

    # -- the callee analysis: summaries (summaries.py) ------------------------------------------

    def _kill_of(self, site: Callsite) -> Kill:
        """What a call does to the state: the enforcement's verdict, or -- for a call of a bare
        name that is no builtin -- the callee's summary. Only a module-level function has one
        (its name is bound once and never rebound, so the call is that function's); a class
        instantiated, a nested function, a lambda or a parameter called havocs the world."""
        verdict = self.enforcement.kill_of(site)
        return verdict if isinstance(verdict, Kill) else self._program_summary(verdict).kill

    def _program_summary(self, call: ProgramCall) -> Summary:
        return self.summaries.get(call.name, HAVOC)

    def _result_of(self, value: ast.expr | None) -> Result:
        """What a ``return`` hands back, as far as the callee analysis cares: a standard value,
        or possibly a program object."""
        if value is None:
            return Std("none")
        match self._interpreter().interpret(value):
            case Std() as std:
                return std
            case None:
                # a call the expression semantics do not know: a module-level function's own result
                return self._maybe_call(value, self._call_result)
            case _:
                return Std()  # text, a path, a container of facts, a handle: inert

    def _call_result(self, call: ast.Call) -> Result:
        verdict = self.enforcement.kill_of(self._digest(call, self.state))
        return self._program_summary(verdict).result if isinstance(verdict, ProgramCall) else None

    def _seed(self, node: ast.FunctionDef) -> State:
        """The state a function body starts from: the module constants it does not shadow -- a
        constant's location (and any pure atom: the value is immutable) holds everywhere, an
        environment check is anchored to a program point and does not survive into an arbitrary
        call; a standard constant is seeded only when nothing can open it -- and the rely of its
        contract, for the parameters."""
        entry = self.contracts.get(node.name)
        contract = entry[1] if entry is not None and entry[0] is node else None
        a = node.args
        local = {p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)}
        for extra in (a.vararg, a.kwarg):
            if extra is not None:
                local.add(extra.arg)
        local |= _assigned_names(node.body)
        seed: State = {
            k: v if isinstance(v, Std) else self.enforcement.forget(v, OPAQUE)
            for k, v in self.module_constants.items()
            if k not in local
        }
        if contract is not None:
            for k, v in contract.params.items():
                # a container parameter arrives with param provenance: its escape is an error
                seed[k] = replace(v, param=True) if isinstance(v, Container) else v
        return seed

    def _summarize(self, node: ast.FunctionDef) -> Summary:
        """What one call of the module-level function *node* does, walked from its seed with the
        summaries as they stand: the kill its body applies, and what it returns -- ``None`` when
        it falls off the end, never inert for a generator function (the body's kill is applied
        at creation, the generator is a program object)."""
        with self._unrecorded(), self._function_scope(None, self._seed(node)) as frame:
            self._block(node.body)
            if _falls_through(node.body):
                self._result = join_result(self._result, Std("none"))
        return Summary(frame.kill, None if is_generator(node) else frame.result)

    def _compute_summaries(self) -> None:
        """The summaries of the module-level functions, as a fixpoint: every summary starts at
        the bottom (a call does nothing, returns nowhere) and each round re-summarizes every
        body against the current summaries, joining onto the old one, until nothing grows.
        Terminates: the lattice is finite and the join only ascends."""
        self.summaries = {name: BOTTOM for name in self.functions}
        changed = True
        while changed:
            changed = False
            for name, node in self.functions.items():
                grown = self.summaries[name] | self._summarize(node)
                if grown != self.summaries[name]:
                    self.summaries[name] = grown
                    changed = True

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
            fact: ValidationFact | Container | Data | Std | None = None
            if site is not None:
                fact = self.enforcement.handle(site)
                if fact is None:
                    fact = self.enforcement.extract_fact(site)
            if fact is None:
                fact = self._interpreter().interpret(value)
                if isinstance(fact, Container):
                    fact = None  # ``y = xs`` aliases a tracked container: its escape, visit_Name's
            if fact is None:
                fact = self._guaranteed(value)
            if fact is None and site is not None:
                fact = self.enforcement.check_single_fact(site)
            if fact is None:
                # a module-level function's summary result: a standard value, or nothing known
                result = self._maybe_call(value, self._call_result)
                fact = result if isinstance(result, Std) else None
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
        elif isinstance(target, ast.Subscript):
            self.visit(target)
            if not self._interpreter().is_inert(value):
                self._kill_state(OPENING)  # ``d[k] = gen``: into some standard value
        elif isinstance(target, (ast.Tuple, ast.List)) and self._interpreter().is_inert(value):
            self.visit(target)  # the rebinding kills, then each name is an element of an inert value
            self.state.update(destructure(target, Std()))
        else:
            self.visit(target)  # tuple/attribute targets: kill the names involved; an attribute store opens

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
        if not self.enforcement.establishes(self._interpreter().operand(value), c.elem):
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
        self, node: ast.expr, sources: frozenset[SourceId] | None, declared: Container
    ) -> bool:
        if sources is None:
            return False  # the extractor's audit reported the non-source
        if not self.enforcement.establishes(StrFact(atoms=frozenset(sources)), declared.elem):
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
        inner.update(self._interpreter().iteration_bindings(gen.target, gen.iter))
        for cond in gen.ifs:
            inner = self._refine(inner, cond)
        fact = self._maybe_call(
            elt, lambda c: self.enforcement.check_single_fact(self._digest(c, inner))
        )
        if fact is None:
            fact = self._interpreter(inner).operand(elt)
        if fact is not None and not isinstance(fact, str):
            # what any iteration may do, rehearsed from the state after the comprehension ran
            # (the comprehension's own walk already answers for every iteration)
            every = self._rehearse(lambda: self.visit(comp), self.state)
            fact = self.enforcement.forget(fact, every)
        if not self.enforcement.establishes(fact, declared.elem):
            self._violation(
                elt,
                f"the comprehension element does not establish {describe_value(declared.elem)}",
            )
            return False
        return True

    def _elements_establish(self, elts: Sequence[ast.expr], elem: ValidationFact) -> bool:
        ok = True
        semantics = self._interpreter()
        for i, e in enumerate(elts):
            if isinstance(e, ast.Starred) or not self.enforcement.establishes(
                semantics.operand(e), elem
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
        self.visit(node.value)
        target = node.target
        if isinstance(target, ast.Name):
            # ``x op= v`` rebinds x to ``x op v``: text stays text, a standard value stays one
            # over an inert operand
            combined = ast.copy_location(
                ast.BinOp(left=ast.Name(id=target.id, ctx=ast.Load()), op=node.op, right=node.value),
                node,
            )
            fact = self._interpreter().interpret(combined)
            self.visit(target)  # the rebinding kill
            if fact is not None:
                self.state[target.id] = fact
        else:
            self.visit(target)  # a subscript or attribute target: the store lands in some value
        if not self._interpreter().is_inert(node.value):
            self._kill_state(OPENING)  # ``lst += [f]``: a program object may now sit in it

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        self.generic_visit(node)
        if isinstance(node.ctx, ast.Store):
            # a store through an attribute may register a program object with a standard value
            # or a handle -- the receiver, or anything aliasing it -- so the state is opened
            self._kill_state(OPENING)
        elif isinstance(node.ctx, ast.Load) and node.attr in self.property_names:
            # a read by a name some class defines as a property may run that getter (EFFECTS.md):
            # program code, unless the receiver is known to be no program object
            receiver = node.value
            if isinstance(receiver, ast.Name) and receiver.id in self.modules:
                return
            if not inert(self._interpreter().interpret(receiver)):
                self._kill_state(OPAQUE)

    def visit_Lambda(self, node: ast.Lambda) -> Any:
        # the defaults are evaluated now. The body runs only when the lambda is called, which
        # havocs, so its kills do not count here; but its sinks and its roster obligations (a
        # write to a container it closes over) are audited now, in a scope of its own with the
        # parameters unknown
        for d in [*node.args.defaults, *node.args.kw_defaults]:
            if d is not None:
                self.visit(d)
        a = node.args
        params = [p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
        params += [extra.arg for extra in (a.vararg, a.kwarg) if extra is not None]
        with self.state_snapshot(), self._measuring(counted=False):
            for name in params:
                self.state.pop(name, None)
            self.visit(node.body)

    # -- comprehensions: their own scope, eager --------------------------------------------------

    def _comprehension(
        self, generators: Sequence[ast.comprehension], body: Sequence[ast.expr]
    ) -> None:
        """Walk a comprehension in its own scope: each iterable in the state so far, then the
        ``if`` clauses and the element expressions under the iteration bindings, so that a call
        inside sees what its receiver is (``[x.strip() for x in lines]``). Eager for a generator
        expression too: its body's kills are applied at creation (EFFECTS.md). The scope's names
        return to their outer values afterwards, and the state takes what every iteration may
        do (``_every_iteration``)."""
        outer = self.state
        self.state = dict(outer)
        bound: set[str] = set()

        def iteration() -> None:
            for gen in generators:
                self.visit(gen.iter)
                names = {n.id for n in ast.walk(gen.target) if isinstance(n, ast.Name)}
                bound.update(names)
                for name in names:
                    self.state.pop(name, None)
                self.state.update(self._interpreter().iteration_bindings(gen.target, gen.iter))
                for cond in gen.ifs:
                    self.visit(cond)
                    self.state = self._refine(self.state, cond)
            for e in body:
                self.visit(e)

        once = self._measure(iteration)
        if once.opens:
            # the first iteration is the walked one; the later ones start from what it opened
            once = once | self._rehearse(iteration, self._killed(dict(outer), once))
        self.state = {k: v for k, v in self.state.items() if k not in bound} | {
            k: v for k, v in outer.items() if k in bound
        }
        self._kill_state(once)

    def visit_ListComp(self, node: ast.ListComp) -> Any:
        self._comprehension(node.generators, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> Any:
        self._comprehension(node.generators, [node.elt])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> Any:
        self._comprehension(node.generators, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> Any:
        self._comprehension(node.generators, [node.key, node.value])

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
        semantics = self._interpreter()
        return all(
            not isinstance(e, ast.Starred)
            and self.enforcement.establishes(semantics.operand(e), elem)
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
                self._kill_state(self._kill_of(site))
                # ... and its success -- the only way past this statement -- establishes
                self._establish(audit.establishes)
            case _:
                self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> Any:
        callee = resolve_callee(node.func)
        if callee is None:
            raise InvalidProgram(node.func, "computed callee")  # f()(): no name to reason about
        self._container_call(node)
        # children first: an inner call's effects precede the outer one. The receiver of a
        # method call is visited, the method name itself is not a read (a property called is
        # program code either way: the receiver is no standard value, so the call havocs)
        if isinstance(node.func, ast.Attribute):
            self.visit(node.func.value)
        for a in node.args:
            self.visit(a)
        for k in node.keywords:
            self.visit(k.value)
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
        self._kill_state(self._kill_of(site))

    def _container_call(self, node: ast.Call) -> None:
        """The roster methods on a tracked container: obligations for the writes, kind
        conformance, and the Sequence read-only rule. Pure reads need nothing here --
        the ``Interpreter`` knows ``pop`` and subscripts -- and an off-roster method is an
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
            if not self.enforcement.establishes(self._interpreter().operand(node.args[0]), c.elem):
                self._unvouched_write(
                    node.args[0], name, c, "the appended element does not establish"
                )
        elif method == "insert" and len(node.args) == 2:
            if not self.enforcement.establishes(self._interpreter().operand(node.args[1]), c.elem):
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
                arguments[param] = Argument(node, self._interpreter({}).operand(default), defaulted=True)
            elif not isinstance(supplied, ast.expr):
                arguments[param] = Argument(node, None, starred=True)
            else:
                var = supplied.id if isinstance(supplied, ast.Name) else None
                entry = self.state.get(var) if var is not None else None
                arguments[param] = Argument(
                    supplied,
                    self._interpreter().operand(supplied),
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
        bindings: Mapping[str, ValidationFact | Std] | None = None,
    ) -> None:
        # names assigned in the loop are unknown at every iteration boundary; one pass over the body
        # in that state covers all iterations, and nothing the body established survives the loop.
        # A ``for`` header rebinds its target on every iteration, so *bindings* is applied after the
        # kill and holds at every iteration start.
        # a container escaping anywhere in the body is a violation reported by the walked
        # pass itself: no escaped-set propagates to the boundary, because for any program
        # that survives, that set is empty (CONTAINERS.md)
        killed = _kill(self.state, _assigned_names([node]))

        def iteration(*, header: bool) -> None:
            if test is not None:
                if header:
                    self.visit(test)  # a ``while`` header re-runs every time round
                self.state = self._refine(self.state, test)
            self._bind_iteration(node, bindings or {})
            self._block(node.body)

        # some iteration (or the header itself) may run an effectful call: nothing it reaches
        # survives an iteration boundary, so it neither enters the body nor survives the loop
        killed = self._killed(killed, self._every_iteration(lambda: iteration(header=True), killed))
        with self.state_snapshot():
            self.state = dict(killed)
            iteration(header=False)  # the header's first run was visited by the caller
        with self.state_snapshot():
            self.state = dict(killed)
            self._block(node.orelse)  # runs only when the loop was not left by ``break``
            orelse_end = self.state
        self.state = _join(orelse_end, killed) if _may_break(node.body) else orelse_end

    def _bind_iteration(
        self, node: ast.For | ast.While, bindings: Mapping[str, ValidationFact | Std]
    ) -> None:
        """Bind the loop target at the start of an iteration. A fact binding was read off the
        iterable in the pre-loop state and holds for every iteration: the iterator was made
        from that value. A standard-value binding says the iterable was inert *then*; the
        iterator walks the live object, which an iteration may have opened (``for x in xs:
        xs.append(f)``), so it is re-read from the state of this iteration."""
        for name, bound in bindings.items():
            self.state[name] = bound
        if isinstance(node, ast.For) and any(isinstance(b, Std) for b in bindings.values()):
            fresh = self._interpreter().iteration_bindings(node.target, node.iter)
            for name, bound in bindings.items():
                if isinstance(bound, Std):
                    now = fresh.get(name)
                    if now is None:
                        self.state.pop(name, None)
                    else:
                        self.state[name] = now

    def visit_For(self, node: ast.For) -> Any:
        self.visit(node.iter)
        # a Name target is a rebinding kill; a subscript target reaches visit_Name, so
        # ``for x[0] in ...`` is the container escape it deserves to be
        self.visit(node.target)
        # the iterable is evaluated once, before the loop, in the pre-loop state
        self._loop(node, None, self._interpreter().iteration_bindings(node.target, node.iter))

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
                return is_path_typed(self._interpreter().expr(recv.node))  # Path.open
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
        with self.state_snapshot():
            body_kills = self._measure(bind_and_walk)
            body_end = self.state
        # the body may have called before the escape
        self.state = _join(body_end, self._killed(escaped, body_kills))

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
            # the body may have called before raising
            body_kills = self._measure(lambda: self._block(node.body))
            self._block(node.orelse)  # runs only after the body completed normally
            ends.append(self.state)
        handler_entry = self._killed(handler_entry, body_kills)
        if handlers_chain:
            # ... and, for ``except*``, so may the handlers that ran before this one
            for h in node.handlers:
                handler_entry = self._killed(
                    handler_entry, self._rehearse(lambda h=h: self._block(h.body), handler_entry)
                )
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
        # the callee analysis' summaries, before any call is walked: a module-level function may
        # be called before its definition is reached
        self.functions = module_functions(node)
        self.property_names = property_names(node)
        self._compute_summaries()
        self.generic_visit(node)

    def _module_constants(self, module: ast.Module) -> dict[str, ValidationFact | Std]:
        """The module-level constants every function body may rely on: a name bound by exactly
        one unconditional top-level assignment, to a value nothing can change. Scalars only: a
        container is mutable, and a body may not close over one at all (``safepy``, CONTAINERS.md)."""
        counts = _module_scope_binds(module.body)
        state: dict[str, ValidationFact | Std] = {}
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
                # earlier constants are in scope for later ones
                fact = self._interpreter(state).interpret(value)
                if fact is None:
                    fact = self._guaranteed(value)
            except InvalidProgram:
                continue  # a malformed value; the main walk reports it
            match fact:
                case StrFact() | PathFact() | Located():
                    state[name] = fact
                case Std(openable=False):
                    # a number, a bytes literal, ...: immutable, so it holds everywhere; a list
                    # or a dict does not -- some function may have opened it by the time
                    # another runs
                    state[name] = fact
                case _:
                    pass
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
        guarantee = None if contract is None else contract.returns
        with self._function_scope(guarantee, self._seed(node)):
            self._block(node.body)
            if guarantee is not None and not is_plain_type(guarantee) and _falls_through(node.body):
                self._violation(node, f"{node.name} may fall off its end without establishing its guarantee")
        self.state.pop(node.name, None)

    def visit_Return(self, node: ast.Return) -> Any:
        value = node.value
        if isinstance(value, ast.Name) and isinstance(
            (c := self.state.get(value.id)), Container
        ):
            self._result = join_result(self._result, Std())  # a container of facts: inert
            self._return_container(node, value.id, c)
            return
        if value is not None:
            self.visit(value)
        self._result = join_result(self._result, self._result_of(value))
        guarantee = self._guarantee
        if guarantee is None or is_plain_type(guarantee):
            return  # a plain return type is the type checker's business
        if isinstance(guarantee, Container):
            self._violation(
                node,
                "return does not establish the container guarantee (return a tracked local)",
            )
            return
        if value is None or not self.enforcement.establishes(self._interpreter().operand(value), guarantee):
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
    if vocabulary is not None:
        # a contract's atoms are spelled by kind (certora.validated / certora.source); the
        # policy's kind table holds the author to it (ATOMS.md)
        problems: list[tuple[ast.AST, str]] = []
        for fdef, contract in functions.contracts.values():
            for declared in (*contract.params.values(), contract.returns):
                fact = declared.elem if isinstance(declared, Container) else declared
                problem = None if fact is None else vocabulary.annotation_problem(fact)
                if problem is not None:
                    problems.append((fdef, f"{fdef.name}: {problem}"))
        if problems:
            return Report(violations=problems)

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

    closures = ContainerClosureAnalysis()
    closures.visit(tree)
    if closures.violations:
        return Report(violations=list(closures.violations))

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
