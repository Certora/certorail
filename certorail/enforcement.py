"""Enforcement: what the policy has to say about one call.

The dataflow walker (``walker.py``) owns the program -- its syntax, the state (a fact per
variable), control flow, joins, and kills by assignment. This module owns every decision that
says *site*, *dies*, *yields* or *does not establish*:

- the shape audits, which turn a call into a ``Site`` for the policy to evaluate, or into
  violations (``audit``);
- the kill: what a call does to the state (``kill_of``: the regions it writes, whether it may
  run program code) and which atoms a write set kills (``survivors``, ``forget``), EFFECTS.md;
- provenance: the source handle a call yields, the fact an extractor produces (``handle``,
  ``with_handle``, ``extract_fact``, ``check_single_fact``), PROVENANCE.md;
- entailment: does a value establish what a rely, a guarantee, a container element or a check
  demands (``establishes``, ``rely_failures``).

It never reads an ``ast`` node. The walker digests a call into a ``Callsite`` -- the callee, the
arguments and keywords as the state sees them, the receiver's fact -- and hands that over, one
call at a time; ``ast`` appears here only as an opaque handle to report against. What comes back
is a verdict or a delta (an ``Audit``: sites, violations, and the atoms a check establishes on
which variables), and the walker applies it. Nothing here mutates state.

Also here, because the policy and the host need them without the walker: the ``Site`` records,
the analysis-side vocabulary (``Vocabulary``, ``CheckSignature``, ``SourceTable``,
``WriteTable``), the container roster, and the renderers ``describe_sink`` / ``describe_value``.
"""
import ast
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import KW_ONLY, dataclass, field, replace
from typing import Protocol

from . import jqpath
from .analysis import (
    ANY_STR,
    Alternation,
    Container,
    Data,
    Exact,
    Located,
    LocationFact,
    NameAccess,
    PathFact,
    PseudoRegex,
    StaticPath,
    Std,
    StrFact,
    UrlString,
    ValidationFact,
    as_fact,
    as_text,
    atoms_of,
    bind_values,
    carried,
    entails,
    holds,
    inert_receiver,
    is_path_typed,
    known_text,
    locate,
    location_le,
    pretty_location,
    pretty_regex,
    scalar,
    url_of,
    _regex_subsumes,
)
from .annotations import Contract, is_plain_type
from .dangerous import (
    CHECK_CALLEE,
    CHECK_SINGLE_CALLEE,
    EXEC_CALLEE,
    EXEC_CWD,
    EXEC_OPTION_KEYWORDS,
    EXEC_REQUIRED_KEYWORDS,
    EXEC_RESERVED_KEYWORDS,
    EXTRACT_ALL_CALLEE,
    EXTRACT_CALLEE,
    FIELD_CALLEE,
    FILE_WRITE_METHODS,
    LINES_CALLEE,
    NETWORK_BODY_METHODS,
    NETWORK_METHODS,
    NETWORK_NAMESPACE,
    PATHMATCH_CALLEE,
    PATH_SINK_FUNCTIONS,
    PATH_SINK_METHOD_TARGETS,
    PATH_SINK_METHODS,
    AccessKind,
    inert_condition,
)
from .effects import EVERYTHING, NOTHING, Effects, Medium
from .footprints import Footprint, overlaps
from .ids import BUILTIN_ATOMS, Atom, CheckId, ParamName, ProgramName, RegionId, SourceId, ValidationName
from .locations import parse_location
from .templates import Binding, Elements, Many, Value, matches_leading

# ---------------------------------------------------------------------------
# the container roster (CONTAINERS.md): the method surface that keeps a tracked list/set tracked
# ---------------------------------------------------------------------------

# Writes carry an entailment obligation; "sequence" -- the borrowed view a Sequence[...]
# parameter receives -- admits none of the mutators.
CONTAINER_METHODS: frozenset[str] = frozenset(
    {"append", "insert", "extend", "add", "remove", "discard", "clear", "sort", "pop"}
)
# which kinds carry which method (a mismatch is a violation, not an escape)
METHOD_KINDS: dict[str, tuple[str, ...]] = {
    "append": ("list",), "insert": ("list",), "extend": ("list",), "sort": ("list",),
    "add": ("set",), "discard": ("set",),
    "remove": ("list", "set"), "clear": ("list", "set"), "pop": ("list", "set"),
}
# bare-name calls that only read a container handed to them
CONTAINER_READ_CALLS: frozenset[str] = frozenset(
    {"len", "sorted", "list", "set", "tuple", "iter", "reversed", "enumerate"}
)

# Methods of the standard containers that reach their arguments only through ``__hash__`` and
# ``__eq__`` -- fixed, since no program class defines a dunder -- so they run no program code
# whatever they are given (EFFECTS.md). Storing a non-inert argument still opens the state.
HASH_IDENTITY_METHODS: frozenset[str] = frozenset(
    {"append", "insert", "index", "count", "remove", "get", "setdefault", "pop", "add", "discard"}
)


# ---------------------------------------------------------------------------
# the kill: what one call does to the state
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Kill:
    """What one call does to the state (EFFECTS.md): the regions it may write -- every
    environmental atom reading one dies -- and whether it *opens* the standard values and
    handles: program code may have run inside it, so any list, dict, set or unknown-kind value
    may now hold a program object through an alias, or a non-inert value was stored into one.

    ``file_writes`` are the program's own writes to proven locations, which write no named
    region as such: what they kill is *derived* -- an atom dies when a write can lie at or below
    one of the footprints instantiated for it (``footprints.py``), or when the atom depends on
    everything or on the whole filesystem. A write to an unproven location is ``EVERYTHING``
    instead (and the sink audit rejects the program anyway)."""

    writes: Effects
    opens: bool
    file_writes: tuple[LocationFact, ...] = ()

    @property
    def nothing(self) -> bool:
        return self.writes.empty and not self.opens and not self.file_writes

    def __or__(self, other: "Kill") -> "Kill":
        writes = list(self.file_writes)
        for w in other.file_writes:
            if w not in writes:  # locations are not hashable (a regex holds lists): dedupe by equality
                writes.append(w)
        return Kill(self.writes | other.writes, self.opens or other.opens, tuple(writes))


NO_KILL = Kill(NOTHING, opens=False)  # the interpreter's own code over inert values
OPENING = Kill(NOTHING, opens=True)  # a store that may put a program object into a standard value
OPAQUE = Kill(EVERYTHING, opens=True)  # program code may run: anything may happen


@dataclass(frozen=True)
class ProgramCall:
    """A call of a bare name that is no builtin: a function or a class this program defines,
    or a variable holding a callable. What it does is the program's business -- the walker
    resolves it to a summary (``summaries.py``) or to havoc -- not the policy's."""

    name: str


# ---------------------------------------------------------------------------
# sites: what the policy evaluates
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SinkSite:
    """A filesystem operation (``open``, ``os.listdir``, ``p.read_text()``, ...) and what the
    analysis knew about the path it touches."""

    node: ast.AST
    what: str
    fact: ValidationFact | None
    kind: AccessKind

    @property
    def confined(self) -> bool:
        return isinstance(self.fact, Located)


@dataclass(frozen=True)
class ExecSite:
    """A ``certora.exec(program, *args, cwd=...)`` call: the controlled shell-out."""

    node: ast.AST
    program: str
    arguments: tuple[Value, ...]
    cwd: ValidationFact | None
    # hole bindings by keyword (TEMPLATES.md): a value, a display (Many), or a typed container
    # (Elements); which holes exist is the policy's business
    keywords: Mapping[str, Binding] = field(default_factory=dict)

    @property
    def what(self) -> str:
        return f"exec({self.program!r})"

    @property
    def confined(self) -> bool:
        return isinstance(self.cwd, Located)


@dataclass(frozen=True)
class CheckSite:
    """A ``certora.check(name, key=value, ..., cwd=...)`` call: a policy-declared runtime
    validation. Falling through it (success) establishes the validation's atoms on the bare-Name
    arguments; the evaluator itself is a subprocess, so the site also kills every live check."""

    node: ast.AST
    name: str
    arguments: dict[str, Value]
    cwd: ValidationFact | None
    # from the validation's declaration: False means the check runs anywhere, so the site has
    # no cwd to prove
    needs_cwd: bool = True

    @property
    def what(self) -> str:
        return f"check({self.name!r})"

    @property
    def confined(self) -> bool:
        return not self.needs_cwd or isinstance(self.cwd, Located)


@dataclass(frozen=True)
class NetworkSite:
    """A ``certora.network.<method>(url, ...)`` call: one brokered, policy-checked request."""

    node: ast.AST
    method: str  # the HTTP method, upper-case
    url: Value

    @property
    def what(self) -> str:
        return f"network.{self.method.lower()}"

    @property
    def confined(self) -> bool:
        lifted = url_of(self.url)
        return lifted is not None and lifted.scheme is not None and lifted.netloc is not None


type Site = SinkSite | ExecSite | CheckSite | NetworkSite


# ---------------------------------------------------------------------------
# the vocabulary: the policy as the analysis sees it (Policy.vocabulary)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckSignature:
    """The analysis-side half of one policy ``validation()``: what ``certora.check(name, ...)``
    takes and what its success establishes. Derived from the policy (``Policy.vocabulary``) and
    handed to ``analyze`` -- the atom vocabulary is part of the language the program is written
    against, the way user-defined types are; the evaluator itself stays policy-side."""

    name: ValidationName
    params: tuple[ParamName, ...]
    establishes: dict[ParamName, frozenset[Atom]]  # parameter name, or "cwd" -> validation atoms
    # what the evaluator's own run writes (EFFECTS.md): NOTHING for an effect-free check, the
    # whole media it reaches when the policy declared no regions
    writes: Effects = EVERYTHING
    needs_cwd: bool = True  # False: the check does not care where it runs; cwd= may be omitted

    @property
    def effect_free(self) -> bool:
        """The evaluator mutates nothing, so its run kills no atoms."""
        return self.writes.empty


def host_matches(pattern: str, host: str) -> bool:
    """A network rule's host: an exact name, or ``*.suffix`` (subdomains, not the suffix)."""
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


@dataclass(frozen=True)
class WriteTable:
    """What the policy's exec and network rules write (EFFECTS.md), keyed as the walker resolves
    sites: an exec by program and the leading words after it, a network request by host and
    methods. A check's write set rides its ``CheckSignature``."""

    exec: tuple[tuple[ProgramName, tuple[str, ...], Effects], ...] = ()
    network: tuple[tuple[str, frozenset[str], Effects], ...] = ()


@dataclass(frozen=True)
class SourceTable:
    """Which rules yield which *source atom* (PROVENANCE.md), as the walker needs them to bind a
    handle: an exec by program and leading words, a network request by host pattern, a file
    read by location."""

    exec: tuple[tuple[ProgramName, tuple[str, ...], SourceId], ...] = ()
    # (host pattern, permitted URL paths -- empty: any, atom)
    network: tuple[tuple[str, tuple[LocationFact, ...], SourceId], ...] = ()
    read: tuple[tuple[LocationFact, SourceId], ...] = ()

    @property
    def atoms(self) -> frozenset[SourceId]:
        return frozenset(
            [a for _, _, a in self.exec] + [a for _, _, a in self.network] + [a for _, a in self.read]
        )


class Discharge(Protocol):
    """The host's literal-checker runner (``Policy.discharger``): may some effect-free evaluator
    establish the pure *atom* on exactly this *text*, run right now under the sandbox root? The
    analysis asks it while discharging relies, guarantees, hole constraints and container
    elements on statically-known text, so a constant needs neither a ``certora.check`` nor a
    regex definition."""

    def __call__(self, atom: Atom, text: str) -> bool: ...


@dataclass(frozen=True)
class Vocabulary:
    """The policy's atoms as the analysis sees them (ATOMS.md): the check signatures, and the
    kind table -- which atoms are *pure* (true of the value's text alone, so no effect can
    invalidate them: they die only with the value; an environmental atom is about the world at
    a location and dies at every call that may change what it depends on), which of the pure
    ones a regex defines or a literal checker decides, which are sources. ``missing`` is the one
    place "does this value carry X" is answered from all of it."""

    signatures: dict[ValidationName, CheckSignature] = field(default_factory=dict)
    # every pure atom: the built-ins, the defined and checker-established check atoms, the sources
    pure_atoms: frozenset[Atom] = frozenset()
    # *defined* atoms: name -> the text property that is its meaning. The analysis establishes
    # one directly on any value whose known text entails it -- a literal needs no runtime check
    # -- and it is pure by construction (a subset of ``pure_atoms``).
    defined: dict[CheckId, PseudoRegex] = field(default_factory=dict)
    # pure check atoms some effect-free single-input validation establishes: a literal checker
    # can decide them on exactly-known text (a subset of ``pure_atoms``)
    checkable: frozenset[CheckId] = frozenset()
    # source atoms and the rules that yield them (also a subset of ``pure_atoms``)
    sources: SourceTable = field(default_factory=SourceTable)
    # EFFECTS.md, for the kill by intersection: per environmental atom the state it depends on
    # (an atom absent here depends on everything), per rule what it writes, and each declared
    # region's medium
    reads: Mapping[Atom, Effects] = field(default_factory=dict)
    writes: WriteTable = field(default_factory=WriteTable)
    medium_of: Mapping[RegionId, Medium] = field(default_factory=dict)
    # per environmental atom, the instantiated footprints of the filesystem regions it reads:
    # each region's footprint joined onto the cwd of each validation establishing the atom (an
    # atom absent here reads no filesystem region by name; ``ANYWHERE`` when a footprint has no
    # cwd to anchor it)
    footprints: Mapping[Atom, tuple[Footprint, ...]] = field(default_factory=dict)

    def decidable_from_text(self) -> frozenset[Atom]:
        """The atoms a string alone can be shown to carry, by kind: the built-ins (structure),
        the defined ones (their regex), the checkable ones (a literal checker). Not the
        environmental ones (a check at a place and time) and not the sources (provenance is not
        a property of text): what the broker's re-check of a templated exec may ask about."""
        return frozenset(BUILTIN_ATOMS.values()) | frozenset(self.defined) | self.checkable

    def missing(
        self,
        value: str | ValidationFact | None,
        required: frozenset[Atom],
        discharge: Discharge | None = None,
    ) -> frozenset[Atom]:
        """The atoms of *required* that *value* does not carry. An atom the fact states is
        carried; otherwise its kind says how it could still be: a built-in by structure
        (``holds``: the fact's regex and the implication table, a located value's head); a
        defined atom by its regex subsuming the known text; a checkable atom by the literal
        checker, when a *discharge* is given and the text is exactly known. Nothing else --
        an environmental atom, a source -- is ever inferred. Without a discharger the answer is
        weaker, never wrong: the checkable atoms stay missing."""
        if not required:
            return required
        if value is None:
            return required
        fact = as_fact(value)
        out: set[Atom] = set()
        text: str | None | bool = False  # unknown until needed
        for atom in required:
            if atom in fact.atoms:
                continue
            if atom in BUILTIN_ATOMS:
                if holds(BUILTIN_ATOMS[atom], fact):
                    continue
            elif atom in self.defined:
                if _regex_subsumes(self.defined[CheckId(atom)], as_text(fact).regex):
                    continue
            elif discharge is not None and atom in self.checkable:
                if text is False:
                    text = known_text(fact)
                if isinstance(text, str) and discharge(atom, text):
                    continue
            out.add(atom)
        return frozenset(out)

    def annotation_problem(self, fact: ValidationFact) -> str | None:
        """A contract's spelling disagrees with the kind: ``certora.source(x)`` names no source
        atom of this policy, or ``certora.validated(x)`` names one. The annotation parser marks
        the kind it was spelled with; the policy's kind table decides."""
        sources = self.sources.atoms
        for a in sorted(fact.atoms):
            if isinstance(a, SourceId) and a not in sources:
                return f"certora.source({a!r}): no rule of the policy yields that source atom"
            if isinstance(a, CheckId) and a in sources:
                return f"certora.validated({a!r}): {a!r} is a source atom; spell it certora.source({a!r})"
        return None


# ---------------------------------------------------------------------------
# the digest: one call as the walker hands it over
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Callsite:
    """One call, digested by the walker against its state. Nothing here is syntax except the
    opaque handles used to place a report: the arguments and keywords are values as the state
    sees them (known text as a ``str``), the receiver of a method call is its state entry (or
    the value of a computed receiver, ``line.strip().split()``), and ``handle_of(which)``
    answers what source handle stands behind positional *which* or the keyword named *which* --
    a name bound to one, or a source call written inline -- without the enforcement having to
    look.

    The three ``inert_*`` flags are decided by the walker over the argument expressions, for
    the argument conditions of the callee analysis (EFFECTS.md; ``dangerous.INERT_CALLEES``):
    ``inert_keywords`` -- every ``name=value`` is inert; ``inert_splats`` -- every ``*xs`` and
    every ``**m`` splats an inert value; ``inert_arguments`` -- both, and every plain positional
    argument is inert too."""

    node: ast.AST
    callee: NameAccess
    args: tuple[Value, ...]
    arg_nodes: tuple[ast.AST, ...]
    keywords: Mapping[str, Binding]
    keyword_nodes: Mapping[str, ast.AST]
    keyword_names: Mapping[str, str | None]  # the bare variable a keyword names, if it does
    splat: bool  # *args or **kwargs present
    receiver: ValidationFact | Container | Data | Std | None
    handle_of: Callable[[int | str], Data | None]
    inert_arguments: bool
    inert_keywords: bool
    inert_splats: bool

    @property
    def method(self) -> str | None:
        """The attribute a method call names (``p.write_text`` -> ``write_text``); None for a
        bare-name call."""
        names = self.callee.field_names
        return names[-1] if names else None

    def node_of(self, index: int, keyword: str) -> ast.AST:
        """Where to report about the parameter that is positional *index* or keyword *keyword*:
        the argument's own node, else the call's."""
        if index < len(self.arg_nodes):
            return self.arg_nodes[index]
        return self.keyword_nodes.get(keyword, self.node)

    def handle_for(self, index: int, keyword: str) -> Data | None:
        """The source handle behind the parameter that is positional *index* or keyword
        *keyword*."""
        return self.handle_of(index) if index < len(self.args) else self.handle_of(keyword)

    def keyword(self, name: str) -> Value:
        """A keyword's value where one value is expected; a display or a container bound there
        reads as unknown."""
        b = self.keywords.get(name)
        return None if isinstance(b, (Many, Elements)) else b


@dataclass(frozen=True)
class Argument:
    """One argument to a contracted parameter, as the walker bound it."""

    node: ast.AST  # the argument expression; the call itself for a defaulted parameter
    value: Value  # as the state sees it; a default is evaluated in the empty state
    container: Container | None = None  # a tracked container passed by name
    name: str | None = None  # the bare name passed, if the argument is one
    starred: bool = False  # bound to *args / **kwargs: not checkable
    defaulted: bool = False


@dataclass(frozen=True)
class Audit:
    """What one call meant to the policy: the sites it is, the violations it carries, and the
    atoms its success establishes on which variables (a check, applied by the walker at the
    statement's fall-through)."""

    sites: tuple[Site, ...] = ()
    violations: tuple[tuple[ast.AST, str], ...] = ()
    establishes: Mapping[str, frozenset[Atom]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# value helpers
# ---------------------------------------------------------------------------


def _as_fact(value: Value) -> ValidationFact | None:
    """A value as a fact: known text is a string fact with that exact text."""
    return StrFact(regex=Exact(value)) if isinstance(value, str) else value


def _exact_text(value: Value) -> str | None:
    """The exact text of a value that is a literal or a name bound to one; None for anything
    else (a located value has text too, but is not what a program name or a validation name is
    spelled with)."""
    match value:
        case str():
            return value
        case StrFact(regex=Exact(exact_str=s)):
            return s
        case _:
            return None


def _at_sink(value: Value) -> ValidationFact | None:
    """What a sink records about its path: the path reading when the value has one (a literal
    ``"./out.txt"``, a validated name), otherwise the value as it was, for the report."""
    fact = _as_fact(value)
    located = locate(fact)
    return fact if located is None else located


def _open_kind(mode: str | None) -> AccessKind:
    """What an ``open`` does, from its mode; an unknown mode is taken as a write."""
    if mode is None:
        return "write"
    return "write" if any(c in mode for c in "wax+") else "read"


def _mode_text(value: Value, absent: str | None) -> str | None:
    """An ``open`` mode as text: *absent* when not given, the literal when known, None (unknown,
    so a write) otherwise."""
    if value is None:
        return absent
    return value if isinstance(value, str) else None


def _hosts_of(url: ValidationFact | None) -> list[str] | None:
    """Every host a proven URL's netloc may denote -- an exact netloc, or an alternation of
    exact ones -- lower-cased, without a trailing dot; None when the URL is not proven that far.
    A rule must admit all of them before it can be said to cover the request."""
    lifted = url_of(url)
    if lifted is None or lifted.netloc is None:
        return None
    match lifted.netloc:
        case Exact(exact_str=text):
            texts = [text]
        case Alternation(any_of=branches) if all(isinstance(b, Exact) for b in branches):
            texts = [b.exact_str for b in branches if isinstance(b, Exact)]
        case _:
            return None
    hosts: list[str] = []
    for text in texts:
        host = urllib.parse.urlsplit(f"//{text}").hostname
        if host is None:
            return None
        hosts.append(host.lower().rstrip("."))
    return hosts


@dataclass
class OpenCall:
    """The builtin ``open``'s signature, as a dataclass so that ``bind_values`` can bind a
    digested call to it: the generated ``__init__`` is the signature, and what gets bound are
    the values the walker read."""

    file: Value
    mode: Value | str = "r"
    encoding: Value = None
    errors: Value = None
    newline: Value = None
    closefd: Value | bool = True
    opener: Value = None


@dataclass
class PathOpenCall:
    """``pathlib.Path.open``'s signature, the receiver being the path."""

    mode: Value | str = "r"
    buffering: Value | int = -1
    encoding: Value = None
    errors: Value = None
    newline: Value = None


def _bind[T](spec: type[T], site: Callsite) -> T | None:
    """A call bound to *spec*; None when it cannot be bound statically -- a splat, a display or
    a container where a scalar goes, or any way ``inspect.Signature.bind`` can refuse."""
    if site.splat or any(isinstance(b, (Many, Elements)) for b in site.keywords.values()):
        return None
    return bind_values(spec, site.args, site.keywords)


# the ``certora`` calls the analysis audits by shape, each as the signature ``markers`` gives it,
# so a call that binds at runtime binds here and one that does not -- a parameter twice, an
# unknown keyword, a missing argument -- is refused for the same reason


@dataclass
class ExtractCall:
    """``certora.extract(x, path)`` / ``certora.extract_all(x, path)``."""

    x: Value
    path: Value


@dataclass
class LinesCall:
    """``certora.lines(x)``."""

    x: Value


@dataclass
class FieldCall:
    """``certora.field(line, index, sep=None)``."""

    line: Value
    index: Value
    sep: Value = None


@dataclass
class PathmatchCall:
    """``certora.pathmatch(text, location)``."""

    text: Value
    location: Value


@dataclass
class NetworkCall:
    """``certora.network.<method>(url, *, headers=None, body=None, timeout=None)``; whether
    ``body`` is admissible depends on the method and is checked after binding."""

    url: Value
    _: KW_ONLY
    headers: Value = None
    body: Value = None
    timeout: Value = None


# ---------------------------------------------------------------------------
# the enforcement
# ---------------------------------------------------------------------------


class Enforcement:
    """The policy's side of the analysis, stateless but for its configuration: the vocabulary
    (``Policy.vocabulary``), the literal-checker runner (``Policy.discharger``; None: no
    running), and the names that denote modules."""

    def __init__(
        self,
        vocabulary: Vocabulary,
        discharge: Discharge | None,
        modules: frozenset[str],
    ) -> None:
        self.vocabulary = vocabulary
        self._discharge = discharge
        self.modules = modules

    # -- entailment ---------------------------------------------------------------------------

    def establishes(self, value: Value, required: ValidationFact) -> bool:
        """Does *value* establish *required*? ``entails``, with the atoms decided by
        ``Vocabulary.missing`` -- structure, regex definitions, literal checkers on
        exactly-known text -- rather than by structure alone."""
        return entails(
            value, required, lambda fact, atoms: self.vocabulary.missing(fact, atoms, self._discharge)
        )

    def rely_failures(
        self, fname: str, contract: Contract, arguments: Mapping[str, Argument]
    ) -> list[tuple[ast.AST, str]]:
        """Every argument to a contracted parameter must establish its rely; a parameter left to
        its default is checked against the default. *arguments* holds what the walker bound, by
        parameter name; a parameter absent from it was left unbound without a default (the
        binding would have failed)."""
        out: list[tuple[ast.AST, str]] = []
        for param, rely in contract.params.items():
            if is_plain_type(rely):
                continue  # a type rely: the injected runtime guard's job, not ours
            arg = arguments.get(param)
            if arg is None:
                continue
            if isinstance(rely, Container):
                failure = self._container_argument_failure(fname, param, rely, arg)
                if failure is not None:
                    out.append(failure)
                continue
            if arg.starred:
                out.append((arg.node, f"call to {fname}: arguments to *{param} cannot be checked against its rely"))
                continue
            if not self.establishes(arg.value, rely):
                which = "the default for" if arg.defaulted else "the argument for"
                out.append(
                    (arg.node, f"call to {fname}: {which} {param} does not establish {describe_value(rely)}")
                )
        return out

    def _container_argument_failure(
        self, fname: str, param: str, rely: Container, arg: Argument
    ) -> tuple[ast.AST, str] | None:
        """A container parameter: a ``list``/``set`` rely is invariant -- the callee may write,
        so the element types must coincide (mutual entailment: the equivalence the entailment
        preorder induces, not structural equality) -- while a ``Sequence`` rely is a read-only
        borrow and admits any container whose elements entail its."""
        if arg.name is None:
            return (arg.node, f"call to {fname}: the argument for {param} must be a tracked container name")
        c = arg.container
        if c is None:
            return (arg.node, f"call to {fname}: {arg.name!r} is not a tracked container")
        if rely.kind == "sequence":
            if not self.establishes(c.elem, rely.elem):
                return (
                    arg.node,
                    f"call to {fname}: the elements of {arg.name!r} do not establish "
                    f"{describe_value(rely.elem)}",
                )
            return None
        if c.kind != rely.kind:
            return (arg.node, f"call to {fname}: {param} takes a {rely.kind}, got a {c.kind}")
        if not (self.establishes(c.elem, rely.elem) and self.establishes(rely.elem, c.elem)):
            return (
                arg.node,
                f"call to {fname}: {param} requires exactly {describe_value(rely.elem)} "
                "elements (invariance: the callee may write)",
            )
        return None

    # -- the kill (EFFECTS.md) ----------------------------------------------------------------

    def kill_of(self, site: Callsite) -> Kill | ProgramCall:
        """What this call does to the state (EFFECTS.md, the callee analysis).

        The ``certora`` calls and the file sinks are effects with a known medium that run no
        program code: a check writes what its signature declares, an exec or a request what the
        rule it falls under writes, a file write everything (until footprints are derived), a
        read nothing. A roster builtin or module function whose argument condition is
        satisfied (``dangerous.INERT_CALLEES``: every argument inert, or only the keywords and
        the splats) and a method on an inert receiver with inert arguments are the interpreter's
        own code over inert values: no kill. The hash-and-identity methods need no inert
        arguments, but storing a non-inert value opens the state. A bare name off the roster is
        a ``ProgramCall``, the walker's to resolve. Anything else -- a module function off the
        roster, a method on an unknown receiver or on a program object, a roster call handed a
        program object -- may run program code: it writes everything and opens everything."""
        callee = site.callee
        if callee.is_var_base:
            full = callee.full_path
            if callee.matches(*CHECK_CALLEE) or callee.matches(*CHECK_SINGLE_CALLEE):
                signature = self._signature(site)
                return Kill(EVERYTHING if signature is None else signature.writes, opens=False)
            if callee.matches(*EXEC_CALLEE):
                return Kill(self._exec_writes(site), opens=False)
            network = next((m for m in NETWORK_METHODS if callee.matches(*NETWORK_NAMESPACE, m)), None)
            if network is not None:
                return Kill(self._network_writes(site, network), opens=False)
            if full == ("open",):
                bound = _bind(OpenCall, site)
                if bound is None:
                    return OPAQUE if not (site.inert_keywords and site.inert_splats) else Kill(EVERYTHING, opens=False)
                return self._open_kill(site, bound.mode, bound.file)
            if full == ("print",):
                # print(..., file=f) writes through the handle: a file write at its location.
                # (A write handle is inert, so the roster condition alone would let it pass.)
                target = site.handle_of("file")
                if target is not None and target.writes is not None:
                    return self._handle_write(target) if site.inert_keywords and site.inert_splats else OPAQUE
            condition = inert_condition(full, self.modules)
            if condition is not None:
                satisfied = (
                    site.inert_arguments
                    if condition == "all"
                    else site.inert_keywords and site.inert_splats
                )
                return NO_KILL if satisfied else OPAQUE
            if len(full) == 1:
                return ProgramCall(full[0])
            if full[0] in self.modules:
                return OPAQUE  # a module function off the roster
        elif callee.computed_base is None:
            return OPAQUE  # ``super().m()``: a program method
        # a method call, on a variable or on a computed receiver: the receiver's entry decides
        method = site.method
        assert method is not None
        receiver = site.receiver
        if method in PATH_SINK_METHODS:
            path = scalar(receiver)
            if not is_path_typed(path):
                return OPAQUE  # a sink's name on something not proven a path: unknown code
            if method == "open":
                bound = _bind(PathOpenCall, site)
                if bound is None:
                    return OPAQUE if not (site.inert_keywords and site.inert_splats) else Kill(EVERYTHING, opens=False)
                return self._open_kill(site, bound.mode, path)
            if not site.inert_arguments:
                return OPAQUE
            if PATH_SINK_METHODS[method] != "write":
                return NO_KILL  # a read or a listing on a proven path changes nothing
            # a write is an effect on the file, and on the target for the two methods that
            # write a second path; what it kills is derived from the locations
            if method in PATH_SINK_METHOD_TARGETS:
                keyword, _ = PATH_SINK_METHOD_TARGETS[method]
                target = site.keyword(keyword) if keyword in site.keywords else (site.args[0] if site.args else None)
                return self._file_write(path, target)
            return self._file_write(path)
        if isinstance(receiver, Container):
            # a roster mutation runs no program code and its obligation was applied; an
            # off-roster method is the container's escape, reported by the walker
            return NO_KILL if method in CONTAINER_METHODS else OPAQUE
        if isinstance(receiver, Data) and receiver.writes is not None and method in FILE_WRITE_METHODS:
            # a write through a handle opened for writing: a file write at its location
            return self._handle_write(receiver) if site.inert_arguments else OPAQUE
        if inert_receiver(receiver):
            if method in HASH_IDENTITY_METHODS and site.inert_keywords and site.inert_splats:
                return NO_KILL if site.inert_arguments else OPENING
            return NO_KILL if site.inert_arguments else OPAQUE
        return OPAQUE

    def _open_kill(self, site: Callsite, mode: Value, path: Value) -> Kill:
        """``open`` / ``Path.open``: opening for writing truncates or creates the file -- a file
        write at *path*, its kill derived -- and opening for reading changes nothing. Either way
        the interpreter's code, unless a keyword (``opener=``) or a splat is not inert; an
        unknown mode is taken as a write."""
        if not (site.inert_keywords and site.inert_splats):
            return OPAQUE
        if _open_kind(_mode_text(mode, "r")) == "write":
            return self._file_write(path)
        return NO_KILL

    def survivors(self, atoms: frozenset[Atom], kill: Kill) -> frozenset[Atom]:
        """The atoms of *atoms* that outlive *kill*: every built-in (a property of the text),
        every pure atom, and every environmental atom whose state the kill misses. An atom the
        policy gave no ``reads`` depends on everything, so any effect kills it; one reading the
        whole filesystem dies at any file write; one reading named filesystem regions dies at a
        file write that can lie at or below a footprint instantiated for it."""
        if kill.writes.empty and not kill.file_writes:
            return atoms
        vocabulary = self.vocabulary
        pure = vocabulary.pure_atoms

        def dies(a: Atom) -> bool:
            reads = vocabulary.reads.get(a)
            if reads is None:
                return True  # depends on everything: any effect
            if kill.writes.meets(reads, vocabulary.medium_of):
                return True
            if not kill.file_writes:
                return False
            if "fs" in reads.media:
                return True
            footprints = vocabulary.footprints.get(a, ())
            return any(overlaps(w, fp) for w in kill.file_writes for fp in footprints)

        return frozenset(a for a in atoms if a in BUILTIN_ATOMS or a in pure or not dies(a))

    def forget(self, fact: ValidationFact, kill: Kill) -> ValidationFact:
        """*fact* after *kill*."""
        kept = self.survivors(fact.atoms, kill)
        return fact if kept == fact.atoms else replace(fact, atoms=kept)

    def _file_write(self, *paths: Value) -> Kill:
        """The kill of the program's own write to *paths*: derived from the proven locations,
        everything when one is not proven (the sink audit rejects the program then anyway)."""
        located: list[LocationFact] = []
        for p in paths:
            found = locate(_as_fact(p))
            if found is None:
                return Kill(EVERYTHING, opens=False)
            located.append(found.location)
        return Kill(NOTHING, opens=False, file_writes=tuple(located))

    @staticmethod
    def _handle_write(handle: Data) -> Kill:
        """The kill of a write through a handle: a file write at each location the file may be
        at; everything for a handle whose location was lost (none is built today)."""
        assert handle.writes is not None
        if not handle.writes:
            return Kill(EVERYTHING, opens=False)
        return Kill(NOTHING, opens=False, file_writes=handle.writes)

    def _exec_writes(self, site: Callsite) -> Effects:
        """What the rule this exec selects writes: by the literal program and the leading words,
        as the policy selects it. No literal program, or no rule, is everything -- the policy
        denies such a site anyway, and until then nothing can be said about it."""
        program = _exact_text(site.args[0]) if site.args else None
        if program is None:
            return EVERYTHING
        for name, words, writes in self.vocabulary.writes.exec:
            if name == program and matches_leading(words, site.args[1:]):
                return writes
        return EVERYTHING

    def _network_writes(self, site: Callsite, method: str) -> Effects:
        """What the rules a request may fall under write: every rule whose host admits every host
        the proven URL may denote and whose methods admit this one, unioned. An unproven URL, or
        no admitting rule, is everything."""
        hosts = _hosts_of(_as_fact(site.args[0])) if site.args else None
        if hosts is None:
            return EVERYTHING
        wanted = method.upper()
        total: Effects | None = None
        for pattern, methods, writes in self.vocabulary.writes.network:
            if all(host_matches(pattern, h) for h in hosts) and (not methods or wanted in methods):
                total = writes if total is None else total | writes
        return EVERYTHING if total is None else total

    def _signature(self, site: Callsite) -> CheckSignature | None:
        """The validation a ``certora.check``/``check_single`` names, when its first argument is
        a literal (or a name bound to one) the policy declares."""
        if not site.args:
            return None
        name = _exact_text(site.args[0])
        return None if name is None else self.vocabulary.signatures.get(ValidationName(name))

    # -- provenance (PROVENANCE.md) -----------------------------------------------------------

    def _exec_sources(self, program: str, arguments: Sequence[Value]) -> frozenset[SourceId]:
        for name, words, atom in self.vocabulary.sources.exec:
            if name == program and matches_leading(words, arguments):
                return frozenset({atom})
        return frozenset()

    def _network_sources(self, url: ValidationFact | None) -> frozenset[SourceId]:
        """The source atoms of the rule(s) a proven URL's host falls under: every host the netloc
        may denote must match, or the response vouches for nothing."""
        lifted = url_of(url)
        hosts = _hosts_of(url)
        if lifted is None or hosts is None:
            return frozenset()
        path = lifted.path
        return frozenset(
            atom
            for pattern, paths, atom in self.vocabulary.sources.network
            if all(host_matches(pattern, h) for h in hosts)
            and (not paths or (path is not None and any(location_le(path, p) for p in paths)))
        )

    def _read_sources(self, path: ValidationFact | None) -> frozenset[SourceId] | None:
        """The source atoms of the ``[[source]]`` locations a proven path lies within; None when
        the path is not proven at all (then there is no handle, and the read is unconfined
        anyway)."""
        located = locate(path)
        if located is None:
            return None
        return frozenset(
            atom for loc, atom in self.vocabulary.sources.read if location_le(located.location, loc)
        )

    def handle(self, site: Callsite) -> Data | None:
        """The handle a call binds, or None when it binds none: a *source* handle from
        ``certora.exec`` / ``certora.network.<m>``, ``p.read_text()`` / ``read_bytes()`` on a
        proven path, ``f.read()`` on a handle, or an ``open`` for reading; a *write* handle from
        an ``open`` for writing on a proven path."""
        callee = site.callee
        if callee.matches(*EXEC_CALLEE) and site.args:
            program = _exact_text(site.args[0])
            return Data() if program is None else Data(self._exec_sources(program, site.args[1:]))
        if site.args and any(callee.matches(*NETWORK_NAMESPACE, m) for m in NETWORK_METHODS):
            return Data(self._network_sources(_as_fact(site.args[0])))
        if site.method in ("read_text", "read_bytes") and not site.args:
            sources = self._read_sources(scalar(site.receiver))
            return None if sources is None else Data(sources)
        if site.method == "read" and not site.args and isinstance(site.receiver, Data):
            return site.receiver  # text = f.read(): the text is the handle's
        return self.with_handle(site)

    def with_handle(self, site: Callsite) -> Data | None:
        """``open(p, mode)`` / ``p.open(mode)`` on a proven path, as ``with ... as f`` or
        ``f = ...`` binds it: for reading a source handle carrying the location's source atoms,
        for writing a write handle at the location. An unproven path binds nothing: the file
        object is then unknown, every method on it opaque, and the sink audit rejects the
        program besides."""
        path: Value
        mode: Value
        if site.callee.matches("open"):
            builtin = _bind(OpenCall, site)
            if builtin is None:
                return None
            path, mode = builtin.file, builtin.mode
        elif site.method == "open":
            method = _bind(PathOpenCall, site)
            if method is None:
                return None
            path, mode = scalar(site.receiver), method.mode
        else:
            return None
        located = locate(_as_fact(path))
        if located is None:
            return None
        if _open_kind(_mode_text(mode, "r")) == "write":
            return Data(writes=(located.location,))
        sources = self._read_sources(located)
        return None if sources is None else Data(sources)

    def extract_fact(self, site: Callsite) -> ValidationFact | None:
        """The result fact of ``certora.extract(h, path)`` (the source atoms, on text of unknown
        shape) or of ``certora.field(line, i)`` (a projection: the line's source atoms survive,
        nothing else does)."""
        callee = site.callee
        if callee.matches(*EXTRACT_CALLEE) and _bind(ExtractCall, site) is not None:
            source = site.handle_for(0, "x")
            return None if source is None else StrFact(atoms=frozenset(source.sources))
        if callee.matches(*FIELD_CALLEE) and (bound := _bind(FieldCall, site)) is not None:
            fact = _as_fact(bound.line)
            if fact is None:
                return StrFact()
            return StrFact(atoms=atoms_of(fact) & self.vocabulary.sources.atoms)
        return None

    def check_single_fact(self, site: Callsite) -> ValidationFact | None:
        """The result fact of a direct ``certora.check_single(name, v)``: v's fact plus the
        validation's atoms on its single parameter. Success postdominates the expression and
        the broker refuses non-str values, so the str reading is sound even for an unknown
        argument. (The walker recognizes assignment and comprehension-element position; anywhere
        else the result is simply unknown.)"""
        if (
            not site.callee.matches(*CHECK_SINGLE_CALLEE)
            or site.splat
            or len(site.args) != 2
            or any(k != "cwd" for k in site.keywords)
        ):
            return None
        signature = self._signature(site)
        if signature is None or len(signature.params) != 1:
            return None  # the audit reported the shape problem; the result stays unknown
        atoms = signature.establishes.get(signature.params[0], frozenset())
        base = _as_fact(site.args[1])
        if base is None:
            base = StrFact()
        return replace(base, atoms=base.atoms | atoms)

    # -- sites: the shape audits --------------------------------------------------------------

    def audit(self, site: Callsite) -> Audit:
        """What this call is to the policy: the ``certora`` calls by name, the network methods,
        and otherwise the filesystem sinks."""
        callee = site.callee
        if callee.is_var_base:
            if callee.matches(*EXEC_CALLEE):
                return self._audit_exec(site)
            if callee.matches(*CHECK_CALLEE):
                return self._audit_check(site)
            if callee.matches(*CHECK_SINGLE_CALLEE):
                return self._audit_check_single(site)
            if callee.matches(*EXTRACT_CALLEE):
                return self._audit_extract(site, plural=False)
            if callee.matches(*EXTRACT_ALL_CALLEE):
                return self._audit_extract(site, plural=True)
            if callee.matches(*LINES_CALLEE):
                return self._audit_lines(site)
            if callee.matches(*FIELD_CALLEE):
                return self._audit_field(site)
            if callee.matches(*PATHMATCH_CALLEE):
                return self._audit_pathmatch(site)
            method = next((m for m in NETWORK_METHODS if callee.matches(*NETWORK_NAMESPACE, m)), None)
            if method is not None:
                return self._audit_network(site, method)
        return self._audit_sink(site)

    def _audit_exec(self, site: Callsite) -> Audit:
        """``certora.exec(program, *args, cwd=..., HOLE=...)``: the shape is checked here
        (violations), the cwd's provenance is a sink question (``confined``), and the arguments
        and hole bindings are recorded for the policy, which alone knows the program's forms."""
        node = site.node
        if site.splat:
            return Audit(violations=((node, "exec: *args / **kwargs are not admissible; spell the command out"),))
        violations: list[tuple[ast.AST, str]] = [
            (node, f"exec: {name}= is required") for name in sorted(EXEC_REQUIRED_KEYWORDS - site.keywords.keys())
        ]
        # an option is a literal bool: it configures the call and binds nothing
        for name in sorted(EXEC_OPTION_KEYWORDS & site.keywords.keys()):
            given = site.keyword_nodes[name]
            if not (isinstance(given, ast.Constant) and isinstance(given.value, bool)):
                violations.append((given, f"exec: {name}= must be the literal True or False"))
        if not site.args:
            violations.append((node, "exec: no program given"))
            return Audit(violations=tuple(violations))
        program = _exact_text(site.args[0])
        if program is None:
            # without the program there is no rule to hold the site against: nothing to record
            violations.append(
                (site.arg_nodes[0], "exec: the program must be a string literal (or a name bound to one)")
            )
            return Audit(violations=tuple(violations))
        exec_site = ExecSite(
            node,
            program,
            tuple(site.args[1:]),
            _at_sink(site.keyword(EXEC_CWD)) if EXEC_CWD in site.keywords else None,
            {name: b for name, b in site.keywords.items() if name not in EXEC_RESERVED_KEYWORDS},
        )
        return Audit((exec_site,), tuple(violations))

    def _audit_check(self, site: Callsite) -> Audit:
        """``certora.check(name, key=value, ..., cwd=...)``: run the policy's evaluator for
        *name*; falling through (success) establishes the declared atoms on the bare-Name
        arguments, for the statements after it. The shape mirrors ``certora.exec``: no splats, a
        literal name, keywords fixed by the policy's declaration, cwd a sink like exec's."""
        node = site.node
        if site.splat:
            return Audit(violations=((node, "check: *args / **kwargs are not admissible; spell the arguments out"),))
        if len(site.args) != 1:
            return Audit(violations=((node, "check: exactly one positional argument, the validation name"),))
        name = _exact_text(site.args[0])
        if name is None:
            return Audit(violations=(
                (site.arg_nodes[0], "check: the validation name must be a string literal (or a name bound to one)"),
            ))
        signature = self.vocabulary.signatures.get(ValidationName(name))
        if signature is None:
            return Audit(violations=((node, f"check: the policy declares no validation named {name!r}"),))
        violations: list[tuple[ast.AST, str]] = []
        has_cwd = "cwd" in site.keywords
        needs_cwd = signature.needs_cwd
        if not has_cwd and needs_cwd:
            violations.append((node, "check: cwd= is required"))
        expected, given = frozenset(signature.params), frozenset(site.keywords) - {"cwd"}
        for missing in sorted(expected - given):
            violations.append((node, f"check: {missing}= is required by validation {name!r}"))
        for extra in sorted(given - expected):
            violations.append((node, f"check: keyword {extra!r} is not part of validation {name!r}"))
        check_site = CheckSite(
            node,
            name,
            {k: site.keyword(k) for k in site.keywords if k != "cwd"},
            _at_sink(site.keyword("cwd")) if has_cwd else None,
            needs_cwd,
        )
        # success -- the only way past the statement -- establishes the atoms, on arguments that
        # are bare names: a fact needs a variable to live on. Anything else is dropped, soundly;
        # checks only ever enable.
        establishes: dict[str, frozenset[Atom]] = {}
        for target, atoms in signature.establishes.items():
            variable = site.keyword_names.get(target)
            if variable is not None:
                establishes[variable] = establishes.get(variable, frozenset()) | atoms
        return Audit((check_site,), tuple(violations), establishes)

    def _audit_check_single(self, site: Callsite) -> Audit:
        """``certora.check_single(name, value, cwd=...)``: the functional check. Exactly one
        declared parameter, and the shape of ``check`` otherwise; the RESULT's fact is
        ``check_single_fact``'s business, the site is a ``CheckSite`` like its statement
        sibling, and the kill is the walker's (this is an expression, not a statement)."""
        node = site.node
        if site.splat:
            return Audit(violations=((node, "check_single: *args / **kwargs are not admissible"),))
        violations: list[tuple[ast.AST, str]] = [
            (node, f"check_single: keyword {extra!r} is not admissible")
            for extra in sorted(frozenset(site.keywords) - {"cwd"})
        ]
        if len(site.args) != 2:
            violations.append((node, "check_single: exactly two positional arguments, the name and the value"))
            return Audit(violations=tuple(violations))
        name = _exact_text(site.args[0])
        if name is None:
            violations.append((site.arg_nodes[0], "check_single: the validation name must be a string literal"))
            return Audit(violations=tuple(violations))
        signature = self.vocabulary.signatures.get(ValidationName(name))
        if signature is None:
            violations.append((node, f"check_single: the policy declares no validation named {name!r}"))
            return Audit(violations=tuple(violations))
        if len(signature.params) != 1:
            # no single parameter, no site: there is nothing the value could be bound to
            violations.append((
                node,
                f"check_single: validation {name!r} declares {len(signature.params)} "
                "parameters; check_single takes exactly one",
            ))
            return Audit(violations=tuple(violations))
        has_cwd = "cwd" in site.keywords
        if not has_cwd and signature.needs_cwd:
            violations.append((node, "check_single: cwd= is required"))
        check_site = CheckSite(
            node,
            name,
            {signature.params[0]: site.args[1]},
            _at_sink(site.keyword("cwd")) if has_cwd else None,
            signature.needs_cwd,
        )
        return Audit((check_site,), tuple(violations))

    def _audit_extract(self, site: Callsite, plural: bool) -> Audit:
        """``certora.extract(source, path)`` / ``extract_all``: a source handle (or a source call
        inline) and a literal path in the jq subset, of the function's plurality."""
        what = "extract_all" if plural else "extract"
        bound = _bind(ExtractCall, site)
        if bound is None:
            return Audit(violations=((site.node, f"{what}: exactly two arguments, {what}(x, path) -- the source and the path"),))
        violations: list[tuple[ast.AST, str]] = []
        path_node = site.node_of(1, "path")
        if not isinstance(bound.path, str):
            violations.append((path_node, f"{what}: the path must be a string literal"))
        else:
            try:
                steps = jqpath.parse(bound.path)
            except ValueError as e:
                violations.append((path_node, f"{what}: {e}"))
            else:
                if jqpath.plural(steps) != plural:
                    violations.append((
                        path_node,
                        "extract: a plural path ([]) needs extract_all"
                        if not plural
                        else "extract_all: the path needs one []",
                    ))
        if site.handle_for(0, "x") is None:
            violations.append((
                site.node_of(0, "x"),
                f"{what}: the first argument must be a source -- the result of certora.exec or "
                "certora.network, a file read, or one of those inline",
            ))
        return Audit(violations=tuple(violations))

    def _audit_lines(self, site: Callsite) -> Audit:
        if _bind(LinesCall, site) is None:
            return Audit(violations=((site.node, "lines: exactly one argument, lines(x) -- the source"),))
        if site.handle_for(0, "x") is None:
            return Audit(violations=((site.node_of(0, "x"), "lines: the argument must be a source"),))
        return Audit()

    def _audit_field(self, site: Callsite) -> Audit:
        if _bind(FieldCall, site) is None:
            return Audit(violations=((site.node, "field: field(line, index, sep=None)"),))
        return Audit()

    def _audit_pathmatch(self, site: Callsite) -> Audit:
        """``certora.pathmatch(text, "<location>")``: the guard's shape. What it establishes is
        ``guards``' business; a spelling that does not parse establishes nothing, and is said so
        here rather than discovered at the sink."""
        bound = _bind(PathmatchCall, site)
        if bound is None:
            return Audit(violations=((site.node, "pathmatch: exactly two arguments, pathmatch(text, location) -- the path and the location"),))
        location_node = site.node_of(1, "location")
        if not isinstance(bound.location, str):
            return Audit(violations=((location_node, "pathmatch: the location must be a string literal"),))
        try:
            parse_location(bound.location)
        except ValueError as e:
            return Audit(violations=((location_node, f"pathmatch: {e}"),))
        return Audit()

    def _audit_network(self, site: Callsite, method: str) -> Audit:
        """``certora.network.<method>(url, *, headers=..., body=..., timeout=...)``: one
        brokered request. The URL is the sink -- the policy must know where it points -- and
        the rest is data the broker caps at runtime."""
        node = site.node
        admitted = {"headers", "timeout"} | ({"body"} if method in NETWORK_BODY_METHODS else set())
        unknown = tuple(
            (node, f"network: keyword {k!r} is not admissible for {method}")
            for k in site.keywords
            if k not in admitted
        )
        bound = _bind(NetworkCall, site)
        if bound is None:
            # a keyword outside the method's signature is the likelier reason; say that first
            shape = f"network: {method}(url, *, {', '.join(sorted(admitted))})"
            return Audit(violations=unknown or ((node, shape),))
        # bound, but with a body on a method that takes none: the site stands, the keyword does not
        violations: tuple[tuple[ast.AST, str], ...] = unknown
        # the fact is stored unlifted: the policy lifts (url_of) for the endpoint check, while
        # the raw fact keeps its exactly-known text for literal-checker discharge of `requires`
        return Audit((NetworkSite(node, method.upper(), _as_fact(bound.url)),), violations)

    def _audit_sink(self, site: Callsite) -> Audit:
        """A filesystem operation, with what is known about the path it touches. The path's
        provenance is not a violation here; ``Report.ok`` decides on ``confined``."""
        callee, node = site.callee, site.node
        full = callee.full_path if callee.is_var_base else None
        if full == ("open",):
            return self._audit_open(site)
        if full is not None and full in PATH_SINK_FUNCTIONS:
            index, kind = PATH_SINK_FUNCTIONS[full]
            fact = site.args[index] if index < len(site.args) else Located(StaticPath(()), "str")
            return Audit((SinkSite(node, ".".join(full), _at_sink(fact), kind),))
        if full is not None and len(full) > 1 and callee.base_name in self.modules:
            return Audit()  # a module function that is no sink (json.loads, re.match, certora.field)
        name = site.method
        if name is None or name not in PATH_SINK_METHODS:
            return Audit()
        # an unknown receiver is unproven, not "probably not a Path" -- but a receiver KNOWN to
        # be a str is no Path at all (str subclasses are banned), and its `.replace` is
        # str.replace, not the rename sink
        receiver = scalar(site.receiver)
        match receiver:
            case StrFact() | UrlString() | Located(repr="str"):
                return Audit()
            case _:
                pass
        kind = PATH_SINK_METHODS[name]
        if name == "open":  # Path.open(mode=...) / Path.open("w"): a call that cannot be bound is a write
            bound = _bind(PathOpenCall, site)
            kind = "write" if bound is None else _open_kind(_mode_text(bound.mode, "r"))
        sites: list[Site] = []
        violations: list[tuple[ast.AST, str]] = []
        if name in PATH_SINK_METHOD_TARGETS:
            # p.replace(target) / p.link_to(target): the target is written too, and is audited
            # as a sink of its own, with what is known about ITS path
            keyword, target_kind = PATH_SINK_METHOD_TARGETS[name]
            if keyword in site.keywords:
                target: Value = site.keyword(keyword)
            elif site.args:
                target = site.args[0]
            else:
                target = None
                violations.append((node, f"{name}(): the {keyword} argument is required"))
            if not violations:
                sites.append(SinkSite(node, f"<path>.{name}({keyword})", _at_sink(target), target_kind))
        sites.append(SinkSite(node, f"<path>.{name}", _at_sink(receiver), kind))
        return Audit(tuple(sites), tuple(violations))

    def _audit_open(self, site: Callsite) -> Audit:
        """The builtin ``open``: its arguments bound to its signature, the mode deciding read
        from write."""
        node = site.node
        bound = _bind(OpenCall, site)
        if bound is None:
            return Audit(violations=((node, "open(): arguments cannot be bound statically"),))
        violations: tuple[tuple[ast.AST, str], ...] = ()
        mode = _mode_text(bound.mode, "r")
        if mode is None:
            mode = "?"
            violations = ((node, "open(): mode must be a string literal"),)
        return Audit(
            (SinkSite(node, f"open(mode={mode!r})", _at_sink(bound.file), _open_kind(mode)),),
            violations,
        )


# ---------------------------------------------------------------------------
# rendering sites and facts, for reports
# ---------------------------------------------------------------------------


def _atoms_suffix(atoms: frozenset[Atom]) -> str:
    """The stated built-ins in brackets, the policy atoms as "validated"."""
    builtin = sorted(a for a in atoms if a in BUILTIN_ATOMS)
    policy = sorted(carried(atoms))
    return (f" [{', '.join(builtin)}]" if builtin else "") + (
        f" (validated: {', '.join(policy)})" if policy else ""
    )


_STD_NOUNS: dict[str, str] = {
    "bytes": "bytes", "number": "a number", "bool": "a bool", "none": "None", "match": "a match",
    "pattern": "a pattern", "list": "a list", "tuple": "a tuple", "set": "a set",
    "frozenset": "a frozenset", "dict": "a dict",
}


def describe_value(v: Value | Container | Std) -> str:
    match v:
        case None:
            return "unknown"
        case Container(kind=kind, elem=elem):
            return f"{kind} of {describe_value(elem)}"
        case Std(kind=kind, closed=closed):
            noun = _STD_NOUNS.get(kind, "a standard value") if kind is not None else "a standard value"
            return noun + ("" if closed else " that may hold a program object")
        case str():
            return repr(v)
        case Located(location=loc, repr=rp, atoms=atoms):
            return f"{rp} at {pretty_location(loc)}" + _atoms_suffix(atoms)
        case StrFact(regex=regex, atoms=atoms):
            text = "text" if regex == ANY_STR else f"text matching {pretty_regex(regex)}"
            return text + _atoms_suffix(atoms)
        case PathFact(atoms=atoms):
            return "path of unknown location" + _atoms_suffix(atoms)
        case UrlString(netloc=netloc, path=path, scheme=scheme, atoms=atoms):
            claims = ", ".join(
                bit
                for bit in (
                    f"scheme {scheme}" if scheme is not None else None,
                    f"netloc {pretty_regex(netloc)}" if netloc is not None else None,
                    f"path {pretty_location(path)}" if path is not None else None,
                )
                if bit is not None
            )
            return f"url ({claims or 'nothing known'})" + _atoms_suffix(atoms)


def describe_entry(entry: Value | Container | Std | Data) -> str:
    """A state entry as ``certora.reveal_fact`` reports it: the scalar facts and containers as
    ``describe_value`` renders them, a source handle by what it yields and can do, and nothing
    tracked as exactly that."""
    match entry:
        case None:
            return "nothing is known about it (not tracked at this point)"
        case Data(sources=sources, closed=closed, writes=writes):
            what = "a source handle"
            if sources:
                what += " yielding " + ", ".join(sorted(sources))
            if writes is not None:
                what = "a file open for writing at " + " or ".join(pretty_location(w) for w in writes)
            return what + ("" if closed else ", touched by program code (no longer inert)")
        case _:
            return describe_value(entry)


def _describe_binding(value: Binding) -> str:
    match value:
        case Many(elements=elements):
            return "[" + ", ".join(describe_value(e) for e in elements) + "]"
        case Elements(elem=elem):
            return f"elements of {describe_value(elem)}"
        case _:
            return describe_value(value)


def describe_sink(site: Site) -> str:
    match site:
        case SinkSite(fact=None):
            return "nothing is known about the path"
        case SinkSite(fact=Located(location=loc)):
            return f"confined to {pretty_location(loc)}"
        case SinkSite():
            return "the path is read as text; it is not confined"
        case NetworkSite(method=method, url=url):
            return f"{method} {describe_value(url)}"
        case ExecSite(arguments=arguments, cwd=cwd, keywords=keywords):
            args = ", ".join(describe_value(a) for a in arguments) or "none"
            holes = "".join(
                f"; {name}={_describe_binding(value)}" for name, value in sorted(keywords.items())
            )
            return f"cwd {describe_value(cwd)}; arguments: {args}{holes}"
        case CheckSite(arguments=arguments, cwd=cwd):
            args = ", ".join(f"{k}={describe_value(v)}" for k, v in sorted(arguments.items())) or "none"
            return f"cwd {describe_value(cwd)}; arguments: {args}"
