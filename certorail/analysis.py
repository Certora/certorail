import ast
import fnmatch
import inspect
import pathlib
import re
import urllib.parse
from typing import Any, cast, Callable, Literal, Mapping, Sequence
from dataclasses import dataclass, is_dataclass, replace

from .dangerous import INERT_BUILTIN_TYPES, INERT_BUILTIN_VALUES, inert_condition
from .ids import AtomId

sensitive_builtins = (
    "getattr",
    "setattr",
    "delattr",
    "vars",
    "locals",
    "globals",
    "compile",
    "eval",
    "exec",
    "open",
    "breakpoint",
    "help",
    # first-class slice objects would type-confuse the subscript transfers: xs[s] with s a
    # runtime slice yields a *list* where the analysis, seeing a non-Slice index expression,
    # claims an element fact. With the constructor banned, an index is a syntactic ast.Slice
    # or a runtime int, and the syntactic test is complete.
    "slice",
)

validator_funcs = frozenset([
    "certora_within",
    "certora_matches"
])

def is_dunder(x: str) -> bool:
    return x.startswith("__") and x.endswith("__")

@dataclass
class RegexMatch:
    regex: str

@dataclass
class PathConfinement:
    confined_path: str

type ContainerSort = Literal["set", "list", "dict_key", "dict_val", "tuple"]

@dataclass
class ContainerOf:
    of: "ValidationRule"
    sort: ContainerSort


type ValidationRule = PathConfinement | RegexMatch | ContainerOf

@dataclass
class ValidatedUsage:
    ident: str
    validation_rule: ValidationRule

@dataclass
class OpenCall:
    where: ast.AST
    mode: str
    target: str | list[ValidationRule]

type AuditEvents = OpenCall

@dataclass
class Validated:
    ident: str
    validations: list[ValidationRule]


@dataclass
class NameAccess:
    """An attribute chain ``base.f1.f2...``. The base is a name, ``super()``, or any other
    expression (a call result, a subscript, ...): ``x().foo`` is ``y = x(); y.foo``, so a computed
    base is a receiver like any other, merely one nothing is known about."""
    _wrappedBase: ast.expr | Literal["super"]
    fields: Sequence[tuple[str, ast.Attribute]]

    @property
    def full_path(self) -> tuple[str,...]:
        return (self.base_name,) + self.field_names

    @property
    def computed_base(self) -> ast.expr | None:
        """The base expression when it is neither a name nor ``super()``."""
        if isinstance(self._wrappedBase, str) or isinstance(self._wrappedBase, ast.Name):
            return None
        return self._wrappedBase

    @property
    def base_name(self) -> str:
        assert isinstance(self._wrappedBase, ast.Name)
        return self._wrappedBase.id

    @property
    def base_var(self) -> ast.Name:
        assert isinstance(self._wrappedBase, ast.Name)
        return self._wrappedBase

    @property
    def is_var_base(self) -> bool:
        return isinstance(self._wrappedBase, ast.Name)

    @property
    def field_names(self) -> tuple[str, ...]:
        return tuple(fld for (fld, _) in self.fields)

    def matches(self, *names: str) -> bool:
        return len(names) > 0 and self.is_var_base and self.base_name == names[0] and tuple(names[1:]) == self.field_names

def unfold_attr(e: ast.Attribute) -> NameAccess:
    attr_path : list[tuple[str, ast.Attribute]] = []
    it: ast.expr = e
    while True:
        if isinstance(it, ast.Attribute):
            attr_path.append((it.attr, it))
            it = it.value
        elif isinstance(it, ast.Name):
            return NameAccess(it, list(reversed(attr_path)))
        elif isinstance(it, ast.Call) and len(it.args) == 0 and len(it.keywords) == 0 and \
            isinstance(it.func, ast.Name) and it.func.id == "super":
            return NameAccess("super", list(reversed(attr_path)))
        else:
            return NameAccess(it, list(reversed(attr_path)))  # a computed base

def is_call_to(
    i: ast.AST
) -> str | None:
    if not isinstance(i, ast.Call):
        return None
    if not isinstance(i.func, ast.Name):
        return None
    return i.func.id

def resolve_callee(
    i: ast.AST
) -> NameAccess | None:
    if isinstance(i, ast.Name):
        return NameAccess(i, ())
    elif isinstance(i, ast.Attribute):
        return unfold_attr(i)
    else:
        return None  # a computed callee: ``f()()``, ``fs[0]()``
    

class InvalidConstantForm(Exception):
    ...

def cast_as_const_or_default[T](
    t: type[T],
    elem: Any
) -> T:
    if not isinstance(elem, ast.expr) and not isinstance(elem, t):
        raise InvalidConstantForm(f"Unexpected type: {type(elem)}")
    return as_const_or_default(t, elem)

def as_const_or_default[T](
    t: type[T],
    elem: T | ast.expr
) -> T:
    if isinstance(elem, t):
        return elem
    if not isinstance(elem, ast.Constant):
        raise InvalidConstantForm(f"Not a constnat expr: {type(elem).__name__}")
    if not isinstance(elem.value, t):
        raise InvalidConstantForm(f"Invalid constant type, expected: {t}, got {type(elem.value)}")
    return elem.value

def as_const[T](t: type[T], elem: ast.expr) -> T:
    if not isinstance(elem, ast.Constant):
        raise InvalidConstantForm(f"Expression is not a constant, got: {type(elem)}")
    if not isinstance(elem.value, t):
        raise InvalidConstantForm(f"Constant value is not a {t}, got {type(elem.value)}")
    return elem.value

def as_const_or_null[T](t: type[T], elem: ast.expr) -> T | None:
    if not isinstance(elem, ast.Constant):
        return None
    if not isinstance(elem.value, t):
        return None
    return elem.value

def bind_values[T](spec: type[T], args: Sequence[object], kwargs: Mapping[str, object]) -> T | None:
    """Match positional *args* and keyword *kwargs* -- AST nodes, facts, strings, whatever a
    caller has for the arguments of a call -- against the dataclass type *spec*, whose generated
    ``__init__`` is the signature. On success returns ``spec(...)`` built from them. Returns None
    when the call can't be statically bound:

      - too many positional arguments
      - unknown or duplicate keyword arguments
      - a required (no-default) field isn't supplied
      - a kw_only field passed positionally
      - an argument supplied both positionally and by keyword

    Only *binding* failures become None. The instance is constructed after binding succeeds, so
    exceptions from your own __post_init__ (a natural place for validation) propagate instead of
    masquerading as parse failures.
    """
    if not (isinstance(spec, type) and is_dataclass(spec)):
        raise TypeError(f"spec must be a dataclass type, got {spec!r}")
    try:
        bound = inspect.signature(spec).bind(*args, **kwargs)
    except TypeError:  # any way the binding can fail at runtime
        return None
    return spec(*bound.args, **bound.kwargs)


def bind_call_args[T](call: ast.Call, spec: type[T]) -> T | None:
    """``bind_values`` over a call's argument expressions. Splats defeat static binding."""
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    kwargs: dict[str, ast.expr] = {}
    for kw in call.keywords:
        if kw.arg is None:  # a **splat
            return None
        if kw.arg in kwargs:  # impossible in parsed source; hand-built ASTs only
            return None
        kwargs[kw.arg] = kw.value
    return bind_values(spec, call.args, kwargs)

def is_prefix[T](s: Sequence[T], r: Sequence[T]) -> bool:
    if len(s) > len(r):
        return False
    for i in range(0, len(s)):
        if s[i] != r[i]:
            return False
    return True

@dataclass(frozen=True)
class RegexLit:
    reg: str

@dataclass(frozen=True)
class Exact:
    exact_str: str

@dataclass(frozen=True)
class Concat:
    seq: list["PseudoRegex"]

@dataclass(frozen=True)
class Alternation:
    any_of: list["PseudoRegex"]

@dataclass(frozen=True)
class AnyStr:
    """Any string at all: the top of the string domain.

    Distinct from ``RegexLit(".*")``, which is opaque to every structural check and, since ``.``
    does not match a newline, is not actually top.
    """

@dataclass(frozen=True)
class Both:
    """The intersection of its parts: every conjunct holds of the value. Built by ``both`` when
    two independent readings of one value's text meet -- the shape an f-string gave it and the
    regex a ``re.fullmatch`` guard asserted -- each a sound description on its own, neither
    implying the other. Only ``both`` constructs one, and it never holds a wildcard, a duplicate,
    a nested Both or a finite part (those resolve); the parts are in canonical order, so equal
    conjunctions are structurally equal (``walker._join`` compares facts for equality)."""
    all_of: list["PseudoRegex"]

type PseudoRegex = Alternation | Concat | RegexLit | Exact | AnyStr | Both

ANY_STR = AnyStr()

# ---------------------------------------------------------------------------
# Path components
#
# The elements of a LocationFact. Every Component denotes a *safe* name: no "/", and none of "",
# "." or "..". That invariant is what lets the location operations stay structural; the string
# domain (PseudoRegex) enters only through Matching, as a further restriction on the name.
# ---------------------------------------------------------------------------

def is_safe_name(s: str) -> bool:
    return s not in ("", ".", "..") and "/" not in s

@dataclass(frozen=True)
class Named:
    """One specific component."""
    name: str

    def __post_init__(self) -> None:
        if not is_safe_name(self.name):
            raise ValueError(f"not a path component: {self.name!r}")

@dataclass(frozen=True)
class AnyName:
    """Any single safe component."""

@dataclass(frozen=True)
class Matching:
    """A safe component whose name fullmatches ``regex``.

    The conjunction is the meaning: the regex itself may admit strings that are not components.
    """
    regex: PseudoRegex

@dataclass(frozen=True)
class OneOf:
    """One of finitely many specific components (``x in ("a", "b")``)."""
    names: frozenset[str]

    def __post_init__(self) -> None:
        bad = [n for n in self.names if not is_safe_name(n)]
        if bad:
            raise ValueError(f"not path components: {bad!r}")

type Component = Named | AnyName | Matching | OneOf

ANY_NAME = AnyName()

@dataclass(frozen=True)
class StaticPath:
    """``absolute`` anchors the components at the filesystem root instead of the sandbox root.
    The two anchors never relate: no relative location lies within an absolute one or vice versa
    (``location_le``), even when the sandbox root happens to sit under the absolute prefix."""
    path_components: tuple[Component, ...]
    absolute: bool = False

    @property
    def final_component(self) -> Component:
        return self.path_components[-1]

    def merge_other(self, other: "LocationFact") -> "LocationFact":
        if other.absolute:
            return other  # joining onto an absolute path discards the left side (pathlib)
        if isinstance(other, StaticPath):
            return StaticPath(self.path_components + other.path_components, self.absolute)
        else:
            return DirSplat(
                self.path_components + other.static_prefix, other.final_component, self.absolute
            )

    def extend_static(self, other: tuple[str, ...]) -> "StaticPath":
        return StaticPath(self.path_components + tuple(Named(i) for i in other), self.absolute)

    def extend_single(self, other: Component) -> "StaticPath":
        return StaticPath(self.path_components + (other,), self.absolute)

    def to_splat(self, final_component: Component) -> "DirSplat":
        return DirSplat(self.path_components, final_component, self.absolute)

@dataclass(frozen=True)
class DirSplat:
    static_prefix: tuple[Component, ...]
    final_component: Component
    absolute: bool = False

    def merge_other(self, other: "LocationFact") -> "LocationFact":
        if other.absolute:
            return other  # joining onto an absolute path discards the left side (pathlib)
        return DirSplat(
            static_prefix=self.static_prefix,
            final_component=other.final_component,
            absolute=self.absolute,
        )

    def extend_static(self, ext: tuple[str, ...]) -> "DirSplat":
        return DirSplat(
            static_prefix=self.static_prefix,
            final_component=Named(ext[-1]),
            absolute=self.absolute,
        )

    def extend_single(self, other: Component) -> "DirSplat":
        return DirSplat(
            self.static_prefix,
            other,
            self.absolute
        )

    def to_splat(self, final_component: Component) -> "DirSplat":
        return DirSplat(self.static_prefix, final_component, self.absolute)


type LocationFact = StaticPath | DirSplat

# ---------------------------------------------------------------------------
# LocationFact -> PseudoRegex
#
# PseudoRegex is read as a language: L(Exact s) = {s}, L(RegexLit r) = the fullmatch language of
# r, Concat = concatenation, Alternation = union. The translation below produces a PseudoRegex
# whose language contains the canonical (PurePath) string of every path a LocationFact denotes.
# ---------------------------------------------------------------------------

SLASH = Exact("/")
ROOT = Exact(".")                    # canonical spelling of the empty relative path

# One safe component (see ``is_safe_name``) as a regex, written without anchors so it can sit
# anywhere inside a Concat:   [^.]...  |  .[^.]...  |  ..[at least one more char]
_COMPONENT_RE = r"(?:[^/.][^/]*|\.[^/.][^/]*|\.\.[^/]+)"
COMPONENT = RegexLit(_COMPONENT_RE)
# Zero or more such components, each followed by "/". PseudoRegex has no repetition node, so this
# is the one place the translation is a literal rather than structural.
DESCENDANTS = RegexLit(f"(?:{_COMPONENT_RE}/)*")


def concat(*ps: PseudoRegex) -> PseudoRegex:
    """Concatenation that flattens nested Concats and fuses adjacent literals.

    Fusing matters for precision: ``_explicit_check_no_parent`` answers False for any Concat but
    consults ``_safe_path_extension`` for an Exact, so ``data`` + ``/`` + ``uploads`` has to come
    out as ``Exact("data/uploads")`` for the atoms to stay derivable from the result.
    """
    flat: list[PseudoRegex] = []
    for p in ps:
        for q in (p.seq if isinstance(p, Concat) else [p]):
            if flat and isinstance(flat[-1], Exact) and isinstance(q, Exact):
                flat[-1] = Exact(flat[-1].exact_str + q.exact_str)
            elif flat and flat[-1] == ANY_STR and q == ANY_STR:
                continue  # adjacent wildcards are one wildcard
            else:
                flat.append(q)
    if len(flat) == 1:
        return flat[0]
    return Concat(flat)


def alternation(*ps: PseudoRegex) -> PseudoRegex:
    """Union that flattens nested Alternations and drops duplicate branches; any wildcard branch
    absorbs the rest."""
    flat: list[PseudoRegex] = []
    for p in ps:
        for q in (p.any_of if isinstance(p, Alternation) else [p]):
            if q == ANY_STR:
                return ANY_STR
            if q not in flat:
                flat.append(q)
    if len(flat) == 1:
        return flat[0]
    return Alternation(flat)


def _finite(p: PseudoRegex) -> list[str] | None:
    """The strings of a finite language: an Exact, or an Alternation of Exacts."""
    match p:
        case Exact(exact_str=s):
            return [s]
        case Alternation(any_of=branches) if all(isinstance(b, Exact) for b in branches):
            return [b.exact_str for b in branches if isinstance(b, Exact)]
        case _:
            return None


def both(*ps: PseudoRegex) -> PseudoRegex:
    """Intersection: the meet of the string domain. Flattens nested Boths, drops wildcards and
    duplicates, and resolves a finite part against the rest exactly -- ``{a,b,c} & {b,c,d}`` is
    ``{b,c}``, ``{a,b} & [ab]`` is ``{a,b}``, and an exact text absorbs everything (``abc & \\w+``
    is ``abc``). A finite part none of whose strings the others accept describes a dead path
    (``x == "abc" and re.fullmatch(r"\\d+", x)``): its fall-through is unreachable, so keeping
    the finite part claims nothing false there. What remains is sorted into a canonical order.

    Why a meet: a guard's regex and the regex the value already carried both hold, and keeping
    one by preference (as ``guards.apply`` once did) dropped whichever a later question needed --
    a ``re.fullmatch`` guard on an f-string-shaped value could discharge neither a regex
    guarantee nor a defined atom.
    """
    flat: list[PseudoRegex] = []
    for p in ps:
        for q in (p.all_of if isinstance(p, Both) else [p]):
            if q != ANY_STR and q not in flat:
                flat.append(q)
    for i, q in enumerate(flat):
        strings = _finite(q)
        if strings is None:
            continue
        others = flat[:i] + flat[i + 1 :]
        survivors = [s for s in strings if all(_regex_accepts(o, s) for o in others)]
        return alternation(*(Exact(s) for s in (survivors or strings)))
    if not flat:
        return ANY_STR
    if len(flat) == 1:
        return flat[0]
    return Both(sorted(flat, key=repr))


def component_to_regex(c: Component) -> PseudoRegex:
    """The string language of one component.

    Exact except for ``Matching``, whose "is a safe component" conjunct is dropped (``both`` could
    keep it; nothing downstream needs the tighter language): the result is looser there, never
    tighter.
    """
    match c:
        case Named(name=name):
            return Exact(name)
        case AnyName():
            return COMPONENT
        case Matching(regex=regex):
            return regex
        case OneOf(names=names):
            return alternation(*(Exact(n) for n in sorted(names)))


def _joined(components: Sequence[Component]) -> PseudoRegex:
    pieces: list[PseudoRegex] = []
    for i, c in enumerate(components):
        if i:
            pieces.append(SLASH)
        pieces.append(component_to_regex(c))
    return concat(*pieces)


def location_to_regex(loc: LocationFact) -> PseudoRegex:
    """A PseudoRegex whose language contains the canonical string of every path denoted by *loc*.

    Exact except where a ``Matching`` component is rendered (see ``component_to_regex``).
    """
    match loc:
        case StaticPath(path_components=(), absolute=ab):
            return SLASH if ab else ROOT
        case StaticPath(path_components=components, absolute=ab):
            joined = _joined(components)
            return concat(SLASH, joined) if ab else joined
        case DirSplat(static_prefix=prefix, final_component=final, absolute=ab):
            head: list[PseudoRegex] = [_joined(prefix), SLASH] if prefix else []
            if ab:
                head = [SLASH, *head]
            below = concat(*head, DESCENDANTS, component_to_regex(final))
            if final != ANY_NAME:
                return below
            # an unconstrained leaf means "at or below": the prefix itself is denoted too
            self_spelling = (
                (concat(SLASH, _joined(prefix)) if ab else _joined(prefix))
                if prefix
                else (SLASH if ab else ROOT)
            )
            return alternation(self_spelling, below)


def pretty_regex(p: PseudoRegex) -> str:
    """A regex-like spelling for reports: literals as themselves, ``.*`` for anything."""
    match p:
        case Exact(exact_str=s):
            return s
        case AnyStr():
            return ".*"
        case RegexLit(reg=r):
            return f"/{r}/"
        case Concat(seq=pieces):
            return "".join(pretty_regex(q) for q in pieces)
        case Alternation(any_of=branches):
            return "(" + "|".join(pretty_regex(b) for b in branches) + ")"
        case Both(all_of=parts):
            return "(" + "&".join(pretty_regex(q) for q in parts) + ")"


def pretty_component(c: Component) -> str:
    match c:
        case Named(name=n):
            return n
        case AnyName():
            return "*"
        case Matching(regex=r):
            return f"<{pretty_regex(r)}>"
        case OneOf(names=ns):
            return "{" + ",".join(sorted(ns)) + "}"


def pretty_location(loc: LocationFact) -> str:
    """A glob-like spelling for reports: ``repos/*/foundry.toml``, ``data/**/<.*\\.txt>``, ``.``."""
    match loc:
        case StaticPath(path_components=(), absolute=ab):
            return "/" if ab else "."
        case StaticPath(path_components=cs, absolute=ab):
            return ("/" if ab else "") + "/".join(pretty_component(c) for c in cs)
        case DirSplat(static_prefix=ps, final_component=leaf, absolute=ab):
            prefix = "/".join(pretty_component(c) for c in ps)
            tail = "**" if leaf == ANY_NAME else f"**/{pretty_component(leaf)}"
            return ("/" if ab else "") + (f"{prefix}/{tail}" if prefix else tail)


def splat_under(loc: LocationFact) -> DirSplat:
    """The location "somewhere at or below *loc*"."""
    match loc:
        case StaticPath(path_components=components, absolute=ab):
            return DirSplat(components, ANY_NAME, ab)
        case DirSplat(static_prefix=prefix, absolute=ab):
            return DirSplat(prefix, ANY_NAME, ab)


# ---------------------------------------------------------------------------
# Subsumption of components
#
# ``subsumes(general, specific)`` holds when every name *specific* can denote also satisfies
# *general*, i.e. L(specific) ⊆ L(general). It is conservative: False means "cannot show it",
# not "disjoint". Regex leaves are only ever asked about concrete strings (``re.fullmatch``), so
# no regex-inclusion reasoning is attempted beyond syntactic equality and Alternation splitting.
# ---------------------------------------------------------------------------


def _regex_accepts(p: PseudoRegex, s: str) -> bool:
    """Is the concrete string *s* in the language of *p*?"""
    match p:
        case AnyStr():
            return True
        case Exact(exact_str=e):
            return e == s
        case RegexLit(reg=r):
            try:
                return re.fullmatch(r, s) is not None
            except re.error:
                return False
        case Alternation(any_of=branches):
            return any(_regex_accepts(b, s) for b in branches)
        case Concat(seq=pieces):
            return _concat_accepts(pieces, s)
        case Both(all_of=parts):
            return all(_regex_accepts(p, s) for p in parts)


def _concat_accepts(pieces: Sequence[PseudoRegex], s: str) -> bool:
    # try every split point for the head piece; strings here are single path components
    if not pieces:
        return s == ""
    head, rest = pieces[0], pieces[1:]
    return any(
        _regex_accepts(head, s[:i]) and _concat_accepts(rest, s[i:]) for i in range(len(s) + 1)
    )


def _regex_subsumes(general: PseudoRegex, specific: PseudoRegex) -> bool:
    """L(specific) ⊆ L(general), by the obvious rules.

    A conjunction on the general side is exact: inside every conjunct. On the specific side it is
    sufficient -- some conjunct already inside, as the intersection lies within each -- but not
    complete: ``[ab]+ & [bc]+`` is ``b+`` and is not shown to lie within ``b+``. The general-side
    arm comes first. With a conjunction on both sides that reads "for every conjunct of general,
    some conjunct of specific implies it", which is insensitive to order and to extra conjuncts
    on the specific side; the other order would demand one conjunct of specific implying all of
    general, and fail ``a & b ⊆ b & a``.
    """
    if general == specific or general == ANY_STR:
        return True
    match general:
        case Both(all_of=parts):
            return all(_regex_subsumes(g, specific) for g in parts)
        case _:
            ...
    match specific:
        case Exact(exact_str=s):
            return _regex_accepts(general, s)
        case Alternation(any_of=branches):
            return all(_regex_subsumes(general, b) for b in branches)
        case Both(all_of=parts):
            return any(_regex_subsumes(general, p) for p in parts)
        case _:
            ...
    match general:
        case Alternation(any_of=branches):
            return any(_regex_subsumes(b, specific) for b in branches)
        case _:
            ...
    return False


def _normalize_component(c: Component) -> Component:
    """Fold a Matching with a finite language into the equivalent Named/OneOf, and a singleton
    OneOf into a Named, so the structural cases below see one spelling per meaning."""
    match c:
        case Matching(regex=AnyStr()):
            return ANY_NAME
        case Matching(regex=Exact(exact_str=s)) if is_safe_name(s):
            return Named(s)
        case Matching(regex=Alternation(any_of=branches)) if all(
            isinstance(b, Exact) for b in branches
        ):
            names = frozenset(b.exact_str for b in branches if isinstance(b, Exact))
            if not all(is_safe_name(n) for n in names):
                return c
            return Named(next(iter(names))) if len(names) == 1 else OneOf(names)
        case OneOf(names=names) if len(names) == 1:
            return Named(next(iter(names)))
        case _:
            return c


def subsumes(general: Component, specific: Component) -> bool:
    """Does every name *specific* can denote also satisfy *general*?

    Conservative: False means "cannot show it". A ``Matching`` on the general side is checked
    against concrete names by ``re.fullmatch`` (the "safe component" conjunct is already true of
    any ``Named``); a ``Named``/``OneOf`` on the general side can never be shown to cover a regex.
    """
    general, specific = _normalize_component(general), _normalize_component(specific)
    if general == specific or general == ANY_NAME:
        return True
    match general, specific:
        case _, AnyName():
            return False  # only AnyName covers every name
        case OneOf(names=gs), Named(name=s):
            return s in gs
        case OneOf(names=gs), OneOf(names=ss):
            return ss <= gs
        case Matching(regex=r), Named(name=s):
            return _regex_accepts(r, s)
        case Matching(regex=r), OneOf(names=ss):
            return all(_regex_accepts(r, s) for s in ss)
        case Matching(regex=g), Matching(regex=s):
            return _regex_subsumes(g, s)
        case _:
            return False


# "not-dot-dot": the string is not exactly "..". Together with "no-slash" it implies
# "no-parent-traversal" (a single component traverses upward only if it is exactly "..").
type AtomicFact = Literal["no-slash", "no-parent-traversal", "not-absolute", "not-dot-dot"]

ALL_ATOMS: frozenset[AtomicFact] = frozenset(
    {"no-slash", "no-parent-traversal", "not-absolute", "not-dot-dot"}
)

def _explicit_check_no_parent(regex: PseudoRegex) -> bool:
    match regex:
        case Alternation():
            return all(_explicit_check_no_parent(p) for p in regex.any_of)
        case Exact():
            return _safe_path_extension(regex.exact_str) is not None
        case RegexLit() | AnyStr():
            return False
        case Concat():
            return False
        case Both(all_of=parts):
            return any(_explicit_check_no_parent(p) for p in parts)

def _explicit_check_no_slash(regex: PseudoRegex) -> bool:
    match regex:
        case Alternation():
            return all(_explicit_check_no_slash(p) for p in regex.any_of)
        case Exact():
            return "/" not in regex.exact_str
        case RegexLit() | AnyStr():
            return False
        case Concat():
            return all(_explicit_check_no_slash(p) for p in regex.seq)
        case Both(all_of=parts):
            return any(_explicit_check_no_slash(p) for p in parts)

def _explicit_check_not_absolute(regex: PseudoRegex) -> bool:
    match regex:
        case Alternation():
            return all(_explicit_check_not_absolute(p) for p in regex.any_of)
        case Exact():
            return not regex.exact_str.startswith("/")
        case RegexLit() | AnyStr():
            return False
        case Concat():
            return _explicit_check_not_absolute(regex.seq[0])
        case Both(all_of=parts):
            return any(_explicit_check_not_absolute(p) for p in parts)

def _explicit_check_not_dot_dot(regex: PseudoRegex) -> bool:
    match regex:
        case Alternation():
            return all(_explicit_check_not_dot_dot(p) for p in regex.any_of)
        case Exact():
            return regex.exact_str != ".."
        case RegexLit() | AnyStr():
            return False
        case Concat():
            # some literal piece contributes a character other than "."
            return any(isinstance(p, Exact) and p.exact_str.strip(".") != "" for p in regex.seq)
        case Both(all_of=parts):
            return any(_explicit_check_not_dot_dot(p) for p in parts)

def _explicit_check(other: AtomicFact, regex: PseudoRegex) -> bool:
    match other:
        case "no-parent-traversal":
            return _explicit_check_no_parent(regex)
        case "no-slash":
            return _explicit_check_no_slash(regex)
        case "not-absolute":
            return _explicit_check_not_absolute(regex)
        case "not-dot-dot":
            return _explicit_check_not_dot_dot(regex)

def _holds(atom: AtomicFact, atoms: frozenset[AtomicFact], regex: PseudoRegex) -> bool:
    """Does *atom* hold, either as stated, as derivable from the regex, or as implied by other atoms?"""
    if atom in atoms or _explicit_check(atom, regex):
        return True
    match atom:
        case "not-absolute":
            # a string without "/" cannot start with one
            return _holds("no-slash", atoms, regex)
        case "no-parent-traversal":
            # a single component traverses upward only if it is exactly ".."
            return _holds("no-slash", atoms, regex) and _holds("not-dot-dot", atoms, regex)
        case _:
            return False

# ---------------------------------------------------------------------------
# Facts
#
# A value is read in one of these ways, never several at once:
#   * as *text*   -- StrFact / PathFact: what its characters look like (regex, atoms). Nothing is
#                    known about it as a path; ``locate`` is the partial lift to the path reading.
#   * as a *path* -- Located: where it points, and whether it is spelled as a str or a Path.
#                    Nothing is tracked about its text; ``as_text`` is the forgetful map back.
#   * as a *URL*  -- UrlString: claims about its urlsplit reading (netloc, path, scheme).
#                    Nothing is tracked about its text either; ``url_of`` is the partial lift.
# Going into text is giving up on the path (or URL) reading; the transfer functions stay in
# path-land for as long as the operation is a path operation.
#
# Every fact additionally carries ``checks``: the policy-declared validations (certora.check) this
# exact value has passed. Checks belong to the value as it was at the check site: they ride along
# assignment and the same-value respellings (str(), locate), and everything that builds a *new*
# value -- joins, string methods, concatenation -- starts with none. The walker kills them at
# every call that may have effects.
# ---------------------------------------------------------------------------

type Repr = Literal["str", "path"]

@dataclass(frozen=True)
class StrFact:
    """A ``str`` read as text."""
    regex: PseudoRegex = ANY_STR
    atoms: frozenset[AtomicFact] = frozenset()
    checks: frozenset[str] = frozenset()

    def __contains__(self, atom: AtomicFact) -> bool:
        return _holds(atom, self.atoms, self.regex)

@dataclass(frozen=True)
class PathFact:
    """A ``pathlib.Path`` of unknown location, read as text through ``str(p)``: ``no-slash`` means
    a single relative component, ``not-absolute`` means ``not p.is_absolute()``,
    ``no-parent-traversal`` means no ``..`` part."""
    atoms: frozenset[AtomicFact] = frozenset()
    checks: frozenset[str] = frozenset()

    def __contains__(self, atom: AtomicFact) -> bool:
        return _holds(atom, self.atoms, ANY_STR)

@dataclass(frozen=True)
class Located:
    """A value read as a path: where it points, spelled as a ``str`` or a ``pathlib.Path``."""
    location: LocationFact
    repr: Repr
    checks: frozenset[str] = frozenset()

@dataclass(frozen=True)
class UrlString:
    """A ``str`` read as a URL: claims about its ``urllib.parse.urlsplit`` reading. Each
    component is one claim, ``None`` claiming nothing -- the netloc's text lies in the regex's
    language, the (server-absolute, hence anchored) path is one the LocationFact denotes, the
    scheme is exactly the literal. Nothing else is tracked about the text: reading a value as
    a URL gives up its text reading, as ``Located`` gives up text for paths.

    The claims are ``urlsplit`` claims. ``urlparse`` agrees on scheme and netloc but shears
    ``;params`` off the last path segment, so a ``.path`` observed through ``urlparse`` is NOT
    evidence about the urlsplit path (the guards only trust ``urlsplit`` for it). Path claims
    are lexical: dot-segments are not resolved, so a location claim can only be built from
    text shown free of ``..`` (the same discipline as filesystem containment)."""
    netloc: PseudoRegex | None = None
    path: LocationFact | None = None
    scheme: Literal["http", "https"] | None = None
    checks: frozenset[str] = frozenset()

type ValidationFact = StrFact | PathFact | Located | UrlString

@dataclass(frozen=True)
class Container:
    """A tracked ``list``/``set``: the reduced-product partner of the scalar facts
    (CONTAINERS.md). Deliberately NOT a ValidationFact: the scalar transfer functions never
    see one -- ``interpret_expr`` yields None for a container-valued name -- and the two
    domains meet only at the roster operations the walker recognizes.

    ``elem`` is an ordinary ValidationFact: the *current* element fact, degraded by kills
    like any scalar (the annotation is only the birth/interface invariant). ``kind``
    "sequence" is the read-only borrow a ``Sequence[...]`` parameter receives: no mutators,
    ever. ``param`` provenance -- received through a function boundary, directly or by
    aliasing -- makes escape an error instead of a forget."""
    kind: Literal["list", "set", "sequence"]
    elem: ValidationFact
    param: bool = False

@dataclass(frozen=True)
class Data:
    """A *source handle* (PROVENANCE.md): the result of a ``certora.exec``, a ``certora.network``
    request, or a file read, bound to a name. Like ``Container``, deliberately NOT a
    ValidationFact: ``interpret_expr`` yields None for a handle-valued name, and the two domains
    meet only at the extractors (``certora.extract`` & co.) and at iteration (``for line in f``).

    ``sources`` is the *source atoms* the handle yields -- the pure atoms the policy attached to
    the rule that produced it. Empty for a handle from a rule that names no source: still
    extractable, vouching for nothing.

    ``closed`` is the inertness bit shared with ``Std`` (EFFECTS.md, the callee analysis): a
    handle is a Python object an attribute store can patch (``h.read = f``), so it is inert --
    handing it to an extractor or calling its methods runs no program code -- only while no
    program code can have touched it. Any call that may run program code, and any attribute
    store, opens every handle in the state, since an alias may have been the receiver."""
    sources: frozenset[str] = frozenset()
    closed: bool = True

    def opened(self) -> "Data":
        return replace(self, closed=False) if self.closed else self

type StdKind = Literal[
    "bytes", "number", "bool", "none", "match", "pattern", "list", "tuple", "set", "frozenset", "dict"
]

@dataclass(frozen=True)
class Std:
    """A value of standard type about which nothing more is tracked: the coarse partner of the
    facts, for the callee analysis (EFFECTS.md) -- a number, ``None``, a ``re.Match``, a list
    or a dict of such things. Like ``Container`` and ``Data``, deliberately NOT a
    ValidationFact: ``interpret_expr`` yields None for a Std-valued name, nothing is ever
    established on one, and it exists only to answer "can a call on, or with, this value run
    program code?".

    ``kind`` names the type when it is known -- a literal, a display, a constructor, a roster
    call; None is a standard value of unknown kind: an element read out of a closed container,
    the result of a method on an inert receiver. Every named kind is a C type: it cannot be
    patched with an attribute, so its methods are the interpreter's own.

    ``closed`` says the value holds no program object: for a container, every element is inert,
    recursively; for an unknown kind, also that no program object has been registered with it.
    A closed value is *inert* -- no operation on it transfers control to program code -- and
    inertness is what exempts a call from the kill. The scalar kinds are closed by construction
    and stay so. A container, a tuple (it may hold a list) or an unknown kind is *opened* by any
    call that may run program code -- an alias may have been mutated behind the analysis' back
    -- and by any store of a non-inert value into a standard value (``lst.append(f)``,
    ``d[k] = gen``, ``obj.attr = v``): the whole state at once, since the receiver may alias
    anything."""
    kind: StdKind | None = None
    closed: bool = True

    @property
    def openable(self) -> bool:
        """Can program code end up inside this value? Not inside a scalar, a match, a pattern,
        or a frozenset (its elements are hashable, hence immutable all the way down)."""
        return self.kind not in ("bytes", "number", "bool", "none", "match", "pattern", "frozenset")

    def opened(self) -> "Std":
        return replace(self, closed=False) if self.closed and self.openable else self

# what the expression semantics read facts from: the walker's state. A Mapping, not a dict,
# both because these functions only ever read it and because covariance then lets a plain
# dict[str, ValidationFact] (tests, sub-states) flow in despite dict's invariance.
type Entry = ValidationFact | Container | Data | Std
type StateMap = Mapping[str, Entry]

def inert(entry: Entry | None) -> bool:
    """Is a state entry an inert value (EFFECTS.md)? A str or path fact and a tracked container
    (of facts) always; a standard value and a source handle while closed; an unknown value
    never."""
    match entry:
        case None:
            return False
        case Std(closed=closed) | Data(closed=closed):
            return closed
        case _:
            return True

def inert_receiver(entry: Entry | None) -> bool:
    """Does the receiver's entry make a method call the interpreter's own code? An inert value,
    of course; also a standard value of *known* kind even when opened -- a C type's methods
    never dispatch to the contents beyond the fixed dunders (``lst.sort()`` compares with
    ``__lt__``, which no program class defines) -- but not an opened unknown kind, which may be
    a stdlib object a program callback was registered with, nor an opened handle."""
    match entry:
        case Std(kind=kind, closed=closed):
            return kind is not None or closed
        case _:
            return inert(entry)

def is_path_typed(fact: ValidationFact | None) -> bool:
    return isinstance(fact, PathFact) or (isinstance(fact, Located) and fact.repr == "path")

def location_of(fact: ValidationFact | None) -> LocationFact | None:
    return fact.location if isinstance(fact, Located) else None

def checks_of(fact: ValidationFact | None) -> frozenset[str]:
    return frozenset() if fact is None else fact.checks

def drop_checks(fact: ValidationFact, keep: frozenset[str] = frozenset()) -> ValidationFact:
    """The value with its environment-dependent checks forgotten (the crude kill). *keep* is the
    policy's pure atoms -- true of the value's text alone, so no effect can invalidate them."""
    kept = fact.checks & keep
    return fact if kept == fact.checks else replace(fact, checks=kept)

def known_text(value: "str | ValidationFact | None") -> str | None:
    """The exact text of a statically-known value: a literal, a str fact with an exact regex, or
    a located value whose path is fully constant. This is what a *literal checker* can be run on."""
    match value:
        case str():
            return value
        case StrFact(regex=Exact(exact_str=s)):
            return s
        case Located(location=StaticPath(path_components=cs, absolute=ab)) if all(
            isinstance(c, Named) for c in cs
        ):
            joined = "/".join(c.name for c in cs if isinstance(c, Named))
            return "/" + joined if ab else joined or "."
        case _:
            return None

def saturate(
    value: str | ValidationFact | None, defined: Mapping[AtomId, PseudoRegex]
) -> "str | ValidationFact | None":
    """The value with every *defined* atom its known text entails added to ``checks``. A defined
    atom is a pure text property (the policy's ``atom()``), so establishing it from the text is
    sound anywhere -- this is how a literal satisfies an atom with no runtime check."""
    if value is None or not defined:
        return value
    fact: ValidationFact = StrFact(regex=Exact(value)) if isinstance(value, str) else value
    text = as_text(fact).regex
    gained = frozenset(
        name
        for name, meaning in defined.items()
        if name not in fact.checks and _regex_subsumes(meaning, text)
    )
    return fact if not gained else replace(fact, checks=fact.checks | gained)


class InvalidProgram(Exception):
    def __init__(self, node: ast.AST, msg: str):
        super().__init__(msg)
        self.node = node

def reroot(
    s: StaticPath,
    new_root: StaticPath
):
    return StaticPath(
        s.path_components + new_root.path_components
    )

def _safe_path_extension(s: str) -> tuple[str, ...] | None:
    as_path = pathlib.PurePath(s)
    if as_path.is_absolute():
        return None
    if any(p == ".." for p in as_path.parts):
        return None
    last = as_path.name
    if last:
        return as_path.parts
    else:
        return None


def as_component(fact: StrFact | PathFact) -> Component | None:
    """Lift a text value to a single path component, if its atoms allow it.

    This is the only place the text atoms are consumed on behalf of the location domain: a value
    is a component iff it has no "/" and no ".." (``_holds`` supplies the derived forms of both).
    The regex, if any, then decides how precise the component is.
    """
    if not ("no-slash" in fact and "no-parent-traversal" in fact):
        return None
    regex = fact.regex if isinstance(fact, StrFact) else ANY_STR
    match regex:
        case AnyStr():
            return ANY_NAME
        case Exact(exact_str=s):
            return Named(s) if is_safe_name(s) else None
        case Alternation(any_of=branches) if all(isinstance(b, Exact) for b in branches):
            names = [b.exact_str for b in branches if isinstance(b, Exact)]
            return OneOf(frozenset(names)) if all(is_safe_name(n) for n in names) else None
        case _:
            return Matching(regex)

def _literal_location(s: str) -> StaticPath | None:
    as_path = pathlib.PurePath(s)
    if as_path.is_absolute():
        rest = as_path.parts[1:]  # parts[0] is the "/" anchor
        if any(p == ".." for p in rest):
            return None
        return StaticPath(tuple(Named(p) for p in rest), absolute=True)
    if not as_path.parts:
        return StaticPath(())  # "", ".", "./": the current directory, i.e. the sandbox root
    parts = _safe_path_extension(s)
    return None if parts is None else StaticPath(tuple(Named(p) for p in parts))

def locate(fact: ValidationFact | None) -> Located | None:
    """The path reading of a value, if it has one.

    A located value is returned as is. A text value is located iff its text is a safe path: a
    known literal is parsed (an absolute one anchors at the filesystem root); a single safe
    component sits directly under the root; a relative string free of ".." is somewhere at or
    below the root. Anything else has no path reading (yet).
    """
    match fact:
        case None:
            return None
        case Located():
            return fact
        case StrFact() | PathFact():
            rp: Repr = "str" if isinstance(fact, StrFact) else "path"
            if isinstance(fact, StrFact) and isinstance(fact.regex, Exact):
                loc = _literal_location(fact.regex.exact_str)
                return None if loc is None else Located(loc, rp, fact.checks)
            if (comp := as_component(fact)) is not None:
                return Located(StaticPath((comp,)), rp, fact.checks)
            if "no-parent-traversal" in fact and "not-absolute" in fact:
                return Located(DirSplat((), ANY_NAME), rp, fact.checks)
            return None
        case UrlString():
            return None  # a URL is not a filesystem path


def url_of(value: str | ValidationFact | None) -> UrlString | None:
    """The URL reading of a value: a ``UrlString`` as is; exactly-known text parsed by
    ``urlsplit``. The lift is partial -- of anything else, nothing."""
    if isinstance(value, UrlString):
        return value
    text = known_text(value)
    if text is None:
        return None
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        return None
    scheme = parts.scheme if parts.scheme in ("http", "https") else None
    # a ".."-bearing path has no location (lexical claims only); the netloc stays exact
    return UrlString(
        netloc=Exact(parts.netloc),
        path=_literal_location(parts.path),
        scheme=scheme,
        checks=checks_of(value) if not isinstance(value, str) else frozenset(),
    )


def containment_of(fact: ValidationFact | None) -> LocationFact | None:
    located = locate(fact)
    return None if located is None else located.location

# --- entailment ----------------------------------------------------------------------------------
#
# The rely/guarantee check: does what is known of a value establish what a contract requires?
# Conservative throughout -- False means "not shown", never "disjoint".

def location_le(actual: LocationFact, required: LocationFact) -> bool:
    """Is every path *actual* may denote one that *required* denotes? Anchors never relate: a
    relative (sandbox-root) location is not within an absolute one or vice versa, even when the
    sandbox root happens to lie under the absolute prefix."""
    if actual.absolute != required.absolute:
        return False
    match actual, required:
        case StaticPath(path_components=cs), StaticPath(path_components=ds):
            return len(cs) == len(ds) and all(subsumes(d, c) for d, c in zip(ds, cs))
        case StaticPath(path_components=cs), DirSplat(static_prefix=ps, final_component=leaf):
            if len(cs) < len(ps) or not all(subsumes(p, c) for p, c in zip(ps, cs)):
                return False
            if len(cs) == len(ps):
                return leaf == ANY_NAME  # the prefix itself is denoted only by an unconstrained leaf
            return subsumes(leaf, cs[-1])
        case DirSplat(), StaticPath():
            return False
        case DirSplat(static_prefix=ps, final_component=l), DirSplat(static_prefix=qs, final_component=m):
            # a's leaves must satisfy m (an unconstrained l therefore needs an unconstrained m),
            # and a's prefix must lie under b's
            return (
                len(ps) >= len(qs)
                and all(subsumes(q, p) for q, p in zip(qs, ps))
                and subsumes(m, l)
            )

def entails(actual: str | ValidationFact | None, required: ValidationFact) -> bool:
    """Does what is known of *actual* establish *required*?"""
    if actual is None:
        return False
    fact: ValidationFact = StrFact(regex=Exact(actual)) if isinstance(actual, str) else actual
    match required:
        case UrlString(netloc=netloc, path=path, scheme=scheme, checks=checks):
            # component-wise: each stated claim must be established; None claims nothing.
            # url_of makes exactly-known text discharge with no guard ceremony.
            got = url_of(fact)
            if got is None:
                return False
            if netloc is not None and (
                got.netloc is None or not _regex_subsumes(netloc, got.netloc)
            ):
                return False
            if path is not None and (got.path is None or not location_le(got.path, path)):
                return False
            if scheme is not None and got.scheme != scheme:
                return False
            return checks <= got.checks
        case Located(location=loc, repr=rp, checks=checks):
            got = locate(fact)
            return (
                got is not None
                and got.repr == rp
                and location_le(got.location, loc)
                and checks <= got.checks
            )
        case StrFact(regex=regex, atoms=atoms, checks=checks):
            match fact:
                case StrFact():
                    return (
                        _regex_subsumes(regex, fact.regex)
                        and all(a in fact for a in atoms)
                        and checks <= fact.checks
                    )
                case Located(repr="str") | UrlString():
                    # a str, but nothing is tracked about its text
                    return regex == ANY_STR and not atoms and checks <= fact.checks
                case _:
                    return False
        case PathFact(atoms=atoms, checks=checks):
            match fact:
                case PathFact():
                    return all(a in fact for a in atoms) and checks <= fact.checks
                case Located(repr="path"):
                    # nothing lexical is tracked about a located value
                    return not atoms and checks <= fact.checks
                case _:
                    return False

def combine_containment(
    cont: LocationFact,
    child: str | ValidationFact | None
) -> LocationFact | None:
    """*cont* extended by one more argument of a join: a literal (possibly several components), a
    located value (its whole location), or a text value that is a safe component / relative path."""
    match child:
        case None:
            return None
        case str():
            if not pathlib.PurePath(child).parts:
                return cont  # joining "." or "" adds nothing
            parts = _safe_path_extension(child)
            return None if parts is None else cont.extend_static(parts)
        case Located(location=loc):
            return cont.merge_other(loc)
        case UrlString():
            return None  # a URL glued onto a path is no longer a path we can place
        case StrFact(regex=Exact(exact_str=s)):
            if not pathlib.PurePath(s).parts:
                return cont  # a value known to be exactly "" or ".": joining it adds nothing
            parts = _safe_path_extension(s)  # a known literal, possibly several components
            return None if parts is None else cont.extend_static(parts)
        case _:
            if (component := as_component(child)) is not None:
                return cont.extend_single(component)
            if "no-parent-traversal" in child and "not-absolute" in child:
                return cont.to_splat(ANY_NAME)
            return None

def as_text(v: str | ValidationFact | None) -> StrFact:
    """The text reading of a value: the forgetful map. A located value's location is rendered to a
    regex (its atoms then follow from that regex where it is exact); of an unknown value nothing
    is known."""
    match v:
        case None:
            return StrFact()
        case str():
            return StrFact(regex=Exact(v))
        case StrFact():
            return v
        case PathFact(atoms=atoms):
            return StrFact(atoms=atoms)
        case Located(location=loc):
            return StrFact(regex=location_to_regex(loc))
        case UrlString():
            return StrFact()  # component claims do not (yet) reconstruct the text

def as_str_value(fact: ValidationFact | None) -> ValidationFact | None:
    """``str(x)`` / ``os.fspath(x)``: the same value, spelled as a str."""
    match fact:
        case None:
            return None
        case Located(location=loc, checks=checks):
            return Located(loc, "str", checks)
        case PathFact(atoms=atoms, checks=checks):
            return StrFact(atoms=atoms, checks=checks)
        case StrFact() | UrlString():
            return fact  # already a str; str() is the identity and every claim survives

# --- concatenated text ---------------------------------------------------------------------------
#
# ``a + "/" + b`` and f"{a}/{b}" are joins when the text spells  component "/" component "/" ... :
# then the result is still located (as a str). Any other concatenation is text, and the path reading
# has been given up.
#
# The spelling is read left to right by a small automaton. Its states are the classes below --
# nothing read yet; at a "/" with a complete location behind it; inside a component, gathering the
# text of that component; dead -- and each transition consumes one piece of text. A located piece
# is *replayed* as the spelling of its components, which is what makes ``f"audit-{name}/y"`` glue
# ``audit-`` onto the first component of ``name`` and continue from its last.

type _Chunk = str | StrFact | PathFact  # what accumulates inside one component

def _component_token(c: Component) -> _Chunk:
    """A component spelled as text: a literal, or a text fact that ``as_component`` lifts back."""
    match c:
        case Named(name=n):
            return n
        case AnyName():
            return StrFact(atoms=ALL_ATOMS)
        case Matching(regex=r):
            return StrFact(regex=r, atoms=ALL_ATOMS)
        case OneOf(names=ns):
            return StrFact(regex=alternation(*(Exact(n) for n in sorted(ns))), atoms=ALL_ATOMS)

def _component_of(chunks: Sequence[_Chunk]) -> Component | None:
    """The text of one component as a component, or None if it can't be shown to be one."""
    literals = [c for c in chunks if isinstance(c, str)]
    facts = [c for c in chunks if isinstance(c, (StrFact, PathFact))]
    if not facts:
        s = "".join(literals)
        return Named(s) if is_safe_name(s) else None
    if len(chunks) == 1:
        return as_component(facts[0])
    if not all("no-slash" in f for f in facts):
        return None
    # a literal with a non-dot character rules out "", "." and ".." for the whole component
    if not any(lit.strip(".") for lit in literals):
        return None
    return Matching(concat(*(Exact(c) if isinstance(c, str) else as_text(c).regex for c in chunks)))

class _Spelling:
    """A state of the reader. Each transition consumes one piece of text and returns the next state;
    the base class is the dead state's behaviour, which the live states override."""

    def chunk(self, c: _Chunk) -> "_Spelling":
        """A slash-free literal, or a text fact."""
        return _DEAD

    def sep(self) -> "_Spelling":
        """A ``/``."""
        return _DEAD

    def splat(self) -> "_Spelling":
        """The ``**`` of a DirSplat."""
        return _DEAD

    def unknown(self) -> "_Spelling":
        return _DEAD

    def finish(self) -> LocationFact | None:
        return None

    def located(self, loc: LocationFact) -> "_Spelling":
        """Replay the spelling of a located value. An absolute location spells a leading "/":
        at the start of the text that anchors the result, anywhere else it is just a separator
        (the concatenated *string* stays whatever the text says)."""
        state: _Spelling = self.sep() if loc.absolute else self
        match loc:
            case StaticPath(path_components=(), absolute=ab):
                return state if ab else state.chunk(".")  # "/", or the root as PurePath spells it
            case StaticPath(path_components=cs):
                return state._components(cs)
            case DirSplat(static_prefix=ps, final_component=leaf):
                state = state._components(ps).sep() if ps else state
                return state.splat().sep().chunk(_component_token(leaf))

    def _components(self, cs: Sequence[Component]) -> "_Spelling":
        state: _Spelling = self
        for i, c in enumerate(cs):
            if i:
                state = state.sep()
            state = state.chunk(_component_token(c))
        return state

    def piece(self, p: str | ValidationFact | None) -> "_Spelling":
        """Consume one piece of the concatenation."""
        match p:
            case None:
                return self.unknown()
            case str():
                state: _Spelling = self
                for i, chunk in enumerate(p.split("/")):
                    if i:
                        state = state.sep()
                    if chunk:
                        state = state.chunk(chunk)
                return state
            case Located(location=loc):
                return self.located(loc)
            case UrlString():
                return self.unknown()  # nothing is tracked about a URL-read value's text
            case StrFact() | PathFact():
                return self.chunk(p)

class _Dead(_Spelling):
    """No path reading: some piece could not be placed."""

class _Start(_Spelling):
    """Nothing read yet."""

    def chunk(self, c: _Chunk) -> _Spelling:
        return _Open(None, (c,))

    def sep(self) -> _Spelling:
        return _Boundary(StaticPath((), absolute=True))  # a leading "/": absolute

    def splat(self) -> _Spelling:
        return _Boundary(DirSplat((), ANY_NAME))

@dataclass(frozen=True)
class _Boundary(_Spelling):
    """A complete location with a "/" just read: the next chunk starts a new component."""
    loc: LocationFact

    def chunk(self, c: _Chunk) -> _Spelling:
        return _Open(self.loc, (c,))

    def sep(self) -> _Spelling:
        return self  # "//" collapses

    def splat(self) -> _Spelling:
        return _Boundary(splat_under(self.loc))

    def finish(self) -> LocationFact | None:
        return self.loc  # a trailing "/" adds nothing

@dataclass(frozen=True)
class _Open(_Spelling):
    """Inside a component: *chunks* is its text so far, *prefix* the location before it (None at
    the very start). Closing the component decides what it is."""
    prefix: LocationFact | None
    chunks: tuple[_Chunk, ...]

    def chunk(self, c: _Chunk) -> _Spelling:
        return _Open(self.prefix, (*self.chunks, c))

    def sep(self) -> _Spelling:
        loc = self._close()
        return _DEAD if loc is None else _Boundary(loc)

    def splat(self) -> _Spelling:
        return _DEAD  # text glued onto "**" has no location

    def finish(self) -> LocationFact | None:
        return self._close()

    def _close(self) -> LocationFact | None:
        if all(isinstance(c, str) for c in self.chunks) and "".join(cast(str, c) for c in self.chunks) == ".":
            return StaticPath(()) if self.prefix is None else self.prefix  # "." adds nothing
        match self.chunks:
            case ((StrFact() | PathFact()) as fact,):
                # a lone text value is a whole path in its own right: an exact literal may have
                # several components, a ".."-free relative string is a splat
                if self.prefix is None:
                    return containment_of(fact)
                return combine_containment(self.prefix, fact)
            case _:
                comp = _component_of(self.chunks)
                if comp is None:
                    return None
                return StaticPath((comp,)) if self.prefix is None else self.prefix.extend_single(comp)

_DEAD = _Dead()
_START = _Start()

def _text_of_pieces(pieces: Sequence[str | ValidationFact | None]) -> StrFact:
    """The text reading of a concatenation that is not a join."""

    def slash_free(p: str | ValidationFact | None) -> bool:
        match p:
            case str():
                return "/" not in p
            case StrFact() | PathFact():
                return "no-slash" in p
            case _:
                return False  # unknown, or a located value (a path may well contain "/")

    atoms: frozenset[AtomicFact] = (
        frozenset({"no-slash"}) if all(slash_free(p) for p in pieces) else frozenset()
    )
    regexes = [as_text(p).regex for p in pieces]
    return StrFact(regex=concat(*regexes) if regexes else Exact(""), atoms=atoms)

def join_text(pieces: Sequence[str | ValidationFact | None]) -> ValidationFact:
    """Concatenation of text: ``+`` chains and f-strings."""
    if all(isinstance(p, str) for p in pieces):
        return StrFact(regex=Exact("".join(cast(str, p) for p in pieces)))  # a literal; ``locate`` parses it
    state: _Spelling = _START
    for p in pieces:
        state = state.piece(p)
    loc = state.finish()
    return Located(loc, "str") if loc is not None else _text_of_pieces(pieces)

def _argv_read(e: ast.expr) -> bool:
    """``sys.argv``, or a subscript of it: a source of strs of unknown text. (The type is the
    whole fact -- a ``StrFact()`` instead of ``None`` is what lets guards and checks refine an
    argument-vector value at all.)"""
    if isinstance(e, ast.Subscript):
        e = e.value
    access = resolve_callee(e)
    return access is not None and access.matches("sys", "argv")


def operand_value(e: ast.expr, st: StateMap) -> str | ValidationFact | None:
    """An operand as the joins see it: a string literal stays a literal (so a multi-component
    literal can be split into components); anything else is interpreted."""
    if (s := as_const_or_null(str, e)) is not None:
        return s
    return interpret_expr(e, st)

def _head_location(v: str | ValidationFact | None) -> LocationFact | None:
    match v:
        case None:
            return None
        case str():
            return _literal_location(v)
        case _:
            return containment_of(v)

def join_args(args: Sequence[ast.expr], st: StateMap) -> LocationFact | None:
    """``pathlib.Path(a, b, ...)`` / ``os.path.join(a, b, ...)``: the first argument's location,
    extended by the rest."""
    loc = _head_location(operand_value(args[0], st))
    for a in args[1:]:
        if loc is None:
            return None
        loc = combine_containment(loc, operand_value(a, st))
    return loc

def _flatten_add(e: ast.expr) -> list[ast.expr]:
    match e:
        case ast.BinOp(left=left, op=ast.Add(), right=right):
            return _flatten_add(left) + _flatten_add(right)
        case _:
            return [e]

def _fstring_pieces(e: ast.JoinedStr, st: StateMap) -> list[str | ValidationFact | None]:
    out: list[str | ValidationFact | None] = []
    for v in e.values:
        match v:
            case ast.Constant(value=str() as s):
                out.append(s)
            case ast.FormattedValue(value=inner, conversion=-1, format_spec=None):
                out.append(operand_value(inner, st))
            case _:
                out.append(None)  # ``!r`` / ``:spec`` rewrite the text unpredictably
    return out

_PATH_CONSTRUCTORS = ("Path", "PurePath", "PosixPath", "PurePosixPath")

# str methods that return a str: on a str receiver the result is text about whose characters
# nothing is known -- the type survives, the path reading (if any) does not
_STR_RETURNING_METHODS = frozenset({
    "replace", "lower", "upper", "casefold", "swapcase", "title", "capitalize",
    "strip", "lstrip", "rstrip", "removeprefix", "removesuffix",
    "format", "zfill", "center", "ljust", "rjust", "expandtabs", "join", "translate",
})

# builtins that return a str whatever they are given (``repr(obj)`` runs ``object.__repr__``:
# no program class defines a dunder); ``str`` is handled apart, since it may keep a fact
_STR_RETURNING_BUILTINS = frozenset({"repr", "format", "chr", "hex", "oct", "bin", "ascii"})

def interpret_expr(e: ast.expr, st: StateMap) -> ValidationFact | None:
    match e:
        case ast.Name(id=name):
            found = st.get(name)
            # a container-, handle- or standard-valued name has no scalar reading: those domains
            # are the walker's, and only their touchpoints reach into them
            return None if isinstance(found, (Container, Data, Std)) else found
        case ast.Constant(value=str() as s):
            return StrFact(regex=Exact(s))
        case ast.Call(func=ast.Attribute(value=ast.Name(id=rname), attr="pop"), args=pargs) if (
            isinstance((popped := st.get(rname)), Container)
            and popped.kind != "sequence"
            and len(pargs) <= 1
        ):
            return popped.elem  # x.pop(): one element, with the container's current fact
        case ast.Call(func=func, args=args, keywords=keywords):
            call = resolve_callee(func)
            if call is None:
                # ``f()()``: a callee with no name at all is refused structurally. (``f().g()`` is
                # fine: the callee is the *name* ``g`` on a computed receiver.)
                raise InvalidProgram(func, "computed callee")
            if keywords or any(isinstance(a, ast.Starred) for a in args):
                return None
            if args and any(call.matches("pathlib", c) for c in _PATH_CONSTRUCTORS):
                loc = join_args(args, st)
                return PathFact() if loc is None else Located(loc, "path")
            if args and call.matches("os", "path", "join"):
                loc = join_args(args, st)
                return None if loc is None else Located(loc, "str")
            if len(args) == 1 and call.matches("str"):
                # ``str(x)`` is a str whatever x is; of a path or text it keeps the claims
                return as_str_value(interpret_expr(args[0], st)) or StrFact()
            if len(args) == 1 and call.matches("os", "fspath"):
                return as_str_value(interpret_expr(args[0], st))  # str or bytes: only a fact says
            if args and call.is_var_base and len(call.full_path) == 1 and call.full_path[0] in _STR_RETURNING_BUILTINS:
                return StrFact()
            if isinstance(func, ast.Attribute) and func.attr in _STR_RETURNING_METHODS:
                receiver = interpret_expr(func.value, st)
                if isinstance(receiver, (StrFact, UrlString)) or (
                    isinstance(receiver, Located) and receiver.repr == "str"
                ):
                    return StrFact()  # text stays text; nothing is known about the new characters
            if isinstance(func, ast.Attribute) and func.attr == "decode" and inert(entry_of(func.value, st)):
                return StrFact()  # bytes.decode(): the only decode an inert value has yields text
            return None
        case ast.BinOp(left=left, op=ast.Div(), right=right):
            # ``str / x`` is a TypeError and ``"lit" / path`` (__rtruediv__) is not modelled
            head = locate(interpret_expr(left, st))
            if head is None or head.repr != "path":
                return None
            loc = combine_containment(head.location, operand_value(right, st))
            return None if loc is None else Located(loc, "path")
        case ast.BinOp(op=ast.Add()):
            values = [operand_value(p, st) for p in _flatten_add(e)]
            if any(is_path_typed(v) for v in values if not isinstance(v, str)):
                return None  # ``Path + str`` is a TypeError
            return join_text(values)
        case ast.JoinedStr():
            return join_text(_fstring_pieces(e, st))
        case ast.Subscript(value=value, slice=index) if _argv_read(value):
            # an element of sys.argv is a str of unknown text; a slice is a list of them --
            # no scalar fact, but the iteration transfer knows its elements
            return None if isinstance(index, ast.Slice) else StrFact()
        case ast.Subscript(value=ast.Name(id=cname), slice=index) if (
            isinstance((indexed := st.get(cname)), Container)
            and indexed.kind in ("list", "sequence")
            and not isinstance(index, ast.Slice)
        ):
            return indexed.elem  # x[i]: an element; a slice is a fresh, untracked copy
        case _:
            return None

# --- standard values: the callee analysis (EFFECTS.md) -------------------------------------------
#
# ``interpret_expr`` answers for text and paths. For everything else the walker needs one bit --
# can a call on, or with, this value run program code? -- and ``std_of`` / ``is_inert`` answer it,
# over a ``Std`` value that tracks a kind and closedness and nothing more. The knowledge here is
# the interpreter's: which builtins and module functions are the interpreter's own code (the
# roster in ``dangerous``), which constructors build which kind, that every operator dunder is
# fixed (a program class may define none but ``__init__``), that an element of a closed
# container is inert.
#
# *modules* are the names that denote modules: a dotted callee is looked up in the roster only
# under one of them, since a variable that happens to be named ``json`` is not the module. The
# default -- no modules -- is the conservative direction: nothing dotted is trusted.

# the constructors: their kind is certain, their closedness is their arguments'
_CONSTRUCTOR_KINDS: dict[str, StdKind] = {
    "list": "list", "tuple": "tuple", "set": "set", "frozenset": "frozenset", "dict": "dict",
    "sorted": "list",
}
# what a roster callee returns, when the kind is worth knowing
_RESULT_KINDS: dict[tuple[str, ...], StdKind] = {
    ("len",): "number", ("int",): "number", ("float",): "number", ("complex",): "number",
    ("abs",): "number", ("round",): "number", ("hash",): "number", ("id",): "number",
    ("ord",): "number", ("pow",): "number",
    ("bool",): "bool", ("isinstance",): "bool", ("issubclass",): "bool", ("callable",): "bool",
    ("any",): "bool", ("all",): "bool",
    ("bytes",): "bytes", ("divmod",): "tuple", ("print",): "none",
    ("re", "compile"): "pattern",
    ("re", "match"): "match", ("re", "search"): "match", ("re", "fullmatch"): "match",
    ("re", "findall"): "list", ("re", "split"): "list",
    ("os", "listdir"): "list",
    ("os", "path", "exists"): "bool", ("os", "path", "isfile"): "bool",
    ("os", "path", "isdir"): "bool", ("os", "path", "isabs"): "bool",
    ("os", "path", "split"): "tuple", ("os", "path", "splitext"): "tuple",
}
# ``type(x)`` is the interpreter's code but its result may be a program class
_OPAQUE_RESULTS: frozenset[tuple[str, ...]] = frozenset({("type",)})
# what a method on an inert receiver returns, when the kind is worth knowing; "same" is the
# receiver's own kind (a copy)
_METHOD_RESULT_KINDS: dict[str, StdKind | Literal["same"]] = {
    "split": "list", "rsplit": "list", "splitlines": "list", "findall": "list",
    "partition": "tuple", "rpartition": "tuple", "encode": "bytes", "copy": "same",
}

def entry_of(recv: ast.expr, st: StateMap, modules: frozenset[str] = frozenset()) -> Entry | None:
    """What the state knows about a receiver expression: a name's entry, or the value of a
    computed receiver (``line.strip().split()``, ``"".join``)."""
    if isinstance(recv, ast.Name):
        return st.get(recv.id)
    fact = interpret_expr(recv, st)
    return fact if fact is not None else std_of(recv, st, modules)

def is_inert(e: ast.expr, st: StateMap, modules: frozenset[str] = frozenset()) -> bool:
    """Is the value of *e* inert: a literal, a name bound to an inert entry, a builtin taken as
    a value (applied by an inert callee to inert values only, it runs no program code), a
    display or a comprehension of inert elements, a standard value that is closed?"""
    match e:
        case ast.Constant():
            return True
        case ast.Name(id=name):
            entry = st.get(name)
            if entry is not None:
                return inert(entry)
            return name in INERT_BUILTIN_VALUES  # never rebound (safepy), so never in the state
        case ast.Attribute(value=ast.Name(id=base)) if base in INERT_BUILTIN_TYPES:
            return True  # ``str.lower``: a builtin type's method, as a value
        case ast.Starred(value=inner):
            return is_inert(inner, st, modules)
        case ast.Call(func=func) if resolve_callee(func) is None:
            return False  # a computed callee: refused elsewhere
        case _:
            if interpret_expr(e, st) is not None:
                return True  # text or a path, however much is known about it
            std = std_of(e, st, modules)
            return std is not None and std.closed

def _all_inert(exprs: Sequence[ast.expr], st: StateMap, modules: frozenset[str]) -> bool:
    return all(is_inert(x, st, modules) for x in exprs)

def _comprehension_inert(
    exprs: Sequence[ast.expr], generators: Sequence[ast.comprehension], st: StateMap,
    modules: frozenset[str],
) -> bool:
    """Are the elements a comprehension builds inert? The element expressions, under the
    iteration bindings (an ``if`` clause refines nothing about inertness)."""
    inner: dict[str, Entry] = dict(st)
    for gen in generators:
        if gen.is_async:
            return False
        for n in ast.walk(gen.target):
            if isinstance(n, ast.Name):
                inner.pop(n.id, None)
        inner.update(iteration_bindings(gen.target, gen.iter, inner, modules))
    return _all_inert(exprs, inner, modules)

def std_of(e: ast.expr, st: StateMap, modules: frozenset[str] = frozenset()) -> Std | None:
    """The standard value *e* evaluates to, when that much is known and no fact says more: ask
    ``interpret_expr`` first (it answers for text and paths); this answers for the rest, and
    None when the value may be a program object -- a function, a generator, a class, an
    instance, or a container holding one."""
    match e:
        case ast.Constant(value=bool()):
            return Std("bool")
        case ast.Constant(value=int() | float() | complex()):
            return Std("number")
        case ast.Constant(value=bytes()):
            return Std("bytes")
        case ast.Constant(value=None):
            return Std("none")
        case ast.Constant(value=str()):
            return None  # a fact: interpret_expr's
        case ast.Constant():
            return Std()  # Ellipsis
        case ast.Name(id=name):
            entry = st.get(name)
            return entry if isinstance(entry, Std) else None
        case ast.List(elts=elts):
            return Std("list", _all_inert(elts, st, modules))
        case ast.Tuple(elts=elts):
            return Std("tuple", _all_inert(elts, st, modules))
        case ast.Set(elts=elts):
            return Std("set", _all_inert(elts, st, modules))
        case ast.Dict(keys=keys, values=values):
            # a None key is a ``**x`` splat: its value is the mapping spliced in
            return Std("dict", _all_inert([k for k in keys if k is not None] + values, st, modules))
        case ast.ListComp(elt=elt, generators=gens):
            return Std("list", _comprehension_inert([elt], gens, st, modules))
        case ast.SetComp(elt=elt, generators=gens):
            return Std("set", _comprehension_inert([elt], gens, st, modules))
        case ast.DictComp(key=key, value=value, generators=gens):
            return Std("dict", _comprehension_inert([key, value], gens, st, modules))
        case ast.BoolOp(values=operands):
            return Std() if _all_inert(operands, st, modules) else None  # one of the operands
        case ast.IfExp(body=body, orelse=orelse):
            return Std() if _all_inert([body, orelse], st, modules) else None
        case ast.BinOp(left=left, right=right):
            # every operator dunder is the interpreter's: over inert operands the result is a
            # standard value; over others it may be a program object (an enum's ``|`` yields a
            # member) or hold one (``[f] + [g]``)
            return Std() if _all_inert([left, right], st, modules) else None
        case ast.UnaryOp(op=ast.Not()):
            return Std("bool")
        case ast.UnaryOp(operand=operand):
            return Std() if is_inert(operand, st, modules) else None
        case ast.Compare():
            return Std("bool")  # every comparison dunder is fixed
        case ast.Subscript(value=value, slice=index):
            if not is_inert(value, st, modules):
                return None  # an element of an open container may be anything
            if isinstance(index, ast.Slice):
                whole = std_of(value, st, modules)
                kind = whole.kind if whole is not None and whole.kind in ("list", "tuple") else None
                return Std(kind)  # a slice is a fresh sequence of the same kind
            return Std()  # an element, or a key's value, of a closed container: inert
        case ast.Attribute(value=recv):
            # a data attribute of an inert value is inert (a path's ``name``, a match's
            # ``string``); so is a bound method taken as a value. Not on a tracked container:
            # that is its escape, the walker's to report
            entry = entry_of(recv, st, modules)
            return Std() if inert(entry) and not isinstance(entry, Container) else None
        case ast.Call(func=func, args=args, keywords=keywords):
            return _call_std(func, args, keywords, st, modules)
        case _:
            return None  # a lambda, a generator expression, a yield, ...

def _call_std(
    func: ast.expr, args: Sequence[ast.expr], keywords: Sequence[ast.keyword], st: StateMap,
    modules: frozenset[str],
) -> Std | None:
    callee = resolve_callee(func)
    if callee is None:
        return None
    arguments_inert = _all_inert(args, st, modules) and _all_inert([k.value for k in keywords], st, modules)
    if callee.is_var_base:
        full = callee.full_path
        if len(full) == 1 or full[0] in modules:
            kind = _CONSTRUCTOR_KINDS.get(full[0]) if len(full) == 1 else None
            if kind is not None:
                return Std(kind, arguments_inert)  # ``list(gen)`` is a list, of who knows what
            if full in _OPAQUE_RESULTS:
                return None
            condition = inert_condition(full, modules)
            if condition is None:
                return None  # a program function or class; a module function off the roster
            if condition == "all" and not arguments_inert:
                return None
            if condition == "keywords-and-splats" and not (
                _all_inert([k.value for k in keywords], st, modules)  # ``**m`` included
                and _all_inert([a for a in args if isinstance(a, ast.Starred)], st, modules)
            ):
                return None  # a keyword decides the result (``json.loads(s, object_hook=f)``)
            return Std(_RESULT_KINDS.get(full))
    elif callee.computed_base is None:
        return None  # ``super().m()``: a program method
    # a method call: on an inert receiver, with inert arguments, the interpreter's own code over
    # inert values -- an inert result. Not ``open``: a file object's writes are effects.
    assert isinstance(func, ast.Attribute)
    if func.attr == "open" or not arguments_inert:
        return None
    receiver = entry_of(func.value, st, modules)
    if not inert(receiver):
        return None
    kind = _METHOD_RESULT_KINDS.get(func.attr)
    if kind == "same":
        return Std(receiver.kind if isinstance(receiver, Std) else None)
    return Std(kind)

def destructure(target: ast.expr, elem: Std) -> dict[str, Std]:
    """The names a target binds when every element it takes apart is *elem*: ``a`` is elem;
    ``a, (b, c)`` binds each to elem (an element of an inert value is inert); ``*rest`` is a
    list of them."""
    match target:
        case ast.Name(id=name):
            return {name: elem}
        case ast.Tuple(elts=elts) | ast.List(elts=elts):
            out: dict[str, Std] = {}
            for t in elts:
                out.update(destructure(t, elem))
            return out
        case ast.Starred(value=ast.Name(id=name)):
            return {name: Std("list", elem.closed)}
        case _:
            return {}

# --- iteration -----------------------------------------------------------------------------------
#
# In ``for p in <iterable>`` the loop variable is rebound by the header on every iteration, so its
# fact is the iterable's *element* fact -- no fixpoint needed. Only the directory-traversal
# iterables are modelled: ``iterdir``/``glob``/``rglob`` on a located path, ``os.listdir`` (bare
# names), ``os.walk`` (via its tuple target), through the element-preserving wrappers
# ``sorted``/``list``/``tuple``/``reversed``/``iter`` and ``enumerate``. Any other inert iterable
# yields inert elements of unknown kind (``element_std``).

# the names the loop variable can never have from a listing: never ".", never "..", never a "/"
_LISTED_NAME = StrFact(atoms=ALL_ATOMS)

def _glob_location(base: LocationFact, pattern: str) -> LocationFact | None:
    """Where ``base.glob(pattern)`` yields: each pattern component is a ``Named``, a ``Matching``
    (via ``fnmatch.translate``) or, for ``**``, a descent to "at or below"."""
    if not pattern or pattern.startswith("/"):
        return None  # pathlib rejects empty and non-relative patterns
    loc = base
    for comp in pathlib.PurePath(pattern).parts:
        if comp == "..":
            return None
        if comp == "**":
            loc = splat_under(loc)
        elif any(ch in comp for ch in "*?["):
            # translate() yields "(?s:...)\Z"; the anchor is redundant under fullmatch and would
            # break embedding, so it goes
            loc = loc.extend_single(Matching(RegexLit(fnmatch.translate(comp).removesuffix(r"\Z"))))
        elif is_safe_name(comp):
            loc = loc.extend_single(Named(comp))
        else:
            return None
    return loc

def _path_location(recv: ast.expr, st: StateMap) -> LocationFact | None:
    """The location of a receiver that must be a ``pathlib.Path`` (``iterdir``/``glob`` exist only there)."""
    located = locate(interpret_expr(recv, st))
    return located.location if located is not None and located.repr == "path" else None

_ELEMENT_WRAPPERS = ("sorted", "list", "tuple", "reversed", "iter")

def element_fact(iterable: ast.expr, st: StateMap) -> ValidationFact | None:
    """The fact for ``p`` in ``for p in <iterable>``, when the iterable is a directory traversal."""
    match iterable:
        case ast.Call(func=ast.Name(id=wrapper), args=[inner], keywords=kws) if (
            wrapper in _ELEMENT_WRAPPERS and all(k.arg in ("key", "reverse") for k in kws)
        ):
            return element_fact(inner, st)
        case ast.Call(func=ast.Attribute(value=recv, attr="iterdir"), args=[], keywords=[]):
            loc = _path_location(recv, st)
            return None if loc is None else Located(loc.extend_single(ANY_NAME), "path")
        case ast.Call(
            func=ast.Attribute(value=recv, attr=("glob" | "rglob") as method), args=[pat], keywords=[]
        ):
            loc = _path_location(recv, st)
            pattern = as_const_or_null(str, pat)
            if loc is None or pattern is None:
                return None
            found = _glob_location(splat_under(loc) if method == "rglob" else loc, pattern)
            return None if found is None else Located(found, "path")
        case ast.Call(func=func, args=args, keywords=[]) if (
            len(args) <= 1
            and (callee := resolve_callee(func)) is not None
            and callee.matches("os", "listdir")
        ):
            return _LISTED_NAME  # bare names, whatever the directory
        case _ if _argv_read(iterable):
            # sys.argv or a slice of it: command-line arguments, strs of unknown text
            return StrFact()
        case ast.Name(id=name) if isinstance(st.get(name), Container):
            container = st[name]
            assert isinstance(container, Container)
            return container.elem  # iterating a tracked container: its current element fact
        case ast.Name(id=name) if isinstance(st.get(name), Data):
            handle = st[name]
            assert isinstance(handle, Data)
            # ``for line in f`` over a source handle: each line is something the source
            # produced, unmodified (PROVENANCE.md) -- ``certora.lines`` spelled the stdlib way
            return StrFact(checks=handle.sources)
        case _:
            return None

def element_std(iterable: ast.expr, st: StateMap, modules: frozenset[str]) -> Std | None:
    """The element of an iterable the traversal semantics do not know but inertness does: the
    elements of an inert value are inert (``for line in text.splitlines()``, ``for k, v in
    d.items()``), and ``range`` yields numbers whatever it was given."""
    match iterable:
        case ast.Call(func=ast.Name(id="range")):
            return Std("number")
        case _:
            return Std() if is_inert(iterable, st, modules) else None

def iteration_bindings(
    target: ast.expr, iterable: ast.expr, st: StateMap, modules: frozenset[str] = frozenset()
) -> dict[str, ValidationFact | Std]:
    """Facts for the names ``for <target> in <iterable>`` binds: the traversal iterables' element
    facts, and inert elements of unknown kind for any other inert iterable."""
    match target, iterable:
        case ast.Name(id=name), _:
            fact = element_fact(iterable, st)
            if fact is not None:
                return {name: fact}
            std = element_std(iterable, st, modules)
            return {} if std is None else {name: std}
        case ast.Tuple(elts=[ast.Name(id=index), inner_target]), ast.Call(
            func=ast.Name(id="enumerate"), args=[inner], keywords=_
        ):
            return {index: Std("number"), **iteration_bindings(inner_target, inner, st, modules)}
        case ast.Tuple(elts=[ast.Name(id=dirpath), dirnames, filenames]), ast.Call(
            func=func, args=[top, *_], keywords=_
        ) if (callee := resolve_callee(func)) is not None and callee.matches("os", "walk"):
            # dirpath is a str at or below top; dirnames/filenames are lists of bare names
            lists: dict[str, ValidationFact | Std] = {
                n.id: Std("list") for n in (dirnames, filenames) if isinstance(n, ast.Name)
            }
            loc = _head_location(operand_value(top, st))
            return lists if loc is None else {dirpath: Located(splat_under(loc), "str"), **lists}
        case _:
            std = element_std(iterable, st, modules)
            return {} if std is None else dict(destructure(target, std))

def widen_loc(
    prev: LocationFact,
    next: LocationFact
) -> LocationFact | None:
    ...

def join_component(
    c1: Component,
    c2: Component
) -> Component:
    if isinstance(c1, AnyName) or isinstance(c2, AnyName):
        return AnyName()
    if subsumes(c1, c2):
        return c1
    elif subsumes(c2, c1):
        return c2
    match c1, c2:
        case Named(name=n1), Named(name=n2):
            return OneOf(frozenset({n1, n2}))
        case (Named(name=n1), OneOf(names=existing)) | (OneOf(names=existing), Named(name=n1)):
            return OneOf(frozenset({*existing, n1}))
        case Matching(regex=r1), Matching(regex=r2):
            return Matching(alternation(r1, r2))
        case OneOf(names=n1), OneOf(names=n2):
            return OneOf(frozenset({*n1, *n2}))
        case (Matching(regex=r1), other) | (other, Matching(regex=r1)):
            match other:
                case Named(name=n):
                    return Matching(alternation(r1, Exact(n)))
                case OneOf(names=n):
                    return Matching(alternation(r1, *(Exact(i) for i in n)))

def join_loc(
    left: LocationFact,
    right: LocationFact
) -> LocationFact | None:
    if left.absolute != right.absolute:
        return None  # anchors never relate: there is no location covering both
    match left, right:
        case (DirSplat(static_prefix=dir_prefix) as splat, StaticPath(path_components=known_path) as _static) | \
             (StaticPath(path_components=known_path) as _static, DirSplat(static_prefix=dir_prefix) as splat):
            if len(dir_prefix) > len(known_path):
                return None
            for (splat_comp, static_comp) in zip(dir_prefix, known_path[:-1]):
                if not subsumes(splat_comp, static_comp):
                    return None
            if not subsumes(splat.final_component, known_path[-1]):
                return None
            return splat
        case (StaticPath(path_components=p1), StaticPath(path_components=p2)):
            if len(p1) == len(p2):
                paths = tuple(join_component(
                    c1, c2
                ) for (c1, c2) in zip(p1, p2))
                return StaticPath(paths, left.absolute)
            last_comps = join_component(p1[-1], p2[-1])
            static_prefix = tuple(join_component(
                c1, c2
            ) for (c1, c2) in zip(p1[:-1], p2[:-1]))
            return DirSplat(
                static_prefix=static_prefix, final_component=last_comps, absolute=left.absolute
            )
        case DirSplat(static_prefix=p1, final_component=c1), DirSplat(static_prefix=p2, final_component=c2):
            return DirSplat(
                final_component=join_component(c1, c2),
                static_prefix=tuple(join_component(c1, c2) for (c1, c2) in zip(p1, p2)),
                absolute=left.absolute
            )

def join_regex(
    left: PseudoRegex,
    right: PseudoRegex
) -> PseudoRegex:
    return alternation(left, right)

def widen_regex(
    prev: PseudoRegex,
    next: PseudoRegex
) -> PseudoRegex:
    ...
