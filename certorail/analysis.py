import ast
import fnmatch
import inspect
import pathlib
import re
import urllib.parse
from typing import Any, cast, Callable, Literal, Mapping, Sequence
from dataclasses import dataclass, is_dataclass, replace

from certorail.dangerous import INERT_BUILTIN_TYPES, INERT_BUILTIN_VALUES, NAMESPACE, inert_condition
from certorail.ids import (
    BUILTIN_ATOMS,
    NO_PARENT_TRAVERSAL,
    NO_SLASH,
    NOT_ABSOLUTE,
    NOT_DOT_DOT,
    NOT_OPTION,
    Atom,
    AtomId,
    AtomIdName,
    SourceId,
)

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

def is_dunder(x: str) -> bool:
    return x.startswith("__") and x.endswith("__")

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
class AnyComponent:
    """Any one safe path component: a string with no "/" that is none of "", "." or ".." (see
    ``is_safe_name``). The text an ``AnyName`` component spells, and what a directory listing
    yields -- the text domain's name for it, so text and location convert structurally both
    ways."""

@dataclass(frozen=True)
class Both:
    """The intersection of its parts: every conjunct holds of the value. Built by ``both`` when
    two independent readings of one value's text meet -- the shape an f-string gave it and the
    regex a ``re.fullmatch`` guard asserted -- each a sound description on its own, neither
    implying the other. Only ``both`` constructs one, and it never holds a wildcard, a duplicate,
    a nested Both or a finite part (those resolve); the parts are in canonical order, so equal
    conjunctions are structurally equal (``walker._join`` compares facts for equality)."""
    all_of: list["PseudoRegex"]

type PseudoRegex = Alternation | Concat | RegexLit | Exact | AnyStr | AnyComponent | Both

ANY_STR = AnyStr()
ANY_COMPONENT = AnyComponent()

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

    def to_splat(self, final_component: Component | None) -> "DirSplat":
        return DirSplat(self.path_components, final_component, self.absolute)

@dataclass(frozen=True)
class DirSplat:
    """Paths at some depth under ``static_prefix``. ``final_component`` None: the prefix
    itself and everything below it (``a/**``, reflexive); a component: strictly below the
    prefix, the last component satisfying it (``a/**/*`` any name, ``a/**/<re>``). The two
    are different sets -- they differ in whether the prefix itself is denoted -- and share no
    spelling."""
    static_prefix: tuple[Component, ...]
    final_component: Component | None
    absolute: bool = False

    def merge_other(self, other: "LocationFact") -> "LocationFact":
        """Joined with *other* below: somewhere under the prefix, ending as *other* ends -- the
        intervening components are widened away, but not the depth: the result is strictly
        below the prefix whenever this splat demanded a component or *other* contributes one,
        and only ``.`` joined onto a reflexive splat stays reflexive."""
        if other.absolute:
            return other  # joining onto an absolute path discards the left side (pathlib)
        match other:
            case StaticPath(path_components=()):
                return self  # joining "." adds nothing
            case StaticPath(path_components=cs):
                return DirSplat(self.static_prefix, cs[-1], self.absolute)
            case DirSplat(static_prefix=ps, final_component=None):
                strict = self.final_component is not None or bool(ps)
                return DirSplat(self.static_prefix, ANY_NAME if strict else None, self.absolute)
            case DirSplat(final_component=leaf):
                return DirSplat(self.static_prefix, leaf, self.absolute)

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

    def to_splat(self, final_component: Component | None) -> "DirSplat":
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

# Zero or more safe components (see ``is_safe_name``), each followed by "/". PseudoRegex has no
# repetition node, so this is the one place the translation is a literal rather than structural.
# One component, unanchored:   [^.]...  |  .[^.]...  |  ..[at least one more char]
_COMPONENT_RE = r"(?:[^/.][^/]*|\.[^/.][^/]*|\.\.[^/]+)"
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
            return ANY_COMPONENT
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
            below = concat(*head, DESCENDANTS, component_to_regex(ANY_NAME if final is None else final))
            if final is not None:
                return below
            # no leaf means "at or below": the prefix itself is denoted too
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
        case AnyComponent():
            return "*"
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
            tail = "**" if leaf is None else f"**/{pretty_component(leaf)}"
            return ("/" if ab else "") + (f"{prefix}/{tail}" if prefix else tail)


def splat_under(loc: LocationFact) -> DirSplat:
    """The location "somewhere at or below *loc*", *loc* itself included. Below a strict splat
    the leaf constraint is widened away but the depth is kept: every path is still strictly
    below the prefix."""
    match loc:
        case StaticPath(path_components=components, absolute=ab):
            return DirSplat(components, None, ab)
        case DirSplat(final_component=None):
            return loc
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
        case AnyComponent():
            return is_safe_name(s)
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
        case Matching(regex=AnyStr() | AnyComponent()):
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


# The built-in atoms (ids.BUILTIN_ATOMS, ATOMS.md): structural properties of a value, derived
# from its text or location by ``holds`` below. "not-dot-dot": the string is not exactly "..".
# Together with "no-slash" it implies "no-parent-traversal" (a single component traverses upward
# only if it is exactly ".."). "not-option": the string does not begin with "-".
type AtomicFact = AtomId

# the four path atoms: what a listed name (os.listdir, iterdir) or a matched component carries.
# Not not-option -- "-rf" is a perfectly good file name
PATH_ATOMS: frozenset[AtomId] = frozenset({NO_SLASH, NO_PARENT_TRAVERSAL, NOT_ABSOLUTE, NOT_DOT_DOT})


def carried(atoms: frozenset[Atom]) -> frozenset[Atom]:
    """*atoms* less the built-ins: what a value keeps when it changes reading (text to path,
    text to URL). A built-in is a property of the text; the new reading derives its own."""
    return frozenset(a for a in atoms if a not in BUILTIN_ATOMS)


def _explicit_check_no_parent(regex: PseudoRegex) -> bool:
    match regex:
        case AnyComponent():
            return True
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
        case AnyComponent():
            return True
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

def _explicit_check_not_dot_dot(regex: PseudoRegex) -> bool:
    match regex:
        case AnyComponent():
            return True
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

# The regex parser behind ``re.compile`` (``sre_parse`` of old). Private, so reached by name and
# typed Any; it is the one parser whose reading of a pattern is the reading that will be enforced.
_RE_PARSER: Any = getattr(re, "_parser")
_RE_CONSTANTS: Any = getattr(re, "_constants")

# the character classes a parsed ``\d`` & co. stand for, by the parser's category name
_CATEGORY_ESCAPES = {
    "DIGIT": r"\d", "NOT_DIGIT": r"\D", "SPACE": r"\s", "NOT_SPACE": r"\S",
    "WORD": r"\w", "NOT_WORD": r"\W",
}


def _charset_admits(items: Any, ch: str) -> bool:
    """Does a bracket class (the ``IN`` operand) admit *ch*? Literals, ranges and the
    categories, under an optional ``NEGATE``; anything unforeseen: may."""
    negate = False
    hit = False
    code = ord(ch)
    for op, av in items:
        if op is _RE_CONSTANTS.NEGATE:
            negate = True
        elif op is _RE_CONSTANTS.LITERAL:
            hit = hit or av == code
        elif op is _RE_CONSTANTS.RANGE:
            lo, hi = av
            hit = hit or lo <= code <= hi
        elif op is _RE_CONSTANTS.CATEGORY:
            escape = _CATEGORY_ESCAPES.get(str(av).removeprefix("CATEGORY_"))
            if escape is None:
                return True
            hit = hit or re.fullmatch(escape, ch) is not None
        else:
            return True
    return hit != negate


def _first(sub: Any, ch: str) -> tuple[bool, bool]:
    """Of a parsed (sub)pattern: (may its first matched character be *ch*, can it match the
    empty string). A sequence's first character comes from its first non-nullable item and
    everything nullable before it."""
    may = False
    for op, av in sub:
        item_may, item_nullable = _first_item(op, av, ch)
        may = may or item_may
        if not item_nullable:
            return may, False
    return may, True


def _first_item(op: Any, av: Any, ch: str) -> tuple[bool, bool]:
    c = _RE_CONSTANTS
    if op is c.LITERAL:
        return av == ord(ch), False
    if op is c.NOT_LITERAL:
        return av != ord(ch), False
    if op is c.ANY:
        return True, False
    if op is c.IN:
        return _charset_admits(av, ch), False
    if op is c.AT or op is c.ASSERT or op is c.ASSERT_NOT:
        return False, True  # zero-width; ignoring a lookaround only widens "may": sound
    if op is c.SUBPATTERN:
        return _first(av[3], ch)
    if op is c.ATOMIC_GROUP:
        return _first(av, ch)
    if op is c.BRANCH:
        results = [_first(b, ch) for b in av[1]]
        return any(m for m, _ in results), any(n for _, n in results)
    if op in (c.MAX_REPEAT, c.MIN_REPEAT, c.POSSESSIVE_REPEAT):
        lo, _, body = av
        body_may, body_nullable = _first(body, ch)
        return body_may, lo == 0 or body_nullable
    if op is c.GROUPREF_EXISTS:
        _, yes, no = av
        yes_may, yes_nullable = _first(yes, ch)
        no_may, no_nullable = _first(no, ch) if no is not None else (False, True)
        return yes_may or no_may, yes_nullable or no_nullable
    return True, True  # GROUPREF and anything unforeseen: may, and may be empty


def _literal_regex_may_start_with(reg: str, prefix: str) -> bool:
    """Could a string this regex fullmatches begin with *prefix*? Decided on the parse tree the
    ``re`` module itself builds, for a one-character, caseless prefix (``/``, ``-``); anything
    else -- an unparsable pattern, a longer prefix, a letter a case-insensitive flag could
    match either way -- is "may"."""
    if len(prefix) != 1 or prefix.lower() != prefix.upper():
        return True
    try:
        parsed = _RE_PARSER.parse(reg)
    except re.error:
        return True
    may, _ = _first(parsed, prefix)
    return may


def may_start_with(p: PseudoRegex, prefix: str) -> bool:
    """Could some string in the language of *p* begin with *prefix*? Conservative: True unless
    the structure shows otherwise.

    A concatenation is read piece by piece. A piece either produces a string that begins with
    what is left of the prefix -- and then so may the whole -- or matches a proper part of that
    remainder exactly, the empty string included, and hands the rest on to the next piece. So
    ``"" + x`` asks about ``x``, and a piece that may be empty never decides the question
    alone."""
    if not prefix:
        return True
    match p:
        case AnyStr():
            return True
        case AnyComponent():
            return "/" not in prefix  # "." and ".." extend to safe names (".x", "..x")
        case Exact(exact_str=s):
            return s.startswith(prefix)
        case Alternation(any_of=branches):
            return any(may_start_with(b, prefix) for b in branches)
        case Both(all_of=parts):
            return all(may_start_with(q, prefix) for q in parts)  # an intersection: every part must
        case RegexLit(reg=reg):
            return _literal_regex_may_start_with(reg, prefix)
        case Concat(seq=pieces):
            remainders = {prefix}
            for piece in pieces:
                if any(may_start_with(piece, r) for r in remainders):
                    return True
                remainders = {
                    r[k:] for r in remainders for k in range(len(r)) if _regex_accepts(piece, r[:k])
                }
                if not remainders:
                    return False
            return False  # every string of the whole is a proper part of the prefix


def _explicit_check(other: AtomId, regex: PseudoRegex) -> bool:
    """Does the text's regex alone establish the built-in *other*?"""
    if other == NO_PARENT_TRAVERSAL:
        return _explicit_check_no_parent(regex)
    if other == NO_SLASH:
        return _explicit_check_no_slash(regex)
    if other == NOT_ABSOLUTE:
        return not may_start_with(regex, "/")
    if other == NOT_DOT_DOT:
        return _explicit_check_not_dot_dot(regex)
    if other == NOT_OPTION:
        return not may_start_with(regex, "-")
    return False


def _holds(atom: Atom, atoms: frozenset[Atom], regex: PseudoRegex) -> bool:
    """Does *atom* hold of a text value: as stated, or -- for a built-in -- as derivable from the
    regex or implied by other built-ins? A policy atom holds only as stated; whether the
    vocabulary can supply it from the text is ``Vocabulary.missing``'s question."""
    if atom in atoms:
        return True
    if atom not in BUILTIN_ATOMS:
        return False
    if _explicit_check(BUILTIN_ATOMS[atom], regex):
        return True
    # the implication table
    if atom == NOT_ABSOLUTE:
        # a string without "/" cannot start with one
        return _holds(NO_SLASH, atoms, regex)
    if atom == NO_PARENT_TRAVERSAL:
        # a single component traverses upward only if it is exactly ".."
        return _holds(NO_SLASH, atoms, regex) and _holds(NOT_DOT_DOT, atoms, regex)
    if atom == NOT_DOT_DOT:
        # a string with no ".." part is not the string ".."
        return NO_PARENT_TRAVERSAL in atoms or _explicit_check_no_parent(regex)
    return False


def holds(atom: Atom, fact: "ValidationFact") -> bool:
    """Does *atom* hold of *fact*, structurally? Stated atoms hold of every fact; a built-in also
    by derivation from a text fact's regex and atoms, and -- for ``not-option`` -- from a located
    value's head: an absolute path begins with "/", a path under a literally named directory
    with that name. Nothing else is derivable of a located or URL value, whose text is not
    tracked."""
    match fact:
        case StrFact(regex=regex, atoms=atoms):
            return _holds(atom, atoms, regex)
        case PathFact(atoms=atoms):
            return _holds(atom, atoms, ANY_STR)
        case Located(location=loc, atoms=atoms):
            if atom in atoms:
                return True
            if atom != NOT_OPTION:
                return False
            if loc.absolute:
                return True
            components = loc.path_components if isinstance(loc, StaticPath) else loc.static_prefix
            if not components:
                # "." itself for a StaticPath; for a DirSplat the first component is unknown
                return isinstance(loc, StaticPath)
            match components[0]:
                case Named(name=n):
                    return not n.startswith("-")
                case OneOf(names=ns):
                    return not any(n.startswith("-") for n in ns)
                case _:
                    return False
        case UrlString(atoms=atoms):
            return atom in atoms


def may_start_with_dash(value: "str | ValidationFact | None") -> bool:
    """Could this token's text begin with ``-``, and so be read by a tool as an option? True
    unless its structure shows otherwise (``holds`` of ``not-option``)."""
    match value:
        case str():
            return value.startswith("-")
        case None:
            return True
        case _:
            return not holds(NOT_OPTION, value)

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
# Every fact additionally carries ``atoms``: the atoms this exact value carries (ATOMS.md), of
# every kind -- built-ins stated by a guard or an annotation, check atoms established by
# ``certora.check`` or a guard's regex, source atoms constructed by extraction. Atoms belong to
# the value as it was when it gained them: they ride along assignment and the same-value
# respellings (str(), locate), and everything that builds a *new* value -- joins, string methods,
# concatenation -- starts with none but what its own structure gives. The walker kills the
# environmental ones at every call that may have effects. Built-ins are not only stated:
# ``holds`` derives them from a fact's shape, and ``x in fact`` asks it.
# ---------------------------------------------------------------------------

type Repr = Literal["str", "path"]

type StructuralIdName = AtomId | AtomIdName

@dataclass(frozen=True)
class StrFact:
    """A ``str`` read as text."""
    regex: PseudoRegex = ANY_STR
    atoms: frozenset[Atom] = frozenset()

    def __contains__(self, atom: StructuralIdName) -> bool:
        if not isinstance(atom, AtomId):
            atom = AtomId(atom)
        return _holds(atom, self.atoms, self.regex)

@dataclass(frozen=True)
class PathFact:
    """A ``pathlib.Path`` of unknown location, read as text through ``str(p)``: ``no-slash`` means
    a single relative component, ``not-absolute`` means ``not p.is_absolute()``,
    ``no-parent-traversal`` means no ``..`` part."""
    atoms: frozenset[Atom] = frozenset()

    def __contains__(self, atom: StructuralIdName) -> bool:
        if not isinstance(atom, AtomId):
            atom = AtomId(atom)
        return _holds(atom, self.atoms, ANY_STR)

@dataclass(frozen=True)
class Located:
    """A value read as a path: where it points, spelled as a ``str`` or a ``pathlib.Path``."""
    location: LocationFact
    repr: Repr
    atoms: frozenset[Atom] = frozenset()

    def __contains__(self, atom: StructuralIdName) -> bool:
        if not isinstance(atom, AtomId):
            atom = AtomId(atom)
        return holds(atom, self)

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
    atoms: frozenset[Atom] = frozenset()

    def __contains__(self, atom: Atom) -> bool:
        return holds(atom, self)

type ValidationFact = StrFact | PathFact | Located | UrlString

@dataclass(frozen=True)
class Container:
    """A tracked ``list``/``set``: the reduced-product partner of the scalar facts
    (CONTAINERS.md). Deliberately NOT a ValidationFact: the scalar transfer functions never
    see one -- the scalar projection (``scalar``, ``Interpreter.expr``) is None for a
    container-valued name -- and the two
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
    ValidationFact: the scalar projection is None for a handle-valued name, and the two domains
    meet only at the extractors (``certora.extract`` & co.) and at iteration (``for line in f``).

    ``sources`` is the *source atoms* the handle yields -- the pure atoms the policy attached to
    the rule that produced it. Empty for a handle from a rule that names no source: still
    extractable, vouching for nothing.

    ``closed`` is the inertness bit shared with ``Std`` (EFFECTS.md, the callee analysis): a
    handle is a Python object an attribute store can patch (``h.read = f``), so it is inert --
    handing it to an extractor or calling its methods runs no program code -- only while no
    program code can have touched it. Any call that may run program code, and any attribute
    store, opens every handle in the state, since an alias may have been the receiver.

    ``writes`` makes the handle a *file opened for writing* at a proven location (EFFECTS.md,
    "File writes"): None for a read handle (and a source); a tuple of the locations the file
    may be at otherwise -- one for ``f = open(p, "w")``, several after a join. A write through
    it (``f.write``, ``print(file=f)``) is a file write like ``p.write_text()``: a write of the
    whole filesystem medium. **The locations themselves are not load-bearing**: no kill and no
    audit reads them (the open was audited at its sink, and a write through the handle writes
    the whole medium whatever they say); only ``reveal_fact``'s wording and the join's union
    touch them. What matters is None versus not-None. This is what keeps a file object out of
    the inert set by accident: a write-mode ``open`` at an *unproven* location binds no handle
    at all, so the object is unknown and every method on it opaque."""
    sources: frozenset[SourceId] = frozenset()
    closed: bool = True
    writes: tuple[LocationFact, ...] | None = None

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
    ValidationFact: the scalar projection is None for a Std-valued name, nothing is ever
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

def atoms_of(fact: ValidationFact | None) -> frozenset[Atom]:
    """The atoms a value states; nothing of an unknown value."""
    return frozenset() if fact is None else fact.atoms

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

def as_fact(value: str | ValidationFact) -> ValidationFact:
    """A literal as the exactly-known text fact it is; a fact as itself."""
    return StrFact(regex=Exact(value)) if isinstance(value, str) else value


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
    is a component iff it has no "/" and no ".." (``_holds`` supplies the derived forms of both)
    and its regex rules out "" and "." -- a join with either stays where it is, so neither names
    a component. The regex then decides how precise the component is, constructor for
    constructor: ``AnyComponent`` is any name, an ``Exact`` one name, an alternation of them a
    set of names, and any other regex restricts the name.
    """
    if not ("no-slash" in fact and "no-parent-traversal" in fact):
        return None
    regex = fact.regex if isinstance(fact, StrFact) else ANY_STR
    if _regex_accepts(regex, "") or _regex_accepts(regex, "."):
        return None
    match regex:
        case AnyComponent():
            return ANY_NAME
        case Exact(exact_str=s):
            return Named(s) if is_safe_name(s) else None
        case Alternation(any_of=branches) if all(isinstance(b, Exact) for b in branches):
            names = [b.exact_str for b in branches if isinstance(b, Exact)]
            return OneOf(frozenset(names)) if all(is_safe_name(n) for n in names) else None
        case _:
            return Matching(regex)

@dataclass(frozen=True)
class EmptyText:
    """The literal ``""`` read as a path: it names nothing. What that means is the caller's to
    say -- a concatenation adds no text, ``pathlib`` and ``os.path.join`` add no component, a
    bare filesystem sink has no location -- so ``_literal_location`` hands it back instead of
    choosing. It is not the root: ``"" + "/x"`` is the absolute ``/x``."""


EMPTY_TEXT = EmptyText()


def _literal_location(s: str) -> StaticPath | EmptyText | None:
    """A literal's path reading: a location, ``EMPTY_TEXT`` for ``""``, or None for a text that
    is not a safe path (a ``..`` part)."""
    if s == "":
        return EMPTY_TEXT
    as_path = pathlib.PurePath(s)
    if as_path.is_absolute():
        rest = as_path.parts[1:]  # parts[0] is the "/" anchor
        if any(p == ".." for p in rest):
            return None
        return StaticPath(tuple(Named(p) for p in rest), absolute=True)
    if not as_path.parts:
        return StaticPath(())  # ".", "./": the current directory, i.e. the sandbox root
    parts = _safe_path_extension(s)
    return None if parts is None else StaticPath(tuple(Named(p) for p in parts))


def _literal_static(s: str) -> StaticPath | None:
    """A literal's location where ``""`` names nothing to place: a bare sink, a cwd, a guard's
    or a marker's operand."""
    loc = _literal_location(s)
    return loc if isinstance(loc, StaticPath) else None

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
            kept = carried(fact.atoms)  # the path reading derives its own built-ins
            if isinstance(fact, StrFact) and isinstance(fact.regex, Exact):
                loc = _literal_static(fact.regex.exact_str)  # "" on its own has no location
                return None if loc is None else Located(loc, rp, kept)
            if isinstance(fact, StrFact) and isinstance(fact.regex, Alternation) and all(
                isinstance(b, Exact) for b in fact.regex.any_of
            ):
                # one of several literals (a constant collection, iterated): each is located and
                # the locations joined; none if any literal is not a safe path or anchors mix
                loc = _literal_locations_joined([b.exact_str for b in fact.regex.any_of if isinstance(b, Exact)])
                return None if loc is None else Located(loc, rp, kept)
            if (comp := as_component(fact)) is not None:
                return Located(StaticPath((comp,)), rp, kept)
            if "no-parent-traversal" in fact and "not-absolute" in fact:
                return Located(DirSplat((), None), rp, kept)  # the root, or anywhere below
            return None
        case UrlString():
            return None  # a URL is not a filesystem path


def _literal_locations_joined(texts: Sequence[str]) -> LocationFact | None:
    """The one location covering every literal in *texts* (``join_loc`` folded), or None when
    some literal is not a safe path, is ``""`` (which names nothing), or the literals mix
    anchors."""
    joined: LocationFact | None = None
    for text in texts:
        loc = _literal_static(text)
        if loc is None:
            return None
        joined = loc if joined is None else join_loc(joined, loc)
        if joined is None:
            return None
    return joined


def url_path_location(path: str) -> StaticPath | None:
    """The location of a URL's path as ``urlsplit`` gives it: the one reading the analysis and
    the broker share. An empty path is the server root. A path whose percent-decoding would
    spell something else -- a ``..`` segment, or a separator -- has no location, since the
    origin may read it either way."""
    decoded = urllib.parse.unquote(path)
    if decoded.count("/") != path.count("/") or ".." in decoded.split("/"):
        return None
    return _literal_static(path or "/")


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
    # a path that is, or decodes to, ".."-bearing has no location (lexical claims only); the
    # netloc stays exact
    return UrlString(
        netloc=Exact(parts.netloc),
        path=url_path_location(parts.path),
        scheme=scheme,
        atoms=carried(atoms_of(value)) if not isinstance(value, str) else frozenset(),
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
                return leaf is None  # the prefix itself is denoted only by the reflexive form
            return leaf is None or subsumes(leaf, cs[-1])
        case DirSplat(), StaticPath():
            return False
        case DirSplat(static_prefix=ps, final_component=l), DirSplat(static_prefix=qs, final_component=m):
            # a's prefix must lie under b's, and a's leaves must satisfy m: a reflexive b covers
            # any a; a reflexive a (which denotes its prefix) needs a reflexive b
            if len(ps) < len(qs) or not all(subsumes(q, p) for q, p in zip(qs, ps)):
                return False
            if m is None:
                return True
            return l is not None and subsumes(m, l)

# the atoms of *required* a fact does not carry. ``structural_missing`` is the answer the
# analysis can give alone -- stated atoms, and built-ins by ``holds``; ``Vocabulary.missing``
# (enforcement) adds the policy's routes: defined regexes and literal checkers.
type AtomsMissing = Callable[[ValidationFact, frozenset[Atom]], frozenset[Atom]]


def structural_missing(fact: ValidationFact, required: frozenset[Atom]) -> frozenset[Atom]:
    return frozenset(a for a in required if not holds(a, fact))


def entails(
    actual: str | ValidationFact | None,
    required: ValidationFact,
    missing: AtomsMissing = structural_missing,
) -> bool:
    """Does what is known of *actual* establish *required*? The shape -- regex, location, URL
    claims -- by the lattice; the atoms by *missing*, which the caller supplies with whatever
    it has: structure alone here, or the vocabulary's regex definitions and literal checkers
    (``Vocabulary.missing``, with a discharger)."""
    if actual is None:
        return False
    fact: ValidationFact = StrFact(regex=Exact(actual)) if isinstance(actual, str) else actual
    match required:
        case UrlString(netloc=netloc, path=path, scheme=scheme, atoms=atoms):
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
            return not missing(got, atoms)
        case Located(location=loc, repr=rp, atoms=atoms):
            got = locate(fact)
            return (
                got is not None
                and got.repr == rp
                and location_le(got.location, loc)
                and not missing(got, atoms)
            )
        case StrFact(regex=regex, atoms=atoms):
            match fact:
                case StrFact():
                    return _regex_subsumes(regex, fact.regex) and not missing(fact, atoms)
                case Located(repr="str") | UrlString():
                    # a str, but nothing is tracked about its text
                    return regex == ANY_STR and not missing(fact, atoms)
                case _:
                    return False
        case PathFact(atoms=atoms):
            match fact:
                case PathFact() | Located(repr="path"):
                    return not missing(fact, atoms)
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
                return splat_under(cont)  # a relative path free of "..": "." included
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
        case Located(location=loc, atoms=atoms):
            return Located(loc, "str", atoms)
        case PathFact(atoms=atoms):
            return StrFact(atoms=atoms)
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
    """A component spelled as text: a literal, or a text fact that ``as_component`` lifts back.
    A component is never "" or ".", so its text says so (``AnyComponent``, or a ``Matching``
    regex met with it where the regex alone would admit either)."""
    match c:
        case Named(name=n):
            return n
        case AnyName():
            return StrFact(regex=ANY_COMPONENT, atoms=PATH_ATOMS)
        case Matching(regex=r):
            if _regex_accepts(r, "") or _regex_accepts(r, "."):
                r = both(r, ANY_COMPONENT)
            return StrFact(regex=r, atoms=PATH_ATOMS)
        case OneOf(names=ns):
            return StrFact(regex=alternation(*(Exact(n) for n in sorted(ns))), atoms=PATH_ATOMS)

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
                state = state.splat()
                return state if leaf is None else state.sep().chunk(_component_token(leaf))

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
            case StrFact(regex=Exact(exact_str=s)):
                return self.piece(s)  # exactly-known text reads as the literal it is ("" adds nothing)
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
        return _AfterSplat(DirSplat((), None))


@dataclass(frozen=True)
class _AfterSplat(_Spelling):
    """Just replayed a ``**``: the text so far is some path at or below *loc*, and it ends in a
    component, not a separator (``data/**`` stands for ``data``, ``data/x``, ``data/x/y``). So a
    chunk glued on here (``f"{p}.bak"``) lands inside that last component -- ``data.bak``,
    ``data/x.bak`` -- and has no location; only a ``/`` opens a new component below."""
    loc: LocationFact

    def sep(self) -> _Spelling:
        return _Boundary(self.loc)

    def splat(self) -> _Spelling:
        return self  # "**" onto "**" adds nothing

    def finish(self) -> LocationFact | None:
        return self.loc

@dataclass(frozen=True)
class _Boundary(_Spelling):
    """A complete location with a "/" just read: the next chunk starts a new component."""
    loc: LocationFact

    def chunk(self, c: _Chunk) -> _Spelling:
        return _Open(self.loc, (c,))

    def sep(self) -> _Spelling:
        return self  # "//" collapses

    def splat(self) -> _Spelling:
        return _AfterSplat(splat_under(self.loc))

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
        if self.prefix is None and self._may_be_empty():
            return _DEAD  # the text so far may be "", and then this "/" is a leading one
        loc = self._close()
        return _DEAD if loc is None else _Boundary(loc)

    def _may_be_empty(self) -> bool:
        """Can the component's text so far be ""? Only if every chunk can: a literal chunk never
        is (``piece`` skips empty literals), a text fact may be."""
        return all(isinstance(c, StrFact) and _regex_accepts(c.regex, "") for c in self.chunks)

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

    atoms: frozenset[Atom] = (
        frozenset({NO_SLASH}) if all(slash_free(p) for p in pieces) else frozenset()
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


# The names that denote modules, for the expression semantics: a dotted callee is a module
# function only under one of them (``json.loads`` is the module's only if ``json`` was imported;
# a program class of that name is program code). The walker passes the program's actual imports
# plus the marker namespace; this default is the vocabulary the recognizers know about, for
# callers without a program (tests, the guards).
KNOWN_MODULES: frozenset[str] = frozenset(
    {"os", "pathlib", "re", "sys", "typing", "urllib", NAMESPACE}
)

def scalar(entry: Entry | None) -> ValidationFact | None:
    """A state entry as a fact: containers, handles and standard values have no scalar reading
    -- those domains are the walker's, and only their touchpoints reach into them."""
    return None if isinstance(entry, (Container, Data, Std)) else entry

def _head_location(v: str | ValidationFact | None) -> LocationFact | EmptyText | None:
    """Where a join starts: a literal's reading (``EMPTY_TEXT`` for ``""``, known or spelled),
    or a value's containment."""
    match v:
        case None:
            return None
        case str() | StrFact(regex=Exact()):
            text = known_text(v)
            assert text is not None
            return _literal_location(text)
        case _:
            return containment_of(v)

def _flatten_add(e: ast.expr) -> list[ast.expr]:
    match e:
        case ast.BinOp(left=left, op=ast.Add(), right=right):
            return _flatten_add(left) + _flatten_add(right)
        case _:
            return [e]

def is_text(fact: ValidationFact | None) -> bool:
    """Is the value a ``str``: text, a URL reading, a path spelled as a str?"""
    return isinstance(fact, (StrFact, UrlString)) or (isinstance(fact, Located) and fact.repr == "str")

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

# --- standard values (EFFECTS.md, the callee analysis) --------------------------------------------
#
# Beside text and paths, the walker needs one bit about every other value -- can a call on, or
# with, it run program code? -- and a ``Std`` tracks a kind and closedness for that. The
# knowledge is the interpreter's: which builtins and module functions are its own code (the
# roster in ``dangerous``), which constructors build which kind, that every operator dunder is
# fixed (a program class may define none but ``__init__``), that an element of a closed
# container is inert.

# the constructors: their kind is certain, their closedness is their arguments'
_CONSTRUCTOR_KINDS: dict[str, StdKind] = {
    "list": "list", "tuple": "tuple", "set": "set", "frozenset": "frozenset", "dict": "dict",
    "sorted": "list",
}
# what a roster callee returns, when the kind is worth knowing: every kind here is closed
# whatever the arguments (a list of strs, a match, a number)
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
# what a method on an inert receiver returns when the kind is fixed by the method -- and then
# closed whatever the arguments: a list of strs, a bytes -- or "same", the receiver's own kind
# and closedness (a copy)
_METHOD_RESULT_KINDS: dict[str, StdKind | Literal["same"]] = {
    "split": "list", "rsplit": "list", "splitlines": "list", "findall": "list",
    "partition": "tuple", "rpartition": "tuple", "encode": "bytes", "copy": "same",
}

def _module_call(call: NameAccess, modules: frozenset[str], *path: str) -> bool:
    """Is *call* the module function *path* -- spelled so, under a name that denotes the module?"""
    return call.matches(*path) and path[0] in modules

# the names the loop variable can never have from a listing: never ".", never "..", never a "/"
_LISTED_NAME = StrFact(regex=ANY_COMPONENT, atoms=PATH_ATOMS)

_ELEMENT_WRAPPERS = ("sorted", "list", "tuple", "reversed", "iter")


@dataclass(frozen=True)
class Interpreter:
    """The expression semantics against one state, under the names that denote modules.

    ``interpret`` answers what an expression evaluates to, as precisely as the state knows: a
    fact for text and paths, the tracked container or the handle a name is bound to (their
    touchpoints project), a standard value for the rest of the interpreter's own values, None
    for an unknown value -- a program object, or a value derived from one. The other methods
    are that answer seen through one domain's eyes: ``expr`` the scalar facts, ``operand`` the
    text joins, ``is_inert`` the callee analysis, ``iteration_bindings`` the loop headers.

    *modules* are the names that denote modules: only under one of them is a dotted callee the
    module's function; a variable or a class that happens to be named ``json`` is program code.
    The walker passes the program's imports; the default is the vocabulary the recognizers
    know about, for callers without a program."""

    st: StateMap
    modules: frozenset[str] = KNOWN_MODULES

    def under(self, st: StateMap) -> "Interpreter":
        """The same semantics against another state (a comprehension's scope, a seed); *st* is
        the caller's own."""
        return replace(self, st=st)

    # -- projections ------------------------------------------------------------------------

    def expr(self, e: ast.expr) -> ValidationFact | None:
        """The fact *e* evaluates to, for the text and path transfer functions."""
        return scalar(self.interpret(e))

    def operand(self, e: ast.expr) -> str | ValidationFact | None:
        """An operand as the joins see it: a string literal stays a literal (so a
        multi-component literal can be split into components); anything else is interpreted."""
        if (s := as_const_or_null(str, e)) is not None:
            return s
        return self.expr(e)

    def is_inert(self, e: ast.expr) -> bool:
        """Is the value of *e* inert: text, a path, a tracked container, a closed standard value
        or handle -- anything but an unknown value or a program object?"""
        match e:
            case ast.Starred(value=inner):
                return self.is_inert(inner)
            case ast.Call(func=func) if resolve_callee(func) is None:
                return False  # a computed callee: refused elsewhere
            case _:
                return inert(self.interpret(e))

    def _all_inert(self, exprs: Sequence[ast.expr]) -> bool:
        return all(self.is_inert(x) for x in exprs)

    # -- the semantics ----------------------------------------------------------------------

    def interpret(self, e: ast.expr) -> Entry | None:
        st = self.st
        match e:
            case ast.Name(id=name):
                found = st.get(name)
                if found is None and name in INERT_BUILTIN_VALUES:
                    return Std()  # a builtin as a value (``key=len``): never rebound, so never in the state
                return found
            case ast.Constant(value=str() as s):
                return StrFact(regex=Exact(s))
            case ast.Constant(value=bool()):
                return Std("bool")
            case ast.Constant(value=int() | float() | complex()):
                return Std("number")
            case ast.Constant(value=bytes()):
                return Std("bytes")
            case ast.Constant(value=None):
                return Std("none")
            case ast.Constant():
                return Std()  # Ellipsis
            case ast.Call(func=func, args=args, keywords=keywords):
                return self._call(func, args, keywords)
            case ast.BinOp(left=left, op=ast.Div(), right=right):
                # ``path / x`` joins when x is shown safe (no ``..``, not absolute, a proven
                # location or a vouched-for name); otherwise the join is unknown -- not merely a
                # path of unknown location, since where it went is the whole question. ``"lit"
                # / path`` (__rtruediv__) and ``7 / 2`` are standard values over inert operands
                head = locate(self.expr(left))
                if head is not None and head.repr == "path":
                    loc = combine_containment(head.location, self.operand(right))
                    return None if loc is None else Located(loc, "path")
                return Std() if self._all_inert([left, right]) else None
            case ast.BinOp(left=left, op=ast.Add(), right=right):
                values = [self.operand(p) for p in _flatten_add(e)]
                if any(isinstance(v, str) or is_text(v) for v in values) and not any(
                    is_path_typed(v) for v in values if not isinstance(v, str)
                ):
                    # text concatenation: a str plus anything is a str or a TypeError (no
                    # program class defines ``__radd__``); a path in the chain is a TypeError
                    return join_text(values)
                return Std() if self._all_inert([left, right]) else None
            case ast.BinOp(left=left, right=right):
                # every operator dunder is the interpreter's: over inert operands the result is
                # a standard value; over others it may be a program object (an enum's ``|``
                # yields a member) or hold one (``[f] * 2``)
                return Std() if self._all_inert([left, right]) else None
            case ast.JoinedStr():
                return join_text(self._fstring_pieces(e))
            case ast.Subscript(value=value, slice=index):
                return self._subscript(value, index)
            case ast.List(elts=elts):
                return Std("list", self._all_inert(elts))
            case ast.Tuple(elts=elts):
                return Std("tuple", self._all_inert(elts))
            case ast.Set(elts=elts):
                return Std("set", self._all_inert(elts))
            case ast.Dict(keys=keys, values=values):
                # a None key is a ``**x`` splat: its value is the mapping spliced in
                return Std("dict", self._all_inert([k for k in keys if k is not None] + values))
            case ast.ListComp(elt=elt, generators=gens):
                return Std("list", self._comprehension_inert([elt], gens))
            case ast.SetComp(elt=elt, generators=gens):
                return Std("set", self._comprehension_inert([elt], gens))
            case ast.DictComp(key=key, value=value, generators=gens):
                return Std("dict", self._comprehension_inert([key, value], gens))
            case ast.BoolOp(values=operands):
                return Std() if self._all_inert(operands) else None  # one of the operands
            case ast.IfExp(body=body, orelse=orelse):
                return Std() if self._all_inert([body, orelse]) else None
            case ast.UnaryOp(op=ast.Not()):
                return Std("bool")
            case ast.UnaryOp(operand=operand):
                return Std() if self.is_inert(operand) else None
            case ast.Compare():
                return Std("bool")  # every comparison dunder is fixed
            case ast.Attribute(value=ast.Name(id=base) as recv, attr=attr):
                if base not in st:
                    if base in INERT_BUILTIN_TYPES:
                        return Std()  # ``str.lower``: a builtin type's method, as a value
                    if base == "sys" and attr == "argv" and "sys" in self.modules:
                        return Std("list")  # the argument vector: strs
                return self._attribute(recv)
            case ast.Attribute(value=recv):
                return self._attribute(recv)
            case _:
                return None  # a lambda, a generator expression, a yield, ...

    def _attribute(self, recv: ast.expr) -> Entry | None:
        # a data attribute of an inert value is inert (a path's ``name``, a match's
        # ``string``); so is a bound method taken as a value. Not on a tracked container: that
        # is its escape, the walker's to report
        entry = self.interpret(recv)
        return Std() if inert(entry) and not isinstance(entry, Container) else None

    def _subscript(self, value: ast.expr, index: ast.expr) -> Entry | None:
        sliced = isinstance(index, ast.Slice)
        if _argv_read(value):
            # an element of sys.argv is a str of unknown text; a slice is a list of them
            return Std("list") if sliced else StrFact()
        whole = self.interpret(value)
        match whole:
            case Container(kind="list" | "sequence", elem=elem):
                # x[i]: an element; a slice is a fresh list of them, untracked but inert
                return Std("list") if sliced else elem
            case Container():
                return None  # a set is unsubscriptable
            case _ if is_text(scalar(whole)):
                return StrFact()  # a character, or a substring: text, the path reading gone
            case Std(kind=kind, closed=True):
                if sliced:
                    return Std(kind if kind in ("list", "tuple", "bytes") else None)  # a copy
                return Std()  # an element, or a key's value, of a closed value: inert
            case _ if inert(whole):
                return Std() if not sliced else None  # a path is unsubscriptable; a handle too
            case _:
                return None  # an element of an open container may be anything

    def _fstring_pieces(self, e: ast.JoinedStr) -> list[str | ValidationFact | None]:
        out: list[str | ValidationFact | None] = []
        for v in e.values:
            match v:
                case ast.Constant(value=str() as s):
                    out.append(s)
                case ast.FormattedValue(value=inner, conversion=-1, format_spec=None):
                    out.append(self.operand(inner))
                case _:
                    out.append(None)  # ``!r`` / ``:spec`` rewrite the text unpredictably
        return out

    def _join_args(self, args: Sequence[ast.expr], empty: LocationFact | None) -> LocationFact | None:
        """``pathlib.Path(a, b, ...)`` / ``os.path.join(a, b, ...)``: the first argument's
        location, extended by the rest. A leading ``""`` adds nothing, so the next argument
        starts the join; a join of nothing but ``""`` is *empty* -- the root for ``pathlib``
        (``Path("")`` is ``.``), no location for ``os.path.join`` (the result is ``""``)."""
        loc = _head_location(self.operand(args[0]))
        for a in args[1:]:
            if isinstance(loc, EmptyText):
                loc = _head_location(self.operand(a))
            elif loc is None:
                return None
            else:
                loc = combine_containment(loc, self.operand(a))
        return empty if isinstance(loc, EmptyText) else loc

    def _comprehension_inert(
        self, exprs: Sequence[ast.expr], generators: Sequence[ast.comprehension]
    ) -> bool:
        """Are the elements a comprehension builds inert? The element expressions, under the
        iteration bindings (an ``if`` clause refines nothing about inertness)."""
        inner: dict[str, Entry] = dict(self.st)
        for gen in generators:
            if gen.is_async:
                return False
            for n in ast.walk(gen.target):
                if isinstance(n, ast.Name):
                    inner.pop(n.id, None)
            inner.update(self.under(inner).iteration_bindings(gen.target, gen.iter))
        return self.under(inner)._all_inert(exprs)

    def _call(
        self, func: ast.expr, args: Sequence[ast.expr], keywords: Sequence[ast.keyword]
    ) -> Entry | None:
        call = resolve_callee(func)
        if call is None:
            # ``f()()``: a callee with no name at all is refused structurally. (``f().g()`` is
            # fine: the callee is the *name* ``g`` on a computed receiver.)
            raise InvalidProgram(func, "computed callee")
        modules = self.modules
        # the argument conditions (``dangerous.INERT_CALLEES``), over the expressions
        positional = [a for a in args if not isinstance(a, ast.Starred)]
        splats = [a for a in args if isinstance(a, ast.Starred)] + [k.value for k in keywords if k.arg is None]
        named = [k.value for k in keywords if k.arg is not None]
        keywords_and_splats_inert = self._all_inert(named) and self._all_inert(splats)
        all_inert = keywords_and_splats_inert and self._all_inert(positional)
        plain = not keywords and not splats  # positional arguments only

        # a bare name, or a member of a module: a builtin, a constructor, a roster function or
        # a program function. ``line.strip()`` is none of these -- its base is a variable -- and
        # falls through to the method branch
        if call.is_var_base and (len(call.full_path) == 1 or call.full_path[0] in modules):
            full = call.full_path
            # -- the path and text constructors: a fact
            if plain and args and any(_module_call(call, modules, "pathlib", c) for c in _PATH_CONSTRUCTORS):
                loc = self._join_args(args, empty=StaticPath(()))
                return PathFact() if loc is None else Located(loc, "path")
            if plain and args and _module_call(call, modules, "os", "path", "join"):
                loc = self._join_args(args, empty=None)
                return None if loc is None else Located(loc, "str")
            if plain and len(args) == 1 and call.matches("str"):
                # ``str(x)`` is a str whatever x is; of a path or text it keeps the claims
                return as_str_value(self.expr(args[0])) or StrFact()
            if plain and len(args) == 1 and _module_call(call, modules, "os", "fspath"):
                return as_str_value(self.expr(args[0]))  # str or bytes: only a fact says
            if len(full) == 1 and full[0] in _STR_RETURNING_BUILTINS:
                return StrFact() if keywords_and_splats_inert else None
            # -- the standard constructors: their kind, closed iff the arguments are inert
            if len(full) == 1 and (kind := _CONSTRUCTOR_KINDS.get(full[0])) is not None:
                return Std(kind, all_inert)  # ``list(gen)`` is a list, of who knows what
            if full in _OPAQUE_RESULTS:
                return None  # ``type(x)`` may be a program class
            # -- the roster: the interpreter's own code under its argument condition
            condition = inert_condition(full, modules)
            if condition is None:
                return None  # a program function or class; a module function off the roster
            if not (all_inert if condition == "all" else keywords_and_splats_inert):
                return None  # program code may decide the result (``json.loads(s, object_hook=f)``)
            return Std(_RESULT_KINDS.get(full))
        if not call.is_var_base and call.computed_base is None:
            return None  # ``super().m()``: a program method

        # -- a method call, on a variable or a computed receiver: the receiver decides
        assert isinstance(func, ast.Attribute)
        method = func.attr
        receiver = self.interpret(func.value)
        if isinstance(receiver, Container):
            if method == "pop" and receiver.kind != "sequence" and len(args) <= 1 and not keywords:
                return receiver.elem  # x.pop(): one element, with the container's current fact
            return None  # the other roster methods return None or are the walker's; the rest escape
        if not inert(receiver):
            return None  # a program object's method, or a method on an opened unknown value
        if method == "open":
            return None  # a file object: its writes are effects, so it is no standard value
        fact = scalar(receiver)
        if method in _STR_RETURNING_METHODS and is_text(fact):
            return StrFact()  # text stays text; nothing is known about the new characters
        if method == "decode":
            return StrFact()  # bytes.decode(): the only decode an inert value has yields text
        kind = _METHOD_RESULT_KINDS.get(method)
        if kind == "same":
            return Std(receiver.kind, receiver.closed) if isinstance(receiver, Std) else Std()
        if kind is not None:
            return Std(kind)  # fixed by the method, closed whatever the arguments
        # a result of unknown kind holds what it is handed (``d.get(k, default)``,
        # ``xs.pop()``): inert only over inert arguments
        return Std() if all_inert else None

    # -- iteration --------------------------------------------------------------------------
    #
    # In ``for p in <iterable>`` the loop variable is rebound by the header on every iteration,
    # so its fact is the iterable's *element* fact -- no fixpoint needed. The directory
    # traversals are modelled exactly: ``iterdir``/``glob``/``rglob`` on a located path,
    # ``os.listdir`` (bare names), ``os.walk`` (via its tuple target), through the
    # element-preserving wrappers ``sorted``/``list``/``tuple``/``reversed``/``iter`` and
    # ``enumerate``. Any other inert iterable yields inert elements of unknown kind.

    def _path_location(self, recv: ast.expr) -> LocationFact | None:
        """The location of a receiver that must be a ``pathlib.Path`` (``iterdir``/``glob``
        exist only there)."""
        located = locate(self.expr(recv))
        return located.location if located is not None and located.repr == "path" else None

    def element_fact(self, iterable: ast.expr) -> ValidationFact | None:
        """The fact for ``p`` in ``for p in <iterable>``, when the iterable is a directory
        traversal, a container of facts, a handle, or the argument vector."""
        match iterable:
            case ast.Call(func=ast.Name(id=wrapper), args=[inner], keywords=kws) if (
                wrapper in _ELEMENT_WRAPPERS and all(k.arg in ("key", "reverse") for k in kws)
            ):
                return self.element_fact(inner)
            case ast.Call(func=ast.Attribute(value=recv, attr="iterdir"), args=[], keywords=[]):
                loc = self._path_location(recv)
                return None if loc is None else Located(loc.extend_single(ANY_NAME), "path")
            case ast.Call(
                func=ast.Attribute(value=recv, attr=("glob" | "rglob") as method), args=[pat], keywords=[]
            ):
                loc = self._path_location(recv)
                pattern = as_const_or_null(str, pat)
                if loc is None or pattern is None:
                    return None
                found = _glob_location(splat_under(loc) if method == "rglob" else loc, pattern)
                return None if found is None else Located(found, "path")
            case ast.Call(func=func, args=args, keywords=[]) if (
                len(args) <= 1
                and (callee := resolve_callee(func)) is not None
                and _module_call(callee, self.modules, "os", "listdir")
            ):
                return _LISTED_NAME  # bare names, whatever the directory
            case _ if _argv_read(iterable):
                # sys.argv or a slice of it: command-line arguments, strs of unknown text
                return StrFact()
            case ast.Name(id=name) if isinstance(self.st.get(name), Container):
                container = self.st[name]
                assert isinstance(container, Container)
                return container.elem  # iterating a tracked container: its current element fact
            case ast.Name(id=name) if isinstance(self.st.get(name), Data):
                handle = self.st[name]
                assert isinstance(handle, Data)
                # ``for line in f`` over a source handle: each line is something the source
                # produced, unmodified (PROVENANCE.md) -- ``certora.lines`` spelled the stdlib way
                return StrFact(atoms=frozenset(handle.sources))
            case (ast.List(elts=elts) | ast.Tuple(elts=elts) | ast.Set(elts=elts)) if elts and not any(
                isinstance(e, ast.Starred) for e in elts
            ):
                # a constant collection: the element is one of the values, so its fact is the one
                # covering all of them -- one fold over the display (``join_fact``); an element the
                # interpreter cannot read, or a pair with no covering fact, yields nothing
                joined: ValidationFact | None = None
                for e in elts:
                    v = self.operand(e)
                    if v is None:
                        return None
                    fact = as_fact(v)
                    joined = fact if joined is None else join_fact(joined, fact)
                    if joined is None:
                        return None
                return joined
            case _:
                return None

    def element_std(self, iterable: ast.expr) -> Std | None:
        """The element of an iterable the traversal semantics do not know but inertness does:
        the elements of an inert value are inert (``for line in text.splitlines()``, ``for k, v
        in d.items()``), and ``range`` yields numbers whatever it was given."""
        match iterable:
            case ast.Call(func=ast.Name(id="range")):
                return Std("number")
            case _:
                return Std() if self.is_inert(iterable) else None

    def iteration_bindings(self, target: ast.expr, iterable: ast.expr) -> dict[str, ValidationFact | Std]:
        """Facts for the names ``for <target> in <iterable>`` binds: the traversal iterables'
        element facts, and inert elements of unknown kind for any other inert iterable."""
        match target, iterable:
            case ast.Name(id=name), _:
                fact = self.element_fact(iterable)
                if fact is not None:
                    return {name: fact}
                std = self.element_std(iterable)
                return {} if std is None else {name: std}
            case ast.Tuple(elts=[ast.Name(id=index), inner_target]), ast.Call(
                func=ast.Name(id="enumerate"), args=[inner], keywords=_
            ):
                return {index: Std("number"), **self.iteration_bindings(inner_target, inner)}
            case ast.Tuple(elts=[ast.Name(id=dirpath), dirnames, filenames]), ast.Call(
                func=func, args=[top, *_], keywords=_
            ) if (callee := resolve_callee(func)) is not None and _module_call(callee, self.modules, "os", "walk"):
                # dirpath is a str at or below top; dirnames/filenames are lists of bare names
                lists: dict[str, ValidationFact | Std] = {
                    n.id: Std("list") for n in (dirnames, filenames) if isinstance(n, ast.Name)
                }
                loc = _head_location(self.operand(top))
                if not isinstance(loc, (StaticPath, DirSplat)):
                    return lists  # an unplaced top, or os.walk(""), which yields nothing
                return {dirpath: Located(splat_under(loc), "str"), **lists}
            case _:
                std = self.element_std(iterable)
                return {} if std is None else dict(destructure(target, std))


# the one-off entry points: the semantics against *st* for a single expression (tests, guards)

def interpret_expr(e: ast.expr, st: StateMap, modules: frozenset[str] = KNOWN_MODULES) -> ValidationFact | None:
    return Interpreter(st, modules).expr(e)

def operand_value(e: ast.expr, st: StateMap, modules: frozenset[str] = KNOWN_MODULES) -> str | ValidationFact | None:
    return Interpreter(st, modules).operand(e)

def iteration_bindings(
    target: ast.expr, iterable: ast.expr, st: StateMap, modules: frozenset[str] = KNOWN_MODULES
) -> dict[str, ValidationFact | Std]:
    return Interpreter(st, modules).iteration_bindings(target, iterable)

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
    """The location covering every path *left* or *right* denotes: pointwise where the two
    agree in shape, degrading to a splat where they do not. Total on one anchor -- ``**`` (or
    ``/**``) covers every path of an anchor, so the only None is a mix of anchors, which no
    location relates.

    Used to abstract a *constant collection* of literals as one fact (``for f in ["a/x", "a/y"]``,
    ``locate`` of an alternation of exact texts): a finite one-shot fold. Deliberately NOT the
    walker's control-flow join, which does not merge two located values (see the join decision
    recorded with the design notes): no lattice iteration is implied anywhere."""
    if left.absolute != right.absolute:
        return None  # anchors never relate: there is no location covering both
    match left, right:
        case (DirSplat(static_prefix=dir_prefix) as splat, StaticPath(path_components=known_path)) | \
             (StaticPath(path_components=known_path), DirSplat(static_prefix=dir_prefix) as splat):
            # the prefix the two agree on pointwise, over the components both have
            shared = min(len(dir_prefix), len(known_path))
            prefix = tuple(join_component(a, b) for a, b in zip(dir_prefix[:shared], known_path[:shared]))
            below = known_path[shared:]  # the static path's components past the splat's prefix
            if len(dir_prefix) > len(known_path) or not below:
                # the static path ends at or inside the (joined) prefix: only the reflexive form
                # denotes the prefix itself
                return DirSplat(prefix, None, left.absolute)
            if splat.final_component is None:
                return DirSplat(prefix, None, left.absolute)
            # the static path lies strictly below: a strict splat with a leaf covering both
            return DirSplat(prefix, join_component(splat.final_component, below[-1]), left.absolute)
        case (StaticPath(path_components=p1), StaticPath(path_components=p2)):
            if len(p1) == len(p2):
                paths = tuple(join_component(
                    c1, c2
                ) for (c1, c2) in zip(p1, p2))
                return StaticPath(paths, left.absolute)
            if not p1 or not p2:
                return DirSplat((), None, left.absolute)  # the root and a path below it
            last_comps = join_component(p1[-1], p2[-1])
            static_prefix = tuple(join_component(
                c1, c2
            ) for (c1, c2) in zip(p1[:-1], p2[:-1]))
            return DirSplat(
                static_prefix=static_prefix, final_component=last_comps, absolute=left.absolute
            )
        case DirSplat(static_prefix=p1, final_component=c1), DirSplat(static_prefix=p2, final_component=c2):
            return DirSplat(
                final_component=None if c1 is None or c2 is None else join_component(c1, c2),
                static_prefix=tuple(join_component(c1, c2) for (c1, c2) in zip(p1, p2)),
                absolute=left.absolute
            )

def join_regex(
    left: PseudoRegex,
    right: PseudoRegex
) -> PseudoRegex:
    return alternation(left, right)


def join_fact(left: ValidationFact, right: ValidationFact) -> ValidationFact | None:
    """The fact covering a value that is *left* or *right*, for abstracting a constant
    collection of literals as one element fact. Two text facts join to the alternation of their
    regexes and the atoms both carry; two located values of one spelling to the location covering
    both (``join_loc``); anything else -- different readings, unrelated anchors -- has no single
    fact, and the caller knows nothing. A one-shot fold over a finite display, never the
    walker's control-flow join."""
    match left, right:
        case StrFact(regex=r1, atoms=a1), StrFact(regex=r2, atoms=a2):
            return StrFact(regex=alternation(r1, r2), atoms=a1 & a2)
        case PathFact(atoms=a1), PathFact(atoms=a2):
            return PathFact(atoms=a1 & a2)
        case Located(location=l1, repr=rp1, atoms=a1), Located(location=l2, repr=rp2, atoms=a2) if rp1 == rp2:
            loc = join_loc(l1, l2)
            return None if loc is None else Located(loc, rp1, a1 & a2)
        case _:
            return None

def widen_regex(
    prev: PseudoRegex,
    next: PseudoRegex
) -> PseudoRegex:
    ...
