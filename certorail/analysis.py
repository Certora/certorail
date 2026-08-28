import ast
from contextlib import contextmanager
import fnmatch
import functools
import inspect
import pathlib
import re
import stat
from turtle import isvisible
from types import UnionType
from typing import Any, cast, Callable, Literal, Sequence, final, override, reveal_type
from dataclasses import dataclass, is_dataclass
from typing_extensions import TypeForm
from .dangerous import DANGEROUS_MEMBERS, FORBIDDEN_MODULES
from .typed_ast_tsp import typed_ast

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
    "breakpoint"
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

@dataclass(frozen=True)
class OptionMonad[T]:
    s: T | None

    def map[S](self, m: Callable[[T], S]) -> "OptionMonad[S]":
        if self.s is None:
            return OptionMonad(None)
        d = m(self.s)
        if d is None:
            raise ValueError("You maybe don't know how monads work")
        return OptionMonad(d)

    def bind[S](self, m: "Callable[[T], S | None | OptionMonad[S]]") -> "OptionMonad[S]":
        if self.s is None:
            return OptionMonad(None)
        res =  m(self.s)
        if isinstance(res, OptionMonad):
            return res
        return OptionMonad(res)

    def downcast[X](self, t: type[X]) -> "OptionMonad[X]":
        if self.s is None or not isinstance(self.s, t):
            return OptionMonad(None)
        return OptionMonad(self.s)

    @classmethod
    def lift[R](cls, s: R | None) -> "OptionMonad[R]":
        return OptionMonad(s)

    def unwrap(self) -> T | None:
        return self.s

    def unwrap_or(self, default: T) -> T:
        if self.s is None:
            return default
        return self.s

@dataclass
class CertoraMatch:
    target: ast.expr
    matches: ast.expr


@dataclass
class PyOpenCall:
    file: ast.expr
    mode: ast.expr | str = "r"
    encoding: ast.expr | None = None
    errors : ast.expr | None = None
    newline: ast.expr | None = None
    closefd: ast.expr | bool = True
    opener: ast.expr | None = None

def bind_call_args[T](call: ast.Call, spec: type[T]) -> T | None:
    """Match the arguments of *call* against the dataclass type *spec*.
 
    On success returns ``spec(...)`` built from the call's argument
    expressions. Returns None when the call can't be statically bound:
 
      - *args / **kwargs splats anywhere in the call
      - too many positional arguments
      - unknown or duplicate keyword arguments
      - a required (no-default) field isn't supplied
      - a kw_only field passed positionally
      - an argument supplied both positionally and by keyword
 
    Only *binding* failures become None. The instance is constructed after
    binding succeeds, so exceptions from your own __post_init__ (a natural
    place for validation) propagate instead of masquerading as parse
    failures.
    """
    if not (isinstance(spec, type) and is_dataclass(spec)):
        raise TypeError(f"spec must be a dataclass type, got {spec!r}")
 
    # Splats defeat static binding.
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    kwargs: dict[str, ast.expr] = {}
    for kw in call.keywords:
        if kw.arg is None:  # a **splat
            return None
        if kw.arg in kwargs:  # impossible in parsed source; hand-built ASTs only
            return None
        kwargs[kw.arg] = kw.value
 
    # The dataclass's generated __init__ is the signature; bind against it.
    try:
        bound = inspect.signature(spec).bind(*call.args, **kwargs)
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

type PseudoRegex = Alternation | Concat | RegexLit | Exact | AnyStr

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
    path_components: tuple[Component, ...]

    @property
    def final_component(self) -> Component:
        return self.path_components[-1]

    def merge_other(self, other: "LocationFact") -> "LocationFact":
        if isinstance(other, StaticPath):
            return StaticPath(self.path_components + other.path_components)
        else:
            return DirSplat(self.path_components + other.static_prefix, other.final_component)

    def extend_static(self, other: tuple[str, ...]) -> "StaticPath":
        return StaticPath(self.path_components + tuple(Named(i) for i in other))

    def extend_single(self, other: Component) -> "StaticPath":
        return StaticPath(self.path_components + (other,))

    def to_splat(self, final_component: Component) -> "DirSplat":
        return DirSplat(self.path_components, final_component)

@dataclass(frozen=True)
class DirSplat:
    static_prefix: tuple[Component, ...]
    final_component: Component

    def merge_other(self, other: "LocationFact") -> "DirSplat":
        return DirSplat(static_prefix=self.static_prefix, final_component=other.final_component)

    def extend_static(self, ext: tuple[str, ...]) -> "DirSplat":
        return DirSplat(
            static_prefix=self.static_prefix,
            final_component=Named(ext[-1])
        )

    def extend_single(self, other: Component) -> "DirSplat":
        return DirSplat(
            self.static_prefix,
            other
        )

    def to_splat(self, final_component: Component) -> "DirSplat":
        return DirSplat(self.static_prefix, final_component)


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


def component_to_regex(c: Component) -> PseudoRegex:
    """The string language of one component.

    Exact except for ``Matching``, whose "is a safe component" conjunct has to be dropped because
    PseudoRegex has no intersection: the result is looser there, never tighter.
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
        case StaticPath(path_components=()):
            return ROOT
        case StaticPath(path_components=components):
            return _joined(components)
        case DirSplat(static_prefix=prefix, final_component=final):
            head: list[PseudoRegex] = [_joined(prefix), SLASH] if prefix else []
            below = concat(*head, DESCENDANTS, component_to_regex(final))
            if final != ANY_NAME:
                return below
            # an unconstrained leaf means "at or below": the prefix itself is denoted too
            return alternation(_joined(prefix) if prefix else ROOT, below)


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
        case StaticPath(path_components=()):
            return "."
        case StaticPath(path_components=cs):
            return "/".join(pretty_component(c) for c in cs)
        case DirSplat(static_prefix=ps, final_component=leaf):
            prefix = "/".join(pretty_component(c) for c in ps)
            tail = "**" if leaf == ANY_NAME else f"**/{pretty_component(leaf)}"
            return f"{prefix}/{tail}" if prefix else tail


def splat_under(loc: LocationFact) -> DirSplat:
    """The location "somewhere at or below *loc*"."""
    match loc:
        case StaticPath(path_components=components):
            return DirSplat(components, ANY_NAME)
        case DirSplat(static_prefix=prefix):
            return DirSplat(prefix, ANY_NAME)


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


def _concat_accepts(pieces: Sequence[PseudoRegex], s: str) -> bool:
    # try every split point for the head piece; strings here are single path components
    if not pieces:
        return s == ""
    head, rest = pieces[0], pieces[1:]
    return any(
        _regex_accepts(head, s[:i]) and _concat_accepts(rest, s[i:]) for i in range(len(s) + 1)
    )


def _regex_subsumes(general: PseudoRegex, specific: PseudoRegex) -> bool:
    """L(specific) ⊆ L(general), by the obvious rules."""
    if general == specific or general == ANY_STR:
        return True
    match specific:
        case Exact(exact_str=s):
            return _regex_accepts(general, s)
        case Alternation(any_of=branches):
            return all(_regex_subsumes(general, b) for b in branches)
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
# A value is read in one of two ways, never both:
#   * as *text*   -- StrFact / PathFact: what its characters look like (regex, atoms). Nothing is
#                    known about it as a path; ``locate`` is the partial lift to the path reading.
#   * as a *path* -- Located: where it points, and whether it is spelled as a str or a Path.
#                    Nothing is tracked about its text; ``as_text`` is the forgetful map back.
# Going into text is giving up on the path reading; the transfer functions stay in path-land for
# as long as the operation is a path operation.
# ---------------------------------------------------------------------------

type Repr = Literal["str", "path"]

@dataclass(frozen=True)
class StrFact:
    """A ``str`` read as text."""
    regex: PseudoRegex = ANY_STR
    atoms: frozenset[AtomicFact] = frozenset()

    def __contains__(self, atom: AtomicFact) -> bool:
        return _holds(atom, self.atoms, self.regex)

@dataclass(frozen=True)
class PathFact:
    """A ``pathlib.Path`` of unknown location, read as text through ``str(p)``: ``no-slash`` means
    a single relative component, ``not-absolute`` means ``not p.is_absolute()``,
    ``no-parent-traversal`` means no ``..`` part."""
    atoms: frozenset[AtomicFact] = frozenset()

    def __contains__(self, atom: AtomicFact) -> bool:
        return _holds(atom, self.atoms, ANY_STR)

@dataclass(frozen=True)
class Located:
    """A value read as a path: where it points, spelled as a ``str`` or a ``pathlib.Path``."""
    location: LocationFact
    repr: Repr

type ValidationFact = StrFact | PathFact | Located

def is_path_typed(fact: ValidationFact | None) -> bool:
    return isinstance(fact, PathFact) or (isinstance(fact, Located) and fact.repr == "path")

def location_of(fact: ValidationFact | None) -> LocationFact | None:
    return fact.location if isinstance(fact, Located) else None


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
    if not pathlib.PurePath(s).parts:
        return StaticPath(())  # "", ".", "./": the current directory, i.e. the sandbox root
    parts = _safe_path_extension(s)
    return None if parts is None else StaticPath(tuple(Named(p) for p in parts))

def locate(fact: ValidationFact | None) -> Located | None:
    """The path reading of a value, if it has one.

    A located value is returned as is. A text value is located iff its text is a safe relative
    path: a known literal is parsed; a single safe component sits directly under the root; a
    relative string free of ".." is somewhere at or below the root. Anything else has no path
    reading (yet).
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
                return None if loc is None else Located(loc, rp)
            if (comp := as_component(fact)) is not None:
                return Located(StaticPath((comp,)), rp)
            if "no-parent-traversal" in fact and "not-absolute" in fact:
                return Located(DirSplat((), ANY_NAME), rp)
            return None

def containment_of(fact: ValidationFact | None) -> LocationFact | None:
    located = locate(fact)
    return None if located is None else located.location

# --- entailment ----------------------------------------------------------------------------------
#
# The rely/guarantee check: does what is known of a value establish what a contract requires?
# Conservative throughout -- False means "not shown", never "disjoint".

def location_le(actual: LocationFact, required: LocationFact) -> bool:
    """Is every path *actual* may denote one that *required* denotes?"""
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
        case Located(location=loc, repr=rp):
            got = locate(fact)
            return got is not None and got.repr == rp and location_le(got.location, loc)
        case StrFact(regex=regex, atoms=atoms):
            match fact:
                case StrFact():
                    return _regex_subsumes(regex, fact.regex) and all(a in fact for a in atoms)
                case Located(repr="str"):
                    return regex == ANY_STR and not atoms  # a str, but nothing is tracked about its text
                case _:
                    return False
        case PathFact(atoms=atoms):
            match fact:
                case PathFact():
                    return all(a in fact for a in atoms)
                case Located(repr="path"):
                    return not atoms  # nothing lexical is tracked about a located value
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
        case StrFact(regex=Exact(exact_str=s)):
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

def as_str_value(fact: ValidationFact | None) -> ValidationFact | None:
    """``str(x)`` / ``os.fspath(x)``: the same value, spelled as a str."""
    match fact:
        case None:
            return None
        case Located(location=loc):
            return Located(loc, "str")
        case PathFact(atoms=atoms):
            return StrFact(atoms=atoms)
        case StrFact():
            return fact

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
        """Replay the spelling of a located value."""
        match loc:
            case StaticPath(path_components=()):
                return self.chunk(".")  # the root, as PurePath spells it
            case StaticPath(path_components=cs):
                return self._components(cs)
            case DirSplat(static_prefix=ps, final_component=leaf):
                state = self._components(ps).sep() if ps else self
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
            case StrFact() | PathFact():
                return self.chunk(p)

class _Dead(_Spelling):
    """No path reading: some piece could not be placed."""

class _Start(_Spelling):
    """Nothing read yet."""

    def chunk(self, c: _Chunk) -> _Spelling:
        return _Open(None, (c,))

    def sep(self) -> _Spelling:
        return _DEAD  # a leading "/": absolute

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

def bind[T, R](f: Callable[[T], OptionMonad[R] | R | None]) -> Callable[[OptionMonad[T]], OptionMonad[R]]:
    return lambda m: m.bind(f)

def map_[T, R](f: Callable[[T], R]) -> Callable[[OptionMonad[T]], OptionMonad[R]]:
    return lambda m: m.map(f)


class OperandInterpreter():
    def __init__(self, st: dict[str, ValidationFact]):
        self.st = st

    def interp[R](
        self,
        e: ast.expr,
        on_str: Callable[[OptionMonad[str]], OptionMonad[R]],
        on_fact: Callable[[OptionMonad[ValidationFact]], OptionMonad[R]],
        on_expr: Callable[[OptionMonad[ast.expr]], OptionMonad[R]] | None = None
    ) -> R | None:
        if (as_str := as_const_or_null(str, e)):
            return on_str(OptionMonad(as_str)).unwrap()
        if not isinstance(e, ast.Name):
            if on_expr is None:
                return None
            return on_expr(OptionMonad(e)).unwrap()
        res = self.st.get(e.id)
        if res is None:
            return None
        return on_fact(OptionMonad(res)).unwrap()

    def interp_bind[R](
        self,
        e: ast.expr,
        on_str: Callable[[OptionMonad[str]], OptionMonad[R]],
        on_fact: Callable[[OptionMonad[ValidationFact]], OptionMonad[R]],
        on_expr : Callable[[OptionMonad[ast.expr]], OptionMonad[R]] | None = None
    ) -> OptionMonad[R]:
        return OptionMonad.lift(self.interp(e, on_str, on_fact, on_expr))

def type_cast[T](t: TypeForm[T]) -> Callable[[T], T]:
    return lambda x: x


def take_if[T](pred: Callable[[T], bool]) -> Callable[[T], T | None]:
    def to_ret(it: T) -> T | None:
        if not pred(it):
            return None
        else:
            return it
    return to_ret

class _default:
    @classmethod
    def BindNone[T, R](cls) -> Callable[[OptionMonad[T]], OptionMonad[R]]:
        return lambda _ign: OptionMonad.lift(None)

    @classmethod
    def Cast[R](cls, ty: TypeForm[R]) -> Callable[[OptionMonad[R]], OptionMonad[R]]:
        return lambda x: x.bind(type_cast(ty))

@dataclass(frozen=True, eq=False)
class CurriedMonad[M, R]:
    staged: Callable[[OptionMonad[M]], OptionMonad[R]]

    def bind_curried[S](self, c: Callable[[R], OptionMonad[S] | S | None]) -> "CurriedMonad[M, S]":
        return CurriedMonad(lambda to_exec: self.staged(to_exec).bind(c))

    def __call__(self, arg: OptionMonad[M]) -> OptionMonad[R]:
        return self.staged(arg)

def operand_value(e: ast.expr, st: dict[str, ValidationFact]) -> str | ValidationFact | None:
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

def join_args(args: Sequence[ast.expr], st: dict[str, ValidationFact]) -> LocationFact | None:
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

def _fstring_pieces(e: ast.JoinedStr, st: dict[str, ValidationFact]) -> list[str | ValidationFact | None]:
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

def interpret_expr(e: ast.expr, st: dict[str, ValidationFact]) -> ValidationFact | None:
    match e:
        case ast.Name(id=name):
            return st.get(name)
        case ast.Constant(value=str() as s):
            return StrFact(regex=Exact(s))
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
            if len(args) == 1 and (call.matches("str") or call.matches("os", "fspath")):
                return as_str_value(interpret_expr(args[0], st))
            if isinstance(func, ast.Attribute) and func.attr in _STR_RETURNING_METHODS:
                receiver = interpret_expr(func.value, st)
                if isinstance(receiver, StrFact) or (isinstance(receiver, Located) and receiver.repr == "str"):
                    return StrFact()  # text stays text; nothing is known about the new characters
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
        case _:
            return None

# --- iteration -----------------------------------------------------------------------------------
#
# In ``for p in <iterable>`` the loop variable is rebound by the header on every iteration, so its
# fact is the iterable's *element* fact -- no fixpoint needed. Only the directory-traversal
# iterables are modelled: ``iterdir``/``glob``/``rglob`` on a located path, ``os.listdir`` (bare
# names), ``os.walk`` (via its tuple target), through the element-preserving wrappers
# ``sorted``/``list``/``tuple``/``reversed``/``iter`` and ``enumerate``.

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

def _path_location(recv: ast.expr, st: dict[str, ValidationFact]) -> LocationFact | None:
    """The location of a receiver that must be a ``pathlib.Path`` (``iterdir``/``glob`` exist only there)."""
    located = locate(interpret_expr(recv, st))
    return located.location if located is not None and located.repr == "path" else None

_ELEMENT_WRAPPERS = ("sorted", "list", "tuple", "reversed", "iter")

def element_fact(iterable: ast.expr, st: dict[str, ValidationFact]) -> ValidationFact | None:
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
        case _:
            return None

def iteration_bindings(
    target: ast.expr, iterable: ast.expr, st: dict[str, ValidationFact]
) -> dict[str, ValidationFact]:
    """Facts for the names ``for <target> in <iterable>`` binds, for the traversal iterables."""
    match target, iterable:
        case ast.Name(id=name), _:
            fact = element_fact(iterable, st)
            return {} if fact is None else {name: fact}
        case ast.Tuple(elts=[ast.Name(), inner_target]), ast.Call(
            func=ast.Name(id="enumerate"), args=[inner], keywords=_
        ):
            return iteration_bindings(inner_target, inner, st)  # the index is an int: nothing
        case ast.Tuple(elts=[ast.Name(id=dirpath), _, _]), ast.Call(
            func=func, args=[top, *_], keywords=_
        ) if (callee := resolve_callee(func)) is not None and callee.matches("os", "walk"):
            # dirpath is a str at or below top; dirnames/filenames are lists of bare names, which
            # the state cannot hold yet
            loc = _head_location(operand_value(top, st))
            return {} if loc is None else {dirpath: Located(splat_under(loc), "str")}
        case _:
            return {}

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
                return StaticPath(paths)
            last_comps = join_component(p1[-1], p2[-1])
            static_prefix = tuple(join_component(
                c1, c2
            ) for (c1, c2) in zip(p1[:-1], p2[:-1]))
            return DirSplat(static_prefix=static_prefix, final_component=last_comps)
        case DirSplat(static_prefix=p1, final_component=c1), DirSplat(static_prefix=p2, final_component=c2):
            return DirSplat(
                final_component=join_component(c1, c2),
                static_prefix=tuple(join_component(c1, c2) for (c1, c2) in zip(p1, p2))
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
