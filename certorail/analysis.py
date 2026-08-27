import ast
from contextlib import contextmanager
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
    _wrappedBase: ast.Name | Literal["super"]
    fields: Sequence[tuple[str, ast.Attribute]]

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

def unfold_attr(e: ast.Attribute) -> NameAccess | ast.AST:
    attr_path : list[tuple[str, ast.Attribute]] = []
    it = e
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
            return it

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
        r = unfold_attr(i)
        return r if isinstance(r, NameAccess) else None
    else:
        return None
    

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

@dataclass(frozen=True)
class StrFact:
    """What is known about a value of type ``str``.

    ``containment`` is set when the string is known to *denote* a path at some location (e.g. a
    ``certora_within`` guard); it does not make the value a path.
    """
    regex: PseudoRegex = ANY_STR
    containment: LocationFact | None = None
    atoms: frozenset[AtomicFact] = frozenset()

    def __contains__(self, atom: AtomicFact) -> bool:
        return _holds(atom, self.atoms, self.regex)

@dataclass(frozen=True)
class PathFact:
    """What is known about a value of type ``pathlib.Path``.

    Atoms are read through ``str(p)``: ``no-slash`` means a single relative component,
    ``not-absolute`` means ``not p.is_absolute()``, ``no-parent-traversal`` means no ``..`` part.
    """
    containment: LocationFact | None = None
    atoms: frozenset[AtomicFact] = frozenset()

    def __contains__(self, atom: AtomicFact) -> bool:
        return _holds(atom, self.atoms, ANY_STR)

type ValidationFact = StrFact | PathFact


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


def as_component(fact: ValidationFact) -> Component | None:
    """Lift a validated value to a single path component, if its atoms allow it.

    This is the only place the string domain's atoms are consumed on behalf of the location
    domain: a value is a component iff it has no "/" and no ".." (``_holds`` supplies the
    derived forms of both). The regex, if any, then decides how precise the component is.
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

def combine_containment(
    cont: LocationFact,
    child: str | ValidationFact | None
) -> LocationFact | None:
    if child is None:
        return None
    
    if isinstance(child, str):
        as_path = _safe_path_extension(child)
        if as_path is None:
            return None
        return cont.extend_static(as_path)

    elif child.containment is not None:
        return cont.merge_other(child.containment)
    elif (component := as_component(child)) is not None:
        return cont.extend_single(component)
    elif "no-parent-traversal" in child and "not-absolute" in child:
        return cont.to_splat(ANY_NAME)
    else:
        return None

def interp_to_str(fact: ValidationFact | str | None) -> StrFact:
    if fact is None:
        return StrFact()
    elif isinstance(fact, str):
        return StrFact(Exact(fact))
    cont = fact
    if not isinstance(cont, StrFact):
        return StrFact(
            regex=location_to_regex(cont.containment) if cont.containment is not None else ANY_STR,
            containment=cont.containment,
            atoms=cont.atoms
        )
    else:
        return cont

def combine_str(
    cont: str | ValidationFact | None,
    other: str | ValidationFact | None
) -> StrFact:
    cont = interp_to_str(cont)
    
    if other is None:
        return StrFact(regex = concat(cont.regex, ANY_STR), containment=None, atoms=frozenset())
    if isinstance(other, str):
        return combine_str(
            cont,
            StrFact(regex=Exact(other), containment=None, atoms=frozenset())
        )
    to_add : set[AtomicFact] = set({})
    for f in ("no-slash",):
        if f in cont and f in other:
            to_add.add(f)
    contain = OptionMonad.lift(cont.containment).bind(
        lambda c: combine_containment(c, other)
    ).unwrap()
    
    if isinstance(other, StrFact):
        other_reg = other.regex
    else:
        other_reg = location_to_regex(other.containment) if other.containment is not None else ANY_STR
    return StrFact(
        regex=concat(cont.regex, other_reg),
        containment=contain,
        atoms=frozenset(to_add)
    )

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

def interpret_expr(e: ast.expr, st: dict[str, ValidationFact]) -> ValidationFact | None:
    interp = OperandInterpreter(st)
    if isinstance(e, ast.Name):
        return st.get(e.id, None)

    wrapper : CurriedMonad[ast.expr, ValidationFact] = CurriedMonad(lambda exp_m: exp_m.bind(lambda exp: interpret_expr(exp, st)))

    if isinstance(e, ast.Call):
        node = e
        call = resolve_callee(node.func)
        if call is None:
            raise InvalidProgram(node.func, "invalid call")
        if call.matches("pathlib", "Path") and len(e.args) > 0:
            accum = interp.interp(e.args[0],
                on_fact=bind(lambda proj: proj.containment),
                on_str=lambda nm: (
                    nm.bind(_safe_path_extension).map(lambda feats: tuple(Named(i) for i in feats)).map(StaticPath)
                ),
                on_expr=wrapper.bind_curried(lambda fact: fact.containment)
            )
            if accum is None:
                return None
            for i in e.args[1:]:
                d = interp.interp(
                    i,
                    on_str=map_(type_cast(str | ValidationFact)),
                    on_fact=map_(type_cast(str | ValidationFact)),
                    on_expr=wrapper.bind_curried(type_cast(str | ValidationFact))
                )
                if d is None:
                    return None
                accum = combine_containment(accum, d)
                if accum is None:
                    return None
            return PathFact(containment=accum)
    elif isinstance(e, ast.BinOp) and isinstance(e.op, ast.Div):
        return interp.interp_bind(
            e.left,
            on_str=_default.BindNone(),
            on_fact=lambda nm: nm,
            on_expr=wrapper
        ).bind(take_if(
            lambda d: isinstance(d, PathFact)
        )).bind(lambda fact: fact.containment).bind(lambda fact: \
            combine_containment(
                cast(LocationFact, fact),
                interp.interp(
                    e.right,
                    on_str=map_(type_cast(str | ValidationFact)),
                    on_fact=map_(type_cast(str | ValidationFact)),
                    on_expr=wrapper.bind_curried(type_cast(str | ValidationFact))
                )
            )
        ).map(lambda loc: PathFact(containment=loc)).unwrap()
    elif isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
        return interp.interp_bind(
            e.left,
            on_fact=lambda nm: nm,
            on_str=map_(lambda s: StrFact(Exact(s))),
            on_expr=wrapper
        ).downcast(StrFact).bind(lambda l_as_str: \
            interp.interp_bind(
                e.right,
                on_str=map_(type_cast(str | ValidationFact)),
                on_fact=map_(type_cast(str | ValidationFact)),
                on_expr=wrapper.bind_curried(type_cast(str | ValidationFact))
            ).map(lambda r_as_str: \
                combine_str(l_as_str, r_as_str)
            )
        ).unwrap()

    elif isinstance(e, ast.Constant) and (as_str := as_const_or_null(str, e)) is not None:
        return StrFact(regex=Exact(as_str))
    elif isinstance(e, ast.JoinedStr):
        if len(e.values) == 0:
            return StrFact(regex=Exact(""))

        atoms = list(interp.interp(
            v,
            on_str=lambda nm: nm.map(type_cast(str | ValidationFact)),
            on_fact=lambda nm: nm.map(type_cast(str | ValidationFact)),
            on_expr=wrapper.bind_curried(type_cast(str | ValidationFact))
        ) for v in e.values)

        combined = functools.reduce(combine_str, atoms[1:], interp_to_str(atoms[0]))
        return combined

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
