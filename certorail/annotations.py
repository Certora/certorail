"""``typing.Annotated`` hints -> dataflow facts.

A parameter annotation is the *rely* of a function: :func:`parse_function` turns it into the fact
the body analysis may assume about that parameter, and which every caller has to discharge. The
return annotation is the *guarantee*: the fact every ``return`` has to establish, and which callers
may assume about the call. Neither direction is checked here; this module only reads annotations.

Only the source of the annotation is consulted (never the runtime marker objects), so every marker
argument has to be a constant or a nested marker. Malformed markers raise
:class:`InvalidAnnotation`: an annotation is a specification, and silently dropping a misspelt
one would weaken a rely without anyone noticing.

The marker vocabulary lives in ``markers.py`` and is reached as ``certora.<name>``; the base type
is ``str`` or one of the ``pathlib`` path classes. Anything else -- containers included -- carries
no fact and may not carry markers.
"""
import ast
import inspect
from collections.abc import Sequence
from dataclasses import dataclass

from .analysis import (
    ANY_NAME,
    ANY_STR,
    AtomicFact,
    Component,
    DirSplat,
    Exact,
    InvalidProgram,
    Located,
    LocationFact,
    Matching,
    Named,
    OneOf,
    PathFact,
    PseudoRegex,
    RegexLit,
    StaticPath,
    StrFact,
    ValidationFact,
    _literal_location,
    _safe_path_extension,
    alternation,
    concat,
    is_safe_name,
)
from .markers import NAMESPACE
from .terms import Call, Dotted, Items, Subscript, Term, Var, lower


class InvalidAnnotation(InvalidProgram):
    """An annotation that uses the marker vocabulary incorrectly."""


def _err(t: Term, msg: str) -> InvalidAnnotation:
    return InvalidAnnotation(t.node, msg)


# ---------------------------------------------------------------------------
# facts for parameters and returns
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Contract:
    """What a function relies on (per parameter) and guarantees (return)."""

    params: dict[str, ValidationFact]
    returns: ValidationFact | None

    @property
    def has_rely_markers(self) -> bool:
        """Does any parameter say more than a plain type? Such a rely is discharged at direct call
        sites only, so the function's name may not travel (see ``safepy.ValidationAnalysis``)."""
        return any(not is_plain_type(f) for f in self.params.values())

    @property
    def has_markers(self) -> bool:
        """Does any part of the contract say more than a plain type?"""
        return self.has_rely_markers or not is_plain_type(self.returns)


def is_plain_type(fact: ValidationFact | None) -> bool:
    """A bare type annotation (``str``, ``pathlib.Path``) carrying no marker. These are enforced by
    the runtime guard injected at function entry, not discharged statically; only marker-bearing
    relies and guarantees are the analysis' to check."""
    match fact:
        case None:
            return True
        case StrFact() | PathFact():
            return fact == StrFact() or fact == PathFact()
        case Located():
            return False


# ---------------------------------------------------------------------------
# markers
# ---------------------------------------------------------------------------

# ``certora.<attr>`` atoms; must agree with the constants in ``markers.py``.
_ATOMS: dict[str, AtomicFact] = {
    "no_slash": "no-slash",
    "no_parent_traversal": "no-parent-traversal",
    "not_absolute": "not-absolute",
    "not_dot_dot": "not-dot-dot",
}
_REGEX_MARKERS = ("matches", "one_of", "seq")
_LOCATION_MARKERS = ("within", "exactly")

type Args = tuple[Term, ...]
type Kwargs = tuple[tuple[str, Term], ...]


def _marker_call(t: Term) -> tuple[str, Args, Kwargs] | None:
    """``certora.<name>(...)`` -> ``(name, args, kwargs)``."""
    match t:
        case Call((ns, name), args, kwargs) if ns == NAMESPACE:
            return name, args, kwargs
        case _:
            return None


def _bind(
    t: Term, args: Args, kwargs: Kwargs, params: Sequence[str], required: int, what: str
) -> list[Term | None]:
    """Bind a marker's arguments to *params* (the first *required* being mandatory)."""
    if len(args) > len(params):
        raise _err(t, f"{what}: too many arguments")
    bound: list[Term | None] = list(args) + [None] * (len(params) - len(args))
    for name, value in kwargs:
        if name not in params:
            raise _err(value, f"{what}: unknown argument {name!r}")
        i = params.index(name)
        if bound[i] is not None:
            raise _err(value, f"{what}: {name!r} given twice")
        bound[i] = value
    if any(b is None for b in bound[:required]):
        raise _err(t, f"{what}: missing argument")
    return bound


def _str_args(t: Term, args: Args, kwargs: Kwargs, what: str) -> list[str]:
    """The positional string-literal arguments of a variadic marker."""
    if kwargs:
        raise _err(t, f"{what} takes no keyword arguments")
    if not args:
        raise _err(t, f"{what} needs at least one argument")
    out: list[str] = []
    for a in args:
        s = a.as_str()
        if s is None:
            raise _err(a, f"{what} arguments must be string literals")
        out.append(s)
    return out


# --- regex markers: what a string looks like ---------------------------------


def _regex_of(t: Term, name: str, args: Args, kwargs: Kwargs) -> PseudoRegex:
    match name:
        case "matches":
            (regex,) = _bind(t, args, kwargs, ("regex",), 1, "matches")
            assert regex is not None
            r = regex.as_str()
            if r is None:
                raise _err(regex, "matches() takes a string literal")
            return RegexLit(r)
        case "one_of":
            return alternation(*(Exact(s) for s in _str_args(t, args, kwargs, "one_of")))
        case "seq":
            if kwargs:
                raise _err(t, "seq takes no keyword arguments")
            if not args:
                raise _err(t, "seq needs at least one piece")
            return concat(*(_fragment_regex(a) for a in args))
        case _:
            raise _err(t, f"unknown marker certora.{name}")


def _fragment_regex(t: Term) -> PseudoRegex:
    """A literal or a regex marker, as a description of a string."""
    if (s := t.as_str()) is not None:
        return Exact(s)
    m = _marker_call(t)
    if m is None or m[0] not in _REGEX_MARKERS:
        raise _err(t, "expected a string literal or one of certora.matches/one_of/seq")
    return _regex_of(t, *m)


# --- location markers: where a path is ---------------------------------------


def _components_of(t: Term) -> tuple[Component, ...]:
    """A fragment in component position. A literal may name several components
    (``"data/uploads"``); a marker names exactly one."""
    if (s := t.as_str()) is not None:
        parts = _safe_path_extension(s)
        if parts is None:
            raise _err(t, "path fragments must be relative, non-empty and free of '..'")
        return tuple(Named(p) for p in parts)
    m = _marker_call(t)
    if m is None or m[0] not in _REGEX_MARKERS:
        raise _err(t, "expected a path literal or one of certora.matches/one_of/seq")
    name, args, kwargs = m
    if name == "one_of":
        names = _str_args(t, args, kwargs, "one_of")
        if not all(is_safe_name(n) for n in names):
            raise _err(t, "one_of() in a path names single components")
        return (OneOf(frozenset(names)),)
    return (Matching(_regex_of(t, name, args, kwargs)),)


def _single_component(t: Term, what: str) -> Component:
    comps = _components_of(t)
    if len(comps) != 1:
        raise _err(t, f"{what} must be a single component")
    return comps[0]


def _location_of(t: Term, name: str, args: Args, kwargs: Kwargs) -> LocationFact:
    match name:
        case "exactly":
            if kwargs:
                raise _err(t, "exactly takes no keyword arguments")
            if not args:
                raise _err(t, "exactly needs at least one component")
            return StaticPath(tuple(c for a in args for c in _components_of(a)))
        case "within":
            prefix_t, leaf_t = _bind(t, args, kwargs, ("prefix", "leaf"), 1, "within")
            assert prefix_t is not None
            absolute = False
            prefix_str = prefix_t.as_str()
            # "." is the sandbox root: an empty prefix; a leading "/" the filesystem root
            if prefix_str in (".", ""):
                prefix: tuple[Component, ...] = ()
            elif prefix_str is not None and prefix_str.startswith("/"):
                base = _literal_location(prefix_str)
                if base is None:
                    raise _err(t, f"absolute path {prefix_str!r} must be free of '..'")
                prefix = base.path_components
                absolute = True
            else:
                prefix = _components_of(prefix_t)
            leaf = ANY_NAME if leaf_t is None else _single_component(leaf_t, "within(leaf=)")
            return DirSplat(prefix, leaf, absolute)
        case _:
            raise _err(t, f"unknown marker certora.{name}")


# ---------------------------------------------------------------------------
# annotations
# ---------------------------------------------------------------------------


def _scalar_fact(t: Term) -> ValidationFact | None:
    match t:
        case Var("str"):
            return StrFact()
        case Dotted(("pathlib", "Path" | "PurePath" | "PosixPath" | "PurePosixPath")):
            return PathFact()
        case _:
            return None


def _annotated(base: Term, metadata: Sequence[Term]) -> ValidationFact:
    fact = _parse(base)
    if not isinstance(fact, (StrFact, PathFact)):
        raise _err(base, "markers apply to str and pathlib paths only")

    atoms: set[AtomicFact] = set()
    checks: set[str] = set()
    regex: PseudoRegex | None = None
    containment: LocationFact | None = None
    located_by: Term | None = None
    for m in metadata:
        match m:
            case Dotted((ns, atom_name)) if ns == NAMESPACE:
                if atom_name not in _ATOMS:
                    raise _err(m, f"unknown marker certora.{atom_name}")
                atoms.add(_ATOMS[atom_name])
                continue
            case _:
                ...
        call = _marker_call(m)
        if call is None:
            raise _err(m, f"expected a certora marker, got {type(m).__name__}")
        name, args, kwargs = call
        if name == "validated":
            # policy validations the value has passed; combines with location AND text markers
            checks.update(_str_args(m, args, kwargs, "validated"))
        elif name in _LOCATION_MARKERS:
            if containment is not None:
                raise _err(m, "at most one of within()/exactly()")
            containment = _location_of(m, name, args, kwargs)
            located_by = m
        elif name in _REGEX_MARKERS:
            if isinstance(fact, PathFact):
                raise _err(
                    m, "a path has no regex; constrain its leaf with within(..., leaf=) or exactly()"
                )
            if regex is not None:
                raise _err(m, "at most one of matches()/one_of()/seq()")
            regex = _regex_of(m, name, args, kwargs)
        else:
            raise _err(m, f"unknown marker certora.{name}")

    if containment is not None and located_by is not None:
        # a located value is read as a path, not as text: text facts do not combine with it
        if regex is not None or atoms:
            raise _err(
                located_by,
                "within()/exactly() do not combine with text markers; constrain the leaf with "
                "within(..., leaf=...) or exactly(..., <component>) instead",
            )
        return Located(containment, "str" if isinstance(fact, StrFact) else "path", frozenset(checks))
    if isinstance(fact, StrFact):
        return StrFact(regex=ANY_STR if regex is None else regex, atoms=frozenset(atoms), checks=frozenset(checks))
    return PathFact(atoms=frozenset(atoms), checks=frozenset(checks))


def _parse(t: Term) -> ValidationFact | None:
    match t:
        case Subscript(Dotted(("typing", "Annotated")), Items((base, *metadata))) if metadata:
            return _annotated(base, metadata)
        case Subscript(Dotted(("typing", "Annotated")), _):
            raise _err(t, "Annotated[type, marker, ...] needs at least one marker")
        case _:
            fact = _scalar_fact(t)
            if fact is None and _mentions_annotated(t.node):
                raise _err(t, "Annotated inside a container is not tracked; put the markers where the elements are used")
            return fact


def _mentions_annotated(e: ast.AST) -> bool:
    return any(isinstance(n, ast.Attribute) and n.attr == "Annotated" for n in ast.walk(e))


def parse_annotation(e: ast.expr) -> ValidationFact | None:
    """The fact an annotation expresses, or ``None`` if it says nothing the analysis tracks.
    Containers say nothing, so ``Annotated`` inside one is refused rather than silently dropped."""
    return _parse(lower(e))


# ---------------------------------------------------------------------------
# binding a call to a definition
# ---------------------------------------------------------------------------

# stands in for a default's value: binding only needs to know that one exists
_HAS_DEFAULT = object()

type BoundArgument = ast.expr | tuple[ast.expr, ...] | dict[str, ast.expr]


def signature_of(node: ast.FunctionDef) -> inspect.Signature:
    """The definition's signature, with argument *expressions* in place of values."""
    P = inspect.Parameter
    a = node.args
    positional = [*a.posonlyargs, *a.args]
    first_default = len(positional) - len(a.defaults)
    params: list[inspect.Parameter] = []
    for i, arg in enumerate(positional):
        kind = P.POSITIONAL_ONLY if i < len(a.posonlyargs) else P.POSITIONAL_OR_KEYWORD
        params.append(P(arg.arg, kind, default=_HAS_DEFAULT if i >= first_default else P.empty))
    if a.vararg is not None:
        params.append(P(a.vararg.arg, P.VAR_POSITIONAL))
    for arg, default in zip(a.kwonlyargs, a.kw_defaults):
        params.append(P(arg.arg, P.KEYWORD_ONLY, default=_HAS_DEFAULT if default is not None else P.empty))
    if a.kwarg is not None:
        params.append(P(a.kwarg.arg, P.VAR_KEYWORD))
    return inspect.Signature(params)


def bind_arguments(call: ast.Call, node: ast.FunctionDef) -> dict[str, BoundArgument] | None:
    """The call's argument expressions by parameter name, or None if the call cannot be bound
    statically (a splat, too many positionals, an unknown or duplicated keyword, a missing
    required parameter). A var-positional parameter receives a tuple, a var-keyword one a dict;
    parameters left to their defaults are absent."""
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(k.arg is None for k in call.keywords):
        return None
    try:
        bound = signature_of(node).bind(*call.args, **{k.arg: k.value for k in call.keywords if k.arg is not None})
    except TypeError:
        return None
    return dict(bound.arguments)


def default_of(node: ast.FunctionDef, param: str) -> ast.expr | None:
    """The default expression of *param*, if it has one."""
    a = node.args
    positional = [*a.posonlyargs, *a.args]
    first_default = len(positional) - len(a.defaults)
    for i, arg in enumerate(positional):
        if arg.arg == param:
            return a.defaults[i - first_default] if i >= first_default else None
    for arg, default in zip(a.kwonlyargs, a.kw_defaults):
        if arg.arg == param:
            return default
    return None


def parse_function(node: ast.FunctionDef) -> Contract:
    """The rely (per annotated parameter) and guarantee (return) of a function.

    Parameters whose annotation says nothing (or have none) are absent from ``params``. ``*args``
    and ``**kwargs`` carry no fact -- the analysis does not track containers -- so a marker on
    either is refused rather than silently dropped.
    """
    params: dict[str, ValidationFact] = {}
    a = node.args
    for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs]:
        if arg.annotation is None:
            continue
        fact = parse_annotation(arg.annotation)
        if fact is not None:
            params[arg.arg] = fact
    for variadic in (a.vararg, a.kwarg):
        if variadic is not None and variadic.annotation is not None:
            if not is_plain_type(parse_annotation(variadic.annotation)):
                raise InvalidAnnotation(
                    variadic.annotation,
                    f"markers on *{variadic.arg} are not checked; use explicit parameters",
                )
    returns = parse_annotation(node.returns) if node.returns is not None else None
    return Contract(params, returns)
