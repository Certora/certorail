"""The location micro-syntax as the analysis' ``LocationFact``: ``locspec`` parses the spelling,
this converts. Used by the policy loader and by the ``certora.pathmatch`` guard, so a location a
program guards for is, component for component, the location a policy grants. And a location as
JSON (``encode_location``), for the documents handed to another process: a view daemon's
specification, the floor guard's."""
import pathlib
from typing import Any

from certorail import locspec
from certorail.analysis import (
    ANY_NAME, AnyName, Component, DirSplat, LocationFact, Matching, Named, OneOf, RegexLit, StaticPath,
)


def _component(c: locspec.Component) -> Component:
    match c:
        case locspec.Lit(name=name):
            return Named(name)
        case locspec.Wild():
            return ANY_NAME
        case locspec.OneOf(names=names):
            return OneOf(names)
        case locspec.Regex(pattern=pattern):
            return Matching(RegexLit(pattern))


def to_location(spec: locspec.Spec) -> LocationFact:
    components = tuple(_component(c) for c in spec.components)
    if not spec.splat:
        return StaticPath(components, spec.absolute)
    # ``a/**`` (no leaf): a and everything below; ``a/**/*`` (a wildcard leaf): strictly below
    leaf = None if spec.leaf is None else _component(spec.leaf)
    return DirSplat(components, leaf, spec.absolute)


def parse_location(text: str) -> LocationFact:
    """The location a compact spelling names; raises ``ValueError`` for a malformed one. A
    leading "/" anchors the location at the filesystem root instead of the sandbox root."""
    return to_location(locspec.parse(text))


def _encode_component(c: Component) -> Any:
    match c:
        case Named(name=n):
            return n
        case AnyName():
            return {"any": True}
        case OneOf(names=ns):
            return {"one_of": sorted(ns)}
        case Matching(regex=RegexLit(reg=r)):
            return {"regex": r}
        case Matching():
            raise ValueError("a policy location's regex is a single pattern")  # never from a document


def _decode_component(v: Any) -> Component:
    if isinstance(v, str):
        return Named(v)
    if "any" in v:
        return AnyName()
    if "one_of" in v:
        return OneOf(frozenset(v["one_of"]))
    return Matching(RegexLit(v["regex"]))


def encode_location(loc: LocationFact) -> dict[str, Any]:
    match loc:
        case StaticPath(path_components=cs, absolute=ab):
            return {"path": [_encode_component(c) for c in cs], "absolute": ab}
        case DirSplat(static_prefix=ps, final_component=leaf, absolute=ab):
            return {
                "prefix": [_encode_component(c) for c in ps],
                "leaf": None if leaf is None else _encode_component(leaf),
                "absolute": ab,
            }


def decode_location(d: dict[str, Any]) -> LocationFact:
    if "path" in d:
        return StaticPath(tuple(_decode_component(c) for c in d["path"]), d["absolute"])
    leaf = d["leaf"]
    return DirSplat(
        tuple(_decode_component(c) for c in d["prefix"]),
        None if leaf is None else _decode_component(leaf),
        d["absolute"],
    )


def enumerable_prefixes(loc: LocationFact) -> list[tuple[str, ...]]:
    """The literal prefixes a location's leading run of names and ``{a,b}`` sets spells,
    exploded: ``/{usr,opt}/data/<x.*>`` is ``/usr/data`` and ``/opt/data``. Every prefix has the
    same length; ``[()]`` when the first component is already a pattern."""
    parts = loc.path_components if isinstance(loc, StaticPath) else loc.static_prefix
    prefixes: list[tuple[str, ...]] = [()]
    for c in parts:
        match c:
            case Named(name=n):
                prefixes = [p + (n,) for p in prefixes]
            case OneOf(names=ns):
                prefixes = [p + (n,) for p in prefixes for n in sorted(ns)]
            case _:
                break
    return prefixes


def absolute_prefix_problem(loc: LocationFact) -> str | None:
    """Why an absolute filesystem location cannot be granted or protected: it must begin with a
    literal name or a ``{a,b}`` set, so the jail can bind (or confine) exactly the prefixes it
    spells. None for a relative location, or an absolute one that does."""
    if not loc.absolute or enumerable_prefixes(loc)[0]:
        return None
    return (
        "an absolute location must begin with a literal name or a {a,b} set, so the jail can "
        "express it: '/', '/**', '/*/x' and '/<regex>/x' cannot be granted or protected"
    )


def bindable_paths(loc: LocationFact, root: pathlib.Path) -> tuple[pathlib.Path, ...] | None:
    """The concrete paths *loc* is exactly the union of -- literal paths, or the tops of literal
    subtrees, each ``{a,b}`` set exploded (``/srv/{a,b}/**`` is ``/srv/a`` and ``/srv/b``) -- under
    *root*, or at the filesystem root for an absolute location; None when a pattern remains (a
    ``*``, a ``<regex>``, a ``**/leaf`` tail), which no set of bind mounts says exactly."""
    match loc:
        case StaticPath(path_components=parts) | DirSplat(static_prefix=parts, final_component=None):
            pass
        case _:
            return None
    if not all(isinstance(c, (Named, OneOf)) for c in parts):
        return None
    base = pathlib.Path("/") if loc.absolute else root
    return tuple(base.joinpath(*p) for p in enumerable_prefixes(loc))


def single_path(loc: LocationFact, root: pathlib.Path) -> pathlib.Path | None:
    """The one concrete path *loc* denotes -- a literal path, or the top of a literal subtree
    (``a/b/**``) -- under *root*, or at the filesystem root for an absolute location; None when
    *loc* is a pattern (a ``*``, a ``<regex>``, a ``**/leaf`` tail) and denotes no one path. What a
    bind mount can say of a location is exactly this."""
    match loc:
        case StaticPath(path_components=parts):
            pass
        case DirSplat(static_prefix=parts, final_component=None):
            pass
        case _:
            return None
    if not all(isinstance(c, Named) for c in parts):
        return None
    names = [c.name for c in parts if isinstance(c, Named)]
    return pathlib.Path("/", *names) if loc.absolute else root.joinpath(*names)
