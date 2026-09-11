"""The location micro-syntax as the analysis' ``LocationFact``: ``locspec`` parses the spelling,
this converts. Used by the policy loader and by the ``certora.pathmatch`` guard, so a location a
program guards for is, component for component, the location a policy grants."""
from . import locspec
from .analysis import ANY_NAME, Component, DirSplat, LocationFact, Matching, Named, OneOf, RegexLit, StaticPath


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
