"""The location micro-syntax -- ``repos/**``, ``repos/*/foundry.toml``,
``/repos/*/*/issues/<\\d+>/comments``, ``{a,b}/x`` -- as a stdlib-only grammar plus a matcher
over concrete paths.

One language, read in three places: the policy loader (``locations.parse_location`` turns a
``Spec`` into the analysis' ``LocationFact``), the analysis' ``certora.pathmatch`` guard (the
same conversion), and the confined program's runtime ``certora.pathmatch`` (``matches`` below).
This module imports nothing of the analysis so the runtime namespace stays light.

    .            the root itself            **           the root and everything below
    a/b          exactly that path          a/**         a and everything below it
    a/*/c        one arbitrary component    a/**/*       anything strictly below a (not a itself)
    a/{x,y}/c    one of the names           a/**/<re>    an entry anywhere below a whose name
    a/<re>/c     a name fullmatching re                  fullmatches re
                                            /a/b         anchored at the filesystem root

A component is a *safe name*: not empty, not ``.`` or ``..``, no ``/``. ``**`` appears at most
once, last or followed by one leaf. Regexes are raw and may contain ``/``.
"""
import pathlib
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Lit:
    name: str


@dataclass(frozen=True)
class Wild:
    """``*``: any one safe name."""


@dataclass(frozen=True)
class OneOf:
    names: frozenset[str]


@dataclass(frozen=True)
class Regex:
    pattern: str


type Component = Lit | Wild | OneOf | Regex


@dataclass(frozen=True)
class Spec:
    """``components`` is the whole path (``splat`` False) or the static prefix of an at-or-below
    location (``splat`` True), whose last component, if constrained, is ``leaf``."""

    components: tuple[Component, ...]
    absolute: bool = False
    splat: bool = False
    leaf: Component | None = None


def is_safe_name(s: str) -> bool:
    return s not in ("", ".", "..") and "/" not in s


def split_components(text: str) -> list[str]:
    """Split on "/", except inside a ``<...>`` component, whose regex may contain "/": the
    component runs to the ">" that precedes a "/" or the end of the string."""
    out: list[str] = []
    start = 0
    in_regex = False
    for i, c in enumerate(text):
        if in_regex:
            if c == ">" and (i + 1 == len(text) or text[i + 1] == "/"):
                in_regex = False
        elif c == "<" and i == start:
            in_regex = True
        elif c == "/":
            out.append(text[start:i])
            start = i + 1
    out.append(text[start:])
    return out


def parse_component(piece: str) -> Component:
    if piece == "*":
        return Wild()
    if piece.startswith("<"):
        if not piece.endswith(">") or len(piece) < 3:
            raise ValueError(f"malformed regex component {piece!r}")
        regex = piece[1:-1]
        try:
            re.compile(regex)
        except re.error as e:
            raise ValueError(f"bad regex in {piece!r}: {e}")
        return Regex(regex)
    if piece.startswith("{"):
        if not piece.endswith("}") or len(piece) < 3:
            raise ValueError(f"malformed choice component {piece!r}")
        names = [n.strip() for n in piece[1:-1].split(",")]
        if not names or not all(is_safe_name(n) for n in names):
            raise ValueError(f"choice components must be plain names: {piece!r}")
        return OneOf(frozenset(names))
    if not is_safe_name(piece):
        raise ValueError(f"not a path component: {piece!r}")
    return Lit(piece)


def parse(text: str) -> Spec:
    """The ``Spec`` a compact spelling names; ``ValueError`` for a malformed one. A leading "/"
    anchors the location at the filesystem root instead of the sandbox root."""
    if text in (".", ""):
        return Spec(())
    absolute = text.startswith("/")
    if absolute:
        text = text[1:]
        if not text:
            return Spec((), absolute=True)  # "/": the filesystem root itself
    pieces = split_components(text)
    if "" in pieces:
        raise ValueError(f"empty path component in {text!r}")
    splat_at = [i for i, p in enumerate(pieces) if p == "**"]
    if not splat_at:
        return Spec(tuple(parse_component(p) for p in pieces), absolute)
    if len(splat_at) > 1 or splat_at[0] < len(pieces) - 2:
        raise ValueError(
            f"'**' may appear once, as the last component or followed by one leaf: {text!r}"
        )
    at = splat_at[0]
    prefix = tuple(parse_component(p) for p in pieces[:at])
    leaf = None if at == len(pieces) - 1 else parse_component(pieces[at + 1])
    return Spec(prefix, absolute, splat=True, leaf=leaf)


def component_matches(c: Component, name: str) -> bool:
    if not is_safe_name(name):
        return False
    match c:
        case Lit(name=n):
            return name == n
        case Wild():
            return True
        case OneOf(names=names):
            return name in names
        case Regex(pattern=pattern):
            return re.fullmatch(pattern, name) is not None


def matches(spec: Spec, text: str) -> bool:
    """Is the concrete path *text* at the location *spec* names? Mirrors the analysis'
    ``location_le`` of a literal path against the location: anchors must agree, a ``..`` anywhere
    is within nothing, and a constrained leaf names the last component at any depth below the
    prefix (the prefix itself is denoted only by an unconstrained ``**``)."""
    if text.startswith("/") != spec.absolute:
        return False
    parts = [p for p in pathlib.PurePosixPath(text).parts if p != "/"]
    if any(p == ".." for p in parts):
        return False
    if not spec.splat:
        return len(parts) == len(spec.components) and all(
            component_matches(c, n) for c, n in zip(spec.components, parts)
        )
    prefix = spec.components
    if len(parts) < len(prefix) or not all(
        component_matches(c, n) for c, n in zip(prefix, parts)
    ):
        return False
    if len(parts) == len(prefix):
        return spec.leaf is None
    return spec.leaf is None or component_matches(spec.leaf, parts[-1])
