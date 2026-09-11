"""Footprints: where a filesystem region lives, and whether a file write can touch it (EFFECTS.md,
"File writes: derived").

A region's ``footprint`` is spelled relative to the cwd of a validation that establishes an atom
reading it (``.git/config``), or absolute. Its **instantiation** joins the validation's cwd
location onto it -- ``repos/**`` and ``.git/config`` give ``repos/**/.git/config`` -- and denotes
that path and every descendant. The location grammar allows one ``**`` and only as the last
component or before one leaf, so an instantiation is not a ``LocationFact``: it is its own
sequence of components and splats, and the write-location test is intersection non-emptiness of
two such sequences -- does some concrete path lie in both what the write may name and what the
footprint (with its implicit trailing descendants) may name? Both sides have finitely many
splats, each standing for any run of components, so the test is a small alignment.

Component equality folds case and normalises Unicode -- NFC, casefold, then git's ``protectHFS``
rule of dropping ignorable code points -- unconditionally: whether two spellings name one file is
a property of the mount, and an APFS directory bind-mounted into a Linux container keeps its
insensitivity. A regex or wildcard component may equal any name, conservatively; only two
concrete names that fold differently are known apart.
"""
import unicodedata
from dataclasses import dataclass
from functools import cache
from typing import Final

from .analysis import (
    AnyName,
    Component,
    DirSplat,
    LocationFact,
    Matching,
    Named,
    OneOf,
    StaticPath,
    _normalize_component,
)


class _Splat:
    """Any run of zero or more components."""

    def __repr__(self) -> str:
        return "**"


SPLAT: Final = _Splat()
type Item = Component | _Splat


@dataclass(frozen=True)
class Footprint:
    """An instantiated footprint: components and splats, anchored at the sandbox root or the
    filesystem root, denoting the paths the sequence spells *and every descendant*."""

    items: tuple[Item, ...]
    absolute: bool = False


# a footprint no cwd anchors: it may lie anywhere, at either anchor
ANYWHERE: Final = (Footprint((SPLAT,), absolute=False), Footprint((SPLAT,), absolute=True))


# git's protectHFS: the code points HFS+ ignores when comparing names, which a name may
# therefore smuggle without changing what it denotes
_IGNORABLE = frozenset(
    [0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
     0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F, 0xFEFF]
)


def fold(name: str) -> str:
    """The spelling under which two names denoting one file compare equal."""
    return "".join(ch for ch in unicodedata.normalize("NFC", name).casefold() if ord(ch) not in _IGNORABLE)


def items_of(loc: LocationFact) -> tuple[Item, ...]:
    """A location as a component sequence: ``a/**`` is ``a`` then a splat (the prefix itself and
    everything below), ``a/**/leaf`` is ``a``, a splat, ``leaf`` -- ``a/**/*`` included, whose
    unconstrained leaf still demands one component below ``a``."""
    match loc:
        case StaticPath(path_components=cs):
            return tuple(cs)
        case DirSplat(static_prefix=ps, final_component=leaf):
            return (*ps, SPLAT) if leaf is None else (*ps, SPLAT, leaf)


def instantiate(base: LocationFact | None, footprint: LocationFact) -> Footprint:
    """The footprint given its base: the cwd of the establishing validation for a relative
    footprint, nothing for an absolute one (which takes no base). *base* None with a relative
    footprint is the unanchored case; callers use ``ANYWHERE`` instead."""
    if footprint.absolute or base is None:
        return Footprint(items_of(footprint), footprint.absolute)
    return Footprint(items_of(base) + items_of(footprint), base.absolute)


def overlaps(write: LocationFact, footprint: Footprint) -> bool:
    """Can a path the write may name lie at or below a path the footprint may name? Anchors
    never relate, as everywhere in the location domain."""
    if write.absolute != footprint.absolute:
        return False
    return _intersects(items_of(write), footprint.items + (SPLAT,))


def _intersects(a: tuple[Item, ...], b: tuple[Item, ...]) -> bool:
    """Is some concrete component sequence in both languages? A splat consumes any run of the
    other side's items (a component denotes at least one name, so consuming it is always
    possible); two components must be able to name the same thing."""

    @cache
    def at(i: int, j: int) -> bool:
        if i == len(a) and j == len(b):
            return True
        if i < len(a) and a[i] is SPLAT:
            if at(i + 1, j) or (j < len(b) and at(i, j + 1)):
                return True
        if j < len(b) and b[j] is SPLAT:
            if at(i, j + 1) or (i < len(a) and at(i + 1, j)):
                return True
        if i < len(a) and j < len(b) and a[i] is not SPLAT and b[j] is not SPLAT:
            return compatible(a[i], b[j]) and at(i + 1, j + 1)
        return False

    return at(0, 0)


def compatible(c: Item, d: Item) -> bool:
    """May the two components name the same entry? Two concrete names are compared folded; a
    regex or a wildcard may name anything, conservatively -- a regex that happens to exclude the
    folded spellings of a name cannot be recognised without enumerating them."""
    assert not isinstance(c, _Splat) and not isinstance(d, _Splat)
    c, d = _normalize_component(c), _normalize_component(d)
    match c, d:
        case (AnyName(), _) | (_, AnyName()) | (Matching(), _) | (_, Matching()):
            return True
        case Named(name=n), Named(name=m):
            return fold(n) == fold(m)
        case (Named(name=n), OneOf(names=ms)) | (OneOf(names=ms), Named(name=n)):
            return fold(n) in {fold(m) for m in ms}
        case OneOf(names=ns), OneOf(names=ms):
            return bool({fold(n) for n in ns} & {fold(m) for m in ms})
        case _:
            return True  # unreachable by the component grammar; conservative if it were not
