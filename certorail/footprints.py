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

Component equality folds case and normalises Unicode -- NFC, then casefold -- unconditionally:
whether two spellings name one file is a property of the mount (APFS is case- and
normalisation-insensitive by default), and an APFS directory bind-mounted into a Linux container
keeps its insensitivity. HFS+'s further rule of ignoring format code points (git's
``protectHFS``) is not applied: no sandbox root lives on HFS+ any more, and keeping it would make
the set of spellings of a name unbounded. A wildcard component may equal any name; a regex
component equals a concrete name exactly when it fullmatches some spelling that folds to it
(``_spellings``: the fold's preimage, finite once format characters are not ignored), so ``\\w+``
is known apart from ``.git`` and ``[^-].*`` is not.
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
    PseudoRegex,
    StaticPath,
    _normalize_component,
    _regex_accepts,
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


def fold(name: str) -> str:
    """The spelling under which two names denoting one file compare equal."""
    return unicodedata.normalize("NFC", name).casefold()


# the exact regex-versus-name test enumerates a name's spellings; past these bounds it gives the
# conservative answer instead
_MAX_NAME = 16
_MAX_SPELLINGS = 20_000


@cache
def _fold_table() -> dict[str, tuple[str, ...]]:
    """Per folded ASCII fragment, every single code point that folds to it -- ``k`` is ``k``,
    ``K`` and the Kelvin sign (NFC takes it to ``K``), ``ss`` is ``ß`` and ``ẞ``, ``fi`` the
    ligature. A code point folds to a fragment of one to three characters; a raw spelling that is
    a sequence of code points folds to the concatenation, so the preimage of a folded name is
    every way of tiling it with fragments and choosing a code point per tile. Nothing non-ASCII
    composes under NFC into a character folding to ASCII except through a single code point
    (the Kelvin sign, the long s, the ligatures), which the scan sees directly."""
    table: dict[str, list[str]] = {}
    for code in range(0x110000):
        ch = chr(code)
        folded = fold(ch)
        if 1 <= len(folded) <= 3 and folded.isascii():
            table.setdefault(folded, []).append(ch)
    return {k: tuple(v) for k, v in table.items()}


def _spellings(folded: str) -> frozenset[str] | None:
    """Every raw name that folds to *folded* (an ASCII folded name), or None when there are too
    many to enumerate, or the name is not one this can be exact about."""
    if not folded.isascii() or len(folded) > _MAX_NAME:
        return None
    table = _fold_table()
    # left to right: extend every partial spelling by a code point for the next fragment
    partial: dict[int, set[str]] = {0: {""}}
    for end in range(1, len(folded) + 1):
        here: set[str] = set()
        for start in range(max(0, end - 3), end):
            fragment = folded[start:end]
            if fragment in table and start in partial:
                for head in partial[start]:
                    for ch in table[fragment]:
                        here.add(head + ch)
        if len(here) > _MAX_SPELLINGS:
            return None
        partial[end] = here
    out = partial.get(len(folded), set())
    return frozenset(out) if out else None


def _regex_may_name(regex: PseudoRegex, folded: str) -> bool:
    """Can a name in the regex's language fold to *folded*? Exact where the spellings of
    *folded* can be enumerated, conservative (True) otherwise."""
    spellings = _spellings(folded)
    if spellings is None:
        return True
    return any(_regex_accepts(regex, s) for s in spellings)


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
    wildcard may name anything; a regex may name a concrete name exactly when it fullmatches
    one of the name's spellings (``_regex_may_name``); two regexes, conservatively, may agree."""
    assert not isinstance(c, _Splat) and not isinstance(d, _Splat)
    c, d = _normalize_component(c), _normalize_component(d)
    match c, d:
        case (AnyName(), _) | (_, AnyName()) | (Matching(), Matching()):
            return True
        case (Matching(regex=r), Named(name=n)) | (Named(name=n), Matching(regex=r)):
            return _regex_may_name(r, fold(n))
        case (Matching(regex=r), OneOf(names=ns)) | (OneOf(names=ns), Matching(regex=r)):
            return any(_regex_may_name(r, fold(n)) for n in ns)
        case Named(name=n), Named(name=m):
            return fold(n) == fold(m)
        case (Named(name=n), OneOf(names=ms)) | (OneOf(names=ms), Named(name=n)):
            return fold(n) in {fold(m) for m in ms}
        case OneOf(names=ns), OneOf(names=ms):
            return bool({fold(n) for n in ns} & {fold(m) for m in ms})
        case _:
            return True  # unreachable by the component grammar; conservative if it were not
