"""Footprints: a location as a component sequence, and whether two locations can name a common
path (``overlaps``).

A ``Footprint`` is a location as components and splats, denoting the paths the sequence spells
and every descendant. ``overlaps`` asks whether some concrete path lies in both what a write may
name and what a footprint may name; both sides have finitely many splats, each standing for any
run of components, so the test is a small alignment. It serves the ``no-write`` protection
(``Policy.protected``) and the FUSE view's filter (``fuseview``). A region's declared
``footprint`` keeps its shape for the reader and for a per-program write jail if one comes; the
kill of environmental atoms does not consult it -- a program's file write is a write of the whole
filesystem medium (EFFECTS.md).

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
    """A location as components and splats, anchored at the sandbox root or the filesystem
    root, denoting the paths the sequence spells *and every descendant*."""

    items: tuple[Item, ...]
    absolute: bool = False


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


def footprint_of(loc: LocationFact) -> Footprint:
    """*loc* as a footprint: its components, anchored where it is."""
    return Footprint(items_of(loc), loc.absolute)


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
