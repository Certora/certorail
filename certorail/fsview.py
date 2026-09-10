"""The policy's filesystem section as mounts (MOUNTS.md): what a child under ``exec.view =
"policy"`` sees of the filesystem, lowered from the same ``read`` / ``write`` / ``list`` grants
and ``no-write`` protections the program is held to.

A location is *bindable* when a bind mount says exactly what it says: literal components ending
in ``**`` (a subtree, itself and everything below) or a literal path (one file or directory)
(``locations.single_path``). Every other shape -- a ``*`` or ``<regex>`` component, a splat
demanding a final component (``src/**/*.py``) -- is a *pattern*. Seatbelt takes a pattern as an
anchored regex over canonical paths (``sandbox.seatbelt.pattern_regex``), so on macOS it is
native; bubblewrap binds paths, so on Linux a pattern is the FUSE view's (``viewdaemon``) or,
without one, omitted and said so on stderr, loudly. Nothing is ever rounded up.

``list`` grants name directories readable for listing and nothing below them. Seatbelt can say
"this path alone" (``literal``); a bind exposes contents, so on Linux a list grant never widens
the view: a directory is visible iff a bind covers it or lies on the way to one (the mountpoint
chain above a bind is empty directories).

This module is pure -- paths in, paths and regexes out -- so the lowering is testable without a
jail. It is the live path; ``certorail.sandbox`` is its successor, built beside it.
"""
from collections.abc import Iterable
from pathlib import Path

from certorail.analysis import LocationFact, pretty_location
from certorail.childjail import PATTERNS_NATIVE, Bind, Mounts, Regex
from certorail.locations import single_path
from certorail.sandbox.seatbelt import NOT_ERE, pattern_regex

__all__ = ["NOT_ERE", "additions", "mounts", "pattern_regex", "single_path"]


def _lower(
    kind: str, locs: Iterable[LocationFact], root: Path, patterns: bool, below: bool,
    out: list[Bind], omitted: list[str],
) -> None:
    for loc in locs:
        bind: Bind | None = single_path(loc, root)
        if bind is None and patterns:
            ere = pattern_regex(loc, root, below=below)
            if ere is None:
                # with patterns native, the only pattern that fails is one whose <regex> is
                # Python-only (the analysis' own intersections never come from a policy)
                omitted.append(f"{kind} {pretty_location(loc)} ({NOT_ERE})")
                continue
            bind = Regex(ere)
        if bind is None:
            omitted.append(f"{kind} {pretty_location(loc)}")
        elif bind not in out:
            out.append(bind)


def mounts(
    root: Path,
    read: tuple[LocationFact, ...],
    write: tuple[LocationFact, ...],
    no_write: tuple[LocationFact, ...],
    listing: tuple[LocationFact, ...] = (),
    *,
    patterns: bool = PATTERNS_NATIVE,
    view: Path | None = None,
) -> Mounts:
    """Lower the policy's grants and protections under *root* to ``Mounts``. Relative locations
    anchor at the root, absolute ones at the filesystem root, as everywhere. With *patterns*
    (Seatbelt) a patterned location is a regex; without (bubblewrap) it is omitted and
    reported, and ``list`` grants are not lowered at all. With a *view* (the FUSE mountpoint
    standing for the root) the root-relative locations are the view's to serve: none is a bind,
    none is omitted, and the view is bound at the root."""
    reads: list[Bind] = []
    writes: list[Bind] = []
    masks: list[Bind] = []
    listings: list[Bind] = []
    omitted: list[str] = []
    if view is not None:
        read, write, no_write, listing = (
            tuple(loc for loc in locs if loc.absolute) for locs in (read, write, no_write, listing)
        )
    _lower("read", read, root, patterns, False, reads, omitted)
    _lower("write", write, root, patterns, False, writes, omitted)
    _lower("no-write", no_write, root, patterns, True, masks, omitted)
    if patterns:
        # the directory itself, whatever shape names it: a pattern with no descendant tail
        _lower("list", listing, root, patterns, False, listings, [])
    needs_view = view is None and not patterns and any(
        not loc.absolute and single_path(loc, root) is None for loc in (*read, *write, *no_write)
    )
    return Mounts(
        tuple(reads), tuple(writes), tuple(masks), tuple(listings), tuple(omitted), needs_view,
        None if view is None else (view, root),
    )


def additions(
    root: Path,
    mount_read: tuple[LocationFact, ...],
    mount_write: tuple[LocationFact, ...],
    *,
    patterns: bool = PATTERNS_NATIVE,
) -> Mounts:
    """One rule's own additions to the view (``exec.mount-read`` / ``exec.mount-write``),
    lowered like grants and reported under their own names; joined onto the policy's mounts
    with ``|``."""
    reads: list[Bind] = []
    writes: list[Bind] = []
    omitted: list[str] = []
    _lower("mount-read", mount_read, root, patterns, False, reads, omitted)
    _lower("mount-write", mount_write, root, patterns, False, writes, omitted)
    return Mounts(tuple(reads), tuple(writes), (), (), tuple(omitted))
