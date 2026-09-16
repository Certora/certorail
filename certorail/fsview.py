"""The policy's filesystem section as mounts (MOUNTS.md): what a child under ``exec.view =
"policy"`` sees of the filesystem, lowered from the same ``read`` / ``write`` / ``list`` grants
and ``no-write`` protections the program is held to.

A location is *bindable* when a bind mount says exactly what it says: literal components ending
in ``**`` (a subtree, itself and everything below) or a literal path (one file or directory).
Every other shape -- a ``*`` or ``<regex>`` component, a splat demanding a final component
(``src/**/*.py``) -- is a *pattern*. Seatbelt takes a pattern as an anchored regex over
canonical paths, so on macOS it is native; bubblewrap binds paths, so on Linux a pattern has no
spelling until a per-request view (FUSE) exists: the view omits it and the host says so on
stderr, loudly. Nothing is ever rounded up.

``list`` grants name directories readable for listing and nothing below them. Seatbelt can say
"this path alone" (``literal``); a bind exposes contents, so on Linux a list grant never widens
the view: a directory is visible iff a bind covers it or lies on the way to one (the mountpoint
chain above a bind is empty directories).

This module is pure -- paths in, paths and regexes out -- so the lowering is testable without a
jail.
"""
import os
import re
from collections.abc import Iterable
from pathlib import Path
from re import _parser as _sre  # pyright: ignore[reportAttributeAccessIssue]  -- Python's own regex parser: the ERE is rendered from its tree

from .analysis import (
    Alternation,
    AnyName,
    AnyStr,
    Both,
    Component,
    Concat,
    DirSplat,
    Exact,
    LocationFact,
    Matching,
    Named,
    OneOf,
    PseudoRegex,
    RegexLit,
    StaticPath,
    pretty_location,
)
from .childjail import PATTERNS_NATIVE, Bind, Mounts, Regex

_ERE_SPECIAL = frozenset(".^$*+?()[]{}|\\")

NOT_ERE = (
    "its <regex> has no POSIX ERE spelling: only literals, '.', [...] of literals and ranges, '|', "
    "plain groups, greedy '* + ? {n,m}' and '^ $' translate -- no \\d \\w \\s (write [0-9]), "
    "no (?...), lookarounds, backreferences or lazy quantifiers"
)


def _escape(text: str) -> str:
    """*text* as a POSIX-ERE literal (what Seatbelt's regex engine reads); ``re.escape`` would
    also escape characters ERE takes literally."""
    return "".join(f"\\{c}" if c in _ERE_SPECIAL else c for c in text)


def _printable(code: int) -> bool:
    # what we know Seatbelt's engine reads as we do: printable ASCII. Anything else is refused
    # rather than guessed at
    return 0x20 <= code < 0x7F


def _ere_set(items: list[tuple[object, object]]) -> str | None:
    """A bracket expression from the parser's set items. ERE has no escapes inside ``[...]``: a
    literal ``]`` goes first, ``-`` last, and a literal ``^`` must not lead; a set that cannot be
    ordered that way (``^`` alone) is refused."""
    negated = False
    members: list[str] = []
    has_close = has_dash = has_caret = False
    for op, av in items:
        if op is _sre.NEGATE:
            negated = True
        elif op is _sre.LITERAL:
            assert isinstance(av, int)
            if not _printable(av):
                return None
            c = chr(av)
            if c == "]":
                has_close = True
            elif c == "-":
                has_dash = True
            elif c == "^":
                has_caret = True
            else:
                members.append(c)
        elif op is _sre.RANGE:
            assert isinstance(av, tuple)
            lo, hi = av
            if not (_printable(lo) and _printable(hi)) or chr(lo) in "]-^" or chr(hi) in "]-^":
                return None
            members.append(f"{chr(lo)}-{chr(hi)}")
        else:
            return None  # CATEGORY (\d inside a set) and the like
    if has_caret:
        if not members and not has_close:
            return None  # nothing to put before it
        members.append("^")
    body = ("]" if has_close else "") + "".join(members) + ("-" if has_dash else "")
    if not body:
        return None
    return f"[{'^' if negated else ''}{body}]"


def _ere_items(items: "_sre.SubPattern | list", group: bool) -> str | None:
    """*items* rendered in sequence; with *group*, wrapped in parentheses when a quantifier is
    about to apply and the sequence is more than one atom."""
    parts: list[str] = []
    for op, av in items:
        part = _ere_node(op, av)
        if part is None:
            return None
        parts.append(part)
    text = "".join(parts)
    return f"({text})" if group and len(items) != 1 else text


def _ere_branch(alternatives: list) -> str | None:
    rendered = [_ere_items(alt, group=False) for alt in alternatives]
    return None if any(r is None for r in rendered) else "|".join(r or "" for r in rendered)


def _ere_node(op: object, av: object) -> str | None:
    if op is _sre.LITERAL:
        assert isinstance(av, int)
        return _escape(chr(av)) if _printable(av) else None
    if op is _sre.NOT_LITERAL:
        assert isinstance(av, int)
        return _ere_set([(_sre.NEGATE, None), (_sre.LITERAL, av)])
    if op is _sre.ANY:
        return "."  # ERE's also matches a newline; documented, not hidden
    if op is _sre.IN:
        assert isinstance(av, list)
        return _ere_set(av)
    if op is _sre.BRANCH:
        assert isinstance(av, tuple)
        inner = _ere_branch(av[1])
        return None if inner is None else f"({inner})"
    if op is _sre.SUBPATTERN:
        assert isinstance(av, tuple)
        _, add_flags, del_flags, body = av
        if add_flags or del_flags:
            return None  # (?i:...) and friends
        if len(body) == 1 and body[0][0] is _sre.BRANCH:
            inner = _ere_branch(body[0][1][1])  # (a|b): one pair of parentheses, not two
        else:
            inner = _ere_items(body, group=False)
        return None if inner is None else f"({inner})"
    if op is _sre.MAX_REPEAT:
        assert isinstance(av, tuple)
        lo, hi, body = av
        atom = _ere_items(body, group=True)
        if atom is None:
            return None
        if (lo, hi) == (0, _sre.MAXREPEAT):
            return f"{atom}*"
        if (lo, hi) == (1, _sre.MAXREPEAT):
            return f"{atom}+"
        if (lo, hi) == (0, 1):
            return f"{atom}?"
        if hi == _sre.MAXREPEAT:
            return f"{atom}{{{lo},}}"
        return f"{atom}{{{lo}}}" if lo == hi else f"{atom}{{{lo},{hi}}}"
    if op is _sre.AT:
        if av is _sre.AT_BEGINNING or av is _sre.AT_BEGINNING_STRING:
            return "^"
        if av is _sre.AT_END or av is _sre.AT_END_STRING:
            return "$"
        return None  # \b \B
    # MIN_REPEAT, POSSESSIVE_REPEAT, ATOMIC_GROUP, CATEGORY, GROUPREF, GROUPREF_EXISTS, ASSERT,
    # ASSERT_NOT: no ERE counterpart
    return None


def ere_of(pattern: str) -> str | None:
    """The policy's ``<regex>`` -- validated at load as a Python regex -- as POSIX ERE with the
    same meaning, or None where Python's dialect says something ERE cannot. The ERE is
    generated from Python's own parse of the pattern, node by node, so a rendering is equivalent
    by construction: literals, ``.``, sets of literals and ranges, alternation, plain groups,
    greedy repeats and the string anchors. Everything else (``\\d \\w \\s``, whose Python meaning
    is a Unicode class; lazy, possessive and atomic forms; lookarounds; backreferences; inline
    flags; non-ASCII) is refused rather than approximated. The one difference let through:
    ``.`` in ERE matches a newline, Python's does not."""
    try:
        parsed = _sre.parse(pattern)
    except re.error:
        return None
    if parsed.state.flags & ~re.UNICODE:
        return None  # (?i) (?m) (?s) (?x): the whole pattern reads differently
    return _ere_items(parsed, group=False)


def _regex(p: PseudoRegex) -> str | None:
    """*p* as ERE, or None for a shape no single regex spells (an intersection, a Python-only
    ``<regex>``)."""
    match p:
        case Exact(exact_str=s):
            return _escape(s)
        case AnyStr():
            return ".*"
        case RegexLit(reg=r):
            ere = ere_of(r)
            return None if ere is None else f"({ere})"
        case Concat(seq=pieces):
            parts = [_regex(q) for q in pieces]
            return None if any(part is None for part in parts) else "".join(part or "" for part in parts)
        case Alternation(any_of=branches):
            parts = [_regex(b) for b in branches]
            return None if any(part is None for part in parts) else "(" + "|".join(part or "" for part in parts) + ")"
        case Both():
            return None


def _component(c: Component) -> str | None:
    match c:
        case Named(name=n):
            return _escape(n)
        case AnyName():
            return "[^/]+"
        case OneOf(names=ns):
            return "(" + "|".join(_escape(n) for n in sorted(ns)) + ")"
        case Matching(regex=r):
            return _regex(r)


def bind_path(loc: LocationFact, root: Path) -> Path | None:
    """The one path a bind of *loc* is, or None when *loc* is a pattern."""
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
    return Path("/", *names) if loc.absolute else root.joinpath(*names)


def pattern_regex(loc: LocationFact, root: Path, *, below: bool) -> Regex | None:
    """*loc* as an anchored ERE over canonical absolute paths -- the paths it denotes, and with
    *below* everything under them too (a protection guards a subtree). None when some component
    has no single-regex spelling."""
    parts = loc.path_components if isinstance(loc, StaticPath) else loc.static_prefix
    rendered = [_component(c) for c in parts]
    if any(r is None for r in rendered):
        return None
    head = "" if loc.absolute else _escape(os.path.realpath(root))
    body = "/".join(r or "" for r in rendered)
    if isinstance(loc, DirSplat):
        if loc.final_component is None:
            return Regex(f"^{head}/{body}(/.*)?$" if body else f"^{head}(/.*)?$")
        leaf = _component(loc.final_component)
        if leaf is None:
            return None
        tail = "(/.*)?" if below else ""
        return Regex(f"^{head}/{body}/(.*/)?{leaf}{tail}$" if body else f"^{head}/(.*/)?{leaf}{tail}$")
    tail = "(/.*)?" if below else ""
    return Regex(f"^{head}/{body}{tail}$" if body else f"^{head}{tail}$")


def _lower(
    kind: str, locs: Iterable[LocationFact], root: Path, patterns: bool, below: bool,
    out: list[Bind], omitted: list[str],
) -> None:
    for loc in locs:
        bind: Bind | None = bind_path(loc, root)
        if bind is None and patterns:
            bind = pattern_regex(loc, root, below=below)
            if bind is None:
                # with patterns native, the only pattern that fails is one whose <regex> is
                # Python-only (the analysis' own intersections never come from a policy)
                omitted.append(f"{kind} {pretty_location(loc)} ({NOT_ERE})")
                continue
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
) -> Mounts:
    """Lower the policy's grants and protections under *root* to ``Mounts``. Relative locations
    anchor at the root, absolute ones at the filesystem root, as everywhere. With *patterns*
    (Seatbelt) a patterned location is a regex; without (bubblewrap) it is omitted and
    reported, and ``list`` grants are not lowered at all."""
    reads: list[Bind] = []
    writes: list[Bind] = []
    masks: list[Bind] = []
    listings: list[Bind] = []
    omitted: list[str] = []
    _lower("read", read, root, patterns, False, reads, omitted)
    _lower("write", write, root, patterns, False, writes, omitted)
    _lower("no-write", no_write, root, patterns, True, masks, omitted)
    if patterns:
        # the directory itself, whatever shape names it: a pattern with no descendant tail
        _lower("list", listing, root, patterns, False, listings, [])
    return Mounts(tuple(reads), tuple(writes), tuple(masks), tuple(listings), tuple(omitted))
