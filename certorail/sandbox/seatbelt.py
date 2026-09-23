"""The macOS spawner: Seatbelt through ``sandbox-exec``. No run-scoped state: patterns are
regex filters, so no view is ever needed, and every plan is a pure function of the confinement.

Lowering (``lower``): a location that is one path is a ``Bind`` -- a ``subpath`` filter for a
tree or a protection, a ``literal`` filter for a literal grant, which names that path alone; a
pattern is a ``RegexRule``, anchored over canonical paths, a protection's covering its subtree;
a ``<regex>`` outside the subset Python and ERE share, or one a profile string cannot hold, is
``Omitted``.

The regex dialect (``ere_of``): a policy ``<regex>`` is validated at load as a Python regex, and
Seatbelt reads POSIX ERE. The ERE is generated from Python's own parse of the pattern, node by
node, so whatever renders means the same thing on both sides by construction; a node with no ERE
counterpart (``\\d \\w \\s``, whose Python meaning is a Unicode class; lazy, possessive and
atomic forms; lookarounds; backreferences; inline flags; non-ASCII) refuses the whole pattern
rather than approximating it. Two differences let through: ``.`` in ERE matches a newline,
Python's does not; and Seatbelt matches every filter without regard to case (measured on a Mac
2026-09-23: ``no\\.txt`` admitted ``NO.txt``). On a case-insensitive volume that widens no grant
-- a path matching ignoring case has a re-casing that matches exactly and names the same file --
and on a case-sensitive one it does; the reference says so.

The profile: everything but file data allowed, then the entries of ``/`` (every process reads
them at startup: measured 2026-09-22, without this ``ls`` and ``cat`` abort before ``main``),
the toolchain, the tool, the scratch directory and the readable locations allowed for reading
(listing a directory is reading it: a read grant covers the directories within it), the
writable locations (under ``write_fs``) and the scratch directory for writing, the protections
denied for writing last. Metadata reads stay allowed so path resolution works: names are
visible, contents are not. Seatbelt's matching, measured on a Mac 2026-09-22: within one
operation later rules win, and a rule on a specific operation shadows every rule on its wildcard
-- with ``file-read-data`` denied an allow on ``file-read*`` never applies -- so the read
allowances are spelled on ``file-read-data`` itself.

Written against Apple's documented profile language and unrun here; ``scripts/probe_seatbelt.py``
is the probe a Mac runs.
"""
import contextlib
import os
import pathlib
import re
import shutil
from collections.abc import Iterator, Sequence
from re import _parser as _sre  # pyright: ignore[reportAttributeAccessIssue]  -- Python's own regex parser

from certorail.analysis import (
    ANY_NAME,
    Alternation,
    AnyComponent,
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
)
from certorail import sbpl
from certorail.childjail import JailUnavailable, Spawn
from certorail.confinement import Confinement, HostFilesystem, PolicyFilesystem
from certorail.locations import single_path
from certorail.sandbox.common import environment, executable, scratch_for
from certorail.sandbox.lowering import Bind, Lowered, Omitted, RegexRule, Role, readable, writable

TOOLCHAIN = (
    "/usr", "/bin", "/sbin", "/System", "/Library", "/private/var/db", "/private/etc", "/dev",
    "/opt/homebrew",
)

NOT_ERE = (
    "its <regex> has no POSIX ERE spelling: only literals, '.', [...] of literals and ranges, '|', "
    "plain groups, greedy '* + ? {n,m}' and '^ $' translate -- no \\d \\w \\s (write [0-9]), "
    "no (?...), lookarounds, backreferences or lazy quantifiers"
)

# ---------------------------------------------------------------------------------------------
# the regex dialect: a policy <regex> as ERE, from Python's parse of it
# ---------------------------------------------------------------------------------------------

_ERE_SPECIAL = frozenset(".^$*+?()[]{}|\\")


def _escape(text: str) -> str:
    """*text* as a POSIX-ERE literal; ``re.escape`` would also escape characters ERE takes
    literally."""
    return "".join(f"\\{c}" if c in _ERE_SPECIAL else c for c in text)


def _printable(code: int) -> bool:
    # what we know Seatbelt's engine reads as we do: printable ASCII. Anything else is refused
    # rather than guessed at
    return 0x20 <= code < 0x7F


_SLASH = ord("/")


def _ere_set(items: list[tuple[object, object]]) -> str | None:
    """A bracket expression from the parser's set items, over one path component: it never
    admits ``/``. ERE has no escapes inside ``[...]``: a literal ``]`` goes first, ``-`` last,
    and a literal ``^`` must not lead; a set that cannot be ordered that way is refused."""
    negated = False
    members: list[str] = []
    has_close = has_dash = has_caret = False
    literals: list[int] = []
    for op, av in items:
        if op is _sre.NEGATE:
            negated = True
        elif op is _sre.LITERAL:
            assert isinstance(av, int)
            literals.append(av)
        elif op is _sre.RANGE:
            assert isinstance(av, tuple)
            lo, hi = av
            pieces = [(lo, _SLASH - 1), (_SLASH + 1, hi)] if lo <= _SLASH <= hi else [(lo, hi)]
            for a, b in pieces:
                if a > b:
                    continue
                if a == b:
                    literals.append(a)
                    continue
                if not (_printable(a) and _printable(b)) or chr(a) in "]-^" or chr(b) in "]-^":
                    return None
                members.append(f"{chr(a)}-{chr(b)}")
        else:
            return None  # CATEGORY (\d inside a set) and the like
    if negated:
        literals.append(_SLASH)
    for av in literals:
        if av == _SLASH and not negated:
            continue
        if not _printable(av):
            return None
        c = chr(av)
        if c == "]":
            has_close = True
        elif c == "-":
            has_dash = True
        elif c == "^":
            has_caret = True
        elif c not in members:
            members.append(c)
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
    # a quantifier applies to one atom: a sequence, or a single item that is itself quantified
    # (``(?:a+)*`` parses as a repeat of a repeat), is parenthesised first
    single_atom = len(items) == 1 and items[0][0] not in (_sre.MAX_REPEAT, _sre.MIN_REPEAT)
    return f"({text})" if group and not single_atom else text


def _ere_branch(alternatives: list) -> str | None:
    rendered = [_ere_items(alt, group=False) for alt in alternatives]
    return None if any(r is None for r in rendered) else "|".join(r or "" for r in rendered)


def _ere_node(op: object, av: object) -> str | None:
    if op is _sre.LITERAL:
        assert isinstance(av, int)
        return _escape(chr(av)) if _printable(av) and av != _SLASH else None
    if op is _sre.NOT_LITERAL:
        assert isinstance(av, int)
        return _ere_set([(_sre.NEGATE, None), (_sre.LITERAL, av)])
    if op is _sre.ANY:
        return "[^/]"  # one component; ERE's also matches a newline, documented, not hidden
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
        return None  # anchors at the component's edges are dropped by ere_of; elsewhere refused
    # MIN_REPEAT, POSSESSIVE_REPEAT, ATOMIC_GROUP, CATEGORY, GROUPREF, GROUPREF_EXISTS, ASSERT,
    # ASSERT_NOT: no ERE counterpart
    return None


def ere_of(pattern: str) -> str | None:
    """The policy's ``<regex>`` as POSIX ERE with the same meaning, or None where Python's dialect
    says something ERE cannot (see the module docstring)."""
    try:
        parsed = _sre.parse(pattern)
    except re.error:
        return None
    if parsed.state.flags & ~re.UNICODE:
        return None  # (?i) (?m) (?s) (?x): the whole pattern reads differently
    items = list(parsed)
    # under fullmatch a leading ^ and a trailing $ say nothing; inside the path regex they would
    # anchor the whole path, so they go, and any other anchor is refused (_ere_node)
    starts = (_sre.AT_BEGINNING, _sre.AT_BEGINNING_STRING)
    ends = (_sre.AT_END, _sre.AT_END_STRING)
    while items and items[0][0] is _sre.AT and items[0][1] in starts:
        items.pop(0)
    while items and items[-1][0] is _sre.AT and items[-1][1] in ends:
        items.pop()
    if not items:
        return None
    return _ere_items(items, group=False)


def _regex(p: PseudoRegex) -> str | None:
    """*p* as ERE, or None for a shape no single regex spells (an intersection, a Python-only
    ``<regex>``)."""
    match p:
        case Exact(exact_str=s):
            return None if "/" in s else _escape(s)
        case AnyStr():
            return "[^/]*"
        case AnyComponent():
            return _component(ANY_NAME)
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


def pattern_regex(loc: LocationFact, root: pathlib.Path, *, below: bool) -> str | None:
    """*loc* as an anchored ERE over canonical absolute paths -- the paths it denotes, and with
    *below* everything under them too (a protection guards a subtree). None when some component
    has no single-regex spelling."""
    parts = loc.path_components if isinstance(loc, StaticPath) else loc.static_prefix
    # the literal names at the front resolve like a bind does (``/tmp`` is ``/private/tmp``, a
    # symlinked directory is its target); what follows the first pattern cannot be resolved
    literal = 0
    while literal < len(parts) and isinstance(parts[literal], Named):
        literal += 1
    anchor = pathlib.Path("/") if loc.absolute else root
    names = [c.name for c in parts[:literal] if isinstance(c, Named)]
    resolved = os.path.realpath(anchor.joinpath(*names))
    rendered = [_component(c) for c in parts[literal:]]
    if any(r is None for r in rendered):
        return None
    head = "" if resolved == "/" else _escape(resolved)
    body = "/".join(r or "" for r in rendered)
    if isinstance(loc, DirSplat):
        if loc.final_component is None:
            return f"^{head}/{body}(/.*)?$" if body else f"^{head}(/.*)?$"
        leaf = _component(loc.final_component)
        if leaf is None:
            return None
        tail = "(/.*)?" if below else ""
        return f"^{head}/{body}/(.*/)?{leaf}{tail}$" if body else f"^{head}/(.*/)?{leaf}{tail}$"
    tail = "(/.*)?" if below else ""
    return f"^{head}/{body}{tail}$" if body else f"^{head}{tail}$"


# ---------------------------------------------------------------------------------------------
# the spawner
# ---------------------------------------------------------------------------------------------


def _canonical(path: str | os.PathLike[str]) -> str:
    # Seatbelt matches canonical paths: the per-user temp dir is under /private/var
    return os.path.realpath(path)


def _filter(item: str | Bind | RegexRule) -> str:
    if isinstance(item, RegexRule):
        rendered = sbpl.regex(item.pattern)
        assert rendered is not None, "lower() omits patterns that cannot sit in a literal"
        return rendered
    if isinstance(item, Bind):
        path = _canonical(item.path)
        return sbpl.subpath(path) if item.subtree else sbpl.literal(path)
    return sbpl.subpath(_canonical(item))


class SeatbeltSpawner:
    def __enter__(self) -> "SeatbeltSpawner":
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    # -- lowering (pure) --------------------------------------------------------------------

    def lower(self, fs: PolicyFilesystem, write_fs: bool) -> tuple[Lowered, ...]:
        out: list[Lowered] = []

        def each(role: Role, locs: tuple[LocationFact, ...]) -> None:
            for loc in locs:
                path = single_path(loc, fs.root)
                if path is not None:
                    # a literal grant is that path alone; a protection guards its whole subtree
                    subtree = isinstance(loc, DirSplat) or role == "no-write"
                    out.append(Bind(path, role, subtree))
                    continue
                regex = pattern_regex(loc, fs.root, below=(role == "no-write"))
                if regex is None or sbpl.regex(regex) is None:
                    out.append(Omitted(loc, role, NOT_ERE))
                else:
                    out.append(RegexRule(regex, role))

        each("read", fs.section.read)
        each("write", fs.section.write)
        each("mount-read", fs.additions.read)
        each("mount-write", fs.additions.write)
        each("no-write", fs.section.no_write)
        return tuple(out)

    # -- the profile ------------------------------------------------------------------------

    def profile(self, c: Confinement, scratch: str | None, exe: str | None) -> str:
        rules = ["(version 1)", "(allow default)"]
        fs = c.filesystem
        if isinstance(fs, PolicyFilesystem):
            lowered = [x for x in self.lower(fs, c.write_fs) if isinstance(x, (Bind, RegexRule))]
            rules.append("(deny file-read-data file-write*)")
            reads: list[str | Bind | RegexRule] = [*TOOLCHAIN, *([exe] if exe is not None else [])]
            reads += [x for x in lowered if readable(x.role)]
            if scratch is not None:
                reads.append(scratch)
            rules.append('(allow file-read-data (literal "/") ' + " ".join(_filter(x) for x in reads) + ")")
            writes: list[str | Bind | RegexRule] = [x for x in lowered if writable(x.role)] if c.write_fs else []
            if scratch is not None:
                writes.append(scratch)
            rules.append("(allow file-write* " + " ".join(_filter(x) for x in writes) + ' (literal "/dev/null"))')
            guards = [x for x in lowered if x.role == "no-write"]
            if guards:
                rules.append("(deny file-write* " + " ".join(_filter(x) for x in guards) + ")")
        elif scratch is not None:
            rules += ["(deny file-write*)", f'(allow file-write* {_filter(scratch)} (literal "/dev/null"))']
        if not c.network:
            rules.append("(deny network*)")
        if not c.spawn:
            rules.append("(deny process-fork)")
        return " ".join(rules)

    # -- spawning ---------------------------------------------------------------------------

    @contextlib.contextmanager
    def spawn(
        self, confinement: Confinement, argv: Sequence[str], cwd: pathlib.Path, base_env: dict[str, str] | None = None,
    ) -> Iterator[Spawn]:
        base = dict(os.environ) if base_env is None else base_env
        if not confinement.restricts:
            yield Spawn(list(argv), dict(base))
            return
        with scratch_for(confinement) as scratch:
            env = environment(confinement.env, base, scratch)
            fs = confinement.filesystem
            if confinement.network and confinement.write_fs and confinement.spawn and isinstance(fs, HostFilesystem):
                yield Spawn(list(argv), env)
                return
            sandbox_exec = shutil.which("sandbox-exec")
            if sandbox_exec is None:
                raise JailUnavailable("sandbox-exec is not available; a jailed grant cannot run without it")
            exe = executable(argv, env) if isinstance(fs, PolicyFilesystem) else None
            yield Spawn([sandbox_exec, "-p", self.profile(confinement, scratch, exe), *argv], env)
