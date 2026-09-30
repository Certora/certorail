"""The machine's configuration: ``world.toml`` in the config directory, namespaced by the process
it configures.

- ``[system.floor]``: what no process may ever write (``never-write``) and none may ever see
  (``never-visible``) -- the certorail process, its tools, its checkers -- whatever the policy
  says: the machine's redlines. Each is a path, or ``{ path, can-override }``: whether a root
  policy may lift it for one of its grants (default: it may).
- ``[system.interpreter] read``: what the certorail process's interpreter reads that discovery
  does not find, for the policy view.
- ``stable``: the stability model (``Stable``) -- which directories nothing replaces while a jail
  lives, where a mount may rest.
- ``view-daemon``: whether the view daemon caches names.

Machine knowledge: the analysis never reads it. It decides which policies load here
(``floor_findings``) and what every jail holds (``sandbox``). Paths are literal and absolute,
``~`` expanded, and resolved once here, so a link inside the floor cannot redirect it.
"""
import enum
import os
import pathlib
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from certorail.analysis import DirSplat, LocationFact, Named, StaticPath, location_le, pretty_location
from certorail.footprints import intersect, items_of
from certorail.policydir import config_dir
from certorail.schema import RedlineDecl, SchemaError, parse_world

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from certorail.policy import Policy


@dataclass(frozen=True)
class Redline:
    """One ``never-*`` entry, resolved: the path, and whether a root policy may lift it."""

    path: pathlib.Path
    can_override: bool = True


@dataclass(frozen=True)
class Floor:
    """``[system.floor]``, resolved."""

    never_write: tuple[Redline, ...] = ()
    never_visible: tuple[Redline, ...] = ()

    @classmethod
    def of(cls, *, never_write: Iterable[pathlib.Path] = (), never_visible: Iterable[pathlib.Path] = ()) -> "Floor":
        """The floor of these paths, each as the string form writes it: a policy may lift it."""
        return cls(tuple(Redline(p) for p in never_write), tuple(Redline(p) for p in never_visible))

    @property
    def empty(self) -> bool:
        return not (self.never_write or self.never_visible)

    @property
    def write_paths(self) -> tuple[pathlib.Path, ...]:
        return tuple(r.path for r in self.never_write)

    @property
    def visible_paths(self) -> tuple[pathlib.Path, ...]:
        return tuple(r.path for r in self.never_visible)


def resolved(text: str) -> pathlib.Path:
    """A machine path as ``world.toml`` holds it: ``~`` expanded, every link followed, once."""
    return pathlib.Path(os.path.realpath(os.path.expanduser(text)))


def home() -> pathlib.Path:
    """The user's home directory, resolved as every machine path is."""
    return resolved("~")


class Selector(enum.Enum):
    """A family of directories ``stable`` names at once."""

    TOPS = "tops"            # the top-level directories: every child of /
    HOME = "home"            # the home directory
    HOME_DOTS = "home-dots"  # the dot directories in it: ~/.ssh, ~/.cargo, ...
    ROOT = "root"            # the sandbox root
    XDG = "xdg"              # the XDG base directories under home: .config, .cache, .local/share, .local/state


@dataclass(frozen=True)
class Stable:
    """``stable``: the stability model -- which directories nothing replaces while a jail lives, so
    that a mount may rest on them: a host world's view of a redline sits at the innermost stable
    directory above it, and a whole run binds a grant plainly only at a stable name. The
    *selectors*, each a family of directories, and the *paths* named outright; *home* is where the
    selectors that say ``~`` look. Empty (``stable = "nothing"``): no directory is stable, so no
    host-view tool can be held under a redline, and a run binds nothing but what it cannot help.
    The user's judgment about this machine, trusted by the placement checker, never checked."""

    selectors: frozenset[Selector] = frozenset({Selector.TOPS, Selector.HOME})
    paths: tuple[pathlib.Path, ...] = ()
    home: pathlib.Path = field(default_factory=home)

    @classmethod
    def nothing(cls) -> "Stable":
        return cls(frozenset(), ())

    @classmethod
    def of(cls, *selectors: Selector, paths: Iterable[pathlib.Path] = (), home_at: pathlib.Path | None = None) -> "Stable":
        return cls(frozenset(selectors), tuple(paths), home() if home_at is None else home_at)

    def describe(self) -> str:
        """As ``world.toml`` would spell it."""
        words = [*sorted(s.value for s in self.selectors), *(str(p) for p in self.paths)]
        return ", ".join(words) if words else "nothing"


@dataclass(frozen=True)
class World:
    """``world.toml``, resolved: the floor, the interpreter's extra reads, the stability model,
    whether the view daemon caches nothing (``view-daemon = "strict"``: a name replaced from
    outside the jail is seen at once, at the price of every path walk through a view), and the file
    they came from (None when this machine has none)."""

    floor: Floor = Floor()
    interpreter_read: tuple[pathlib.Path, ...] = ()
    view_strict: bool = False
    source: pathlib.Path | None = None
    stable: Stable = field(default_factory=Stable)


class WorldFileError(Exception):
    """``world.toml`` does not conform; every problem found, one per line."""


def world_file() -> pathlib.Path:
    return config_dir() / "world.toml"


def _resolved(texts: list[str]) -> tuple[pathlib.Path, ...]:
    return tuple(resolved(t) for t in texts)


def _redlines(entries: list[str | RedlineDecl]) -> tuple[Redline, ...]:
    return tuple(
        Redline(resolved(e)) if isinstance(e, str) else Redline(resolved(e.path), e.can_override)
        for e in entries
    )


def _stable(entries: list[str]) -> Stable:
    """``stable`` as written: selectors by name, the rest paths (the schema admits nothing else)."""
    if entries == ["nothing"]:
        return Stable.nothing()
    names = {s.value for s in Selector}
    return Stable(
        frozenset(Selector(e) for e in entries if e in names),
        tuple(resolved(e) for e in entries if e not in names),
    )


def load_world(path: pathlib.Path | None = None) -> World:
    """The world this machine declares; an empty world when there is no ``world.toml``."""
    file = world_file() if path is None else path
    if not file.is_file():
        return World()
    text = file.read_text(encoding="utf-8")
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise WorldFileError(f"{file}: {e}") from None
    try:
        doc = parse_world(data, str(file))
    except SchemaError as e:
        raise WorldFileError(str(e)) from None
    f = doc.system.floor
    return World(
        Floor(_redlines(f.never_write), _redlines(f.never_visible)),
        _resolved(doc.system.interpreter.read),
        doc.view_daemon == "strict",
        file,
        _stable(doc.stable),
    )


# ---------------------------------------------------------------------------------------------
# the policy against this machine's floor
# ---------------------------------------------------------------------------------------------

type GrantKind = Literal["read", "write", "mount-read", "mount-write"]
type FloorKind = Literal["never-write", "never-visible"]
type LiftKind = Literal["lift-read", "lift-write"]


def _whose(who: str | None) -> str:
    return "" if who is None else f"{who}: "


@dataclass(frozen=True)
class FloorConflict:
    """A grant lying wholly inside a ``never-*`` path, unlifted: it can never be exercised here, so
    the policy does not load on this machine. *who*: the rule the grant is a mount of (None: the
    program's own, ``[filesystem]`` and ``[system.exec]``)."""

    kind: GrantKind
    grant: LocationFact
    floor: FloorKind
    path: pathlib.Path
    who: str | None = None

    def line(self) -> str:
        return (f"{_whose(self.who)}the {self.kind} grant {pretty_location(self.grant)} lies within {self.path}, "
                f"which this machine's world.toml marks {self.floor}: the grant can never be used here")


@dataclass(frozen=True)
class FloorOverlap:
    """A grant reaching into a ``never-*`` path: the floor carves the path out at run time, so an
    operation there fails mid-run. Said to the policy's author as a lint."""

    kind: GrantKind
    grant: LocationFact
    floor: FloorKind
    path: pathlib.Path
    who: str | None = None

    def line(self) -> str:
        what = "writes" if self.floor == "never-write" else "reads and writes"
        return (f"{_whose(self.who)}the {self.kind} grant {pretty_location(self.grant)} includes {self.path}, which "
                f"this machine's world.toml marks {self.floor}: {what} there fail at run time")


@dataclass(frozen=True)
class LiftConflict:
    """A lift that cannot be what it says: it lies in no redline of a kind it lifts, or it reaches
    one this machine marks ``can-override = false``. The policy does not load."""

    who: str
    kind: LiftKind
    lift: LocationFact
    reason: str

    def line(self) -> str:
        return f"{self.who}: the {self.kind} {pretty_location(self.lift)} {self.reason}"


def anchored(loc: LocationFact, root: pathlib.Path) -> LocationFact:
    """*loc* as an absolute location: a relative one placed under *root*, which is absolute."""
    if loc.absolute:
        return loc
    assert root.is_absolute(), f"anchored: the root {root} is not absolute"
    head = tuple(Named(n) for n in root.parts[1:])
    match loc:
        case StaticPath(path_components=cs):
            return StaticPath((*head, *cs), absolute=True)
        case DirSplat(static_prefix=ps, final_component=leaf):
            return DirSplat((*head, *ps), leaf, absolute=True)


def tree(path: pathlib.Path) -> DirSplat:
    """*path* and everything below it, as a location."""
    return DirSplat(tuple(Named(n) for n in path.parts[1:]), None, absolute=True)


def _tagged(kind: GrantKind, locs: tuple[LocationFact, ...]) -> list[tuple[GrantKind, LocationFact]]:
    return [(kind, g) for g in locs]


@dataclass(frozen=True)
class _Process:
    """One process's grants as the floor meets them: whose they are (None: the program's own),
    its reads and writes, and its lifts."""

    who: str | None
    reads: list[tuple[GrantKind, LocationFact]]
    writes: list[tuple[GrantKind, LocationFact]]
    lift_read: tuple[LocationFact, ...]
    lift_write: tuple[LocationFact, ...]


def _processes(policy: "Policy") -> list[_Process]:
    """The program, with ``[filesystem]`` and ``[system.exec]``; and every rule whose tool or
    checker mounts or lifts anything, with its own. A rule's tool also sees ``[filesystem]`` under
    the policy view; the program's check already judges those grants."""
    from certorail.policy import Program

    extra, lifts = policy.system.additions, policy.system.lifts
    out = [_Process(
        None,
        _tagged("read", policy.read) + _tagged("mount-read", extra.read),
        _tagged("write", policy.write) + _tagged("mount-write", extra.write),
        lifts.read, lifts.write,
    )]
    for rule in (*policy.programs, *policy.validations):
        if not (rule.mount_read or rule.mount_write or rule.lift_read or rule.lift_write):
            continue
        who = f"{' '.join(rule.leading_words)!r}" if isinstance(rule, Program) else f"validation {rule.name!r}"
        out.append(_Process(
            who, _tagged("mount-read", rule.mount_read), _tagged("mount-write", rule.mount_write),
            rule.lift_read, rule.lift_write,
        ))
    return out


def floor_findings(
    policy: "Policy", world: World, root: pathlib.Path,
) -> tuple[list[FloorConflict | LiftConflict], list[FloorOverlap]]:
    """Every process's grants under *root* that meet this machine's redlines: the ones a redline
    subsumes, unlifted (load errors), and the ones it overlaps (lints); and every lift that lies
    in no redline it could lift, or reaches one that ``can-override = false`` holds (load
    errors). A ``lift-read`` lifts ``never-visible``; a ``lift-write``, both kinds."""
    real_root = pathlib.Path(os.path.realpath(root))
    conflicts: list[FloorConflict | LiftConflict] = []
    overlaps: list[FloorOverlap] = []
    floor = world.floor

    def lifted(placed: LocationFact, lifts: tuple[LocationFact, ...]) -> bool:
        return any(location_le(placed, anchored(lift, real_root)) for lift in lifts)

    def meet(p: _Process, kind: GrantKind, grant: LocationFact, what: FloorKind, path: pathlib.Path) -> None:
        placed, guarded = anchored(grant, real_root), tree(path)
        lifts = p.lift_write if what == "never-write" or kind in ("write", "mount-write") else (*p.lift_read, *p.lift_write)
        if location_le(placed, guarded):
            if not lifted(placed, lifts):
                conflicts.append(FloorConflict(kind, grant, what, path, p.who))
        elif intersect(items_of(placed), items_of(guarded)):
            overlaps.append(FloorOverlap(kind, grant, what, path, p.who))

    def judge(p: _Process, kind: LiftKind, lift: LocationFact, lifts: tuple[tuple[FloorKind, Redline], ...]) -> None:
        who = "the program ([system.exec])" if p.who is None else p.who
        placed = anchored(lift, real_root)
        if not any(location_le(placed, tree(r.path)) for _, r in lifts):
            reach = "never-visible" if kind == "lift-read" else "never-write or never-visible"
            conflicts.append(LiftConflict(who, kind, lift, f"lies in no {reach} redline of this machine's world.toml: it lifts nothing"))
            return
        for what, r in lifts:
            if not r.can_override and intersect(items_of(placed), items_of(tree(r.path))):
                conflicts.append(LiftConflict(
                    who, kind, lift, f"reaches {r.path}, which this machine's world.toml marks {what} with can-override = false",
                ))

    visible: tuple[tuple[FloorKind, Redline], ...] = tuple(("never-visible", r) for r in floor.never_visible)
    written: tuple[tuple[FloorKind, Redline], ...] = tuple(("never-write", r) for r in floor.never_write)
    for p in _processes(policy):
        for kind, grant in p.writes:
            for path in floor.write_paths:
                meet(p, kind, grant, "never-write", path)
        for kind, grant in (*p.reads, *p.writes):
            for path in floor.visible_paths:
                meet(p, kind, grant, "never-visible", path)
        for lift in p.lift_read:
            judge(p, "lift-read", lift, visible)
        for lift in p.lift_write:
            judge(p, "lift-write", lift, (*written, *visible))
    return conflicts, overlaps
