"""What a jail is granted, as the front end states it and before any backend has a say
(LOWERING2.md, "The representation"). Nothing here knows bubblewrap, Seatbelt or FUSE.

A jail is a world: the host's ``/`` (``HostGrants``), or nothing but what its layers grant
(``PolicyGrants``), which apply in order -- a later layer wins where it overlaps an earlier one.
``state_at`` is that meaning, as a function: the reference every lowering must agree with. A
view's daemon decides each name by the same pieces (``covers``, ``after``).
"""
import enum
import pathlib
from dataclasses import dataclass, field
from typing import Protocol

from certorail.analysis import LocationFact, Named, StaticPath, location_le
from certorail.childjail import Environment
from certorail.world import Stable

__all__ = [
    "Access", "Exactly", "Grant", "Grants", "HostGrants", "Layer", "Lifetime", "LiteralRegion", "Narrowing",
    "Origin", "Pattern", "PolicyGrants", "Process", "Region", "Restriction", "State", "Subtree",
    "after", "covers", "says", "state_at", "within",
]


def within(path: pathlib.Path, top: pathlib.Path) -> bool:
    """Is *path* at or below *top*?"""
    return path == top or top in path.parents


# -- regions ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Subtree:
    """*path* and everything below it (a grant ``a/b/**``, a region, a floor path)."""

    path: pathlib.Path


@dataclass(frozen=True)
class Exactly:
    """*path* alone: a file's contents, a directory's listing (a grant ``a/b``)."""

    path: pathlib.Path


@dataclass(frozen=True)
class Pattern:
    """A location no set of paths says: ``notes/**/<[a-z]+\\.txt>``. *anchor* places it: the root for
    a relative location, ``/`` for an absolute one."""

    location: LocationFact
    anchor: pathlib.Path


type LiteralRegion = Subtree | Exactly
type Region = LiteralRegion | Pattern


# -- effects ------------------------------------------------------------------------------------


class Access(enum.Enum):
    READ_ONLY = "read-only"
    WRITABLE = "writable"


@dataclass(frozen=True)
class Grant:
    """The region exists, with *access*. *stable*: nothing replaces it during a run (the
    toolchain, the interpreter's world)."""

    access: Access
    stable: bool = False


class Narrowing(enum.Enum):
    NO_WRITE = "no-write"
    HIDDEN = "hidden"


@dataclass(frozen=True)
class Restriction:
    """Narrows what exists; never makes anything exist. *sole*: it blocks names the analysis lets
    through, so the jail alone stops them and it must hold by name."""

    narrowing: Narrowing
    sole: bool


class Origin(Protocol):
    """Where a layer came from, for messages. The compiler never looks inside."""

    def describe(self) -> str: ...


@dataclass(frozen=True)
class Layer[R: Subtree | Exactly | Pattern]:
    region: R
    effect: Grant | Restriction
    origin: Origin


# -- jails --------------------------------------------------------------------------------------


class Lifetime(enum.Enum):
    EXEC = "one exec"       # a tool's or a checker's jail
    RUN = "the whole run"   # the certorail process's


@dataclass(frozen=True)
class Process:
    """What a jail's process may do besides touching files."""

    network: bool
    spawn: bool
    exec_: bool
    env: Environment | None = None


@dataclass(frozen=True)
class HostGrants:
    """The host's ``/``, writable where unix allows or read-only: host mode is the user's
    authority. Over it, for a tool's or a checker's jail, *layers*: the machine's redlines, then
    the rule's lifts of them (REDLINES.md), each held in a view at the innermost directory the
    machine's stability model (*stable*, ``world.toml``) says nothing replaces; *root*, the sandbox
    root, is what its ``root`` selector names (None: the certorail process's own host mode, which
    has no layers: the floor guard holds its redlines, in the process, ``floorguard``)."""

    writable: bool
    lifetime: Lifetime
    process: Process
    layers: tuple[Layer[Region], ...] = ()
    root: pathlib.Path | None = None
    stable: Stable = field(default_factory=Stable)


@dataclass(frozen=True)
class PolicyGrants:
    """Nothing but what the layers grant. *root*: the sandbox root, under which the root-relative
    layers lie. *needs*: what the jail's process cannot start without, which nothing may hide.
    *listings*: directories it lists, at least as far as what is granted under them (the
    interpreter's package parent on ``sys.path``) -- a need, not a grant: the directories on the
    way to a mount are there already. *workdir*: the program's working directory, bound for the
    whole run (None for a tool's jail): the jail cannot replace a mountpoint on the empty root,
    and when something outside moves it, the process's cwd -- an inode, not a name -- has already
    followed the moved object, under any jail or none; a bind pinned to it agrees with the cwd,
    where a view would answer ESTALE. *stable*: the machine's stability model, the other names a
    whole run may bind plainly."""

    layers: tuple[Layer[Region], ...]
    lifetime: Lifetime
    process: Process
    root: pathlib.Path
    needs: tuple[pathlib.Path, ...] = ()
    listings: tuple[pathlib.Path, ...] = ()
    workdir: pathlib.Path | None = None
    stable: Stable = field(default_factory=Stable)


type Grants = HostGrants | PolicyGrants


# -- the meaning --------------------------------------------------------------------------------


class State(enum.Enum):
    ABSENT = "absent"
    READ_ONLY = "read-only"
    WRITABLE = "writable"
    HIDDEN = "hidden"


def _matches(pattern: Pattern, path: pathlib.Path) -> bool:
    if not within(path, pattern.anchor):
        return False
    names = StaticPath(tuple(Named(n) for n in path.relative_to(pattern.anchor).parts), pattern.location.absolute)
    return location_le(names, pattern.location)


def covers(region: Region, path: pathlib.Path, *, below: bool = False) -> bool:
    """Does *region* cover *path*? A literal region covers what it names (a ``Subtree`` its path
    and everything below it), a pattern the paths it matches; with *below* -- a restriction's,
    which narrows everything below what it names -- also whatever lies below those."""
    match region:
        case Subtree(path=top):
            return within(path, top)
        case Exactly(path=exact):
            return within(path, exact) if below else path == exact
        case Pattern():
            return any(_matches(region, p) for p in ((path, *path.parents) if below else (path,)))


def says(effect: Grant | Restriction) -> Access | Narrowing:
    """What a layer says of the paths it covers: a grant its access, a restriction its narrowing."""
    return effect.access if isinstance(effect, Grant) else effect.narrowing


def after(state: State, word: Access | Narrowing) -> State:
    """*state*, once a layer saying *word* covers the path: a grant sets its access; ``NO_WRITE``
    turns writable into read-only; ``HIDDEN`` turns anything present into hidden. Neither
    restriction makes an absent path appear."""
    match word:
        case Access.WRITABLE:
            return State.WRITABLE
        case Access.READ_ONLY:
            return State.READ_ONLY
        case Narrowing.NO_WRITE:
            return State.READ_ONLY if state is State.WRITABLE else state
        case Narrowing.HIDDEN:
            return state if state is State.ABSENT else State.HIDDEN


def state_at(grants: Grants, path: pathlib.Path) -> State:
    """What *path* is in the jail: from the base's state -- the host's, writable or read-only, or
    the policy world's nothing -- by the layers in order, each over what it covers (``covers``: a
    restriction's reaches below what it names), as ``after`` says."""
    if isinstance(grants, HostGrants):
        state = State.WRITABLE if grants.writable else State.READ_ONLY
    else:
        state = State.ABSENT
    for layer in grants.layers:
        word = says(layer.effect)
        if covers(layer.region, path, below=isinstance(word, Narrowing)):
            state = after(state, word)
    return state
