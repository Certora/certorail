"""This machine's redlines for the certorail process in host mode, held in the process itself
(FLOORS.md): an audit hook (PEP 578) that the bootstrap installs last before the program runs.

Host mode's promise: the program runs with the user's authority and reaches files through the
names its policy grants -- the analysis proves the names -- wherever those names lead, links
included, but for the floor ``world.toml`` draws. At each operation on a path the guard resolves
the path, at that moment, and refuses as the kernel would (``PermissionError``, ``EACCES``):

- a read, a listing or a write at or below a ``never-visible`` path;
- a write at or below a ``never-write`` path;
- a rename, a removal or a link at or above either, which would carry the path off.

Every operation in the process is held to it, the interpreter's own included: never means never,
whoever asks. What the interpreter cannot start without is checked against ``never-visible``
before the run (``sandbox.program``). So an accepted program meets no permission error but the
floor the user wrote and unix permissions. The policy view (``[system.exec] view = "policy"``) is
the other promise: every access reaches only what the policy grants, held by the kernel.

This is not a sandbox, and does not try to be. Native code raises no audit events, which is one
reason the subset admits none. An operation relative to a directory descriptor cannot be checked
by name: it is refused where its event says so, and ``os.open``'s event does not say (outside the
subset). A path can change between the check and the operation. ``os.stat`` raises no event, so
a never-visible name can be probed but never read.
"""
import enum
import errno
import json
import os
import pathlib
import sys
from dataclasses import dataclass

from certorail.analysis import LocationFact, Named, StaticPath, location_le
from certorail.footprints import fold
from certorail.locations import decode_location, encode_location

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from certorail.confinement import Lifts
    from certorail.world import Floor

__all__ = ["Guard", "install"]

FORMAT = 4


class Act(enum.Enum):
    """What an operation does at one of its paths."""

    READ = "read"      # reads or lists through the path, following a link at it
    WRITE = "write"    # writes through the path, following a link at it
    MAKE = "make"      # makes an empty directory at the path itself
    RELINK = "relink"  # makes, removes or replaces the entry at the path itself, and what is below it
    CHANGE = "change"  # changes the entry or what it leads to: the event does not say which


# The audited operations on paths (CPython's audit events table): each path argument by position
# and what the operation does there, then the directory-descriptor arguments, -1 when absent.
# ``open`` is the one event whose act depends on its arguments (``Guard.refusal``).
_EVENTS: dict[str, tuple[tuple[tuple[int, Act], ...], tuple[int, ...]]] = {
    "os.listdir": (((0, Act.READ),), ()),
    "os.scandir": (((0, Act.READ),), ()),
    "os.mkdir": (((0, Act.MAKE),), (2,)),
    "os.symlink": (((1, Act.RELINK),), (2,)),
    "os.link": (((0, Act.CHANGE), (1, Act.RELINK)), (2, 3)),  # a new name for a file writes it
    "os.rename": (((0, Act.RELINK), (1, Act.RELINK)), (2, 3)),
    "os.remove": (((0, Act.RELINK),), (1,)),
    "os.rmdir": (((0, Act.RELINK),), (1,)),
    "os.truncate": (((0, Act.WRITE),), ()),
    "os.chmod": (((0, Act.CHANGE),), (2,)),
    "os.chown": (((0, Act.CHANGE),), (3,)),
    "os.chflags": (((0, Act.CHANGE),), ()),
    "os.utime": (((0, Act.CHANGE),), (3,)),
    "os.setxattr": (((0, Act.CHANGE),), ()),
    "os.removexattr": (((0, Act.CHANGE),), ()),
}

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def _text(arg: object) -> str | None:
    """A path argument as text: None for a descriptor, which names no path. A missing path is
    the working directory (``os.listdir()``)."""
    if arg is None:
        return "."
    if isinstance(arg, (str, bytes, os.PathLike)):
        return os.fsdecode(os.fspath(arg))
    return None


def _target(text: str) -> pathlib.Path:
    """Where an operation following links reaches through *text*."""
    return pathlib.Path(os.path.realpath(text))


def _entry(text: str) -> pathlib.Path:
    """The entry an operation on *text* itself changes: its directory resolved, its own name not
    followed (a rename moves a link, not what it leads to)."""
    stripped = text.rstrip("/") or "/"
    head, name = os.path.split(stripped)
    if name in ("", ".", ".."):
        return _target(stripped)
    return _target(head or ".") / name


def _within(path: pathlib.Path, top: pathlib.Path) -> bool:
    """Is *path* at or below *top*, names compared folded (``footprints``): whether two spellings
    name one file is the mount's business, and a spelling that might is refused."""
    names, tops = [fold(p) for p in path.parts], [fold(p) for p in top.parts]
    return names[:len(tops)] == tops


def _where(text: str, path: pathlib.Path) -> str:
    """*text* as the program spelled it, and where it leads when that is somewhere else."""
    return repr(text) if os.path.abspath(text) == str(path) else f"{text!r}, which leads to {path},"


def _absolute(loc: LocationFact, root: pathlib.Path) -> LocationFact:
    from certorail.world import anchored

    return anchored(loc, pathlib.Path(os.path.realpath(root)))


def _lifted(path: pathlib.Path, lifts: tuple[LocationFact, ...]) -> bool:
    """Does one of *lifts* (absolute) cover *path*, exactly as spelled? A lift widens, so no
    folding: a spelling that might name the lifted file but does not is refused."""
    names = StaticPath(tuple(Named(n) for n in path.parts[1:]), absolute=True)
    return any(location_le(names, lift) for lift in lifts)


@dataclass(frozen=True)
class Guard:
    """What the hook holds: this machine's ``never-*`` paths, resolved when ``world.toml`` loaded,
    and the lifts of them the root policy wrote for the program (``[system.exec]``, REDLINES.md),
    absolute: readable and read-only (*lift_read*), or writable (*lift_write*)."""

    never_write: tuple[pathlib.Path, ...]
    never_visible: tuple[pathlib.Path, ...]
    lift_read: tuple[LocationFact, ...] = ()
    lift_write: tuple[LocationFact, ...] = ()

    @classmethod
    def of(cls, floor: "Floor", lifts: "Lifts | None" = None, root: pathlib.Path | None = None) -> "Guard":
        """*floor*, less *lifts*: a relative lift lies under *root*."""
        if lifts is None or lifts.empty:
            return cls(floor.write_paths, floor.visible_paths)
        assert root is not None, "a lift may be relative: its root places it"
        return cls(
            floor.write_paths, floor.visible_paths,
            tuple(_absolute(loc, root) for loc in lifts.read), tuple(_absolute(loc, root) for loc in lifts.write),
        )

    @property
    def empty(self) -> bool:
        return not (self.never_write or self.never_visible)

    def document(self) -> str:
        return json.dumps({
            "format": FORMAT,
            "never_write": [str(p) for p in self.never_write],
            "never_visible": [str(p) for p in self.never_visible],
            "lift_read": [encode_location(loc) for loc in self.lift_read],
            "lift_write": [encode_location(loc) for loc in self.lift_write],
        }, sort_keys=True)

    @classmethod
    def parse(cls, text: str) -> "Guard":
        body = json.loads(text)
        if body.get("format") != FORMAT:
            raise ValueError(f"floor guard format {body.get('format')!r}, expected {FORMAT}")
        return cls(
            tuple(pathlib.Path(p) for p in body["never_write"]), tuple(pathlib.Path(p) for p in body["never_visible"]),
            tuple(decode_location(d) for d in body["lift_read"]), tuple(decode_location(d) for d in body["lift_write"]),
        )

    def refusal(self, event: str, args: tuple[object, ...]) -> str | None:
        """Why the audited operation *event* with *args* may not happen here, or None."""
        if event == "open":
            text = _text(args[0]) if args else None
            if text is None:
                return None
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else 0
            # a FileIO's event carries its flags; io.open's own, the mode as written
            writes = (isinstance(flags, int) and flags & _WRITE_FLAGS) or (isinstance(mode, str) and any(c in mode for c in "wax+"))
            return self._check(text, Act.WRITE if writes else Act.READ)
        spec = _EVENTS.get(event)
        if spec is None:
            return None
        paths, descriptors = spec
        for i in descriptors:
            if i < len(args) and isinstance(args[i], int) and args[i] != -1:
                return f"{event} relative to a directory descriptor cannot be checked by name"
        for i, act in paths:
            text = _text(args[i]) if i < len(args) else None
            if text is not None and (why := self._check(text, act)) is not None:
                return why
        return None

    def _check(self, text: str, act: Act) -> str | None:
        match act:
            case Act.READ:
                if not self.never_visible:
                    return None  # the common case, and every import: nothing to resolve
                return self._hidden(text, _target(text))
            case Act.WRITE:
                return self._written(text, _target(text), above=False)
            case Act.MAKE:
                return self._written(text, _entry(text), above=False)
            case Act.RELINK:
                return self._written(text, _entry(text), above=True)
            case Act.CHANGE:
                return self._written(text, _entry(text), above=False) or self._written(text, _target(text), above=False)

    def _hidden(self, text: str, path: pathlib.Path) -> str | None:
        for top in self.never_visible:
            if _within(path, top) and not _lifted(path, (*self.lift_read, *self.lift_write)):
                return f"{_where(text, path)} lies in {top}, which this machine's world.toml marks never-visible"
        return None

    def _written(self, text: str, path: pathlib.Path, *, above: bool) -> str | None:
        """A write at *path*: nothing under ``never-visible`` or ``never-write`` but what a
        ``lift-write`` covers; for a move, a removal or a link (*above*), nothing that holds one
        of them, lifted or not."""
        for kind, tops in (("never-visible", self.never_visible), ("never-write", self.never_write)):
            for top in tops:
                if _within(path, top) and not _lifted(path, self.lift_write):
                    return f"{_where(text, path)} lies in {top}, which this machine's world.toml marks {kind}"
                if above and _within(top, path):
                    return (f"{_where(text, path)} holds {top}, which this machine's world.toml marks {kind}: "
                            "it cannot be moved, removed or relinked")
        return None


def install(guard: Guard) -> None:
    """Hold *guard* for the rest of this process's life: an audit hook cannot be removed."""

    def hook(event: str, args: tuple[object, ...]) -> None:
        if event != "open" and event not in _EVENTS:
            return
        why = guard.refusal(event, args)
        if why is not None:
            raise PermissionError(errno.EACCES, f"certorail: {why}")

    sys.addaudithook(hook)
