"""What a grant's child may do: the rule's contract, with no operating system in sight.

A ``Confinement`` is built in exactly one place, ``Policy.confinement(rule, root)``, from the
rule's media keys and ``exec`` table, and handed to a platform ``Spawner`` (``certorail.sandbox``)
that realises it. Its filesystem half is one of two variants, never a set of nullable knobs:

- ``HostFilesystem``: the host's filesystem, whole (read-only under ``write_fs = False``); the
  tool is trusted as granted. ``exec.view = "host"``, the default.
- ``PolicyFilesystem``: the policy's ``[filesystem]`` section under the root, plus what the rule
  itself mounts (``exec.mount-read`` / ``exec.mount-write``); nothing else exists for the child.
  ``exec.view = "policy"``.

The invariants the schema and the constructors check separately today are held here once: a
rule mounts additions only under the policy filesystem, and writable additions only with the
filesystem medium.
"""
import pathlib
from dataclasses import dataclass

from certorail.analysis import LocationFact
from certorail.childjail import Environment
from certorail.locations import single_path

__all__ = [
    "Additions",
    "Confinement",
    "Environment",
    "FilesystemSection",
    "HostFilesystem",
    "PolicyFilesystem",
]


@dataclass(frozen=True)
class FilesystemSection:
    """The policy's ``[filesystem]`` section: what the program is held to, and what a confined
    tool sees. Relative locations anchor at the root, absolute ones at the filesystem root."""

    read: tuple[LocationFact, ...] = ()
    write: tuple[LocationFact, ...] = ()
    no_write: tuple[LocationFact, ...] = ()
    listing: tuple[LocationFact, ...] = ()

    @property
    def relative_patterns(self) -> tuple[LocationFact, ...]:
        """The root-relative locations no bind mount expresses: what a FUSE view is for."""
        probe = pathlib.Path("/")
        return tuple(
            loc for loc in (*self.read, *self.write, *self.no_write)
            if not loc.absolute and single_path(loc, probe) is None
        )


@dataclass(frozen=True)
class Additions:
    """What one rule mounts for its own child beyond the section. Rules only add; a call never
    widens; the analysis never reads these."""

    read: tuple[LocationFact, ...] = ()
    write: tuple[LocationFact, ...] = ()

    @property
    def empty(self) -> bool:
        return not (self.read or self.write)


class HostFilesystem:
    """The host's filesystem, as the host sees it."""

    def __repr__(self) -> str:
        return "HostFilesystem()"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, HostFilesystem)

    def __hash__(self) -> int:
        return hash(HostFilesystem)


@dataclass(frozen=True)
class PolicyFilesystem:
    """The policy's section under *root*, and the rule's additions, and nothing else."""

    root: pathlib.Path
    section: FilesystemSection
    additions: Additions = Additions()


@dataclass(frozen=True)
class Confinement:
    """What the child may reach: its environment (None: the host's, whole), the network, the
    filesystem medium, process creation, and which filesystem it sees."""

    env: Environment | None = None
    network: bool = True
    write_fs: bool = True
    spawn: bool = True
    filesystem: HostFilesystem | PolicyFilesystem = HostFilesystem()

    def __post_init__(self) -> None:
        if isinstance(self.filesystem, PolicyFilesystem) and self.filesystem.additions.write and not self.write_fs:
            raise ValueError("mount-write with write-fs = false: nothing it mounts could be written")

    @property
    def restricts(self) -> bool:
        """Does this confinement change anything about how the child runs?"""
        return (
            self.env is not None
            or not (self.network and self.write_fs and self.spawn)
            or isinstance(self.filesystem, PolicyFilesystem)
        )

    @property
    def needs_scratch(self) -> bool:
        """A private ``TMPDIR``: the one writable place under ``write_fs = False``, and always
        under the policy filesystem (there is no ``/tmp`` in that world)."""
        return not self.write_fs or isinstance(self.filesystem, PolicyFilesystem)


UNCONFINED = Confinement()
