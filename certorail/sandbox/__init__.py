"""The platform mechanism bound to one run: a ``Spawner`` realises a ``Confinement`` as the
command that actually runs the child (``certorail.confinement``, JAILS.md, MOUNTS.md).

``provision(policy, root)`` is the one platform switch. It returns the spawner for this host --
bubblewrap on Linux, Seatbelt on macOS -- with whatever run-scoped resources the policy needs
already provisioned (on Linux, the FUSE view of the root when the section has a pattern no bind
expresses). The spawner is a context manager over those resources' lifetime; a run holds it open
from before its first child to after its last.

Two operations, both per confinement:

- ``lower(fs, write_fs)``: the pure step. Every location of a ``PolicyFilesystem`` becomes one
  ``Lowered`` value saying what this mechanism does with it (``sandbox.lowering``). What the host
  announces at startup is the ``Omitted`` values over the confined rules; what a plan binds is the
  rest.
- ``spawn(confinement, argv, cwd)``: a context manager yielding the ``Spawn`` for ``Popen`` --
  the wrapped command, the scrubbed environment, the descriptors to pass -- with the per-spawn
  scratch directory alive for the with-block. Nothing is executed here.

The spawners are plain constructors: ``BubblewrapSpawner(root_view=NoView("..."))`` and
``SeatbeltSpawner()`` build on any OS, so ``lower`` and ``spawn`` are testable without the
machine; only ``provision`` touches it.
"""
import sys
from collections.abc import Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from ..childjail import JailUnavailable, Spawn
from ..confinement import Confinement, PolicyFilesystem
from .lowering import Bind, Lowered, Omitted, RegexRule

if TYPE_CHECKING:
    from ..policy import Policy  # the live path imports this package; policy is a caller, not a dependency

__all__ = [
    "Bind",
    "JailUnavailable",
    "Lowered",
    "NoView",
    "Omitted",
    "RegexRule",
    "ServedRoot",
    "Spawn",
    "Spawner",
    "provision",
]


@dataclass(frozen=True)
class ServedRoot:
    """The FUSE view stands for the root for this run (bubblewrap): bound at the root's real
    path before every other bind. The lease is its lifetime."""

    mountpoint: Path
    root: Path


@dataclass(frozen=True)
class NoView:
    """No FUSE view this run, and why: the section needs none, or the host cannot serve one."""

    reason: str


class Spawner(AbstractContextManager["Spawner"], Protocol):
    """A mechanism bound to one run's resources."""

    def lower(self, fs: PolicyFilesystem, write_fs: bool) -> tuple[Lowered, ...]:
        """What this mechanism does with each location of *fs* that is its own to express, in
        the order a plan applies them (what the FUSE view answers for is not among them)."""
        ...

    def spawn(
        self, confinement: Confinement, argv: Sequence[str], cwd: Path, base_env: dict[str, str] | None = None,
    ) -> AbstractContextManager[Spawn]:
        """How to run *argv* at *cwd* under *confinement*; the scratch directory (when the
        confinement needs one) lives for the with-block."""
        ...


def omissions(spawner: Spawner, policy: "Policy", root: Path) -> tuple[Omitted, ...]:
    """What the confined rules' worlds leave out, distinct, in rule order: the startup report."""
    out: list[Omitted] = []
    for rule in (*policy.programs, *policy.validations):
        c = policy.confinement(rule, root)
        if not isinstance(c.filesystem, PolicyFilesystem):
            continue
        for lowered in spawner.lower(c.filesystem, c.write_fs):
            if isinstance(lowered, Omitted) and lowered not in out:
                out.append(lowered)
    return tuple(out)


def provision(policy: "Policy", root: Path) -> Spawner:
    """The spawner for this host, its run-scoped resources provisioned for *policy* under
    *root*. Raises ``JailUnavailable`` on a platform with no mechanism."""
    if sys.platform == "linux":
        from .bubblewrap import BubblewrapSpawner

        return BubblewrapSpawner.provision(policy, root)
    if sys.platform == "darwin":
        from .seatbelt import SeatbeltSpawner

        return SeatbeltSpawner()
    raise JailUnavailable(f"no child jail for platform {sys.platform!r}")
