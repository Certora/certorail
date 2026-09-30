"""What a policy says a jail holds beyond its ``[filesystem]`` section, before any backend has a
say: a rule's own mounts (``exec.mount-read`` / ``exec.mount-write``), and ``[system]`` -- the
certorail process's view, under the policy view its own mounts, and in either view the machine's
redlines it is let past (``lift-read`` / ``lift-write``). The jail compiler's front
end (``sandbox.front``) states each jail from these and the policy.
"""
from dataclasses import dataclass

from certorail.analysis import LocationFact
from certorail.childjail import View

__all__ = ["Additions", "Lifts", "SystemJail"]


@dataclass(frozen=True)
class Additions:
    """What one rule mounts for its own child beyond the section. Rules only add; a call never
    widens; the analysis never reads these."""

    read: tuple[LocationFact, ...] = ()
    write: tuple[LocationFact, ...] = ()

    @property
    def empty(self) -> bool:
        return not (self.read or self.write)


@dataclass(frozen=True)
class Lifts:
    """The machine's redlines one process is let past: readable and read-only (*read*), or
    writable (*write*). A root policy's statement; the analysis never reads these."""

    read: tuple[LocationFact, ...] = ()
    write: tuple[LocationFact, ...] = ()

    @property
    def empty(self) -> bool:
        return not (self.read or self.write)


@dataclass(frozen=True)
class SystemJail:
    """``[system]`` in the root policy: the certorail process at run time -- its view, under the
    policy view what it sees beyond the section, and the redlines it is let past."""

    view: View = View.HOST
    additions: Additions = Additions()
    lifts: Lifts = Lifts()

    def __post_init__(self) -> None:
        if self.view is not View.POLICY and not self.additions.empty:
            raise ValueError('[system.exec] mount-read / mount-write widen the policy view: they need view = "policy"')
