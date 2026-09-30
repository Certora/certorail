"""The certorail process's own jail (FLOORS.md; LOWERING2.md, "Two worlds"): what the front end
grants it -- the host's ``/`` in host mode, the policy's world under ``[system.exec] view =
"policy"`` -- and the interpreter the policy's world is built around. ``sandbox.prepare`` builds
it from a ``ProgramRequest`` and compiles it with the run's other jails, and the run's
``Spawner`` writes it (``Spawner.launch``): bubblewrap's arguments around the interpreter on
Linux, the Seatbelt profile the bootstrap installs on itself on macOS.

Host mode checks the one thing no layer says there: a ``never-visible`` path hiding what this
interpreter needs to start, which the floor guard would refuse it mid-import. Under the policy
view the compiler says the same of the interpreter's world (``PolicyGrants.needs``).
"""
import os
import pathlib
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from certorail.childjail import View
from certorail.sandbox.front import FromFloor, program_host, program_policy
from certorail.sandbox.grants import Grants
from certorail.sandbox.interpreter import InterpreterUnavailable, InterpreterWorld, discover
from certorail.sandbox.place import CompileError, Refusal
from certorail.world import Floor, World

if TYPE_CHECKING:
    from certorail.policy import Policy


@dataclass(frozen=True)
class ProgramRequest:
    """What the certorail process's jail is built from besides the policy, the root and this
    machine's world: the interpreter that will run the program (*python*)."""

    python: str


@dataclass(frozen=True)
class ProgramJail:
    """The certorail process's jail as the front end states it, and the interpreter the policy
    view is built around (None in host mode: this one, wherever it lives)."""

    grants: Grants
    interpreter: InterpreterWorld | None


@dataclass(frozen=True)
class FromSystemView:
    """``[system.exec] view = "policy"`` itself, for a refusal no one layer causes."""

    def describe(self) -> str:
        return '[system.exec] view = "policy"'


def _within(path: pathlib.Path, top: pathlib.Path) -> bool:
    return path == top or top in path.parents


def _host_interpreter() -> tuple[pathlib.Path, ...]:
    """What this interpreter cannot start without: its prefixes and the certorail package."""
    import certorail

    return tuple(dict.fromkeys(pathlib.Path(os.path.realpath(p)) for p in (
        sys.base_prefix, sys.base_exec_prefix, pathlib.Path(certorail.__file__).resolve().parent,
    )))


def _hidden_needs(floor: Floor, needed: Sequence[pathlib.Path]) -> list[Refusal]:
    return [
        Refusal(FromFloor("never-visible", hidden), f"hides {need}, which the interpreter needs")
        for hidden in floor.visible_paths for need in needed
        if _within(need, hidden) or _within(hidden, need)
    ]


def program_jail(
    policy: "Policy", world: World, root: pathlib.Path, python: str, toolchain: Sequence[pathlib.Path],
) -> ProgramJail | CompileError:
    """The certorail process's jail for *policy* under *root* on this machine (*world*), running
    *python*; *toolchain* is what the backend's policy world holds already."""
    if policy.system.view is View.POLICY:
        try:
            interpreter = discover(python, [str(t) for t in toolchain], world.interpreter_read, world.source)
        except InterpreterUnavailable as e:
            return CompileError((Refusal(FromSystemView(), f"needs the interpreter's world: {e}"),))
        return ProgramJail(program_policy(policy, world.floor, root, interpreter, toolchain, world.stable), interpreter)
    refused = _hidden_needs(world.floor, _host_interpreter())
    if refused:
        return CompileError(tuple(refused))
    return ProgramJail(program_host(), None)
