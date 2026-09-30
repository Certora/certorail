"""The jail compiler's front end (LOWERING2.md, "Two worlds"; REDLINES.md): the policy, the
machine's floor and the root, stated as each jail's grants. What each jail gets is decided here
and nowhere else; how a backend holds it is the passes' (``place``).

- ``program_host``: the certorail process in host mode -- the host's ``/``, the user's authority.
  The machine's redlines are the floor guard's (``floorguard``), in the process.
- ``program_policy``: the certorail process under ``[system.exec] view = "policy"``.
- ``tool``: a tool's or a checker's jail, by its rule's ``exec.view``. The machine's redlines
  bind it in either view.

A policy jail's layers come as every read grant, then every write grant, then every restriction:
the policy's grants are a union, and in that order the ordered meaning (``state_at``) is the
union's. The machine's redlines follow, and last the lifts of them a root policy wrote for that
process, over their own paths.
"""
import pathlib
from collections.abc import Sequence
from dataclasses import dataclass

from typing import TYPE_CHECKING

from certorail.analysis import DirSplat, LocationFact, StaticPath, pretty_location
from certorail.childjail import View
from certorail.locations import bindable_paths
from certorail.sandbox.grants import (
    Access, Exactly, Grant, HostGrants, Layer, Lifetime, Narrowing, Pattern, PolicyGrants, Process,
    Region, Restriction, Subtree,
)
from certorail.sandbox.interpreter import InterpreterWorld
from certorail.world import Floor, Stable

if TYPE_CHECKING:
    from certorail.policy import Policy, Program, Validation

__all__ = ["program_host", "program_policy", "tool"]


# -- origins ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class FromPolicy:
    what: str   # "read grant", "write grant", "no-write", "[system.exec] mount-read", ...
    location: LocationFact

    def describe(self) -> str:
        return f"{self.what} {pretty_location(self.location)}"


@dataclass(frozen=True)
class FromFloor:
    what: str   # "never-write", "never-visible"
    path: pathlib.Path

    def describe(self) -> str:
        return f"this machine's {self.what} {self.path}"


@dataclass(frozen=True)
class FromToolchain:
    path: pathlib.Path

    def describe(self) -> str:
        return f"the toolchain's {self.path}"


@dataclass(frozen=True)
class FromInterpreter:
    path: pathlib.Path

    def describe(self) -> str:
        return f"the interpreter's {self.path}"


# -- regions ------------------------------------------------------------------------------------


def _regions(loc: LocationFact, root: pathlib.Path, *, wide: bool) -> tuple[Region, ...]:
    """*loc* as regions: the paths it is exactly the union of, or one pattern. Grants read narrow
    and protections wide: with *wide*, a literal path is its whole subtree (``no-write = ["foo"]``
    protects ``foo/bar`` too), where a grant ``read = ["foo"]`` is ``foo`` alone."""
    paths = bindable_paths(loc, root)
    if paths is None:
        return (Pattern(loc, pathlib.Path("/") if loc.absolute else root),)
    match loc:
        case StaticPath():
            return tuple(Subtree(p) if wide else Exactly(p) for p in paths)
        case DirSplat():
            return tuple(Subtree(p) for p in paths)


def _layers(what: str, locs: Sequence[LocationFact], root: pathlib.Path,
            effect: Grant | Restriction) -> list[Layer[Region]]:
    wide = isinstance(effect, Restriction)
    return [Layer(r, effect, FromPolicy(what, loc)) for loc in locs for r in _regions(loc, root, wide=wide)]


def _floor(floor: Floor) -> list[Layer[Region]]:
    """``never-write`` and ``never-visible``: they cut into what the policy grants, and the analysis
    never reads ``world.toml``, so the jail alone stops them."""
    return [
        *(Layer(Subtree(p), Restriction(Narrowing.NO_WRITE, sole=True), FromFloor("never-write", p))
          for p in floor.write_paths),
        *(Layer(Subtree(p), Restriction(Narrowing.HIDDEN, sole=True), FromFloor("never-visible", p))
          for p in floor.visible_paths),
    ]


def _lifts(whose: str, reads: Sequence[LocationFact], writes: Sequence[LocationFact], root: pathlib.Path) -> list[Layer[Region]]:
    """A process's lifts of the redlines, as grants after them over their own paths: readable and
    read-only, or writable (REDLINES.md). Whether each lies in a redline it may lift was judged at
    load (``world.floor_findings``)."""
    return [
        *_layers(f"{whose} lift-read", reads, root, Grant(Access.READ_ONLY)),
        *_layers(f"{whose} lift-write", writes, root, Grant(Access.WRITABLE)),
    ]


# the certorail process: the broker is an inherited socket, and it creates no process
_PROGRAM = Process(network=False, spawn=False, exec_=False)


# -- the jails ----------------------------------------------------------------------------------


def program_host() -> HostGrants:
    """The certorail process in host mode: the host's ``/``, writable where unix allows. The
    program reaches it through the names the analysis proves, wherever they lead."""
    return HostGrants(True, Lifetime.RUN, _PROGRAM)


def program_policy(policy: "Policy", floor: Floor, root: pathlib.Path,
                   interpreter: InterpreterWorld, toolchain: Sequence[pathlib.Path], stable: Stable = Stable()) -> PolicyGrants:
    """The certorail process under ``[system.exec] view = "policy"``: the toolchain and the
    interpreter's world, the policy's read and write grants with the ``[system.exec]`` mounts,
    then the policy's ``no-write`` and the machine's floor; *stable*, the machine's stability
    model, says what else the run may bind plainly."""
    held = Grant(Access.READ_ONLY, stable=True)  # what a run does not replace: bound as it leads
    layers: list[Layer[Region]] = [Layer(Subtree(p), held, FromToolchain(p)) for p in toolchain]
    layers += [Layer(Subtree(p), held, FromInterpreter(p)) for p in interpreter.paths]
    layers += _layers("read grant", policy.read, root, Grant(Access.READ_ONLY))
    layers += _layers("[system.exec] mount-read", policy.system.additions.read, root, Grant(Access.READ_ONLY))
    layers += _layers("write grant", policy.write, root, Grant(Access.WRITABLE))
    layers += _layers("[system.exec] mount-write", policy.system.additions.write, root, Grant(Access.WRITABLE))
    # the analysis enforces the policy's no-write on the program's own writes, by name
    layers += _layers("no-write", policy.no_write, root, Restriction(Narrowing.NO_WRITE, sole=False))
    layers += _floor(floor)
    layers += _lifts("[system.exec]", policy.system.lifts.read, policy.system.lifts.write, root)
    return PolicyGrants(tuple(layers), Lifetime.RUN, _PROGRAM, root, interpreter.paths, interpreter.listed, workdir=root, stable=stable)


def tool(policy: "Policy", rule: "Program | Validation", root: pathlib.Path,
         toolchain: Sequence[pathlib.Path], floor: Floor = Floor(), stable: Stable = Stable()) -> HostGrants | PolicyGrants:
    """A tool's or a checker's jail, for one exec, under this machine's *floor* and stability
    model (*stable*). The host view is the host's ``/``, read-only under ``write-fs = false``,
    with the redlines and the rule's lifts over it, their views at the stable directories above
    them. The policy view is the toolchain and the policy's section; the policy's ``no-write``
    blocks names the analysis lets through (it sees a tool's arguments, never what the tool writes
    of its own accord), so the jail alone holds it; then the redlines, then the lifts."""
    process = Process(rule.network, rule.spawn, exec_=True, env=rule.env)
    redlines = [*_floor(floor), *_lifts(f"{rule.name}'s", rule.lift_read, rule.lift_write, root)]
    if rule.view is View.HOST:
        return HostGrants(rule.write_fs, Lifetime.EXEC, process, tuple(redlines), root, stable)
    write = Grant(Access.WRITABLE if rule.write_fs else Access.READ_ONLY)
    layers: list[Layer[Region]] = [Layer(Subtree(p), Grant(Access.READ_ONLY, stable=True), FromToolchain(p)) for p in toolchain]
    layers += _layers("read grant", policy.read, root, Grant(Access.READ_ONLY))
    layers += _layers(f"{rule.name}'s mount-read", rule.mount_read, root, Grant(Access.READ_ONLY))
    layers += _layers("write grant", policy.write, root, write)
    layers += _layers(f"{rule.name}'s mount-write", rule.mount_write, root, write)
    layers += _layers("no-write", policy.no_write, root, Restriction(Narrowing.NO_WRITE, sole=True))
    layers += redlines
    return PolicyGrants(tuple(layers), Lifetime.EXEC, process, root, stable=stable)
