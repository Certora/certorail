"""One run's jails: each stated by the front end (``front``), checked and placed for this
machine's backend when the run starts (``place``), the views they need attached, and each spawn
linked and emitted (``emit``) -- bubblewrap on Linux, Seatbelt on macOS.

``prepare(policy, root, program)`` builds the certorail process's jail from *program*, when the
run has one, and compiles it with every tool's and checker's, by its rule's media and ``exec``
table, then attaches the union of their views. What cannot be held refuses the run before
anything runs (``CompileError``): a layer this backend cannot hold, a view this machine cannot
serve or that fails to attach, a jail whose wrapper (bubblewrap, ``sandbox-exec``) is not on
PATH, a bubblewrap plan the placement checker does not certify, or no checker to ask
(``certify``). Nothing is ever left out of a jail, and no jail is ever left off.

A tool's jail lives for one exec and is spawned many times: each spawn asks the placer's
questions of the filesystem again. Where an answer changed -- a directory became a link since
the run started -- the jail is placed again, and certified again, and a spawn whose new plan
needs a view the run did not attach, or is not certified, is refused, naming what changed: the one
way a run is refused after it starts.

``Spawner.unattached`` is for a spawn with no run around it (a broker or a literal checker on
their own): each jail compiled when first spawned, and no views, so a jail that needs one is
refused.
"""
import contextlib
import enum
import os
import pathlib
import shutil
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from certorail.analysis import LocationFact
from certorail.childjail import Jail, JailUnavailable, Spawn
from certorail.sandbox.certify import Checker, CheckerUnavailable, Refused, document, locate
from certorail.sandbox.common import environment, executable, scratch
from certorail.sandbox.emit import Link, bwrap_command, seatbelt_profile
from certorail.sandbox.facts import Disk, Facts, Recorded
from certorail.sandbox.front import tool
from certorail.sandbox.grants import Grants, HostGrants, PolicyGrants
from certorail.sandbox.interpreter import InterpreterWorld
from certorail.sandbox.place import (
    BwrapPlan, CompileError, Refusal, SeatbeltPlan, Serve, place_bubblewrap, place_seatbelt,
)
from certorail.sandbox.program import ProgramRequest, program_jail
from certorail.world import World

if TYPE_CHECKING:
    from certorail.policy import Policy, Program, Validation
    from certorail.viewdaemon import Attachment, ViewSpec

__all__ = [
    "Backend", "Compiled", "CompiledProgram", "Launch", "SelfInstalled", "Spawner", "Wrapped", "compile_jail",
    "prepare",
]


class Backend(enum.Enum):
    BUBBLEWRAP = "bubblewrap"
    SEATBELT = "Seatbelt"

    @classmethod
    def of(cls, platform: str = sys.platform) -> "Backend":
        """*platform*'s backend. Raises ``JailUnavailable`` on a platform with none."""
        if platform == "linux":
            return cls.BUBBLEWRAP
        if platform == "darwin":
            return cls.SEATBELT
        raise JailUnavailable(f"no jail for platform {platform!r}")

    @property
    def toolchain(self) -> tuple[pathlib.Path, ...]:
        """What a policy world holds besides the policy's own grants."""
        from certorail.sandbox import bubblewrap, seatbelt

        return tuple(pathlib.Path(p) for p in (bubblewrap.TOOLCHAIN if self is Backend.BUBBLEWRAP else seatbelt.TOOLCHAIN))

    @property
    def wrapper(self) -> str:
        """The program that jails a process from outside it: bubblewrap, or ``sandbox-exec`` for
        a tool on macOS, where the certorail process installs its own profile instead."""
        return "bwrap" if self is Backend.BUBBLEWRAP else "sandbox-exec"

    @property
    def wrapper_name(self) -> str:
        return "bubblewrap (bwrap)" if self is Backend.BUBBLEWRAP else "sandbox-exec"


@dataclass(frozen=True)
class Compiled:
    """A jail placed for a backend: its grants, the plan, and what placing it read of the
    filesystem, which each spawn asks again."""

    grants: Grants
    plan: BwrapPlan | SeatbeltPlan
    facts: Recorded

    @property
    def views(self) -> tuple[Serve, ...]:
        return self.plan.views if isinstance(self.plan, BwrapPlan) else ()


@dataclass(frozen=True)
class CompiledProgram:
    """The certorail process's jail, compiled, and the interpreter its policy view is built around
    (None in host mode: the run's own, wherever it lives)."""

    compiled: Compiled
    interpreter: InterpreterWorld | None


@dataclass(frozen=True)
class Wrapped:
    """The certorail process starts inside *prefix*: bubblewrap's command, up to ``--``."""

    prefix: tuple[str, ...]


@dataclass(frozen=True)
class SelfInstalled:
    """The certorail process installs *profile* on itself, first thing (``selfjail``): Seatbelt,
    where a process already sandboxed cannot sandbox itself again, so nothing may wrap it."""

    profile: str


@dataclass(frozen=True)
class Launch:
    """How the certorail process starts in its jail: the interpreter to run (None: the one the run
    was given) and the jail around it or inside it."""

    executable: pathlib.Path | None
    jail: Wrapped | SelfInstalled


@dataclass(frozen=True)
class Wrapper:
    """A backend's wrapper, as the origin of the refusal when it is missing."""

    backend: Backend

    def describe(self) -> str:
        return self.backend.wrapper_name


def _wrapped(grants: Grants) -> bool:
    """Does a tool's or a checker's jail need the backend's wrapper? Every one but the host's own
    filesystem, writable, with the network and process creation, and no redline over it: that
    runs as it is."""
    process = grants.process
    return not (
        isinstance(grants, HostGrants) and grants.writable and process.network and process.spawn and not grants.layers
    )


def compile_jail(grants: Grants, backend: Backend, facts: Facts, *, view_unavailable: str | None) -> Compiled | CompileError:
    """*grants* checked and placed for *backend*, against *facts*. *view_unavailable*: why no view
    can be had, when none can; a layer that needs one is then refused."""
    recorded = Recorded(facts)
    if backend is Backend.BUBBLEWRAP:
        placed: BwrapPlan | SeatbeltPlan | CompileError = place_bubblewrap(grants, recorded, view_unavailable=view_unavailable)
    else:
        placed = place_seatbelt(grants, recorded)
    return placed if isinstance(placed, CompileError) else Compiled(grants, placed, recorded)


@dataclass(frozen=True)
class PlacementChecker:
    """The placement checker, as the origin of what it refuses."""

    def describe(self) -> str:
        return "the placement checker"


def _certify(jails: Sequence[tuple[str, Compiled]], checker: Checker | str) -> list[Refusal]:
    """Every bubblewrap plan among *jails* (each named by whose jail it is) certified in one go;
    a refusal for each the checker does not certify, or for all when it cannot be asked. A jail
    nothing wraps, or that Seatbelt holds, has no mounts to certify."""
    plans = [(name, c) for name, c in jails if isinstance(c.plan, BwrapPlan) and _wrapped(c.grants)]
    if not plans:
        return []
    names = ", ".join(dict.fromkeys(name for name, _ in plans))
    if isinstance(checker, str):
        return [Refusal(PlacementChecker(), f"cannot certify the jails of {names}: {checker}")]
    documents = []
    for _, c in plans:
        assert isinstance(c.plan, BwrapPlan)
        documents.append(document(c.grants, c.plan, c.facts))
    try:
        verdicts = checker.certify(documents)
    except CheckerUnavailable as e:
        return [Refusal(PlacementChecker(), f"cannot certify the jails of {names}: {e}")]
    return [
        Refusal(PlacementChecker(), f"does not certify {name}'s jail: " + "; ".join(verdict.reasons))
        for (name, _), verdict in zip(plans, verdicts) if isinstance(verdict, Refused)
    ]


# what decides a rule's jail: its media and exec table, its mounts, and its lifts
type RuleJail = tuple[Jail, tuple[LocationFact, ...], tuple[LocationFact, ...], tuple[LocationFact, ...], tuple[LocationFact, ...]]


def _jail_of(rule: "Program | Validation") -> RuleJail:
    return rule.jail, rule.mount_read, rule.mount_write, rule.lift_read, rule.lift_write


def _spec(view: Serve, strict: bool) -> "ViewSpec":
    from certorail.viewdaemon import ViewSpec

    return ViewSpec.holding(view.directory, view.layers, strict=strict)


def _real(path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.realpath(path))


class Spawner:
    """One run's jails -- the certorail process's (when the run has one) and its tools' and
    checkers' -- the wrapper that holds them from outside (*wrapper*: the backend's, where it was
    found), and the views attached for them: a context manager over the views' leases, held from
    before the run's first spawn to after its last."""

    def __init__(
        self, policy: "Policy", root: pathlib.Path, backend: Backend, facts: Facts, *,
        tools: dict[RuleJail, Compiled], program: CompiledProgram | None, attached: "dict[ViewSpec, Attachment]",
        view_unavailable: str | None, wrapper: str | None, world: World, checker: Checker | str,
    ) -> None:
        self._policy = policy
        self._root = root
        self._backend = backend
        self._facts = facts
        self._tools = tools
        self._program = program
        self._attached = attached
        self._view_unavailable = view_unavailable
        self._wrapper = wrapper
        self._world = world
        self._checker = checker

    @classmethod
    def unattached(
        cls, policy: "Policy", root: pathlib.Path, *, platform: str = sys.platform, world: World = World(),
        checker: Checker | str | None = None,
    ) -> "Spawner":
        """For a spawn with no run around it: each jail compiled, and certified, when first
        spawned, on this machine (*world*: its floor and stability model) when the caller has it,
        and no views, so a jail that needs one is refused. *checker*: the placement checker
        (default: ``certify.locate``), or why there is none. Raises ``JailUnavailable`` on a
        platform with no backend."""
        backend = Backend.of(platform)
        return cls(policy, root, backend, Disk(), tools={}, program=None, attached={},
                   view_unavailable="a spawn outside a run attaches no view", wrapper=shutil.which(backend.wrapper),
                   world=world, checker=locate() if checker is None else checker)

    def __enter__(self) -> "Spawner":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        for attachment in self._attached.values():
            attachment.close()
        self._attached.clear()

    def mountpoints(self, compiled: Compiled) -> dict[Serve, pathlib.Path]:
        """Where each view *compiled* needs is attached."""
        return {view: self._attached[_spec(view, self._world.view_strict)].mountpoint for view in compiled.views}

    def _current(self, rule: "Program | Validation") -> Compiled:
        """*rule*'s jail as it must be placed now: as compiled -- when the run started, or here,
        first, with no run -- or placed again where what it was placed against has changed."""
        key = _jail_of(rule)
        compiled = self._tools.get(key)
        changed = () if compiled is None else compiled.facts.changed(self._facts)
        if compiled is not None and not changed:
            return compiled
        grants = tool(self._policy, rule, self._root, self._backend.toolchain, self._world.floor, self._world.stable)
        placed = compile_jail(grants, self._backend, self._facts, view_unavailable=self._view_unavailable)
        since = "" if not changed else "since the run started, " + "; ".join(c.describe() for c in changed) + ", and "
        if isinstance(placed, CompileError):
            raise JailUnavailable(f"{since}{rule.name}'s jail cannot be held: " + "; ".join(r.describe() for r in placed.refusals))
        # with no wrapper, no wrapped jail spawns (``_held_by_wrapper`` says why), and the rest
        # have nothing to certify
        uncertified = [] if self._wrapper is None else _certify([(rule.name, placed)], self._checker)
        if uncertified:
            raise JailUnavailable(f"{since}{rule.name}'s jail cannot be held: " + "; ".join(r.describe() for r in uncertified))
        missing = [str(view.directory) for view in placed.views if _spec(view, self._world.view_strict) not in self._attached]
        if missing:
            raise JailUnavailable(f"{since}{rule.name}'s jail needs a view of {', '.join(missing)}, which the run did not attach")
        self._tools[key] = placed
        return placed

    def _held_by_wrapper(self) -> str:
        """The wrapper, for a jail that needs it. A run's spawner has it whenever one of its jails
        does (``prepare``); one with no run finds out here."""
        if self._wrapper is None:
            raise JailUnavailable(f"{self._backend.wrapper_name} is not on PATH; a jailed grant cannot run without it")
        return self._wrapper

    def launch(self) -> Launch | None:
        """How the certorail process starts in its jail, or None when the run has none. Nothing
        runs here."""
        if self._program is None:
            return None
        compiled = self._program.compiled
        executable = None if self._program.interpreter is None else self._program.interpreter.executable
        process = compiled.grants.process
        match compiled.plan:
            case BwrapPlan() as plan:
                link = Link(self._root, executable)
                command = bwrap_command(plan, process, link, self.mountpoints(compiled), bwrap=self._held_by_wrapper())
                return Launch(executable, Wrapped(tuple(command)))
            case SeatbeltPlan() as plan:
                # Seatbelt matches real paths
                return Launch(executable, SelfInstalled(seatbelt_profile(plan, process, Link(_real(self._root), executable))))

    @contextlib.contextmanager
    def spawn(
        self, rule: "Program | Validation", argv: Sequence[str], cwd: pathlib.Path, base_env: Mapping[str, str] | None = None,
    ) -> Iterator[Spawn]:
        """How to run *argv* at *cwd* in *rule*'s jail -- the command, the environment, the
        descriptors to pass -- with the scratch directory alive for the with-block. Nothing runs
        here. Raises ``JailUnavailable`` when the jail cannot be held now."""
        compiled = self._current(rule)
        grants = compiled.grants
        process = grants.process
        base = dict(os.environ) if base_env is None else dict(base_env)
        if not _wrapped(grants):
            yield Spawn(list(argv), environment(process.env, base, None))  # the environment alone: nothing to wrap
            return
        with contextlib.ExitStack() as stack:
            # a private TMPDIR: the one writable place under write-fs = false, and there is no /tmp
            # in the policy world
            tmp = stack.enter_context(scratch(isinstance(grants, PolicyGrants) or not grants.writable))
            env = environment(process.env, base, tmp)
            here = pathlib.Path(os.path.abspath(cwd))
            exe = executable(argv, env, here)
            wrapper = self._held_by_wrapper()
            match compiled.plan:
                case BwrapPlan() as plan:
                    seccomp: int | None = None
                    if not process.spawn:
                        from certorail.sandbox.bubblewrap import seccomp_program

                        seccomp = stack.enter_context(seccomp_program()).fileno()
                    link = Link(here, exe, tmp)
                    command = bwrap_command(plan, process, link, self.mountpoints(compiled), bwrap=wrapper, seccomp=seccomp)
                    yield Spawn([*command, *argv], env, () if seccomp is None else (seccomp,))
                case SeatbeltPlan() as plan:
                    # Seatbelt matches real paths: the per-user temp directory is under /private/var
                    link = Link(_real(here), None if exe is None else _real(exe), None if tmp is None else _real(tmp))
                    yield Spawn([wrapper, "-p", seatbelt_profile(plan, process, link), *argv], env)


def prepare(
    policy: "Policy", root: pathlib.Path, program: ProgramRequest | None = None, *,
    world: World = World(), platform: str = sys.platform, facts: Facts = Disk(),
    checker: Checker | str | None = None,
) -> Spawner | CompileError:
    """Every jail of a run under *policy* at *root* on this machine (*world*: its redlines, its
    stability model) compiled -- the certorail process's, built from *program* when the run has
    one, and each tool's and checker's -- each bubblewrap plan certified, the wrapper they need
    found, and the union of their views attached; every reason the run cannot have them
    otherwise. *checker*: the placement checker (default: ``certify.locate``), or why there is
    none. Raises ``JailUnavailable`` on a platform with no backend."""
    from certorail.viewdaemon import ViewUnavailable, attach, unavailable

    backend = Backend.of(platform)
    view_unavailable = unavailable() if backend is Backend.BUBBLEWRAP else None
    refusals: list[Refusal] = []
    # the jails the wrapper holds from outside, by name: every wrapped tool's and checker's, and on
    # Linux the certorail process's (on macOS it installs its own profile)
    wrapped: list[str] = []

    def refuse(error: CompileError) -> None:
        refusals.extend(r for r in error.refusals if r not in refusals)

    def compiled(grants: Grants) -> Compiled | None:
        placed = compile_jail(grants, backend, facts, view_unavailable=view_unavailable)
        if isinstance(placed, CompileError):
            refuse(placed)
            return None
        return placed

    own: CompiledProgram | None = None
    if program is not None:
        jail = program_jail(policy, world, root, program.python, backend.toolchain)
        if isinstance(jail, CompileError):
            refuse(jail)
        else:
            if backend is Backend.BUBBLEWRAP:
                wrapped.append("the certorail process")
            if (placed := compiled(jail.grants)) is not None:
                own = CompiledProgram(placed, jail.interpreter)
    tools: dict[RuleJail, Compiled] = {}
    grants_of: dict[RuleJail, Grants] = {}
    named: dict[RuleJail, list[str]] = {}
    for rule in (*policy.programs, *policy.validations):
        key = _jail_of(rule)
        named.setdefault(key, [])
        if rule.name not in named[key]:
            named[key].append(rule.name)
        if key not in grants_of:
            grants_of[key] = tool(policy, rule, root, backend.toolchain, world.floor, world.stable)
            if (placed := compiled(grants_of[key])) is not None:
                tools[key] = placed
        if _wrapped(grants_of[key]) and rule.name not in wrapped:
            wrapped.append(rule.name)
    if checker is None:
        checker = locate()
    wrapper = shutil.which(backend.wrapper)
    if wrapper is None and wrapped:
        refusals.append(Refusal(Wrapper(backend), f"is not on PATH, and it holds the jails of {', '.join(wrapped)}"))
    elif wrapper is not None:
        placed_jails = [("the certorail process", own.compiled)] if own is not None else []
        placed_jails += [(" and ".join(named[key]), c) for key, c in tools.items()]
        refuse(CompileError(tuple(_certify(placed_jails, checker))))
    if refusals:
        return CompileError(tuple(refusals))
    attached: dict[ViewSpec, Attachment] = {}
    for view in (v for c in (*([] if own is None else [own.compiled]), *tools.values()) for v in c.views):
        spec = _spec(view, world.view_strict)
        if spec in attached:
            continue
        try:
            attached[spec] = attach(spec)
        except ViewUnavailable as e:
            for attachment in attached.values():
                attachment.close()
            return CompileError(tuple(
                Refusal(layer.origin, f"is held in a view of {view.directory}, which did not attach: {e}") for layer in view.layers
            ))
    return Spawner(policy, root, backend, facts, tools=tools, program=own, attached=attached,
                   view_unavailable=view_unavailable, wrapper=wrapper, world=world, checker=checker)
