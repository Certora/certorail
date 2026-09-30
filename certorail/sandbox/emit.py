"""The emitters: a placed jail, linked with what changes per spawn, as the command bubblewrap
runs or the profile Seatbelt installs. Pure: every path they print was decided before them -- by
the plan, the link, the views' mountpoints.

Linking is the last step before a process starts. In the policy world the spawn's executable is
laid under the plan's layers, which decide it like anything else they cover: a grant around it
sets its access, a restriction narrows it, a view shows it or not. Its scratch directory is laid
over every layer, since none can speak for it: it is certorail's own, fresh and empty. What the
process may do besides touching files (``Process``) is rendered here too.
"""
import pathlib
from collections.abc import Mapping
from dataclasses import dataclass

from certorail import sbpl
from certorail.sandbox.grants import Access, Grant, Narrowing, Process, Restriction, State
from certorail.sandbox.place import (
    Bind, BwrapPlan, EmptyBase, HostBase, LiteralRule, Placed, RegexRule, Rule, SeatbeltPlan, Serve, SubpathRule,
)
from certorail.sandbox.tree import Own, Through, flatten

__all__ = ["Link", "bwrap_command", "seatbelt_profile"]


@dataclass(frozen=True)
class Link:
    """What one spawn adds to its jail: where it starts (absolute), the program it runs (None: not
    found, and the process will say so itself), and its private scratch directory, if it has one.
    For Seatbelt, real paths: it matches those."""

    cwd: pathlib.Path
    executable: pathlib.Path | None = None
    scratch: pathlib.Path | None = None


# -- bubblewrap ---------------------------------------------------------------------------------


def bwrap_command(
    plan: BwrapPlan, process: Process, link: Link, mountpoints: Mapping[Serve, pathlib.Path], *,
    bwrap: str, seccomp: int | None = None,
) -> list[str]:
    """The bubblewrap command around a process, up to and including ``--``. *mountpoints*: where
    each view the plan serves is attached. *seccomp*: the descriptor of the fork-denial program,
    for a tool that may not create processes; the certorail process denies itself process creation,
    in the bootstrap."""
    assert seccomp is None or not process.spawn, "a process that may create processes gets no fork denial"
    items: list[Placed] = []
    if isinstance(plan.base, EmptyBase) and link.executable is not None:
        items.append(Bind(link.executable, Access.READ_ONLY))
    items += plan.items
    if link.scratch is not None:
        items.append(Bind(link.scratch, Access.WRITABLE))
    argv = [bwrap, "--die-with-parent"]
    match plan.base:
        case HostBase(writable=True) if process.exec_:
            # the host's filesystem as the user has it, devices included (a plain --bind is
            # nodev): the programs a tool runs may need them
            argv += ["--dev-bind", "/", "/"]
        case HostBase(writable=writable):
            # read-only, or the interpreter, which opens no device: a fresh /dev and /proc
            argv += ["--bind" if writable else "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
        case EmptyBase():
            argv += ["--dev", "/dev", "--proc", "/proc", "--dir", str(link.cwd), "--chdir", str(link.cwd)]
    for mount in flatten(plan.base, items):
        writable = mount.state is State.WRITABLE
        match mount.source:
            case Own():
                # skipped where the host has nothing: a missing path covers nothing
                argv += ["--bind-try" if writable else "--ro-bind-try", str(mount.path), str(mount.path)]
            case Through(view=view, rel=rel):
                argv += ["--bind" if writable else "--ro-bind", str(mountpoints[view] / rel), str(mount.path)]
    if isinstance(plan.base, EmptyBase):
        # the root tmpfs itself -- the mountpoint chain above the mounts, the empty cwd -- is
        # read-only: a write outside every mount fails instead of vanishing into the sandbox
        argv += ["--remount-ro", "/"]
    if not process.network:
        argv.append("--unshare-net")
    if seccomp is not None:
        argv += ["--seccomp", str(seccomp)]
    return [*argv, "--"]


# -- Seatbelt -----------------------------------------------------------------------------------


def _filter(rule: Rule) -> str:
    match rule.filter:
        case SubpathRule(path=path):
            return sbpl.subpath(str(path))
        case LiteralRule(path=path):
            return sbpl.literal(str(path))
        case RegexRule(regex=regex):
            rendered = sbpl.regex(regex)
            assert rendered is not None, "place_seatbelt refuses a pattern no profile string can hold"
            return rendered


def _lines(rule: Rule) -> list[str]:
    """One layer as Seatbelt rules. Within an operation later rules win, and a rule on a specific
    operation shadows every rule on its wildcard, so reads are spelled on ``file-read-data``
    itself (measured on a Mac, 2026-09-22)."""
    f = _filter(rule)
    match rule.effect:
        case Grant(access=Access.WRITABLE):
            return [f"(allow file-read-data file-write* {f})"]
        case Grant():
            return [f"(allow file-read-data {f})", f"(deny file-write* {f})"]  # a grant sets its access
        case Restriction(narrowing=Narrowing.NO_WRITE):
            return [f"(deny file-write* {f})"]
        case Restriction():
            return [f"(deny file-read-data file-write* {f})"]


def seatbelt_profile(plan: SeatbeltPlan, process: Process, link: Link) -> str:
    """The Seatbelt profile of a process: its base, the plan's rules in order, what the spawn
    adds, and what the process may do besides touching files. Names resolve everywhere --
    metadata reads stay allowed -- and contents are what the rules say."""
    lines = ["(version 1)", "(allow default)"]
    scratch = [] if link.scratch is None else [sbpl.subpath(str(link.scratch))]
    match plan.base:
        case EmptyBase():
            lines.append("(deny file-read-data file-write*)")
            if link.executable is not None:
                lines.append(f"(allow file-read-data {sbpl.subpath(str(link.executable))})")
            lines += [line for rule in plan.rules for line in _lines(rule)]
            # after every rule, so none shadows them: the entries of / (every process reads them
            # at startup: measured 2026-09-22), the scratch directory, /dev/null
            lines.append(f"(allow file-read-data {' '.join([sbpl.literal('/'), *scratch])})")
            lines.append(f"(allow file-write* {' '.join([*scratch, sbpl.literal('/dev/null')])})")
        case HostBase(writable=False):
            lines.append("(deny file-write*)")
            lines += [line for rule in plan.rules for line in _lines(rule)]
            lines.append(f"(allow file-write* {' '.join([*scratch, sbpl.literal('/dev/null')])})")
        case HostBase():
            lines += [line for rule in plan.rules for line in _lines(rule)]
    if not process.network:
        lines.append("(deny network*)")
    if not process.spawn:
        lines.append("(deny process-fork)")
    if not process.exec_:
        lines.append("(deny process-exec*)")
    return "\n".join(lines) + "\n"
