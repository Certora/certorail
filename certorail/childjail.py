"""Jailing the children the broker spawns for ``[[program]]`` and ``[[validation]]`` grants
(JAILS.md, option B: per grant, by what the grant declares).

The confined program runs under srt; the tools and checkers its grants name run host-side, in
the broker, and by default with the host's environment and reach -- the tool is trusted as
granted. A grant's media keys and its ``exec`` table narrow that, and every narrowing is
**enforced**, a property of the process rather than a claim::

    network  = false                   # no network at all
    write-fs = false                   # no filesystem writes, save a private TMPDIR discarded after
    exec.env   = ["PATH", "HOME", { GIT_PAGER = "cat" }]   # passed through, or set; the rest is scrubbed
    exec.spawn = false                 # no process creation

``network`` and ``write-fs`` are the grant's *media* (EFFECTS.md): what the tool cannot reach it
cannot write, so the effects analysis and the jail read the same two keys. Region-level claims
that no jail could check stay declarations (``writes = [...]``). Every key defaults to the
unjailed baseline.

The mechanism is always an existing sandboxing tool: on Linux bubblewrap (a read-only bind of
the whole filesystem with the scratch directory bound writable; a private network namespace; a
seccomp filter denying the fork family, ``selfjail.fork_denial_filter``), on macOS Seatbelt
through ``sandbox-exec``. A jailed grant whose mechanism is missing fails closed
(``JailUnavailable``): the tool does not run at all.

What ``spawn = false`` does not stop: a tool replacing *itself* with another program (exec
without fork). It denies creating processes -- hooks, ``-exec``, helpers, shells -- which is
where a tool steered by the tree it reads would run something else.
"""
import contextlib
import os
import platform
import shutil
import sys
import tempfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import IO

from .selfjail import ARCHES, fork_denial_filter


@dataclass(frozen=True)
class Environment:
    """A grant's ``exec.env``: the variables passed through from the broker's environment and
    the variables set to a literal value. One flat mapping: a name is mentioned once, either
    way."""

    passed: tuple[str, ...] = ()
    sets: tuple[tuple[str, str], ...] = ()

    @property
    def empty(self) -> bool:
        return not self.passed and not self.sets


# the host's own variable: it names the scratch directory under write-fs = false
_HOST_SET = frozenset({"TMPDIR"})


def environment_spec(items: Iterable[str | Mapping[str, str]]) -> Environment:
    """``exec.env`` as written -- a string passes that variable through, a table sets each of
    its keys -- checked: names are names (no ``=``, non-empty), each mentioned once, and none
    the host sets itself."""
    passed: list[str] = []
    sets: list[tuple[str, str]] = []
    seen: set[str] = set()

    def name(n: str) -> str:
        if not n or "=" in n:
            raise ValueError(f"an environment variable name, not an assignment: {n!r}")
        if n in _HOST_SET:
            raise ValueError(f"{n} is set by the host under write-fs = false and cannot be listed")
        if n in seen:
            raise ValueError(f"environment variable {n} is mentioned twice")
        seen.add(n)
        return n

    for item in items:
        if isinstance(item, str):
            passed.append(name(item))
        else:
            for k, v in item.items():
                if not isinstance(v, str):
                    raise ValueError(f"environment variable {k}: the value must be a string")
                sets.append((name(k), v))
    return Environment(tuple(passed), tuple(sets))


@dataclass(frozen=True)
class Jail:
    """What a grant's child may reach, as the broker spawns it: the environment (None: the
    broker's, whole), the network, filesystem writes, process creation. A grant assembles one
    from its media keys and its ``exec`` table (``Program.jail``)."""

    env: Environment | None = None
    network: bool = True
    write_fs: bool = True
    spawn: bool = True

    @property
    def restricts(self) -> bool:
        """Does this jail change anything about how the child runs?"""
        return self.env is not None or not (self.network and self.write_fs and self.spawn)


UNJAILED = Jail()


class JailUnavailable(Exception):
    """The platform cannot enforce the restriction asked for; the child must not run."""


@dataclass(frozen=True)
class Spawn:
    """What to hand ``subprocess.Popen``: the command (the jail wrapper, then the tool), the
    environment, and any descriptors the wrapper reads."""

    argv: list[str]
    env: dict[str, str]
    pass_fds: tuple[int, ...] = ()


def environment(jail: Jail, base: Mapping[str, str], scratch: str | None) -> dict[str, str]:
    """The child's environment: *base* whole, or only the names *jail.env* passes through (a
    name the broker lacks is skipped) plus the values it sets; ``TMPDIR`` pointing at the
    scratch directory when there is one, since that is the one place a write-jailed tool may
    write."""
    if jail.env is None:
        env = dict(base)
    else:
        env = {k: base[k] for k in jail.env.passed if k in base}
        env.update(jail.env.sets)
    if scratch is not None:
        env["TMPDIR"] = scratch
    return env


def _bwrap(argv: Sequence[str], jail: Jail, scratch: str | None, seccomp_fd: int | None) -> list[str]:
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise JailUnavailable("bubblewrap (bwrap) is not installed; a jailed grant cannot run without it")
    command = [bwrap, "--die-with-parent"]
    if scratch is None:
        # the filesystem as the host has it, devices included (a plain --bind is nodev, and a
        # Python that cannot open /dev/urandom dies before it starts)
        command += ["--dev-bind", "/", "/"]
    else:
        # everything read-only, then the scratch directory writable over it; a fresh /dev (null,
        # zero, urandom, ...) and /proc so the tool's ordinary device writes still work
        command += ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--bind", scratch, scratch]
    if not jail.network:
        command.append("--unshare-net")
    if seccomp_fd is not None:
        command += ["--seccomp", str(seccomp_fd)]
    return [*command, "--", *argv]


def _seatbelt(argv: Sequence[str], jail: Jail, scratch: str | None) -> list[str]:
    exe = shutil.which("sandbox-exec")
    if exe is None:
        raise JailUnavailable("sandbox-exec is not available; a jailed grant cannot run without it")
    rules = ["(version 1)", "(allow default)"]
    if scratch is not None:
        # Seatbelt matches canonical paths: the per-user temp dir is under /private/var
        canonical = os.path.realpath(scratch)
        rules += ["(deny file-write*)", f'(allow file-write* (subpath "{canonical}") (literal "/dev/null"))']
    if not jail.network:
        rules.append("(deny network*)")
    if not jail.spawn:
        rules.append("(deny process-fork)")
    return [exe, "-p", " ".join(rules), *argv]


def _seccomp_program() -> IO[bytes]:
    """An open, unlinked file holding the fork-denial program, positioned at its start, for
    bubblewrap to read (``--seccomp FD``). A plain temporary file rather than a memfd: not every
    CPython build has ``os.memfd_create``."""
    machine = platform.machine()
    arch = ARCHES.get(machine)
    if arch is None:
        raise JailUnavailable(f"no seccomp filter for machine {machine!r}: spawn = false cannot be enforced")
    program = tempfile.TemporaryFile(prefix="certorail-seccomp-")
    program.write(fork_denial_filter(arch))
    program.flush()
    program.seek(0)
    return program


@contextlib.contextmanager
def confined(argv: Sequence[str], jail: Jail, base_env: Mapping[str, str] | None = None) -> Iterator[Spawn]:
    """How to spawn *argv* under *jail*: the wrapped command and the scrubbed environment, with
    the scratch directory (when writes are jailed) alive for the with-block and discarded after.
    An unrestricting jail yields *argv* as is. Raises ``JailUnavailable`` before anything runs
    when the platform cannot enforce what the jail asks."""
    base = os.environ if base_env is None else base_env
    if not jail.restricts:
        yield Spawn(list(argv), dict(base))
        return
    with contextlib.ExitStack() as stack:
        scratch = None if jail.write_fs else stack.enter_context(tempfile.TemporaryDirectory(prefix="certorail-scratch-"))
        env = environment(jail, base, scratch)
        if jail.network and jail.write_fs and jail.spawn:
            # the environment alone: no wrapper needed
            yield Spawn(list(argv), env)
        elif sys.platform == "linux":
            seccomp_fd = None if jail.spawn else stack.enter_context(_seccomp_program()).fileno()
            yield Spawn(_bwrap(argv, jail, scratch, seccomp_fd), env, () if seccomp_fd is None else (seccomp_fd,))
        elif sys.platform == "darwin":
            yield Spawn(_seatbelt(argv, jail, scratch), env)
        else:
            raise JailUnavailable(f"no child jail for platform {sys.platform!r}")
