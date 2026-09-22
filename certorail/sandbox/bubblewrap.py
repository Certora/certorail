"""The Linux spawner: bubblewrap, with the FUSE view of the root as its one run-scoped resource.

Lowering (``lower``): a location that is one path is a ``Bind``; a pattern without a view, or
outside the root, is ``Omitted`` with the reason. When the run has the view, the root-relative
section is not lowered at all: the view is one bind of the root and the daemon enforces the
section behind it. The rule's additions are always binds when they are one path -- over the
view, if there is one, since an addition is the rule's own trust statement -- and omitted when
they are patterns. ``list`` grants are the view's or nothing: a bind exposes contents, so there
is no bind that lists.

Spawning (``spawn``): the host filesystem is today's world -- the whole filesystem, read-only
under ``write_fs = False`` with the scratch directory writable over it. The policy filesystem is
an empty root holding the toolchain, the tool, a fresh ``/dev`` and ``/proc``, the cwd as an empty
directory, the scratch directory, the view bound at the root (writable iff ``write_fs``), then
the binds in application order -- reads, writes (writable iff ``write_fs``), the additions, the
protections read-only on top -- and the root remounted read-only last, so a write to a path
outside every bind fails instead of landing in the discarded sandbox.
"""
import contextlib
import os
import pathlib
import platform
import shutil
import tempfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import IO

from typing import TYPE_CHECKING

from certorail.childjail import JailUnavailable, Spawn
from certorail.confinement import Confinement, HostFilesystem, PolicyFilesystem
from certorail.locations import single_path
from certorail.selfjail import ARCHES, fork_denial_filter
from certorail.viewdaemon import Attachment, ViewSpec, ViewUnavailable, attach
from certorail.sandbox import NoView, ServedRoot
from certorail.sandbox.common import environment, executable, scratch_for
from certorail.sandbox.lowering import Bind, Lowered, Omitted, Role, readable, writable

if TYPE_CHECKING:
    from certorail.policy import Policy

# The toolchain a policy world holds besides the policy's own binds: where programs, their
# libraries, the loader's cache and the name databases ``ls -l`` reads live. Read-only, each only
# if present. Machine-specific toolchains (a homebrew, a nix store) are MOUNTS.md's ``world.toml``.
TOOLCHAIN = (
    "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin",
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
    "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/localtime",
)


def _seccomp_program() -> IO[bytes]:
    """An open, unlinked file holding the fork-denial program, positioned at its start, for
    bubblewrap to read (``--seccomp FD``)."""
    machine = platform.machine()
    arch = ARCHES.get(machine)
    if arch is None:
        raise JailUnavailable(f"no seccomp filter for machine {machine!r}: spawn = false cannot be enforced")
    program = tempfile.TemporaryFile(prefix="certorail-seccomp-")
    program.write(fork_denial_filter(arch))
    program.flush()
    program.seek(0)
    return program


@dataclass
class BubblewrapSpawner:
    root_view: ServedRoot | NoView
    _lease: Attachment | None = field(default=None, repr=False)

    # -- the run --------------------------------------------------------------------------

    @classmethod
    def provision(cls, policy: "Policy", root: pathlib.Path) -> "BubblewrapSpawner":
        """The spawner for *policy* under *root*: the FUSE view attached when a confined rule
        exists and the section has a root-relative pattern, its absence explained otherwise."""
        section = policy.section()
        if not policy.confines:
            return cls(NoView("no rule runs under the policy filesystem"))
        if not section.relative_patterns:
            return cls(NoView("every root-relative location of the section is one path"))
        try:
            lease = attach(ViewSpec(os.path.realpath(root), section.read, section.write, section.no_write, section.listing))
        except ViewUnavailable as e:
            return cls(NoView(str(e)))
        return cls(ServedRoot(lease.mountpoint, pathlib.Path(root)), lease)

    def __enter__(self) -> "BubblewrapSpawner":
        return self

    def __exit__(self, *exc: object) -> None:
        if self._lease is not None:
            self._lease.close()
            self._lease = None

    # -- lowering (pure) --------------------------------------------------------------------

    def lower(self, fs: PolicyFilesystem, write_fs: bool) -> tuple[Lowered, ...]:
        view = self.root_view
        served = isinstance(view, ServedRoot)
        if isinstance(view, ServedRoot) and view.root != fs.root:
            # a spawner is provisioned for one run, one root; a confinement of another root is
            # a programming error, not a world with nothing in it
            raise ValueError(f"this spawner serves {view.root}, not {fs.root}")
        out: list[Lowered] = []

        def section(role: Role, locs: tuple) -> None:
            for loc in locs:
                if served and not loc.absolute:
                    continue  # the view's: one bind of the root, the daemon behind it
                if role == "list":
                    continue  # a bind cannot list a directory without exposing it
                path = single_path(loc, fs.root)
                if path is not None:
                    out.append(Bind(path, role))
                elif loc.absolute:
                    out.append(Omitted(loc, role, "a pattern outside the root has no bind mount and no view"))
                else:
                    assert isinstance(self.root_view, NoView)
                    out.append(Omitted(loc, role, f"a pattern has no bind mount, and this run has no view: {self.root_view.reason}"))

        def additions(role: Role, locs: tuple) -> None:
            for loc in locs:
                path = single_path(loc, fs.root)
                if path is not None:
                    out.append(Bind(path, role))
                else:
                    out.append(Omitted(loc, role, "a rule's addition must be one path: a pattern has no bind mount"))

        section("read", fs.section.read)
        section("write", fs.section.write)
        section("list", fs.section.listing)
        additions("mount-read", fs.additions.read)
        additions("mount-write", fs.additions.write)
        section("no-write", fs.section.no_write)  # last: read-only over whatever it lies within
        return tuple(out)

    # -- spawning ---------------------------------------------------------------------------

    def _world(self, c: Confinement, fs: PolicyFilesystem, scratch: str, cwd: str, exe: str | None) -> list[str]:
        ops: list[str] = ["--dev", "/dev", "--proc", "/proc", "--dir", cwd, "--chdir", cwd]
        for path in TOOLCHAIN:
            ops += ["--ro-bind-try", path, path]
        if exe is not None:
            ops += ["--ro-bind-try", exe, exe]
        ops += ["--bind", scratch, scratch]
        if isinstance(self.root_view, ServedRoot):
            ops += ["--bind" if c.write_fs else "--ro-bind", str(self.root_view.mountpoint), str(fs.root)]
        for lowered in self.lower(fs, c.write_fs):
            if not isinstance(lowered, Bind):
                continue
            flag = "--bind-try" if writable(lowered.role) and c.write_fs else "--ro-bind-try"
            if lowered.role == "no-write":
                flag = "--ro-bind-try"
            assert readable(lowered.role) or lowered.role == "no-write"
            ops += [flag, str(lowered.path), str(lowered.path)]
        # the root tmpfs itself -- the mountpoint chain above the binds, the empty cwd -- is
        # read-only: a write outside every bind fails instead of vanishing into the sandbox
        ops += ["--remount-ro", "/"]
        return ops

    @contextlib.contextmanager
    def spawn(
        self, confinement: Confinement, argv: Sequence[str], cwd: pathlib.Path, base_env: dict[str, str] | None = None,
    ) -> Iterator[Spawn]:
        base = dict(os.environ) if base_env is None else base_env
        if not confinement.restricts:
            yield Spawn(list(argv), dict(base))
            return
        with contextlib.ExitStack() as stack:
            scratch = stack.enter_context(scratch_for(confinement))
            env = environment(confinement.env, base, scratch)
            fs = confinement.filesystem
            if confinement.network and confinement.write_fs and confinement.spawn and isinstance(fs, HostFilesystem):
                yield Spawn(list(argv), env)  # the environment alone: no wrapper needed
                return
            bwrap = shutil.which("bwrap")
            if bwrap is None:
                raise JailUnavailable("bubblewrap (bwrap) is not installed; a jailed grant cannot run without it")
            command = [bwrap, "--die-with-parent"]
            if isinstance(fs, PolicyFilesystem):
                assert scratch is not None
                command += self._world(confinement, fs, scratch, os.path.abspath(cwd), executable(argv, env))
            elif scratch is None:
                # the filesystem as the host has it, devices included (a plain --bind is nodev)
                command += ["--dev-bind", "/", "/"]
            else:
                command += ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--bind", scratch, scratch]
            if not confinement.network:
                command.append("--unshare-net")
            pass_fds: tuple[int, ...] = ()
            if not confinement.spawn:
                fd = stack.enter_context(_seccomp_program()).fileno()
                command += ["--seccomp", str(fd)]
                pass_fds = (fd,)
            yield Spawn([*command, "--", *argv], env, pass_fds)
