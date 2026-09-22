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
    exec.view  = "policy"              # sees only what the policy grants (MOUNTS.md)

``network`` and ``write-fs`` are the grant's *media* (EFFECTS.md): what the tool cannot reach it
cannot write, so the effects analysis and the jail read the same two keys. Region-level claims
that no jail could check stay declarations (``writes = [...]``). Every key defaults to the
unjailed baseline.

``exec.view`` is what the child sees of the filesystem. ``"host"`` (the default): the host's
filesystem, whole, read-only under ``write-fs = false``. ``"policy"``: an empty world holding
the toolchain, the tool itself, a fresh ``/dev`` and ``/proc``, a private scratch ``TMPDIR``, the
exec's cwd as an empty directory, and the policy's own filesystem section lowered to binds
(``fsview.Mounts``): read grants read-only, write grants writable iff ``write-fs = true``,
``no-write`` protections remounted read-only on top. What no bind expresses is absent, and the
host said so at startup. A path outside the view is ENOENT, not EACCES.

The mechanism is always an existing sandboxing tool: on Linux bubblewrap (a read-only bind of
the whole filesystem with the scratch directory bound writable, or the empty world; a private
network namespace; a seccomp filter denying the fork family, ``selfjail.fork_denial_filter``),
on macOS Seatbelt through ``sandbox-exec``. A jailed grant whose mechanism is missing fails
closed (``JailUnavailable``): the tool does not run at all.

What ``spawn = false`` does not stop: a tool replacing *itself* with another program (exec
without fork). It denies creating processes -- hooks, ``-exec``, helpers, shells -- which is
where a tool steered by the tree it reads would run something else.
"""
import contextlib
import enum
import os
import pathlib
import platform
import shutil
import sys
import tempfile
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import IO

from certorail.selfjail import ARCHES, fork_denial_filter


class View(enum.Enum):
    """What a grant's child sees of the filesystem (``exec.view``)."""

    HOST = "host"
    POLICY = "policy"


@dataclass(frozen=True)
class Regex:
    """A patterned location as Seatbelt takes it: an anchored regex over canonical absolute
    paths (``(regex #"...")``). Seatbelt matches patterns natively; bubblewrap binds paths, so
    on Linux a pattern has no native spelling (``PATTERNS_NATIVE``)."""

    pattern: str


type Bind = pathlib.Path | Regex

# Can the platform's mechanism hold a patterned location? Seatbelt filters by regex; a bind
# mount is one path.
PATTERNS_NATIVE = sys.platform == "darwin"


@dataclass(frozen=True)
class Mounts:
    """The policy view as the mechanism takes it, lowered from the policy's filesystem section
    (``fsview.mounts``): absolute paths, and on macOS regexes for the patterned locations.
    Grants and protections are kept apart: the jail decides how each is mounted (a write grant
    is writable only under ``write-fs = true``, a protection is a read-only remount on top of
    whatever it lies within, or a write denial that wins)."""

    reads: tuple[Bind, ...] = ()
    writes: tuple[Bind, ...] = ()
    no_write: tuple[Bind, ...] = ()
    # ``list`` grants: the directories themselves, readable for listing and nothing below them.
    # Only where the mechanism can say "this path, not its subtree" (Seatbelt); a bind exposes
    # contents, so on Linux a list grant never widens the view
    listings: tuple[Bind, ...] = ()
    # the locations the mechanism cannot express, as the policy spelled them, with what they
    # were for
    omitted: tuple[str, ...] = ()
    # a root-relative location no bind expresses: the FUSE view (``viewdaemon``) would serve it
    needs_view: bool = False
    # the FUSE view standing for the root, when one is attached: bound at *root*'s real path
    # before every other bind, in place of the root-relative ones
    view: tuple[pathlib.Path, pathlib.Path] | None = None  # (mountpoint, root)

    def __or__(self, other: "Mounts") -> "Mounts":
        """This view widened by *other* (a rule's additions): the union, in order, nothing
        repeated."""
        def joined(a: tuple[Bind, ...], b: tuple[Bind, ...]) -> tuple[Bind, ...]:
            return (*a, *(x for x in b if x not in a))

        return Mounts(
            joined(self.reads, other.reads), joined(self.writes, other.writes),
            joined(self.no_write, other.no_write), joined(self.listings, other.listings),
            (*self.omitted, *(o for o in other.omitted if o not in self.omitted)),
            self.needs_view or other.needs_view,
            self.view if self.view is not None else other.view,
        )

    @property
    def paths(self) -> "Mounts":
        """The bind-mountable part: paths only (what bubblewrap takes)."""
        return Mounts(
            tuple(p for p in self.reads if isinstance(p, pathlib.Path)),
            tuple(p for p in self.writes if isinstance(p, pathlib.Path)),
            tuple(p for p in self.no_write if isinstance(p, pathlib.Path)),
            (),
            self.omitted,
            self.needs_view,
            self.view,
        )


# The toolchain a policy view holds besides the policy's own binds: where programs, their
# libraries, the loader's cache and the name databases ``ls -l`` reads live. Read-only, and each
# only if present. Machine-specific toolchains (a homebrew, a nix store) are MOUNTS.md's
# ``world.toml``, not yet built.
_LINUX_TOOLCHAIN = (
    "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin",
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
    "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/localtime",
)
_DARWIN_TOOLCHAIN = (
    "/usr", "/bin", "/sbin", "/System", "/Library", "/private/var/db", "/private/etc", "/dev",
    "/opt/homebrew",
)


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
    view: View = View.HOST

    @property
    def restricts(self) -> bool:
        """Does this jail change anything about how the child runs?"""
        return self.env is not None or not (self.network and self.write_fs and self.spawn) or self.confined

    @property
    def confined(self) -> bool:
        """Does the child see only the policy's view of the filesystem?"""
        return self.view is View.POLICY


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


def _executable(argv: Sequence[str], env: Mapping[str, str]) -> str | None:
    """Where the tool the child runs lives, resolved as the child would resolve it: on the
    environment it will get. None: not found (the child will say so itself)."""
    return shutil.which(argv[0], path=env.get("PATH") or os.defpath)


def _policy_world(jail: Jail, mounts: Mounts, scratch: str, cwd: str, exe: str | None) -> list[str]:
    """The bubblewrap arguments of a policy view: an empty root, then the toolchain, the tool,
    the cwd as an empty directory (so the child starts where it was told, seeing nothing it was
    not granted), the scratch directory writable, and the policy's binds in shadowing order --
    reads, then writes, then the protections read-only over both."""
    ops: list[str] = ["--dev", "/dev", "--proc", "/proc", "--dir", cwd, "--chdir", cwd]
    for path in _LINUX_TOOLCHAIN:
        ops += ["--ro-bind-try", path, path]
    if exe is not None:
        ops += ["--ro-bind-try", exe, exe]
    ops += ["--bind", scratch, scratch]
    binds = mounts.paths
    if mounts.view is not None:
        # the FUSE view stands for the root: the policy's patterns are enforced inside it, and
        # whether the child may write through it at all is this bind's mode
        mountpoint, root = mounts.view
        ops += ["--bind" if jail.write_fs else "--ro-bind", str(mountpoint), str(root)]
    for path in binds.reads:
        ops += ["--ro-bind-try", str(path), str(path)]
    for path in binds.writes:
        ops += ["--bind-try" if jail.write_fs else "--ro-bind-try", str(path), str(path)]
    for path in binds.no_write:
        ops += ["--ro-bind-try", str(path), str(path)]
    # the root tmpfs itself -- the mountpoint chain above the binds, the empty cwd -- is read-only,
    # so a write to a path outside every bind fails instead of landing in the discarded sandbox
    # and reporting success (the binds are their own mounts and keep their own writability)
    ops += ["--remount-ro", "/"]
    return ops


def _unguarded(jail: Jail, mounts: Mounts) -> list[pathlib.Path]:
    """Protections a bind cannot hold yet: a ``no-write`` path that does not exist while a
    writable bind covers where it would be created. Nothing to remount, so the tool could
    create it -- said out loud, not silently accepted. (Seatbelt denies by path whether or not
    it exists, so this is bubblewrap's concern alone.)"""
    if not (jail.confined and jail.write_fs) or sys.platform == "darwin":
        return []
    binds = mounts.paths
    return [
        guarded for guarded in binds.no_write
        if isinstance(guarded, pathlib.Path) and not guarded.exists()
        and any(w == guarded or w in guarded.parents for w in binds.writes if isinstance(w, pathlib.Path))
    ]


def _bwrap(
    argv: Sequence[str], jail: Jail, scratch: str | None, seccomp_fd: int | None,
    world: Sequence[str] | None,
) -> list[str]:
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise JailUnavailable("bubblewrap (bwrap) is not installed; a jailed grant cannot run without it")
    command = [bwrap, "--die-with-parent"]
    if world is not None:
        command += world
    elif scratch is None:
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


def _canonical(path: str | os.PathLike[str]) -> str:
    # Seatbelt matches canonical paths: the per-user temp dir is under /private/var
    return os.path.realpath(path)


def _filters(binds: Iterable[str | Bind], *, exactly: bool = False) -> str:
    """Seatbelt path filters: a path as its subtree (``subpath``), or with *exactly* the path
    alone (``literal``); a regex as itself, already anchored and canonical."""
    out: list[str] = []
    for b in binds:
        if isinstance(b, Regex):
            out.append(f'(regex #"{b.pattern}")')
        else:
            out.append(f'({"literal" if exactly else "subpath"} "{_canonical(b)}")')
    return " ".join(out)


def seatbelt_profile(jail: Jail, scratch: str | None, mounts: Mounts | None, exe: str | None) -> str:
    """The Seatbelt profile of *jail*. Later rules win, so a policy view is: everything but file
    data denied, then the toolchain, the tool, the scratch directory and the policy's read
    grants allowed for reading, the ``list`` grants for reading the directory itself; the write
    grants (under ``write-fs = true``) and the scratch directory for writing; the protections
    denied for writing last. Metadata reads stay allowed so path resolution works: names are
    visible, contents are not."""
    rules = ["(version 1)", "(allow default)"]
    if mounts is not None:
        rules.append("(deny file-read-data file-write*)")
        readable: list[str | Bind] = [*_DARWIN_TOOLCHAIN, *([exe] if exe is not None else []), *mounts.reads, *mounts.writes]
        if scratch is not None:
            readable.append(scratch)
        rules.append(f"(allow file-read* {_filters(readable)})")
        if mounts.listings:
            rules.append(f"(allow file-read-data {_filters(mounts.listings, exactly=True)})")
        writable: list[str | Bind] = list(mounts.writes) if jail.write_fs else []
        if scratch is not None:
            writable.append(scratch)
        rules.append(f'(allow file-write* {_filters(writable)} (literal "/dev/null"))')
        if mounts.no_write:
            rules.append(f"(deny file-write* {_filters(mounts.no_write)})")
    elif scratch is not None:
        rules += ["(deny file-write*)", f'(allow file-write* (subpath "{_canonical(scratch)}") (literal "/dev/null"))']
    if not jail.network:
        rules.append("(deny network*)")
    if not jail.spawn:
        rules.append("(deny process-fork)")
    return " ".join(rules)


def _seatbelt(argv: Sequence[str], profile: str) -> list[str]:
    exe = shutil.which("sandbox-exec")
    if exe is None:
        raise JailUnavailable("sandbox-exec is not available; a jailed grant cannot run without it")
    return [exe, "-p", profile, *argv]


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
def confined(
    argv: Sequence[str],
    jail: Jail,
    base_env: Mapping[str, str] | None = None,
    *,
    mounts: Mounts | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> Iterator[Spawn]:
    """How to spawn *argv* under *jail*: the wrapped command and the scrubbed environment, with
    the scratch directory (when writes are jailed, or the view is the policy's) alive for the
    with-block and discarded after. A policy view needs the policy's *mounts* and the child's
    *cwd* (the caller's, by default), which the world holds as an empty directory. An
    unrestricting jail yields *argv* as is. Raises ``JailUnavailable`` before anything runs when
    the platform cannot enforce what the jail asks."""
    base = os.environ if base_env is None else base_env
    if not jail.restricts:
        yield Spawn(list(argv), dict(base))
        return
    if jail.confined and mounts is None:
        raise JailUnavailable("the policy view was not lowered to mounts; a confined grant cannot run")
    with contextlib.ExitStack() as stack:
        scratch = (
            stack.enter_context(tempfile.TemporaryDirectory(prefix="certorail-scratch-"))
            if jail.confined or not jail.write_fs else None
        )
        env = environment(jail, base, scratch)
        if mounts is not None:
            for guarded in _unguarded(jail, mounts):
                print(
                    f"certorail: no-write {guarded}: does not exist and a write grant covers it, so a "
                    "confined tool could create it",
                    file=sys.stderr,
                )
        if jail.network and jail.write_fs and jail.spawn and not jail.confined:
            # the environment alone: no wrapper needed
            yield Spawn(list(argv), env)
        elif sys.platform == "linux":
            seccomp_fd = None if jail.spawn else stack.enter_context(_seccomp_program()).fileno()
            world = None
            if jail.confined:
                assert mounts is not None and scratch is not None
                here = os.path.abspath(os.getcwd() if cwd is None else os.fspath(cwd))
                world = _policy_world(jail, mounts, scratch, here, _executable(argv, env))
            yield Spawn(_bwrap(argv, jail, scratch, seccomp_fd, world), env, () if seccomp_fd is None else (seccomp_fd,))
        elif sys.platform == "darwin":
            profile = seatbelt_profile(
                jail, scratch, mounts if jail.confined else None, _executable(argv, env) if jail.confined else None
            )
            yield Spawn(_seatbelt(argv, profile), env)
        else:
            raise JailUnavailable(f"no child jail for platform {sys.platform!r}")
