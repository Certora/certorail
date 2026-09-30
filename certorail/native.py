"""certorail's native executables -- the placement checker (``sandbox.certify``) and the view daemon
(``viewdaemon``), both Lean -- and what running one in a jail that holds nothing else takes: the
dynamic loader it names and the shared objects it loads, bound at their own paths; for the daemon,
a FUSE mount made out here and handed in as a descriptor, since a jailed process cannot mount.
"""
import os
import pathlib
import shutil
import socket
import struct
import subprocess
from collections.abc import Mapping

__all__ = [
    "VIEW_DAEMON_ENV", "Unavailable", "interpreter", "libraries", "loader_binds", "locate_view_daemon", "mount",
    "view_command",
]

VIEW_DAEMON_ENV = "CERTORAIL_VIEW_DAEMON"
FSNAME = "certorail-view"


class Unavailable(Exception):
    """The executable cannot be run in its jail; the message says why."""


def interpreter(binary: pathlib.Path) -> str | None:
    """The dynamic loader *binary* names (its PT_INTERP), or None for a static executable."""
    with open(binary, "rb") as f:
        head = f.read(64)
        if head[:4] != b"\x7fELF" or head[4] != 2 or head[5] != 1:
            raise Unavailable(f"{binary}: not a 64-bit little-endian ELF executable")
        (phoff,) = struct.unpack_from("<Q", head, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", head, 0x36)
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            p_type, _, p_offset, _, _, p_filesz = struct.unpack("<IIQQQQ", f.read(40))
            if p_type == 3:  # PT_INTERP
                f.seek(p_offset)
                return f.read(p_filesz).rstrip(b"\0").decode()
    return None


def libraries(binary: pathlib.Path) -> list[str]:
    """The shared objects a dynamically linked *binary* loads, the loader among them, as ldd
    resolves them here."""
    done = subprocess.run(["ldd", str(binary)], capture_output=True, text=True)
    if done.returncode != 0:
        raise Unavailable(f"ldd {binary}: {done.stderr.strip() or done.stdout.strip()}")
    paths: list[str] = []
    for line in done.stdout.splitlines():
        line = line.strip()
        if "=>" in line:
            target = line.split("=>", 1)[1].strip()
            if target.startswith("not found"):
                raise Unavailable(f"{binary} needs {line.split()[0]}, which is not found")
            if target.startswith("/"):
                paths.append(target.split(" (", 1)[0])
        elif line.startswith("/"):
            paths.append(line.split(" (", 1)[0])  # the loader itself
    return paths


def loader_binds(binary: pathlib.Path) -> list[str]:
    """bubblewrap's arguments giving a jail what *binary* needs to load: each shared object it
    loads, read-only at its own path, and the directories they are in as its library path. None
    for a static executable."""
    shared = libraries(binary) if interpreter(binary) is not None else []
    out: list[str] = []
    for path in shared:
        out += ["--ro-bind", path, path]
    if shared:
        out += ["--setenv", "LD_LIBRARY_PATH", ":".join(sorted({os.path.dirname(p) for p in shared}))]
    return out


# -- the view daemon ------------------------------------------------------------------------------


def _checkout_build(relative: str) -> pathlib.Path | None:
    """A checkout's own build beside the package (``lake build``), or None outside one."""
    import importlib.resources

    package = importlib.resources.files("certorail")
    if not isinstance(package, pathlib.Path):
        return None
    built = package.parent / relative
    return built if built.is_file() else None


def locate_view_daemon(environ: Mapping[str, str] = os.environ) -> pathlib.Path | str:
    """The view daemon (``fuse/fuseview-lean``): ``$CERTORAIL_VIEW_DAEMON``, else ``fuseview-lean``
    on PATH, else a checkout's own build. A str: why there is none to run."""
    named = environ.get(VIEW_DAEMON_ENV)
    if named:
        binary = pathlib.Path(named)
        if not binary.is_file():
            return f"${VIEW_DAEMON_ENV} names {named}, which is no file"
        return binary.resolve()
    on_path = shutil.which("fuseview-lean")
    if on_path is not None and pathlib.Path(on_path).is_file():
        return pathlib.Path(on_path).resolve()
    built = _checkout_build("fuse/fuseview-lean/.lake/build/bin/fuseview-lean")
    if built is not None:
        return built
    return (f"no view daemon: set ${VIEW_DAEMON_ENV}, put fuseview-lean on PATH, or build it in a checkout "
            "(lake -d fuse/fuseview-lean build)")


def mount(mnt: pathlib.Path) -> int:
    """A FUSE mount at *mnt*, made by ``fusermount3`` as libfuse makes one: it opens ``/dev/fuse``,
    mounts it, and hands the descriptor back over a socket (``_FUSE_COMMFD``). The descriptor
    serves the mount; whoever holds it is the filesystem."""
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with ours, theirs:
        helper = subprocess.Popen(
            ["fusermount3", "-o", f"fsname={FSNAME},default_permissions", "--", str(mnt)],
            env={**os.environ, "_FUSE_COMMFD": str(theirs.fileno())},
            pass_fds=(theirs.fileno(),),
        )
        theirs.close()  # the helper's end: its exit, sent or not, ends the wait below
        _, fds, _, _ = socket.recv_fds(ours, 1, 1)
        if helper.wait() != 0 or not fds:
            for fd in fds:
                os.close(fd)
            raise Unavailable(f"fusermount3 did not mount {mnt} (exit {helper.returncode})")
        return fds[0]


def view_command(binary: pathlib.Path, spec: pathlib.Path, tree: pathlib.Path, bwrap: str, *,
                 throwaway: bool = False) -> list[str]:
    """The jailed daemon, up to its own arguments: bubblewrap holding the served directory (at its
    own path, so the daemon's checks of where an object is agree with the kernel's), the binary at
    ``/daemon``, its specification at ``/view.json``, a ``/proc`` of its own (the checks ask it),
    bubblewrap's minimal ``/dev``, and the loader and libraries a dynamic binary needs -- nothing
    else of the host, no network, no environment. A bug in the daemon can then show or change
    nothing but what it serves. *throwaway*: the served directory writable through an overlay
    whose upper layer is a tmpfs in the jail (probes; needs bubblewrap 0.9)."""
    served = (["--overlay-src", str(tree), "--tmp-overlay", str(tree)] if throwaway
              else ["--bind", str(tree), str(tree)])
    return [
        bwrap,
        "--unshare-all",       # users, pids, network, ipc, uts, cgroups: its own of each
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        *served,
        "--ro-bind", str(binary), "/daemon",
        "--ro-bind", str(spec), "/view.json",
        "--proc", "/proc",
        "--dev", "/dev",
        *loader_binds(binary),
        "--chdir", "/", "--", "/daemon",
    ]
