"""The long-lived FUSE view (MOUNTS.md): one daemon per (root, filesystem section) keeps the
view mounted at a deterministic path, retires when no run has used it for a while, and is
recovered by the next run when it has died -- so a sequence of ``certorail`` invocations pays
one mount, not one per call.

Layout, under ``$CERTORAIL_VIEWS_DIR``, else ``$XDG_RUNTIME_DIR/certorail/perm-mounts`` (a local
tmpfs, per login: flock is only emulated on NFS), else the config directory's ``perm-mounts``::

    <key>/mnt        the mountpoint (bound by bubblewrap at the root's real path)
    <key>/view.json  what the daemon serves: the root and the lowered filesystem section
    <key>/lock       decisions are taken holding this (flock, exclusive)
    <key>/lease      every run using the view holds this shared; the daemon retires only when
                     it can take it exclusively
    <key>/pid, log   diagnostics

The key is a hash of ``view.json``'s content, so a policy edit is a new view and the old one
idles out. The protocol, validated by ``scripts/probe_view_daemon.py``::

    host:    flock(lock, EX) -> liveness -> [lazy unmount if stale] -> [spawn, wait live]
             -> flock(lease, SH) -> unlock(lock) ... the run ... close(lease)
    daemon:  each tick: flock(lock, EX|NB) and flock(lease, EX|NB) and idle past the limit
             -> unmount and exit while still holding lock; else release both

Liveness is a ``listdir`` of the mountpoint: it must reach the daemon. A ``stat`` is answered
from the kernel's attribute cache after the daemon has died (measured), a ``listdir`` says
ENOTCONN. Both flock files are released by the kernel when their holder dies, so a crashed run
or a crashed spawner leaves nothing to clean up, and a crashed daemon leaves a mount that the
next attach lazily unmounts (``fusermount3 -u -z``: never blocks on a process still sitting
inside the dead mount) before spawning again.
"""
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, override

from .analysis import AnyName, Component, DirSplat, LocationFact, Matching, Named, OneOf, RegexLit, StaticPath
from .policydir import config_dir

FORMAT = 1
DEFAULT_IDLE = 600.0     # seconds without a lease or a request before the daemon retires
TICK = 1.0
SPAWN_DEADLINE = 15.0


class ViewUnavailable(Exception):
    """The view cannot be provided on this host; the caller falls back and says so."""


# ---------------------------------------------------------------------------------------------
# the specification: what a daemon serves, as a document whose hash is the key
# ---------------------------------------------------------------------------------------------


def _encode_component(c: Component) -> Any:
    match c:
        case Named(name=n):
            return n
        case AnyName():
            return {"any": True}
        case OneOf(names=ns):
            return {"one_of": sorted(ns)}
        case Matching(regex=RegexLit(reg=r)):
            return {"regex": r}
        case Matching():
            raise ValueError("a policy location's regex is a single pattern")  # never from a document


def _decode_component(v: Any) -> Component:
    if isinstance(v, str):
        return Named(v)
    if "any" in v:
        return AnyName()
    if "one_of" in v:
        return OneOf(frozenset(v["one_of"]))
    return Matching(RegexLit(v["regex"]))


def _encode(loc: LocationFact) -> dict[str, Any]:
    match loc:
        case StaticPath(path_components=cs, absolute=ab):
            return {"path": [_encode_component(c) for c in cs], "absolute": ab}
        case DirSplat(static_prefix=ps, final_component=leaf, absolute=ab):
            return {
                "prefix": [_encode_component(c) for c in ps],
                "leaf": None if leaf is None else _encode_component(leaf),
                "absolute": ab,
            }


def _decode(d: dict[str, Any]) -> LocationFact:
    if "path" in d:
        return StaticPath(tuple(_decode_component(c) for c in d["path"]), d["absolute"])
    leaf = d["leaf"]
    return DirSplat(
        tuple(_decode_component(c) for c in d["prefix"]),
        None if leaf is None else _decode_component(leaf),
        d["absolute"],
    )


@dataclass(frozen=True)
class ViewSpec:
    """The root and the filesystem section a view serves. Absolute locations are kept for the
    record but the view serves the root alone."""

    root: str  # the real path
    read: tuple[LocationFact, ...]
    write: tuple[LocationFact, ...]
    no_write: tuple[LocationFact, ...]
    listing: tuple[LocationFact, ...]

    def document(self) -> str:
        body = {
            "format": FORMAT,
            "root": self.root,
            "read": [_encode(loc) for loc in self.read],
            "write": [_encode(loc) for loc in self.write],
            "no_write": [_encode(loc) for loc in self.no_write],
            "list": [_encode(loc) for loc in self.listing],
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    @property
    def key(self) -> str:
        return hashlib.sha256(self.document().encode()).hexdigest()[:32]

    @classmethod
    def parse(cls, text: str) -> "ViewSpec":
        body = json.loads(text)
        if body.get("format") != FORMAT:
            raise ValueError(f"view.json format {body.get('format')!r}, expected {FORMAT}")
        return cls(
            body["root"],
            tuple(_decode(d) for d in body["read"]),
            tuple(_decode(d) for d in body["write"]),
            tuple(_decode(d) for d in body["no_write"]),
            tuple(_decode(d) for d in body["list"]),
        )


# ---------------------------------------------------------------------------------------------
# the host side: attach
# ---------------------------------------------------------------------------------------------


def views_dir() -> pathlib.Path:
    override = os.environ.get("CERTORAIL_VIEWS_DIR")
    if override:
        return pathlib.Path(override)
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and os.path.isdir(runtime):
        return pathlib.Path(runtime) / "certorail" / "perm-mounts"
    return config_dir() / "perm-mounts"


def unavailable() -> str | None:
    """Why the view cannot be served here, or None when it can."""
    if sys.platform != "linux":
        return f"the FUSE view is Linux-only ({sys.platform} takes patterns natively)"
    try:
        import pyfuse3  # noqa: F401
    except ImportError:
        return "pyfuse3 is not installed (the certorail[fuse] extra)"
    if shutil.which("fusermount3") is None:
        return "fusermount3 is not on PATH (install fuse3)"
    if not os.path.exists("/dev/fuse"):
        return "/dev/fuse is absent"
    return None


def liveness(mnt: str) -> str:
    """'live' (a mount whose daemon answers), 'stale' (a mount whose daemon is gone), or
    'absent' (no mount here). A listdir, deliberately: see the module docstring."""
    try:
        os.listdir(mnt)
    except OSError as e:
        if e.errno in _DEAD_MOUNT:
            return "stale"
        if e.errno == errno.ENOENT:
            return "absent"
        raise
    try:
        return "live" if os.stat(mnt).st_dev != os.stat(os.path.dirname(mnt)).st_dev else "absent"
    except OSError as e:
        return "stale" if e.errno in _DEAD_MOUNT else "absent"


# what a FUSE mount answers once its daemon is gone: ENOTCONN settled, ECONNABORTED while the
# kernel is still tearing the connection down (both seen), EIO/ENXIO for good measure
_DEAD_MOUNT = frozenset({errno.ENOTCONN, errno.ECONNABORTED, errno.ECONNRESET, errno.EIO, errno.ENXIO})


def lazy_unmount(mnt: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["fusermount3", "-u", "-z", mnt], capture_output=True, text=True)


def _spawn(keydir: pathlib.Path) -> subprocess.Popen[bytes]:
    with open(keydir / "log", "ab") as log:
        return subprocess.Popen(
            [sys.executable, "-m", "certorail.viewdaemon", "daemon", str(keydir)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log,
            start_new_session=True, close_fds=True,  # the daemon must not inherit the lock
        )


@dataclass
class Attachment:
    """A run's hold on a view: the mountpoint to bind at the root, and the lease keeping the
    daemon alive for as long as this is open."""

    mountpoint: pathlib.Path
    keydir: pathlib.Path
    spawned: bool
    _lease: int

    def close(self) -> None:
        if self._lease >= 0:
            os.close(self._lease)
            self._lease = -1

    def __enter__(self) -> "Attachment":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def attach(spec: ViewSpec) -> Attachment:
    """The view for *spec*, mounted and leased: found live, or recovered, or spawned. Raises
    ``ViewUnavailable`` when the host cannot serve it (nothing is left half-done)."""
    reason = unavailable()
    if reason is not None:
        raise ViewUnavailable(reason)
    keydir = views_dir() / spec.key
    mnt = keydir / "mnt"
    try:
        keydir.mkdir(parents=True, exist_ok=True, mode=0o700)
        mnt.mkdir(exist_ok=True)
    except OSError as e:
        raise ViewUnavailable(f"cannot create {keydir}: {e}")
    lock = os.open(keydir / "lock", os.O_RDWR | os.O_CREAT, 0o600)
    spawned = False
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = liveness(str(mnt))
        if state == "stale":
            r = lazy_unmount(str(mnt))
            if liveness(str(mnt)) == "stale":
                raise ViewUnavailable(f"a dead view at {mnt} cannot be unmounted: {r.stderr.strip()}")
            state = "absent"
        if state != "live":
            # written under the lock, before the daemon reads it; the key is its hash, so what
            # the daemon serves is what this run lowered
            (keydir / "view.json").write_text(spec.document(), encoding="utf-8")
            proc = _spawn(keydir)
            spawned = True
            deadline = time.monotonic() + SPAWN_DEADLINE
            while liveness(str(mnt)) != "live":
                if proc.poll() is not None:
                    raise ViewUnavailable(f"the view daemon exited before mounting (exit {proc.returncode}; see {keydir / 'log'})")
                if time.monotonic() > deadline:
                    raise ViewUnavailable(f"the view daemon did not mount within {SPAWN_DEADLINE:g}s (see {keydir / 'log'})")
                time.sleep(0.02)
        # the lease is taken while the lock is still held: the daemon checks the lease only
        # under the same lock, so it cannot retire between the liveness probe and this line
        lease = os.open(keydir / "lease", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(lease, fcntl.LOCK_SH)
    finally:
        os.close(lock)
    return Attachment(mnt, keydir, spawned, lease)


# ---------------------------------------------------------------------------------------------
# the daemon
# ---------------------------------------------------------------------------------------------


def serve(keydir: pathlib.Path, idle: float) -> int:
    import pyfuse3
    import trio

    from .fuseview import Filter, View, raise_fd_limit

    spec = ViewSpec.parse((keydir / "view.json").read_text(encoding="utf-8"))
    mnt = keydir / "mnt"
    last_activity = time.monotonic()

    class Tracked(View):
        """The view, with the hot operations recording activity for the idle clock."""

        @override
        async def lookup(self, parent_inode: pyfuse3.InodeT, name: pyfuse3.FileNameT, ctx: pyfuse3.RequestContext) -> pyfuse3.EntryAttributes:
            nonlocal last_activity
            last_activity = time.monotonic()
            return await super().lookup(parent_inode, name, ctx)

        @override
        async def readdir(self, fh: pyfuse3.FileHandleT, start_id: int, token: pyfuse3.ReaddirToken) -> None:
            nonlocal last_activity
            last_activity = time.monotonic()
            return await super().readdir(fh, start_id, token)

        @override
        async def open(self, inode: pyfuse3.InodeT, flags: pyfuse3.FlagT, ctx: pyfuse3.RequestContext) -> pyfuse3.FileInfo:
            nonlocal last_activity
            last_activity = time.monotonic()
            return await super().open(inode, flags, ctx)

    raise_fd_limit()
    options = set(pyfuse3.default_options)
    options.add("fsname=certorail-view")
    view = Tracked(pathlib.Path(spec.root), Filter(spec.read, spec.write, spec.no_write, spec.listing))
    pyfuse3.init(view, str(mnt), options)
    (keydir / "pid").write_text(f"{os.getpid()} {int(time.time())}\n")
    print(f"certorail view {keydir.name}: serving {spec.root} at {mnt} (pid {os.getpid()})", flush=True)

    stop: dict[str, Any] = {"why": None, "lock": None}

    def on_signal(signum: int, frame: object) -> None:
        stop["why"] = f"signal {signum}"

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    def retire_if_idle() -> bool:
        nonlocal last_activity
        lock = os.open(keydir / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False  # a host is deciding; not our moment
            lease = os.open(keydir / "lease", os.O_RDWR | os.O_CREAT, 0o600)
            try:
                try:
                    fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    last_activity = time.monotonic()  # a run holds a lease: that is activity
                    return False
                if time.monotonic() - last_activity < idle:
                    return False
                # retire holding the lock: no host can find us live and lease us meanwhile
                stop["lock"] = lock
                lock = -1
                return True
            finally:
                os.close(lease)
        finally:
            if lock >= 0:
                os.close(lock)

    async def main() -> None:
        async with trio.open_nursery() as nursery:
            nursery.start_soon(pyfuse3.main)
            while stop["why"] is None:
                await trio.sleep(TICK)
                if retire_if_idle():
                    stop["why"] = f"idle {idle:g}s with no lease"
            print(f"certorail view {keydir.name}: stopping ({stop['why']})", flush=True)
            pyfuse3.terminate()

    try:
        trio.run(main)
    finally:
        try:
            pyfuse3.close(unmount=True)
        finally:
            with open(keydir / "pid", "w"):
                pass
            if stop["lock"] is not None:
                os.close(stop["lock"])
    return 0


# ---------------------------------------------------------------------------------------------
# the verb: certorail view status | stop [KEY] | daemon KEYDIR
# ---------------------------------------------------------------------------------------------


def _pid(keydir: pathlib.Path) -> int | None:
    try:
        return int((keydir / "pid").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _alive(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _status(keydir: pathlib.Path) -> str:
    state = liveness(str(keydir / "mnt")) if (keydir / "mnt").exists() else "absent"
    pid = _pid(keydir)
    try:
        root = json.loads((keydir / "view.json").read_text()).get("root", "?")
    except (OSError, ValueError):
        root = "?"
    who = f"pid {pid}" if _alive(pid) else "no daemon"
    return f"{keydir.name}  {state:6}  {who:12}  {root}"


def main(argv: Sequence[str]) -> int:
    args = list(argv)
    if len(args) == 2 and args[0] == "daemon":
        idle = float(os.environ.get("CERTORAIL_VIEW_IDLE", DEFAULT_IDLE))
        return serve(pathlib.Path(args[1]), idle)
    base = views_dir()
    keys = sorted(p for p in base.iterdir() if p.is_dir()) if base.is_dir() else []
    if args == ["status"] or not args:
        if not keys:
            print(f"no views under {base}")
            return 0
        print(f"views under {base}:")
        for keydir in keys:
            print("  " + _status(keydir))
        return 0
    if args and args[0] == "stop":
        chosen = [k for k in keys if not args[1:] or k.name.startswith(args[1])]
        if not chosen:
            print("nothing to stop", file=sys.stderr)
            return 1
        for keydir in chosen:
            pid = _pid(keydir)
            if _alive(pid):
                assert pid is not None
                os.kill(pid, signal.SIGTERM)
                deadline = time.monotonic() + 10
                while _alive(pid) and time.monotonic() < deadline:
                    time.sleep(0.05)
            if liveness(str(keydir / "mnt")) != "absent":
                lazy_unmount(str(keydir / "mnt"))
            print(f"stopped {keydir.name}")
        return 0
    print("usage: certorail view [status | stop [KEY-PREFIX]]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
