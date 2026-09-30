"""The long-lived FUSE view (MOUNTS.md, LOWERING2.md "Views"): one daemon per (directory, layers)
keeps the view mounted at a deterministic path, retires when no run has used it for a while, and
is recovered by the next run when it has died -- so a sequence of ``certorail`` invocations pays
one mount, not one per call.

The daemon is the Lean view (``fuse/fuseview-lean``; ``native.locate_view_daemon`` finds its
binary), which decides every name by the placement checker's own ``stateFrom`` (``proofs/place``)
and is jailed by bubblewrap with nothing but the directory it serves. This module is its
supervisor: it makes the mount out here (``fusermount3``), hands the daemon the descriptor, and
runs the lease protocol below, asking the daemon for its request counts each tick to know when it
is idle.

Layout, under ``$CERTORAIL_VIEWS_DIR``, else ``$XDG_RUNTIME_DIR/certorail/perm-mounts`` (a local
tmpfs, per login: flock is only emulated on NFS), else the config directory's ``perm-mounts``::

    <key>/mnt        the mountpoint (bound by bubblewrap at the directory it serves)
    <key>/view.json  what the daemon serves: the directory and the layers it holds there
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
from typing import Any

from certorail import native
from certorail.locations import decode_location, encode_location
from certorail.policydir import config_dir
from certorail.sandbox.grants import Access, Exactly, Layer, Narrowing, Pattern, Region, Subtree, says

FORMAT = 2
DEFAULT_IDLE = 600.0     # seconds without a lease or a request before the daemon retires
TICK = 1.0
SPAWN_DEADLINE = 15.0


class ViewUnavailable(Exception):
    """The view cannot be provided on this host; the caller falls back and says so."""


# ---------------------------------------------------------------------------------------------
# the specification: what a daemon serves, as a document whose hash is the key
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ViewLayer:
    """A layer as a view holds it: its region, and what it says there -- a grant's access or a
    restriction's narrowing. Where it came from, and what the placer knew of it, are nothing to
    the daemon."""

    region: Region
    says: Access | Narrowing


def _region_document(region: Region) -> dict[str, Any]:
    match region:
        case Subtree(path=p):
            return {"subtree": str(p)}
        case Exactly(path=p):
            return {"exactly": str(p)}
        case Pattern(location=loc, anchor=anchor):
            return {"pattern": encode_location(loc), "anchor": str(anchor)}


def _region(d: dict[str, Any]) -> Region:
    if "subtree" in d:
        return Subtree(pathlib.Path(d["subtree"]))
    if "exactly" in d:
        return Exactly(pathlib.Path(d["exactly"]))
    return Pattern(decode_location(d["pattern"]), pathlib.Path(d["anchor"]))


def _layer_document(layer: ViewLayer) -> dict[str, Any]:
    word = {"grant": layer.says.value} if isinstance(layer.says, Access) else {"restrict": layer.says.value}
    return {"region": _region_document(layer.region), **word}


def _layer(d: dict[str, Any]) -> ViewLayer:
    return ViewLayer(_region(d["region"]), Access(d["grant"]) if "grant" in d else Narrowing(d["restrict"]))


@dataclass(frozen=True)
class ViewSpec:
    """What a view serves: *directory* (a real path, never under a link: the daemon opens it),
    the layers that decide every name below it, in order -- absolute regions, whatever directory
    they lie in -- and whether it caches nothing (*strict*, ``world.toml``'s ``view-daemon``:
    a name replaced from outside the jail is seen at once)."""

    directory: pathlib.Path
    layers: tuple[ViewLayer, ...]
    strict: bool = False

    @classmethod
    def holding(cls, directory: pathlib.Path, layers: Sequence[Layer[Region]], *, strict: bool = False) -> "ViewSpec":
        """The view of *directory* that holds *layers* (a ``place.Serve``'s)."""
        return cls(directory, tuple(ViewLayer(layer.region, says(layer.effect)) for layer in layers), strict)

    def document(self) -> str:
        body = {
            "format": FORMAT,
            "directory": str(self.directory),
            "layers": [_layer_document(layer) for layer in self.layers],
            "cache": "strict" if self.strict else "cached",
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
        return cls(pathlib.Path(body["directory"]), tuple(_layer(d) for d in body["layers"]),
                   body.get("cache", "cached") == "strict")


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
    if shutil.which("fusermount3") is None:
        return "fusermount3 is not on PATH (install fuse3)"
    if not os.path.exists("/dev/fuse"):
        return "/dev/fuse is absent"
    if shutil.which("bwrap") is None:
        return "bubblewrap (bwrap), which jails the view daemon, is not on PATH"
    daemon = native.locate_view_daemon()
    if isinstance(daemon, str):
        return daemon
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
        if e.errno == errno.EACCES:
            return "live"  # a refusal is an answer: the daemon is there
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
        try:
            mnt.mkdir()
        except FileExistsError:
            # not mkdir(exist_ok=True), which stats it: a dead mount the kernel no longer caches
            # says ENOTCONN there, and recovering it is below
            pass
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
    """Supervise the Lean daemon serving ``keydir/view.json`` at ``keydir/mnt``: make the mount,
    hand the daemon its descriptor in its jail, wait for it to be ready, then each tick ask it for
    its request counts (activity) and retire it -- unmount, which ends it -- once idle with no
    lease held. The pid recorded is this process's: signals and ``certorail view stop`` reach the
    daemon through it."""
    spec = ViewSpec.parse((keydir / "view.json").read_text(encoding="utf-8"))
    mnt = keydir / "mnt"
    binary = native.locate_view_daemon()
    bwrap = shutil.which("bwrap")
    if isinstance(binary, str) or bwrap is None:
        print(f"certorail view {keydir.name}: cannot serve: {binary if isinstance(binary, str) else 'no bwrap'}", flush=True)
        return 1
    command = native.view_command(binary, keydir / "view.json", spec.directory, bwrap)
    fd = native.mount(mnt)
    try:
        daemon = subprocess.Popen([*command, "--fd", str(fd), "/view.json"], pass_fds=(fd,),
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, text=True)
    except BaseException:
        lazy_unmount(str(mnt))
        raise
    finally:
        os.close(fd)  # the daemon's now: when it exits, the connection goes with it
    assert daemon.stdin is not None and daemon.stdout is not None
    if daemon.stdout.readline().strip() != "ready":
        lazy_unmount(str(mnt))
        daemon.wait(timeout=10)
        print(f"certorail view {keydir.name}: the daemon did not start (exit {daemon.returncode})", flush=True)
        return 1
    (keydir / "pid").write_text(f"{os.getpid()} {int(time.time())}\n")
    print(f"certorail view {keydir.name}: serving {spec.directory} at {mnt} (pid {os.getpid()}, daemon {daemon.pid})", flush=True)

    stop: dict[str, Any] = {"why": None, "lock": None}

    def on_signal(signum: int, frame: object) -> None:
        stop["why"] = f"signal {signum}"

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    last_activity = time.monotonic()
    last_counts: str | None = None

    def activity() -> bool:
        """Did the daemon answer any request since last asked? One line in, its counts out."""
        nonlocal last_counts
        assert daemon.stdin is not None and daemon.stdout is not None
        try:
            daemon.stdin.write("\n")
            daemon.stdin.flush()
            counts = daemon.stdout.readline().strip()
        except (OSError, ValueError):
            return False
        changed = last_counts is not None and counts != last_counts
        last_counts = counts
        return changed

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

    try:
        while stop["why"] is None:
            time.sleep(TICK)
            if daemon.poll() is not None:
                stop["why"] = f"the daemon exited ({daemon.returncode})"
                break
            if activity():
                last_activity = time.monotonic()
            if retire_if_idle():
                stop["why"] = f"idle {idle:g}s with no lease"
        print(f"certorail view {keydir.name}: stopping ({stop['why']})", flush=True)
    finally:
        try:
            lazy_unmount(str(mnt))  # ends the daemon: the connection goes with the mount
            try:
                daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
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
        directory = json.loads((keydir / "view.json").read_text()).get("directory", "?")
    except (OSError, ValueError):
        directory = "?"
    who = f"pid {pid}" if _alive(pid) else "no daemon"
    return f"{keydir.name}  {state:6}  {who:12}  {directory}"


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
