"""The FUSE view (viewdaemon): the specification is pure and always tested;
the mount, the daemon protocol and the confined child need the Lean daemon (``fuse/fuseview-lean``,
built), bubblewrap, /dev/fuse and fusermount3, and skip without them. What the daemon decides at
each name is its own test suite's (``lake -d fuse/fuseview-lean exe fuseview-tests``), over the
placement checker's ``stateFrom``."""
import errno
import os
import pathlib
import shutil
import signal
import stat as statmod
import subprocess
import tempfile
import time
import unittest
from collections.abc import Sequence
from unittest import mock

from certorail import viewdaemon
from certorail.childjail import View
from certorail.locations import parse_location as loc
from certorail.policy import Policy, Program, program
from certorail.sandbox import CompileError, prepare
from certorail.sandbox.front import tool
from certorail.sandbox.grants import Access, Exactly, Narrowing, Pattern, Subtree
from certorail.sandbox.place import BwrapPlan, place_bubblewrap
from certorail.viewdaemon import ViewLayer, ViewSpec, liveness
from certorail.world import World
from tests.test_jail_compiler import FakeFS

P = pathlib.Path
READ, WRITE = Access.READ_ONLY, Access.WRITABLE


def section(root: P, read: Sequence[str] = (), write: Sequence[str] = (), no_write: Sequence[str] = ()) -> tuple[ViewLayer, ...]:
    """A filesystem section as a view of *root* holds it: the reads, the writes, then ``no-write``,
    each location matched as it is spelled."""
    return (*(ViewLayer(Pattern(loc(s), root), READ) for s in read),
            *(ViewLayer(Pattern(loc(s), root), WRITE) for s in write),
            *(ViewLayer(Pattern(loc(s), root), Narrowing.NO_WRITE) for s in no_write))


NO_VIEW = viewdaemon.unavailable()
HAS_VIEW = NO_VIEW is None
CAT = shutil.which("cat") or "cat"
LS = shutil.which("ls") or "ls"
TOUCH = shutil.which("touch") or "touch"


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        state = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except OSError:
        return False
    return state != "Z"


class TestAttach(unittest.TestCase):
    def test_a_mountpoint_that_cannot_be_statted_still_reaches_recovery(self) -> None:
        # a dead view whose attributes the kernel no longer caches says ENOTCONN to a stat;
        # attach must still get to its liveness probe and the lazy unmount
        views = pathlib.Path(tempfile.mkdtemp(prefix="certorail-views-"))
        self.addCleanup(shutil.rmtree, views, ignore_errors=True)
        spec = ViewSpec(P("/r"), section(P("/r"), read=["src/**"]))
        (views / spec.key / "mnt").mkdir(parents=True)
        real_stat = pathlib.Path.stat

        def stat(path: pathlib.Path, *args: object, **kwargs: object) -> os.stat_result:
            if path.name == "mnt":
                raise OSError(errno.ENOTCONN, "Transport endpoint is not connected", str(path))
            return real_stat(path, *args, **kwargs)  # pyright: ignore[reportArgumentType]

        class Reached(Exception):
            pass

        self.enterContext(mock.patch.dict(os.environ, {"CERTORAIL_VIEWS_DIR": str(views)}))
        self.enterContext(mock.patch("certorail.viewdaemon.unavailable", return_value=None))
        self.enterContext(mock.patch.object(pathlib.Path, "stat", stat))
        self.enterContext(mock.patch("certorail.viewdaemon.liveness", side_effect=Reached))
        with self.assertRaises(Reached):
            viewdaemon.attach(spec)


class TestViewSpec(unittest.TestCase):
    def test_the_document_round_trips_and_keys_by_content(self) -> None:
        spec = ViewSpec(P("/opt"), (
            *section(P("/opt/r"), read=["src/**/<.*\\.py>", "a/{b,c}/*"], write=["out/**"], no_write=["**/.git"]),
            ViewLayer(Pattern(loc("/opt/data/<[a-z]+>/**"), P("/")), READ),
            ViewLayer(Subtree(P("/opt/tools")), READ), ViewLayer(Exactly(P("/opt/f")), WRITE),
            ViewLayer(Subtree(P("/opt/keys")), Narrowing.HIDDEN),
        ))
        again = ViewSpec.parse(spec.document())
        self.assertEqual(again, spec)
        self.assertEqual(again.key, spec.key)
        # the order is the meaning, so it is part of the key
        other = ViewSpec(P("/opt"), (spec.layers[1], spec.layers[0], *spec.layers[2:]))
        self.assertNotEqual(other.key, spec.key)
        self.assertEqual(len(spec.key), 32)

    def test_a_strict_view_is_another_view(self) -> None:
        # the cache mode is the daemon's to read from the document, and part of the key
        lax, strict = ViewSpec(P("/r"), ()), ViewSpec(P("/r"), (), strict=True)
        self.assertNotEqual(lax.key, strict.key)
        self.assertIn('"cache":"strict"', strict.document())
        self.assertEqual(ViewSpec.parse(strict.document()), strict)
        self.assertEqual(ViewSpec.parse(lax.document()), lax)

    def test_a_view_holds_what_the_placer_gave_it_and_nothing_of_where_it_came_from(self) -> None:
        from certorail.sandbox.grants import Grant, Layer, Restriction

        class Note:
            def describe(self) -> str:
                return "a note"

        layers = (Layer(Subtree(P("/r/out")), Grant(WRITE, stable=True), Note()),
                  Layer(Subtree(P("/r/out/keep")), Restriction(Narrowing.NO_WRITE, sole=True), Note()))
        self.assertEqual(ViewSpec.holding(P("/r"), layers),
                         ViewSpec(P("/r"), (ViewLayer(Subtree(P("/r/out")), WRITE), ViewLayer(Subtree(P("/r/out/keep")), Narrowing.NO_WRITE))))
        self.assertTrue(ViewSpec.holding(P("/r"), layers, strict=True).strict)

    def test_a_jail_needs_a_view_where_a_bind_cannot_say_its_layers(self) -> None:
        root = P("/r")
        fs = FakeFS(dirs=("/r/src",))
        cat = program("cat", cwd=".", view=View.POLICY)

        def placed(read: str) -> BwrapPlan:
            plan = place_bubblewrap(tool(Policy.allow(read=[read], programs=[cat]), cat, root, ()), fs)
            assert isinstance(plan, BwrapPlan)
            return plan

        (view,) = placed("src/**/<.*\\.py>").views
        self.assertEqual(ViewSpec.holding(view.directory, view.layers),
                         ViewSpec(root, (ViewLayer(Pattern(loc("src/**/<.*\\.py>"), root), READ),)))
        self.assertEqual(placed("src/**").views, ())  # one exec, a plain grant: a bind


@unittest.skipUnless(HAS_VIEW, NO_VIEW or "")
class TestDaemon(unittest.TestCase):
    """The long-lived mount: attach, lease, retire, recover -- the Lean daemon under the Python
    supervisor."""

    def setUp(self) -> None:
        self.base = pathlib.Path(tempfile.mkdtemp(prefix="certorail-views-"))
        self.root = self.base / "root"
        (self.root / "src" / "pkg").mkdir(parents=True)
        (self.root / "src" / "a.py").write_text("py\n")
        (self.root / "src" / "a.txt").write_text("txt\n")
        (self.root / "src" / "pkg" / "b.py").write_text("deep\n")
        (self.root / "secrets").mkdir()
        (self.root / "secrets" / "key.pem").write_text("PRIVATE\n")
        (self.root / "out").mkdir()
        (self.root / "out" / ".git").mkdir()
        (self.root / "out" / ".git" / "config").write_text("x\n")
        self.enterContext(mock.patch.dict(os.environ, {
            "CERTORAIL_VIEWS_DIR": str(self.base / "views"), "CERTORAIL_VIEW_IDLE": "1",
        }))
        real = P(os.path.realpath(self.root))
        self.spec = ViewSpec(real, section(real, read=["src/**/<.*\\.py>"], write=["out/**"], no_write=["out/**/.git"]))
        self.addCleanup(self.cleanup)

    def cleanup(self) -> None:
        viewdaemon.main(["stop"])
        shutil.rmtree(self.base, ignore_errors=True)

    def test_attach_serves_the_filtered_root_and_retires_when_unleased(self) -> None:
        a = viewdaemon.attach(self.spec)
        try:
            self.assertTrue(a.spawned)
            self.assertEqual(liveness(str(a.mountpoint)), "live")
            self.assertEqual(sorted(os.listdir(a.mountpoint)), ["out", "src"])  # secrets: nothing granted
            self.assertEqual(sorted(os.listdir(a.mountpoint / "src")), ["a.py", "pkg"])
            self.assertEqual((a.mountpoint / "src" / "pkg" / "b.py").read_text(), "deep\n")
            with self.assertRaises(FileNotFoundError):
                (a.mountpoint / "src" / "a.txt").read_text()
            with self.assertRaises(FileNotFoundError):
                (a.mountpoint / "secrets" / "key.pem").read_text()
            # writes: permitted under the write grant, EPERM at or below the protection
            (a.mountpoint / "out" / "new").write_text("ok")
            self.assertTrue((self.root / "out" / "new").exists())
            with self.assertRaises(PermissionError):
                (a.mountpoint / "out" / ".git" / "config").write_text("no")
            # names are the directory's own: on this case-sensitive filesystem ".GIT" is another
            # name than the protected ".git" (a folding one would refuse it as an alias: EEXIST)
            (a.mountpoint / "out" / ".GIT").mkdir()
            self.assertTrue((self.root / "out" / ".git" / "config").exists())
            with self.assertRaises(PermissionError):
                (a.mountpoint / "src" / "new.py").write_text("no")
            # a second attach finds it
            b = viewdaemon.attach(self.spec)
            self.assertFalse(b.spawned)
            self.assertEqual(b.mountpoint, a.mountpoint)
            b.close()
            time.sleep(2.5)
            self.assertEqual(liveness(str(a.mountpoint)), "live")  # our lease holds it past idle
        finally:
            a.close()
        # wait on the process, not the mount: probing the mount is activity that keeps it alive
        pid = int((a.keydir / "pid").read_text().split()[0])
        deadline = time.monotonic() + 15
        while alive(pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertFalse(alive(pid), "the daemon did not retire with no lease held")
        self.assertEqual(liveness(str(a.mountpoint)), "absent")

    def test_a_dead_daemon_is_recovered(self) -> None:
        a = viewdaemon.attach(self.spec)
        pid = int((a.keydir / "pid").read_text().split()[0])
        os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 5
        while liveness(str(a.mountpoint)) != "stale" and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(liveness(str(a.mountpoint)), "stale")
        a.close()
        b = viewdaemon.attach(self.spec)
        try:
            self.assertTrue(b.spawned)
            self.assertEqual((b.mountpoint / "src" / "a.py").read_text(), "py\n")
        finally:
            b.close()

    def test_a_new_name_cannot_make_a_protected_file_writable(self) -> None:
        a = viewdaemon.attach(self.spec)
        try:
            with self.assertRaises(PermissionError):
                os.link(a.mountpoint / "out" / ".git" / "config", a.mountpoint / "out" / "alias")
            self.assertFalse((self.root / "out" / "alias").exists())
            # a file that already has two names is not written through either of them
            (self.root / "out" / "one").write_text("x\n")
            os.link(self.root / "out" / "one", self.root / "out" / "two")
            with self.assertRaises(PermissionError):
                (a.mountpoint / "out" / "one").write_text("y\n")
            self.assertEqual((self.root / "out" / "one").read_text(), "x\n")
        finally:
            a.close()

    def test_a_literal_directory_shows_its_names_not_their_contents(self) -> None:
        real = P(os.path.realpath(self.root))
        spec = ViewSpec(real, section(real, read=["secrets", "src/**/<.*\\.py>"]))
        a = viewdaemon.attach(spec)
        try:
            self.assertEqual(os.listdir(a.mountpoint / "secrets"), ["key.pem"])
            os.stat(a.mountpoint / "secrets" / "key.pem")  # metadata: fine
            with self.assertRaises(PermissionError):
                (a.mountpoint / "secrets" / "key.pem").read_text()
        finally:
            a.close()

    def test_a_directory_that_is_no_root_with_a_hidden_name(self) -> None:
        # the directory granted exactly (its names), one subtree writable, one hidden
        home = P(os.path.realpath(self.base)) / "home"
        (home / "proj").mkdir(parents=True)
        (home / ".ssh").mkdir()
        (home / ".ssh" / "id_ed25519").write_text("PRIVATE\n")
        (home / "notes.txt").write_text("notes\n")
        spec = ViewSpec(home, (ViewLayer(Exactly(home), READ), ViewLayer(Subtree(home / "proj"), WRITE),
                               ViewLayer(Subtree(home / ".ssh"), Narrowing.HIDDEN)))
        a = viewdaemon.attach(spec)
        try:
            # the hidden name shows; everything at or below it is EACCES, never "not there"
            self.assertEqual(sorted(os.listdir(a.mountpoint)), [".ssh", "notes.txt", "proj"])
            with self.assertRaises(PermissionError):
                (a.mountpoint / ".ssh" / "id_ed25519").read_text()
            with self.assertRaises(PermissionError):
                os.listdir(a.mountpoint / ".ssh")
            with self.assertRaises(PermissionError):
                (a.mountpoint / ".ssh" / "new").write_text("no")  # nor a new name below it
            with self.assertRaises(PermissionError):
                (a.mountpoint / "notes.txt").read_text()   # a name, not its contents
            (a.mountpoint / "proj" / "x").write_text("ok")
            self.assertEqual((home / "proj" / "x").read_text(), "ok")
        finally:
            a.close()

    def test_a_directory_moves_under_the_narrow_rule(self) -> None:
        # cargo makes target by renaming a directory into place
        real = P(os.path.realpath(self.root))
        spec = ViewSpec(real, section(real, read=["**"], write=["out/**"], no_write=["out/keep"]))
        (self.root / "out" / "keep").mkdir()
        a = viewdaemon.attach(spec)
        try:
            (a.mountpoint / "out" / "target.tmp").mkdir()
            (a.mountpoint / "out" / "target.tmp" / "made").write_text("x")
            os.rename(a.mountpoint / "out" / "target.tmp", a.mountpoint / "out" / "target")
            self.assertEqual((self.root / "out" / "target" / "made").read_text(), "x")
            (a.mountpoint / "out" / "target" / "more").write_text("y")  # the moved directory, at its new name
            self.assertEqual((self.root / "out" / "target" / "more").read_text(), "y")
            with self.assertRaises(PermissionError):
                os.rename(a.mountpoint / "out" / "target", a.mountpoint / "out" / "keep" / "target")
        finally:
            a.close()

    def test_a_created_files_mode_is_the_writers_umask_alone(self) -> None:
        # the kernel applies the writer's umask; the daemon, spawned under a stricter one, must
        # not apply its own as well
        previous = os.umask(0o077)
        try:
            a = viewdaemon.attach(self.spec)
        finally:
            os.umask(previous)
        try:
            previous = os.umask(0)
            try:
                os.close(os.open(a.mountpoint / "out" / "shared", os.O_CREAT | os.O_WRONLY, 0o666))
            finally:
                os.umask(previous)
            self.assertEqual(statmod.S_IMODE(os.stat(self.root / "out" / "shared").st_mode), 0o666)
        finally:
            a.close()

    def test_a_strict_view_sees_an_outside_replacement_at_once(self) -> None:
        # world.toml's view-daemon = "strict": no name cache, so a directory replaced from outside
        # the jail is the new one at the next request, not a second later
        real = P(os.path.realpath(self.root))
        spec = ViewSpec(real, section(real, read=["**"]), strict=True)
        a = viewdaemon.attach(spec)
        try:
            self.assertEqual(sorted(os.listdir(a.mountpoint / "src")), ["a.py", "a.txt", "pkg"])
            os.rename(self.root / "src", self.root / "src.old")
            (self.root / "src").mkdir()
            (self.root / "src" / "fresh").write_text("new\n")
            self.assertEqual(os.listdir(a.mountpoint / "src"), ["fresh"])
        finally:
            a.close()

    def test_unavailable_is_an_error_not_a_half_mount(self) -> None:
        with mock.patch("certorail.viewdaemon.unavailable", return_value="no fuse here"):
            with self.assertRaisesRegex(viewdaemon.ViewUnavailable, "no fuse here"):
                viewdaemon.attach(self.spec)

    def test_a_confined_child_sees_the_view_at_the_roots_real_path(self) -> None:
        # the run's jails, compiled and their views attached, as a run prepares them
        reader = program("reader", cwd=".", view=View.POLICY, network=False, write_fs=False, spawn=False)
        writer = program("writer", cwd=".", view=View.POLICY, network=False, spawn=False)
        policy = Policy.allow(read=["src/**/<.*\\.py>"], write=["out/**"], no_write=["out/**/.git"], programs=[reader, writer])
        spawner = prepare(policy, self.root, world=World())
        assert not isinstance(spawner, CompileError), [r.describe() for r in spawner.refusals]
        base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}

        def run(argv: list[str], rule: Program) -> subprocess.CompletedProcess[bytes]:
            with spawner.spawn(rule, argv, self.root, base_env=base) as spawn:
                return subprocess.run(spawn.argv, cwd=self.root, env=spawn.env, pass_fds=spawn.pass_fds, capture_output=True)

        with spawner:
            result = run([CAT, "src/pkg/b.py"], reader)
            self.assertEqual((result.returncode, result.stdout), (0, b"deep\n"), result.stderr)
            result = run([CAT, str(self.root / "src" / "a.txt")], reader)
            self.assertIn(b"No such file or directory", result.stderr)
            result = run([LS, str(self.root)], reader)
            self.assertEqual(sorted(result.stdout.decode().split()), ["out", "src"], result.stderr)
            # write-fs = false: the view is bound read-only, whatever the write grant says
            # (coreutils are the children here: a venv python's libpython lives outside the world)
            result = run([TOUCH, str(self.root / "out" / "x")], reader)
            self.assertIn(b"Read-only file system", result.stderr)
            result = run([TOUCH, str(self.root / "out" / "x")], writer)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((self.root / "out" / "x").exists())
            result = run([TOUCH, str(self.root / "out" / ".git" / "config")], writer)
            self.assertIn(b"Operation not permitted", result.stderr)
            self.assertFalse((self.root / "out" / ".git" / "HEAD").exists())


if __name__ == "__main__":
    unittest.main()
