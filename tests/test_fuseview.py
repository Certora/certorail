"""The FUSE view of the sandbox root (fuseview, viewdaemon; MOUNTS.md): the filter is pure and
always tested; the mount, the daemon protocol and the confined child need pyfuse3, /dev/fuse,
fusermount3 and bubblewrap, and skip without them."""
import errno
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from certorail import viewdaemon
from certorail.childjail import Jail, View, confined
from certorail.locations import parse_location as loc
from certorail.policy import Policy, program
from certorail.viewdaemon import ViewSpec, liveness

try:
    from certorail.fuseview import Filter
    HAS_PYFUSE3 = True
    NO_PYFUSE3 = ""
except ImportError as _e:
    HAS_PYFUSE3 = False
    NO_PYFUSE3 = f"the fuse extra is not importable: {_e} (python {sys.executable}, path {sys.path[:4]})"

HAS_FUSE = (
    HAS_PYFUSE3 and sys.platform == "linux" and os.path.exists("/dev/fuse")
    and shutil.which("fusermount3") is not None
)
HAS_BWRAP = HAS_FUSE and shutil.which("bwrap") is not None
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


@unittest.skipUnless(HAS_PYFUSE3, NO_PYFUSE3)
class TestFilter(unittest.TestCase):
    """The policy's filesystem section asked about concrete relative paths."""

    def setUp(self) -> None:
        self.f = Filter(
            read=(loc("src/**/<.*\\.py>"), loc("docs/**")),
            write=(loc("out/**"),),
            no_write=(loc("out/**/.git"),),
            listing=(loc("."), loc("notes")),
        )

    def test_files(self) -> None:
        self.assertTrue(self.f.file_visible(("src", "a.py")))
        self.assertTrue(self.f.file_visible(("src", "pkg", "deep", "b.py")))
        self.assertFalse(self.f.file_visible(("src", "a.txt")))
        self.assertTrue(self.f.file_visible(("docs", "x", "y.txt")))
        self.assertTrue(self.f.file_visible(("out", "artifact")))  # a write grant reads too
        self.assertFalse(self.f.file_visible(("secrets", "key.pem")))
        self.assertFalse(self.f.file_visible(("a.py",)))

    def test_directories(self) -> None:
        self.assertTrue(self.f.dir_visible(()))
        self.assertTrue(self.f.dir_visible(("src",)))          # a grant has paths below it
        self.assertTrue(self.f.dir_visible(("src", "pkg")))
        self.assertTrue(self.f.dir_visible(("docs",)))
        self.assertTrue(self.f.dir_visible(("notes",)))        # a list grant names it
        self.assertFalse(self.f.dir_visible(("notes", "sub")))
        self.assertFalse(self.f.dir_visible(("secrets",)))

    def test_writes(self) -> None:
        self.assertTrue(self.f.may_write(("out", "new")))
        self.assertTrue(self.f.may_write(("out", "deep", "new")))
        self.assertFalse(self.f.may_write(("out", ".git")))
        self.assertFalse(self.f.may_write(("out", "x", ".git", "config")))  # at or below a protection
        self.assertFalse(self.f.may_write(("src", "a.py")))                 # a read grant is not writable
        self.assertFalse(self.f.may_write(("elsewhere",)))

    def test_names_fold_as_the_analysis_folds(self) -> None:
        self.assertFalse(self.f.may_write(("out", ".GIT")))  # APFS would make that .git
        self.assertTrue(self.f.file_visible(("DOCS", "readme")))


class TestViewSpec(unittest.TestCase):
    def test_the_document_round_trips_and_keys_by_content(self) -> None:
        spec = ViewSpec("/r", (loc("src/**/<.*\\.py>"), loc("a/{b,c}/*")), (loc("out/**"),), (loc("**/.git"),), (loc("."),))
        again = ViewSpec.parse(spec.document())
        self.assertEqual(again, spec)
        self.assertEqual(again.key, spec.key)
        other = ViewSpec("/r", (loc("src/**"),), (loc("out/**"),), (loc("**/.git"),), (loc("."),))
        self.assertNotEqual(other.key, spec.key)
        self.assertEqual(len(spec.key), 32)

    def test_the_policy_says_when_it_needs_the_view(self) -> None:
        root = pathlib.Path("/r")
        patterned = Policy.allow(read=["src/**/<.*\\.py>"], programs=[program("cat", cwd=".", view=View.POLICY)])
        self.assertTrue(patterned.mounts(root).needs_view)
        self.assertEqual(patterned.view_spec(root).read, patterned.read)
        plain = Policy.allow(read=["src/**"], programs=[program("cat", cwd=".", view=View.POLICY)])
        self.assertFalse(plain.mounts(root).needs_view)
        # with a view attached the root-relative section is the view's: no binds, no omissions
        served = patterned.mounts(root, view=pathlib.Path("/mnt/v"))
        self.assertEqual((served.reads, served.omitted, served.view), ((), (), (pathlib.Path("/mnt/v"), root)))
        self.assertFalse(served.needs_view)


@unittest.skipUnless(HAS_FUSE, NO_PYFUSE3 or "/dev/fuse and fusermount3 are the Linux view")
class TestDaemon(unittest.TestCase):
    """The long-lived mount: attach, lease, retire, recover."""

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
        self.policy = Policy.allow(
            read=["src/**/<.*\\.py>"], write=["out/**"], no_write=["out/**/.git"], listing=["."],
            programs=[program("cat", cwd=".", view=View.POLICY)],
        )
        self.spec = self.policy.view_spec(self.root)
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
            with self.assertRaises(PermissionError):
                (a.mountpoint / "out" / ".GIT").mkdir()
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

    def test_unavailable_is_an_error_not_a_half_mount(self) -> None:
        with mock.patch("certorail.viewdaemon.unavailable", return_value="no fuse here"):
            with self.assertRaisesRegex(viewdaemon.ViewUnavailable, "no fuse here"):
                viewdaemon.attach(self.spec)

    @unittest.skipUnless(HAS_BWRAP, "bubblewrap binds the view for the child")
    def test_a_confined_child_sees_the_view_at_the_roots_real_path(self) -> None:
        a = viewdaemon.attach(self.spec)
        try:
            rule = self.policy.programs[0]
            mounts = self.policy.mounts(self.root, rule, a.mountpoint)
            self.assertEqual(mounts.view, (a.mountpoint, self.root))
            base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}

            def run(argv: list[str], jail: Jail) -> subprocess.CompletedProcess[bytes]:
                with confined(argv, jail, base_env=base, mounts=mounts, cwd=self.root) as spawn:
                    return subprocess.run(spawn.argv, cwd=self.root, env=spawn.env, pass_fds=spawn.pass_fds, capture_output=True)

            reader = Jail(network=False, write_fs=False, spawn=False, view=View.POLICY)
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
            writer = Jail(network=False, write_fs=True, spawn=False, view=View.POLICY)
            result = run([TOUCH, str(self.root / "out" / "x")], writer)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((self.root / "out" / "x").exists())
            result = run([TOUCH, str(self.root / "out" / ".git" / "config")], writer)
            self.assertIn(b"Operation not permitted", result.stderr)
            self.assertFalse((self.root / "out" / ".git" / "HEAD").exists())
        finally:
            a.close()


if __name__ == "__main__":
    unittest.main()
