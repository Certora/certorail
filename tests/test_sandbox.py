"""The new confinement/sandbox infrastructure (certorail.confinement, certorail.sandbox): built
beside the live path and not yet used by it. Lowering and spawn construction are pure and always
tested; running a child needs bubblewrap, the served root needs the fuse extra."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from certorail import viewdaemon
from certorail.childjail import Environment, JailUnavailable, View
from certorail.confinement import (
    UNCONFINED,
    Additions,
    Confinement,
    FilesystemSection,
    HostFilesystem,
    PolicyFilesystem,
)
from certorail.locations import parse_location as loc
from certorail.policy import Policy, program, validation
from certorail.sandbox import NoView, ServedRoot, omissions, provision
from certorail.sandbox.bubblewrap import BubblewrapSpawner
from certorail.sandbox.lowering import Bind, Omitted, RegexRule
from certorail.sandbox.seatbelt import NOT_ERE, SeatbeltSpawner

ROOT = pathlib.Path("/sandbox")
SECTION = FilesystemSection(
    read=(loc("src/**"), loc("docs/**/<.*\\.md>"), loc("/opt/data/**"), loc("/srv/*/pub/**")),
    write=(loc("out/**"),),
    no_write=(loc("out/final"), loc("out/**/.git")),
)
HAS_BWRAP = sys.platform == "linux" and shutil.which("bwrap") is not None
HAS_FUSE = HAS_BWRAP and viewdaemon.unavailable() is None
CAT = shutil.which("cat") or "cat"
LS = shutil.which("ls") or "ls"
TOUCH = shutil.which("touch") or "touch"
SYSTEM_PYTHON = next((p for p in ("/usr/bin/python3", "/bin/python3") if os.path.exists(p)), sys.executable)


def confined(fs: PolicyFilesystem | HostFilesystem = HostFilesystem(), **knobs: object) -> Confinement:
    return Confinement(filesystem=fs, **knobs)  # type: ignore[arg-type]


class TestConfinement(unittest.TestCase):
    def test_the_variants_and_the_knobs(self) -> None:
        self.assertFalse(UNCONFINED.restricts)
        self.assertFalse(UNCONFINED.needs_scratch)
        self.assertTrue(Confinement(write_fs=False).restricts)
        self.assertTrue(Confinement(write_fs=False).needs_scratch)
        self.assertTrue(Confinement(env=Environment()).restricts)
        policy_fs = PolicyFilesystem(ROOT, SECTION)
        self.assertTrue(Confinement(filesystem=policy_fs).restricts)
        self.assertTrue(Confinement(filesystem=policy_fs).needs_scratch)  # always: no /tmp in that world
        self.assertEqual(HostFilesystem(), HostFilesystem())
        self.assertNotEqual(HostFilesystem(), policy_fs)

    def test_the_invariants_live_in_the_constructor(self) -> None:
        fs = PolicyFilesystem(ROOT, SECTION, Additions(write=(loc(".git/**"),)))
        with self.assertRaisesRegex(ValueError, "write-fs = false"):
            Confinement(write_fs=False, filesystem=fs)
        Confinement(write_fs=True, filesystem=fs)  # fine

    def test_the_section_knows_its_patterns(self) -> None:
        self.assertEqual([str(p.absolute) for p in SECTION.relative_patterns], ["False", "False"])  # docs/**/<..>, out/**/.git
        self.assertEqual(FilesystemSection(read=(loc("src/**"),)).relative_patterns, ())

    def test_the_policy_builds_it(self) -> None:
        host_rule = program("git", cwd=".", network=False)
        policy_rule = program("cat", cwd=".", write_fs=False, spawn=False, view=View.POLICY, mount_read=["/srv/keys/**"])
        checker = validation("v", argv=["t"], establishes={}, view=View.POLICY)
        policy = Policy.allow(
            read=["src/**"], write=["out/**"], no_write=["out/final"],
            programs=[host_rule, policy_rule], validations=[checker],
        )
        c = policy.confinement(host_rule, ROOT)
        self.assertEqual(c, Confinement(network=False))
        c = policy.confinement(policy_rule, ROOT)
        self.assertEqual(
            c,
            Confinement(
                write_fs=False, spawn=False,
                filesystem=PolicyFilesystem(ROOT, policy.section(), Additions(read=(loc("/srv/keys/**"),))),
            ),
        )
        self.assertEqual(policy.confinement(checker, ROOT).filesystem, PolicyFilesystem(ROOT, policy.section()))
        self.assertEqual(policy.section(), FilesystemSection((loc("src/**"),), (loc("out/**"),), (loc("out/final"),)))


class TestBubblewrapLowering(unittest.TestCase):
    def test_without_a_view(self) -> None:
        spawner = BubblewrapSpawner(NoView("pyfuse3 is not installed"))
        fs = PolicyFilesystem(ROOT, SECTION, Additions(read=(loc("/srv/keys/**"), loc("cfg/*")), write=(loc(".git/**"),)))
        lowered = spawner.lower(fs, write_fs=True)
        self.assertEqual(lowered, (
            Bind(ROOT / "src", "read"),
            Omitted(loc("docs/**/<.*\\.md>"), "read", "a pattern has no bind mount, and this run has no view: pyfuse3 is not installed"),
            Bind(pathlib.Path("/opt/data"), "read"),
            Omitted(loc("/srv/*/pub/**"), "read", "a pattern outside the root has no bind mount and no view"),
            Bind(ROOT / "out", "write"),
            # the list grant: no bind can list without exposing; silently nothing
            Bind(pathlib.Path("/srv/keys"), "mount-read"),
            Omitted(loc("cfg/*"), "mount-read", "a rule's addition must be one path: a pattern has no bind mount"),
            Bind(ROOT / ".git", "mount-write"),
            Bind(ROOT / "out" / "final", "no-write"),
            Omitted(loc("out/**/.git"), "no-write", "a pattern has no bind mount, and this run has no view: pyfuse3 is not installed"),
        ))

    def test_with_a_view_the_section_under_the_root_is_the_daemons(self) -> None:
        spawner = BubblewrapSpawner(ServedRoot(pathlib.Path("/views/k/mnt"), ROOT))
        fs = PolicyFilesystem(ROOT, SECTION, Additions(read=(loc("/srv/keys/**"), loc("hooks/**"))))
        lowered = spawner.lower(fs, write_fs=False)
        # nothing root-relative from the section: the view is one bind and the daemon enforces
        # it; what remains is outside the root, or the rule's own additions
        self.assertEqual(lowered, (
            Bind(pathlib.Path("/opt/data"), "read"),
            Omitted(loc("/srv/*/pub/**"), "read", "a pattern outside the root has no bind mount and no view"),
            Bind(pathlib.Path("/srv/keys"), "mount-read"),
            Bind(ROOT / "hooks", "mount-read"),          # an addition is a bind even over the view
        ))
        # a spawner serves one root: a confinement of another is a programming error
        other = BubblewrapSpawner(ServedRoot(pathlib.Path("/views/k/mnt"), pathlib.Path("/elsewhere")))
        with self.assertRaisesRegex(ValueError, "serves /elsewhere, not /sandbox"):
            other.lower(fs, write_fs=False)


class TestBubblewrapSpawn(unittest.TestCase):
    """The command, built and not run: pure given a spawner."""

    def setUp(self) -> None:
        self.spawner = BubblewrapSpawner(NoView("none needed"))
        self.enterContext(mock.patch("certorail.sandbox.bubblewrap.shutil.which", side_effect=lambda n, path=None: f"/usr/bin/{n}"))

    def spawn(self, c: Confinement, argv: list[str] = ["cat", "x"]) -> tuple[list[str], dict[str, str]]:
        with self.spawner.spawn(c, argv, ROOT, base_env={"PATH": "/usr/bin", "SECRET": "1"}) as s:
            return s.argv, s.env

    def test_unrestricted_and_environment_only(self) -> None:
        self.assertEqual(self.spawn(UNCONFINED), (["cat", "x"], {"PATH": "/usr/bin", "SECRET": "1"}))
        argv, env = self.spawn(Confinement(env=Environment(passed=("PATH",))))
        self.assertEqual((argv, env), (["cat", "x"], {"PATH": "/usr/bin"}))  # no wrapper needed

    def test_the_host_filesystem_worlds(self) -> None:
        argv, env = self.spawn(Confinement(network=False))
        self.assertEqual(argv[:4], ["/usr/bin/bwrap", "--die-with-parent", "--dev-bind", "/"])
        self.assertIn("--unshare-net", argv)
        self.assertNotIn("TMPDIR", env)
        argv, env = self.spawn(Confinement(write_fs=False))
        self.assertEqual(argv[2:5], ["--ro-bind", "/", "/"])
        self.assertIn("--bind", argv)
        self.assertEqual(env["TMPDIR"], argv[argv.index("--bind") + 1])
        self.assertEqual(argv[-3:], ["--", "cat", "x"])

    def test_the_policy_filesystem_world(self) -> None:
        fs = PolicyFilesystem(ROOT, SECTION, Additions(read=(loc("/srv/keys/**"),)))
        argv, env = self.spawn(Confinement(write_fs=True, spawn=False, filesystem=fs))
        text = " ".join(argv)
        self.assertIn("--dev /dev --proc /proc --dir /sandbox --chdir /sandbox", text)
        self.assertIn("--ro-bind-try /usr /usr", text)
        self.assertIn("--ro-bind-try /usr/bin/cat /usr/bin/cat", text)         # the tool itself
        self.assertIn(f"--bind {env['TMPDIR']} {env['TMPDIR']}", text)
        self.assertIn("--ro-bind-try /sandbox/src /sandbox/src", text)
        self.assertIn("--bind-try /sandbox/out /sandbox/out", text)              # write_fs: writable
        self.assertIn("--ro-bind-try /srv/keys /srv/keys", text)
        self.assertLess(text.index("/sandbox/out /sandbox/out"), text.index("--ro-bind-try /sandbox/out/final"))  # protection last
        self.assertIn("--remount-ro / --seccomp", text)
        self.assertEqual(argv[-3:], ["--", "cat", "x"])
        argv, _ = self.spawn(Confinement(write_fs=False, filesystem=fs))
        self.assertIn("--ro-bind-try /sandbox/out /sandbox/out", " ".join(argv))  # no medium: read-only

    def test_the_view_is_bound_at_the_root_first(self) -> None:
        self.spawner = BubblewrapSpawner(ServedRoot(pathlib.Path("/views/k/mnt"), ROOT))
        fs = PolicyFilesystem(ROOT, SECTION)
        argv, _ = self.spawn(Confinement(write_fs=False, filesystem=fs))
        text = " ".join(argv)
        self.assertIn("--ro-bind /views/k/mnt /sandbox", text)
        self.assertNotIn("/sandbox/src", text)  # served, not bound
        self.assertIn("--ro-bind-try /opt/data /opt/data", text)
        argv, _ = self.spawn(Confinement(write_fs=True, filesystem=fs))
        self.assertIn("--bind /views/k/mnt /sandbox", " ".join(argv))

    def test_no_mechanism_no_spawn(self) -> None:
        with mock.patch("certorail.sandbox.bubblewrap.shutil.which", return_value=None):
            with self.assertRaises(JailUnavailable):
                with self.spawner.spawn(Confinement(network=False), ["true"], ROOT):
                    self.fail("must be refused before anything runs")


class TestSeatbelt(unittest.TestCase):
    """Pure on any OS: Seatbelt has no run-scoped state."""

    def test_lowering(self) -> None:
        fs = PolicyFilesystem(ROOT, SECTION, Additions(read=(loc("/srv/keys/**"), loc("cfg/<\\d+>")), write=(loc(".git/**"),)))
        lowered = SeatbeltSpawner().lower(fs, write_fs=True)
        kinds = [type(x).__name__ for x in lowered]
        self.assertEqual(kinds, ["Bind", "RegexRule", "Bind", "RegexRule", "Bind", "Bind", "Omitted", "Bind", "Bind", "RegexRule"])
        self.assertEqual(lowered[6], Omitted(loc("cfg/<\\d+>"), "mount-read", NOT_ERE))
        guard = lowered[9]
        assert isinstance(guard, RegexRule)
        self.assertTrue(guard.pattern.endswith("(.*/)?\\.git(/.*)?$"))  # a protection covers its subtree

    def test_the_profile(self) -> None:
        fs = PolicyFilesystem(ROOT, SECTION)
        spawner = SeatbeltSpawner()
        c = Confinement(network=False, write_fs=False, spawn=False, filesystem=fs)
        profile = spawner.profile(c, "/tmp/scratch", "/usr/bin/cat")
        self.assertIn("(deny file-read-data file-write*)", profile)
        self.assertIn('(allow file-read-data (literal "/"))', profile)  # every process reads the root's entries at startup
        self.assertIn('(subpath "/usr/bin/cat")', profile)
        self.assertIn('(subpath "/sandbox/src")', profile)
        self.assertIn('(regex #"', profile)
        self.assertRegex(profile, r'\(allow file-write\* \(subpath "[^"]*scratch"\) \(literal "/dev/null"\)\)')
        self.assertIn('(deny file-write* (subpath "/sandbox/out/final") (regex #"', profile)
        self.assertIn("(deny network*)", profile)
        self.assertIn("(deny process-fork)", profile)
        writer = Confinement(write_fs=True, filesystem=fs)
        self.assertIn('(allow file-write* (subpath "/sandbox/out")', spawner.profile(writer, "/tmp/scratch", None))
        self.assertEqual(spawner.profile(Confinement(network=False), None, None), "(version 1) (allow default) (deny network*)")


class TestOmissionsReport(unittest.TestCase):
    def test_distinct_over_the_confined_rules(self) -> None:
        policy = Policy.allow(
            read=["src/**/<.*\\.py>"],
            programs=[
                program("cat", cwd=".", view=View.POLICY, mount_read=["cfg/*"]),
                program("ls", cwd=".", view=View.POLICY),
                program("git", cwd="."),  # host filesystem: contributes nothing
            ],
        )
        report = omissions(BubblewrapSpawner(NoView("no fuse")), policy, ROOT)
        self.assertEqual([(o.role, str(o.location.absolute)) for o in report], [("read", "False"), ("mount-read", "False")])
        self.assertEqual(omissions(SeatbeltSpawner(), policy, ROOT), ())


@unittest.skipUnless(HAS_BWRAP, "bubblewrap runs the child")
class TestBubblewrapLive(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="certorail-sbx-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        (self.root / "src").mkdir()
        (self.root / "src" / "main.py").write_text("print(1)\n")
        (self.root / "secrets").mkdir()
        (self.root / "secrets" / "key.pem").write_text("PRIVATE\n")
        (self.root / "out").mkdir()
        (self.root / "out" / "final").write_text("keep\n")

    def run_in(self, spawner: BubblewrapSpawner, c: Confinement, argv: list[str], cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess[bytes]:
        base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        with spawner.spawn(c, argv, cwd or self.root, base_env=base) as s:
            return subprocess.run(s.argv, cwd=cwd or self.root, env=s.env, pass_fds=s.pass_fds, capture_output=True)

    def test_the_policy_world_without_a_view(self) -> None:
        section = FilesystemSection(read=(loc("src/**"),), write=(loc("out/**"),), no_write=(loc("out/final"),))
        fs = PolicyFilesystem(self.root, section)
        spawner = BubblewrapSpawner(NoView("none needed"))
        reader = Confinement(network=False, write_fs=False, spawn=False, filesystem=fs)
        r = self.run_in(spawner, reader, [CAT, "src/main.py"])
        self.assertEqual((r.returncode, r.stdout), (0, b"print(1)\n"), r.stderr)
        r = self.run_in(spawner, reader, [CAT, str(self.root / "secrets" / "key.pem")])
        self.assertIn(b"No such file or directory", r.stderr)
        r = self.run_in(spawner, reader, [LS, str(self.root)])
        self.assertEqual(sorted(r.stdout.decode().split()), ["out", "src"], r.stderr)
        writer = Confinement(write_fs=True, spawn=False, filesystem=fs)
        r = self.run_in(spawner, writer, [TOUCH, str(self.root / "out" / "new")])
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_in(spawner, writer, [TOUCH, str(self.root / "out" / "final")])
        self.assertIn(b"Read-only file system", r.stderr)
        r = self.run_in(spawner, writer, [TOUCH, str(self.root.parent / "escaped")])
        self.assertIn(b"Read-only file system", r.stderr)
        r = self.run_in(spawner, Confinement(spawn=False, filesystem=fs), [SYSTEM_PYTHON, "-c", "import subprocess; subprocess.run(['true'])"])
        self.assertIn(b"PermissionError", r.stderr)

    @unittest.skipUnless(HAS_FUSE, "the served root needs the fuse extra")
    def test_provision_serves_a_patterned_section(self) -> None:
        self.enterContext(mock.patch.dict(os.environ, {"CERTORAIL_VIEWS_DIR": str(self.root.parent / f"{self.root.name}-views"), "CERTORAIL_VIEW_IDLE": "1"}))
        self.addCleanup(lambda: viewdaemon.main(["stop"]))
        (self.root / "src" / "notes.txt").write_text("no\n")
        rule = program("cat", cwd=".", network=False, write_fs=False, spawn=False, view=View.POLICY)
        policy = Policy.allow(read=["src/**/<.*\\.py>"], programs=[rule])
        with provision(policy, self.root) as spawner:
            assert isinstance(spawner, BubblewrapSpawner)
            self.assertIsInstance(spawner.root_view, ServedRoot)
            c = policy.confinement(rule, self.root)
            self.assertEqual(omissions(spawner, policy, self.root), ())
            r = self.run_in(spawner, c, [CAT, "src/main.py"])
            self.assertEqual((r.returncode, r.stdout), (0, b"print(1)\n"), r.stderr)
            r = self.run_in(spawner, c, [CAT, "src/notes.txt"])
            self.assertIn(b"No such file or directory", r.stderr)
            r = self.run_in(spawner, c, [LS, str(self.root / "src")])
            self.assertEqual(r.stdout.decode().split(), ["main.py"], r.stderr)
        # a host-only policy provisions no view, and says why
        plain = Policy.allow(read=["src/**"], programs=[program("git", cwd=".")])
        with provision(plain, self.root) as spawner:
            assert isinstance(spawner, BubblewrapSpawner)
            self.assertEqual(spawner.root_view, NoView("no rule runs under the policy filesystem"))


if __name__ == "__main__":
    unittest.main()
