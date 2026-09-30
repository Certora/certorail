"""One run's jails (certorail.sandbox): compiled when the run starts, their views attached, each
spawn linked and emitted. Building a spawn is pure given a filesystem and the views (both faked
here); running a child needs bubblewrap, a view the Lean view daemon and fusermount3."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from certorail import viewdaemon
from certorail.childjail import JailUnavailable, View
from certorail.policy import Policy, Program, program
from certorail.sandbox import CompileError, Launch, ProgramRequest, SelfInstalled, Spawner, Wrapped, prepare
from certorail.sandbox.facts import Facts, Kind
from certorail.viewdaemon import ViewSpec, ViewUnavailable
from certorail.world import Floor, World
from tests.test_jail_compiler import FakeFS

P = pathlib.Path
ROOT = P("/sandbox")
FS = FakeFS(dirs=("/sandbox/src", "/sandbox/docs", "/sandbox/out", "/opt/data", "/srv/keys", "/usr/bin"))
HAS_BWRAP = sys.platform == "linux" and shutil.which("bwrap") is not None
HAS_FUSE = HAS_BWRAP and viewdaemon.unavailable() is None
CAT = shutil.which("cat") or "cat"
LS = shutil.which("ls") or "ls"
TOUCH = shutil.which("touch") or "touch"
SYSTEM_PYTHON = next((p for p in ("/usr/bin/python3", "/bin/python3") if os.path.exists(p)), sys.executable)


class FakeAttachment:
    """A view's attachment with no daemon behind it: a mountpoint named for the directory."""

    def __init__(self, spec: ViewSpec) -> None:
        self.mountpoint = P("/views") / spec.directory.name
        self.closed = False

    def close(self) -> None:
        self.closed = True


class Now:
    """Facts that can change under a compiled jail: whatever *fs* says now."""

    def __init__(self, fs: FakeFS) -> None:
        self.fs = fs

    def kind(self, path: pathlib.Path) -> Kind:
        return self.fs.kind(path)

    def resolve(self, path: pathlib.Path) -> pathlib.Path:
        return self.fs.resolve(path)

    def children(self, path: pathlib.Path) -> tuple[str, ...]:
        return self.fs.children(path)


def prepared(
    policy: Policy, program: ProgramRequest | None = None, *, platform: str = "linux", facts: Facts = FS,
    world: World = World(),
) -> Spawner:
    """*policy*'s run prepared on a faked filesystem, its views attached with no daemons."""
    with mock.patch("certorail.viewdaemon.unavailable", return_value=None), \
            mock.patch("certorail.viewdaemon.attach", side_effect=FakeAttachment):
        spawner = prepare(policy, ROOT, program, world=world, platform=platform, facts=facts)
    assert isinstance(spawner, Spawner), [r.describe() for r in spawner.refusals]
    return spawner


def which(name: str, path: str | None = None) -> str:
    return name if name.startswith("/") else f"/usr/bin/{name}"


class Built(unittest.TestCase):
    """The spawn, built and not run."""

    def setUp(self) -> None:
        self.enterContext(mock.patch("shutil.which", side_effect=which))

    def spawn(self, spawner: Spawner, rule: Program, argv: tuple[str, ...] = ("cat", "x")) -> tuple[list[str], dict[str, str]]:
        with spawner.spawn(rule, list(argv), ROOT, base_env={"PATH": "/usr/bin", "SECRET": "1"}) as s:
            return s.argv, s.env


class TestHostJails(Built):
    def test_unrestricted_and_environment_only(self) -> None:
        plain, scrubbed = program("cat", cwd="."), program("head", cwd=".", env=["PATH"])
        spawner = prepared(Policy.allow(programs=[plain, scrubbed]))
        self.assertEqual(self.spawn(spawner, plain), (["cat", "x"], {"PATH": "/usr/bin", "SECRET": "1"}))
        self.assertEqual(self.spawn(spawner, scrubbed), (["cat", "x"], {"PATH": "/usr/bin"}))  # nothing to wrap

    def test_the_hosts_filesystem(self) -> None:
        offline, reader = program("cat", cwd=".", network=False), program("head", cwd=".", write_fs=False)
        spawner = prepared(Policy.allow(programs=[offline, reader]))
        argv, env = self.spawn(spawner, offline)
        self.assertEqual(argv, ["/usr/bin/bwrap", "--die-with-parent", "--dev-bind", "/", "/", "--unshare-net", "--", "cat", "x"])
        self.assertNotIn("TMPDIR", env)
        argv, env = self.spawn(spawner, reader)
        self.assertEqual(argv[2:9], ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"])
        self.assertEqual(argv[9:12], ["--bind-try", env["TMPDIR"], env["TMPDIR"]])  # the one writable place
        self.assertEqual(argv[-3:], ["--", "cat", "x"])

    def test_no_mechanism_no_spawn(self) -> None:
        offline = program("cat", cwd=".", network=False)
        with mock.patch("shutil.which", return_value=None):
            spawner = Spawner.unattached(Policy.allow(programs=[offline]), ROOT, platform="linux")
        with self.assertRaisesRegex(JailUnavailable, r"bubblewrap \(bwrap\) is not on PATH"):
            with spawner.spawn(offline, ["true"], ROOT):
                self.fail("must be refused before anything runs")


def sectioned(*rules: Program) -> Policy:
    return Policy.allow(read=["src/**", "docs/**/<.*\\.md>", "/opt/data/**"], write=["out/**"], no_write=["out/final"],
                        programs=list(rules))


class TestPolicyJails(Built):
    def test_the_policy_world(self) -> None:
        writer = program("cat", cwd=".", spawn=False, view=View.POLICY, mount_read=["/srv/keys/**"])
        spawner = prepared(sectioned(writer))
        argv, env = self.spawn(spawner, writer)
        text = " ".join(argv)
        self.assertIn("--dev /dev --proc /proc --dir /sandbox --chdir /sandbox", text)
        self.assertIn("--ro-bind-try /usr /usr", text)
        self.assertNotIn("/usr/bin/cat", text)                       # the toolchain holds the tool already
        self.assertIn("--bind /views/sandbox /sandbox", text)        # the pattern and the protection: a view
        self.assertIn("--ro-bind-try /opt/data /opt/data", text)
        self.assertIn("--ro-bind-try /srv/keys /srv/keys", text)
        self.assertLess(text.index("/views/sandbox"), text.index(f"--bind-try {env['TMPDIR']} {env['TMPDIR']}"))
        self.assertIn("--remount-ro / --seccomp", text)
        self.assertEqual(argv[-3:], ["--", "cat", "x"])

    def test_without_the_medium_the_view_is_read_only(self) -> None:
        reader = program("cat", cwd=".", write_fs=False, view=View.POLICY)
        spawner = prepared(sectioned(reader))
        self.assertIn("--ro-bind /views/sandbox /sandbox", " ".join(self.spawn(spawner, reader)[0]))

    def test_seatbelt(self) -> None:
        reader = program("cat", cwd=".", network=False, spawn=False, view=View.POLICY)
        spawner = prepared(sectioned(reader), platform="darwin")
        argv, env = self.spawn(spawner, reader)
        self.assertEqual(argv[:2], ["/usr/bin/sandbox-exec", "-p"])
        profile = argv[2].splitlines()
        self.assertEqual(profile[2], "(deny file-read-data file-write*)")
        self.assertIn(f'(allow file-read-data (subpath "{os.path.realpath("/usr/bin/cat")}"))', profile)
        self.assertIn('(allow file-read-data file-write* (subpath "/sandbox/out"))', profile)
        self.assertIn('(deny file-write* (subpath "/sandbox/out/final"))', profile)
        self.assertIn(f'(allow file-write* (subpath "{os.path.realpath(env["TMPDIR"])}") (literal "/dev/null"))', profile)
        self.assertEqual(profile[-2:], ["(deny network*)", "(deny process-fork)"])  # a tool may exec: it is exec'd
        self.assertEqual(argv[3:], ["cat", "x"])


class TestEachSpawnAsksAgain(Built):
    """A jail placed when the run started is placed again where the filesystem changed under it."""

    def test_a_grant_that_became_a_link_needs_a_view_the_run_did_not_attach(self) -> None:
        writer = program("cat", cwd=".", view=View.POLICY)
        now = Now(FS)
        spawner = prepared(Policy.allow(read=["src/**"], write=["out/**"], programs=[writer]), facts=now)
        self.assertNotIn("/views", " ".join(self.spawn(spawner, writer)[0]))  # binds alone, for one exec
        now.fs = FakeFS(dirs=("/sandbox/src", "/usr/bin", "/elsewhere"), links={"/sandbox/out": "/elsewhere"})
        with self.assertRaises(JailUnavailable) as caught:
            self.spawn(spawner, writer)
        self.assertEqual(str(caught.exception), (
            "since the run started, /sandbox/out was a directory when the jail was compiled and is a symbolic link now; "
            "/sandbox/out resolved to /sandbox/out when the jail was compiled and resolves to /elsewhere now, "
            "and cat's jail needs a view of /sandbox, which the run did not attach"
        ))


class TestTheProgramsLaunch(Built):
    """The certorail process's jail, as the run starts it: inside bubblewrap on Linux, installing
    its own profile on macOS."""

    def test_bubblewrap_wraps_it(self) -> None:
        launch = prepared(Policy.allow(), ProgramRequest(sys.executable)).launch()
        self.assertEqual(launch, Launch(None, Wrapped((
            "/usr/bin/bwrap", "--die-with-parent", "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-net", "--",
        ))))

    def test_seatbelt_it_installs_itself(self) -> None:
        launch = prepared(Policy.allow(), ProgramRequest(sys.executable), platform="darwin").launch()
        assert launch is not None and isinstance(launch.jail, SelfInstalled), launch
        self.assertEqual(launch.jail.profile.splitlines()[-3:], ["(deny network*)", "(deny process-fork)", "(deny process-exec*)"])

    def test_without_one_there_is_none(self) -> None:
        self.assertIsNone(prepared(Policy.allow()).launch())


class TestRedlinesBindTools(Built):
    """This machine's redlines bind every tool: a host-view one through a view at the
    stable directory above the redline (``/srv``, a top-level directory), the rest of it bound back."""

    WORLD = World(Floor.of(never_visible=(P("/srv/keys"),)))

    def test_a_host_view_tool_is_held_by_a_view_at_the_stable_directory(self) -> None:
        cat = program("cat", cwd=".", network=False)
        text = " ".join(self.spawn(prepared(Policy.allow(programs=[cat]), world=self.WORLD), cat)[0])
        self.assertIn("--dev-bind / /", text)                # the host's own world
        self.assertIn("--bind /views/srv /srv", text)        # the top-level directory's view, holding the redline by name

    def test_a_tool_with_every_medium_is_wrapped_under_a_redline(self) -> None:
        head = program("head", cwd=".")
        self.assertEqual(self.spawn(prepared(Policy.allow(programs=[head])), head)[0], ["cat", "x"])  # nothing to hold
        self.assertEqual(self.spawn(prepared(Policy.allow(programs=[head]), world=self.WORLD), head)[0][0], "/usr/bin/bwrap")

    def test_a_policy_view_tool_holds_them_in_its_world(self) -> None:
        reader = program("cat", cwd=".", view=View.POLICY, mount_read=["/srv/**"])
        spawner = prepared(Policy.allow(read=["src/**"], programs=[reader]), world=self.WORLD)
        self.assertIn("/views/srv", " ".join(self.spawn(spawner, reader)[0]))  # the redline, held by name in a view


class TestWithoutTheWrapper(unittest.TestCase):
    """A jail is never left off: a run whose jails need the backend's wrapper, where it is not on
    PATH, is refused before anything runs, naming them."""

    def prepare(self, policy: Policy, program: ProgramRequest | None, platform: str) -> Spawner | CompileError:
        with mock.patch("shutil.which", return_value=None):
            return prepare(policy, ROOT, program, platform=platform, facts=FS)

    def test_bubblewrap_holds_the_certorail_process_and_the_tools(self) -> None:
        offline, plain = program("cat", cwd=".", network=False), program("head", cwd=".")
        refused = self.prepare(Policy.allow(programs=[offline, plain]), ProgramRequest(sys.executable), "linux")
        assert isinstance(refused, CompileError), refused
        self.assertEqual([r.describe() for r in refused.refusals], [
            "bubblewrap (bwrap): is not on PATH, and it holds the jails of the certorail process, cat",
        ])

    def test_sandbox_exec_holds_the_tools_alone(self) -> None:
        offline = program("cat", cwd=".", network=False)
        refused = self.prepare(Policy.allow(programs=[offline]), ProgramRequest(sys.executable), "darwin")
        assert isinstance(refused, CompileError), refused
        self.assertEqual([r.describe() for r in refused.refusals], ["sandbox-exec: is not on PATH, and it holds the jails of cat"])

    def test_nothing_to_wrap_needs_no_wrapper(self) -> None:
        # --no-jail, and a tool with the host's filesystem and every medium: nothing is jailed
        self.assertIsInstance(self.prepare(Policy.allow(programs=[program("head", cwd=".")]), None, "linux"), Spawner)


class TestPrepare(Built):
    def test_one_jail_per_rule_jail_and_one_view_per_spec(self) -> None:
        cat, ls = program("cat", cwd=".", view=View.POLICY), program("ls", cwd=".", view=View.POLICY)
        attached: list[ViewSpec] = []

        def attach(spec: ViewSpec) -> FakeAttachment:
            attached.append(spec)
            return FakeAttachment(spec)

        with mock.patch("certorail.viewdaemon.unavailable", return_value=None), mock.patch("certorail.viewdaemon.attach", side_effect=attach):
            spawner = prepare(Policy.allow(read=["src/**/<.*\\.py>"], programs=[cat, ls]), ROOT, platform="linux", facts=FS)
        self.assertIsInstance(spawner, Spawner)
        self.assertEqual([spec.directory for spec in attached], [ROOT])

    def test_every_reason_is_said_before_anything_runs(self) -> None:
        cat = program("cat", cwd=".", view=View.POLICY, mount_read=["cfg/<x.*>"])
        with mock.patch("certorail.viewdaemon.unavailable", return_value="a test says so"):
            refused = prepare(Policy.allow(read=["src/**/<.*\\.py>"], programs=[cat]), ROOT, platform="linux", facts=FS)
        assert isinstance(refused, CompileError)
        self.assertEqual([r.origin.describe().split()[0] for r in refused.refusals], ["read", "cat's"])

    def test_a_view_that_does_not_attach_refuses_the_run_and_releases_the_others(self) -> None:
        cat = program("cat", cwd=".", view=View.POLICY)
        policy = Policy.allow(read=["src/**/<.*\\.py>", "/opt/data/<x.*>"], programs=[cat])
        first: list[FakeAttachment] = []

        def attach(spec: ViewSpec) -> FakeAttachment:
            if first:
                raise ViewUnavailable("a test says so")
            first.append(FakeAttachment(spec))
            return first[0]

        with mock.patch("certorail.viewdaemon.unavailable", return_value=None), mock.patch("certorail.viewdaemon.attach", side_effect=attach):
            refused = prepare(policy, ROOT, platform="linux", facts=FS)
        assert isinstance(refused, CompileError)
        self.assertIn("did not attach: a test says so", refused.refusals[0].reason)
        self.assertTrue(first[0].closed)

    def test_the_views_live_as_long_as_the_spawner(self) -> None:
        cat = program("cat", cwd=".", view=View.POLICY)
        made: list[FakeAttachment] = []

        def attach(spec: ViewSpec) -> FakeAttachment:
            made.append(FakeAttachment(spec))
            return made[-1]

        with mock.patch("certorail.viewdaemon.unavailable", return_value=None), mock.patch("certorail.viewdaemon.attach", side_effect=attach):
            spawner = prepare(Policy.allow(read=["src/**/<.*\\.py>"], programs=[cat]), ROOT, platform="linux", facts=FS)
        assert isinstance(spawner, Spawner)
        with spawner:
            self.assertFalse(made[0].closed)
        self.assertTrue(made[0].closed)


class TestUnattached(Built):
    """A spawn with no run around it: jails compiled when first spawned, and no views."""

    def test_a_jail_that_needs_a_view_is_refused(self) -> None:
        cat = program("cat", cwd=".", view=View.POLICY)
        spawner = Spawner.unattached(Policy.allow(read=["src/**/<.*\\.py>"], programs=[cat]), ROOT, platform="linux")
        with self.assertRaisesRegex(JailUnavailable, "none can be had: a spawn outside a run attaches no view"):
            self.spawn(spawner, cat)

    def test_one_of_binds_alone_spawns(self) -> None:
        cat = program("cat", cwd=".", view=View.POLICY, network=False)
        spawner = Spawner.unattached(Policy.allow(read=["src/**"], programs=[cat]), ROOT, platform="linux")
        self.assertIn("--ro-bind-try /sandbox/src /sandbox/src", " ".join(self.spawn(spawner, cat)[0]))


@unittest.skipUnless(HAS_BWRAP, "bubblewrap runs the child")
class TestBubblewrapLive(unittest.TestCase):
    def setUp(self) -> None:
        self.root = P(os.path.realpath(tempfile.mkdtemp(prefix="certorail-sbx-")))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        (self.root / "src").mkdir()
        (self.root / "src" / "main.py").write_text("print(1)\n")
        (self.root / "src" / "notes.txt").write_text("no\n")
        (self.root / "secrets").mkdir()
        (self.root / "secrets" / "key.pem").write_text("PRIVATE\n")
        (self.root / "out").mkdir()
        (self.root / "out" / "final").write_text("keep\n")

    def spawner(self, policy: Policy) -> Spawner:
        spawner = prepare(policy, self.root)
        assert isinstance(spawner, Spawner), [r.describe() for r in spawner.refusals]
        self.addCleanup(spawner.close)
        return spawner

    def run_in(self, spawner: Spawner, rule: Program, argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        with spawner.spawn(rule, argv, self.root, base_env=base) as s:
            return subprocess.run(s.argv, cwd=self.root, env=s.env, pass_fds=s.pass_fds, capture_output=True)

    def test_a_policy_world_of_binds_alone(self) -> None:
        reader = program("reader", cwd=".", network=False, write_fs=False, spawn=False, view=View.POLICY)
        writer = program("writer", cwd=".", spawn=False, view=View.POLICY)
        spawner = self.spawner(Policy.allow(read=["src/**"], write=["out/**"], programs=[reader, writer]))
        r = self.run_in(spawner, reader, [CAT, "src/main.py"])
        self.assertEqual((r.returncode, r.stdout), (0, b"print(1)\n"), r.stderr)
        r = self.run_in(spawner, reader, [CAT, str(self.root / "secrets" / "key.pem")])
        self.assertIn(b"No such file or directory", r.stderr)
        r = self.run_in(spawner, reader, [LS, str(self.root)])
        self.assertEqual(sorted(r.stdout.decode().split()), ["out", "src"], r.stderr)
        r = self.run_in(spawner, writer, [TOUCH, str(self.root / "out" / "new")])
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_in(spawner, writer, [TOUCH, str(self.root.parent / "escaped")])
        self.assertIn(b"Read-only file system", r.stderr)
        r = self.run_in(spawner, writer, [SYSTEM_PYTHON, "-c", "import subprocess; subprocess.run(['true'])"])
        self.assertIn(b"PermissionError", r.stderr)

    @unittest.skipUnless(HAS_FUSE, "a view needs the view daemon, bubblewrap and fusermount3")
    def test_what_binds_cannot_say_a_view_holds(self) -> None:
        self.enterContext(mock.patch.dict(os.environ, {"CERTORAIL_VIEWS_DIR": str(self.root.parent / f"{self.root.name}-views"), "CERTORAIL_VIEW_IDLE": "1"}))
        self.addCleanup(lambda: viewdaemon.main(["stop"]))
        reader = program("reader", cwd=".", network=False, write_fs=False, spawn=False, view=View.POLICY)
        writer = program("writer", cwd=".", spawn=False, view=View.POLICY)
        spawner = self.spawner(Policy.allow(read=["src/**/<.*\\.py>"], write=["out/**"], no_write=["out/final"], programs=[reader, writer]))
        r = self.run_in(spawner, reader, [CAT, "src/main.py"])
        self.assertEqual((r.returncode, r.stdout), (0, b"print(1)\n"), r.stderr)
        r = self.run_in(spawner, reader, [CAT, "src/notes.txt"])
        self.assertIn(b"No such file or directory", r.stderr)
        r = self.run_in(spawner, reader, [LS, str(self.root / "src")])
        self.assertEqual(r.stdout.decode().split(), ["main.py"], r.stderr)
        r = self.run_in(spawner, writer, [TOUCH, str(self.root / "out" / "new")])
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_in(spawner, writer, [TOUCH, str(self.root / "out" / "final")])
        self.assertIn(b"Operation not permitted", r.stderr)     # the protection, held by name in the view
        self.assertEqual((self.root / "out" / "final").read_text(), "keep\n")


if __name__ == "__main__":
    unittest.main()
