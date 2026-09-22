"""The per-grant jail for exec'd tools and checkers (JAILS.md option B, ``childjail``): the
media keys and the ``exec`` table, what ``--describe`` says, and -- where bubblewrap is present
-- that the restrictions are properties of the process, not claims."""
import base64
import io
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import tomllib
import unittest
from unittest import mock

from certorail import markers
from tests.brokerpath import _roundtrip, build_server, exec_request
from certorail.childjail import (
    UNJAILED,
    Environment,
    Jail,
    JailUnavailable,
    Mounts,
    Regex,
    View,
    confined,
    environment,
    environment_spec,
    seatbelt_profile,
)
from certorail.describe import describe
from certorail.ids import CheckId, ParamName
from certorail.policy import Param, Policy, constraint, hole, program, pure, validation
from certorail.policyfile import from_data
from certorail.schema import SchemaError, parse_policy
from certorail.selfjail import ARCHES, fork_denial_filter

HAS_BWRAP = sys.platform == "linux" and shutil.which("bwrap") is not None
ENV_BINARY = shutil.which("env") or "env"
# the child interpreter for the jail probes: the system's, whose libraries the policy world's
# toolchain holds (a venv python loads libpython from beside itself, outside the world)
SYSTEM_PYTHON = next((p for p in ("/usr/bin/python3", "/bin/python3") if os.path.exists(p)), sys.executable)


def py(code: str) -> list[str]:
    return [SYSTEM_PYTHON, "-c", code]


def run(argv: list[str], jail: Jail, cwd: str | None = None) -> subprocess.CompletedProcess[bytes]:
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "MARKER": "1"}
    with confined(argv, jail, base_env=base) as spawn:
        return subprocess.run(spawn.argv, cwd=cwd, env=spawn.env, pass_fds=spawn.pass_fds, capture_output=True)


EMPTY = Environment()
PATH_ONLY = Environment(passed=("PATH",))


def env(*items: str | dict[str, str]) -> Jail:
    return Jail(env=environment_spec(items))


class TestJail(unittest.TestCase):
    def test_the_baseline_restricts_nothing(self) -> None:
        self.assertFalse(UNJAILED.restricts)
        for jail in (Jail(env=EMPTY), Jail(network=False), Jail(write_fs=False), Jail(spawn=False)):
            self.assertTrue(jail.restricts, jail)

    def test_the_spec_is_one_flat_mapping(self) -> None:
        self.assertEqual(
            environment_spec(["PATH", {"A": "1"}, "HOME", {"B": "2", "C": "3"}]),
            Environment(passed=("PATH", "HOME"), sets=(("A", "1"), ("B", "2"), ("C", "3"))),
        )
        for bad, message in (
            (["A=1"], "an environment variable name, not an assignment"),
            (["PATH", "PATH"], "mentioned twice"),
            (["PATH", {"PATH": "/bin"}], "mentioned twice"),
            ([{"A": "1"}, {"A": "2"}], "mentioned twice"),
            (["TMPDIR"], "set by the host"),
            ([{"TMPDIR": "/x"}], "set by the host"),
        ):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, message):
                environment_spec(bad)

    def test_the_environment_is_scrubbed_to_the_names_listed_and_the_values_set(self) -> None:
        base = {"PATH": "/bin", "HOME": "/h", "SECRET": "x"}
        self.assertEqual(environment(UNJAILED, base, None), base)
        self.assertEqual(environment(env("PATH", "MISSING"), base, None), {"PATH": "/bin"})
        self.assertEqual(environment(Jail(env=EMPTY), base, "/scratch"), {"TMPDIR": "/scratch"})
        self.assertEqual(environment(UNJAILED, base, "/scratch"), {**base, "TMPDIR": "/scratch"})
        # a set variable never carries the host's value, whatever the host has
        self.assertEqual(
            environment(env("PATH", {"HOME": "/elsewhere", "NEW": "1"}), base, None),
            {"PATH": "/bin", "HOME": "/elsewhere", "NEW": "1"},
        )

    def test_an_unrestricting_jail_spawns_as_is(self) -> None:
        with confined(["x", "y"], UNJAILED, base_env={"A": "1"}) as spawn:
            self.assertEqual((spawn.argv, spawn.env, spawn.pass_fds), (["x", "y"], {"A": "1"}, ()))

    def test_the_fork_denial_filter_assembles(self) -> None:
        # one BPF instruction is 8 bytes; the program is 10 instructions plus one per fork syscall
        self.assertEqual(len(fork_denial_filter(ARCHES["x86_64"])), 8 * 12)
        self.assertEqual(len(fork_denial_filter(ARCHES["aarch64"])), 8 * 10)

    def test_a_missing_mechanism_fails_closed(self) -> None:
        if sys.platform not in ("linux", "darwin"):
            self.skipTest("no child jail on this platform")
        with mock.patch("certorail.childjail.shutil.which", return_value=None):
            with self.assertRaises(JailUnavailable):
                with confined(["true"], Jail(network=False)):
                    self.fail("the wrapper must be refused before anything runs")
            # the environment alone needs no mechanism
            with confined(["true"], env("PATH"), base_env={"PATH": "/bin", "X": "1"}) as spawn:
                self.assertEqual(spawn.env, {"PATH": "/bin"})


@unittest.skipUnless(HAS_BWRAP, "bubblewrap is the Linux mechanism")
class TestBubblewrap(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_no_filesystem_writes_but_a_private_scratch(self) -> None:
        result = run(py("open('probe', 'w')"), Jail(write_fs=False), cwd=self.tmp)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Read-only file system", result.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "probe")))
        # TMPDIR is the one writable place, and it is gone afterwards
        result = run(py("import os; print(os.environ['TMPDIR']); open(os.path.join(os.environ['TMPDIR'], 'x'), 'w')"), Jail(write_fs=False))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(os.path.exists(result.stdout.decode().strip()))
        # an unjailed write lands
        self.assertEqual(run(py("open('probe', 'w')"), Jail(network=False), cwd=self.tmp).returncode, 0)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "probe")))

    def test_no_network(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        connect = py(f"import socket; socket.create_connection(('127.0.0.1', {port}), timeout=3)")
        self.assertNotEqual(run(connect, Jail(network=False)).returncode, 0)
        self.assertEqual(run(connect, Jail(write_fs=False)).returncode, 0)

    def test_no_subprocesses_but_threads(self) -> None:
        spawn = py("import subprocess, sys; subprocess.run([sys.executable, '-c', 'pass'], check=True)")
        result = run(spawn, Jail(spawn=False))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"PermissionError", result.stderr)
        self.assertEqual(run(spawn, Jail(network=False)).returncode, 0)
        threads = py("import threading; t = threading.Thread(target=lambda: None); t.start(); t.join(); print('ok')")
        result = run(threads, Jail(spawn=False))
        self.assertEqual((result.returncode, result.stdout), (0, b"ok\n"), result.stderr)

    def test_the_environment_reaches_the_child_scrubbed(self) -> None:
        def names(result: subprocess.CompletedProcess[bytes]) -> list[str]:
            self.assertEqual(result.returncode, 0, result.stderr)
            return sorted(line.split("=", 1)[0] for line in result.stdout.decode().splitlines() if "=" in line)

        self.assertEqual(names(run([ENV_BINARY], env("PATH"))), ["PATH"])
        # under bubblewrap: PWD is bwrap's own (it chdirs into the sandbox), TMPDIR the scratch
        self.assertEqual(names(run([ENV_BINARY], Jail(env=PATH_ONLY, write_fs=False))), ["PATH", "PWD", "TMPDIR"])
        self.assertEqual(names(run([ENV_BINARY], Jail(network=False))), ["MARKER", "PATH", "PWD"])
        # a set value arrives as set
        result = run(py("import os; print(os.environ['GREETING'])"), env("PATH", {"GREETING": "hi"}))
        self.assertEqual((result.returncode, result.stdout), (0, b"hi\n"), result.stderr)

    def test_everything_at_once(self) -> None:
        result = run(py("print('still runs')"), Jail(env=PATH_ONLY, network=False, write_fs=False, spawn=False))
        self.assertEqual((result.returncode, result.stdout), (0, b"still runs\n"), result.stderr)


CONFINED = Jail(env=PATH_ONLY, network=False, write_fs=False, spawn=False, view=View.POLICY)
CAT = shutil.which("cat") or "cat"
LS = shutil.which("ls") or "ls"


@unittest.skipUnless(HAS_BWRAP, "bubblewrap is the Linux mechanism")
class TestPolicyView(unittest.TestCase):
    """``exec.view = "policy"`` under bubblewrap: an empty world plus the policy's binds."""

    def setUp(self) -> None:
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="certorail-root-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        (self.root / "src").mkdir()
        (self.root / "src" / "main.py").write_text("print(1)\n")
        (self.root / "secrets").mkdir()
        (self.root / "secrets" / "key.pem").write_text("PRIVATE\n")
        (self.root / "out").mkdir()
        (self.root / "out" / "final").write_text("keep\n")
        (self.root / "README.md").write_text("hello\n")
        self.mounts = Mounts(reads=(self.root / "src", self.root / "README.md"), writes=(self.root / "out",),
                             no_write=(self.root / "out" / "final",))

    def confined(self, argv: list[str], jail: Jail = CONFINED, cwd: pathlib.Path | None = None,
                 mounts: Mounts | None = None) -> subprocess.CompletedProcess[bytes]:
        base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        with confined(argv, jail, base_env=base, mounts=self.mounts if mounts is None else mounts,
                      cwd=self.root if cwd is None else cwd) as spawn:
            return subprocess.run(spawn.argv, cwd=self.root if cwd is None else cwd, env=spawn.env,
                                  pass_fds=spawn.pass_fds, capture_output=True)

    def test_a_granted_file_reads_and_an_ungranted_one_does_not_exist(self) -> None:
        result = self.confined([CAT, str(self.root / "src" / "main.py")])
        self.assertEqual((result.returncode, result.stdout), (0, b"print(1)\n"), result.stderr)
        result = self.confined([CAT, "README.md"])  # relative to the cwd, which is the root
        self.assertEqual((result.returncode, result.stdout), (0, b"hello\n"), result.stderr)
        result = self.confined([CAT, str(self.root / "secrets" / "key.pem")])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"No such file or directory", result.stderr)
        self.assertNotIn(b"PRIVATE", result.stdout)

    def test_the_root_lists_only_what_is_bound(self) -> None:
        result = self.confined([LS, str(self.root)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(result.stdout.decode().split()), ["README.md", "out", "src"])
        # the directories above the root are a mountpoint chain: a sibling of the root is not there
        sibling = pathlib.Path(tempfile.mkdtemp(prefix="certorail-sibling-", dir=self.root.parent))
        self.addCleanup(shutil.rmtree, sibling, ignore_errors=True)
        result = self.confined([LS, str(self.root.parent)])
        listed = result.stdout.decode().split()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.root.name, listed)
        self.assertNotIn(sibling.name, listed)

    def test_the_cwd_exists_but_shows_nothing_unless_granted(self) -> None:
        # cwd is the secrets directory, which no grant covers: the tool starts there and sees nothing
        result = self.confined([LS, "-A"], cwd=self.root / "secrets")
        self.assertEqual((result.returncode, result.stdout), (0, b""), result.stderr)
        result = self.confined(py("import os; print(os.getcwd())"), cwd=self.root / "secrets")
        self.assertEqual((result.returncode, result.stdout.decode().strip()), (0, str(self.root / "secrets")), result.stderr)

    def test_writes_follow_write_fs_and_protections_stay_read_only(self) -> None:
        writer = Jail(env=PATH_ONLY, network=False, write_fs=True, spawn=False, view=View.POLICY)
        # a write grant, writable under write-fs = true
        result = self.confined(py(f"open({str(self.root / 'out' / 'new')!r}, 'w').write('x')"), writer)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "out" / "new").exists())
        # the protection inside it: read-only on top of the writable bind
        result = self.confined(py(f"open({str(self.root / 'out' / 'final')!r}, 'a').write('x')"), writer)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Read-only file system", result.stderr)
        self.assertEqual((self.root / "out" / "final").read_text(), "keep\n")
        # a read grant is never writable, whatever write-fs says
        result = self.confined(py(f"open({str(self.root / 'src' / 'new.py')!r}, 'w')"), writer)
        self.assertIn(b"Read-only file system", result.stderr)
        # under write-fs = false the write grant is read-only too, and TMPDIR is the one place
        result = self.confined(py(f"open({str(self.root / 'out' / 'other')!r}, 'w')"))
        self.assertIn(b"Read-only file system", result.stderr)
        result = self.confined(py("import os; open(os.path.join(os.environ['TMPDIR'], 'x'), 'w'); print('ok')"))
        self.assertEqual((result.returncode, result.stdout), (0, b"ok\n"), result.stderr)

    def test_a_write_outside_every_bind_fails_rather_than_vanishing(self) -> None:
        # a sloppy rule lets the argument through; the world still has nowhere to put it: the
        # mountpoint chain above the root and the empty cwd are read-only, not a silent tmpfs
        writer = Jail(env=PATH_ONLY, network=False, write_fs=True, spawn=False, view=View.POLICY)
        outside = self.root.parent / "certorail-escaped"
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        result = self.confined(py(f"open({str(outside)!r}, 'w')"), writer)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"Read-only file system", result.stderr)
        self.assertFalse(outside.exists())
        result = self.confined(py("open('probe', 'w')"), writer, cwd=self.root / "secrets")
        self.assertIn(b"Read-only file system", result.stderr)
        self.assertFalse((self.root / "secrets" / "probe").exists())

    def test_a_missing_protected_path_under_a_writable_bind_is_said_out_loud(self) -> None:
        writer = Jail(write_fs=True, view=View.POLICY)
        missing = Mounts(writes=(self.root / "out",), no_write=(self.root / "out" / "later",))
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            with confined(["true"], writer, mounts=missing, cwd=self.root):
                pass
        self.assertIn("no-write", err.getvalue())
        self.assertIn(str(self.root / "out" / "later"), err.getvalue())
        # an existing one, or one no write grant covers, is quietly held by the remount
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            with confined(["true"], writer, mounts=self.mounts, cwd=self.root):
                pass
            with confined(["true"], writer, mounts=Mounts(no_write=(self.root / "nowhere",)), cwd=self.root):
                pass
        self.assertEqual(err.getvalue(), "")

    def test_a_rules_own_mounts_widen_its_view(self) -> None:
        elsewhere = pathlib.Path(tempfile.mkdtemp(prefix="certorail-elsewhere-"))
        self.addCleanup(shutil.rmtree, elsewhere, ignore_errors=True)
        (elsewhere / "key").write_text("SECRET\n")
        (elsewhere / "state").mkdir()
        # without the addition the key does not exist for the tool; with it, it reads, and a
        # writable addition takes a write (write-fs = true), while the base stays as it was
        result = self.confined([CAT, str(elsewhere / "key")])
        self.assertIn(b"No such file or directory", result.stderr)
        widened = self.mounts | Mounts(reads=(elsewhere / "key",), writes=(elsewhere / "state",))
        result = self.confined([CAT, str(elsewhere / "key")], mounts=widened)
        self.assertEqual((result.returncode, result.stdout), (0, b"SECRET\n"), result.stderr)
        writer = Jail(env=PATH_ONLY, network=False, write_fs=True, spawn=False, view=View.POLICY)
        result = self.confined(py(f"open({str(elsewhere / 'state' / 'x')!r}, 'w'); print('ok')"), writer, mounts=widened)
        self.assertEqual((result.returncode, result.stdout), (0, b"ok\n"), result.stderr)
        self.assertTrue((elsewhere / "state" / "x").exists())
        result = self.confined([CAT, str(self.root / "secrets" / "key.pem")], mounts=widened)
        self.assertIn(b"No such file or directory", result.stderr)

    def test_the_view_needs_the_mounts(self) -> None:
        with self.assertRaisesRegex(JailUnavailable, "not lowered"):
            with confined(["true"], CONFINED):
                self.fail("a confined grant without mounts must not run")


# ---------------------------------------------------------------------------
# the policy side: the media keys are the jail, the exec table is the rest of it
# ---------------------------------------------------------------------------

READ_ONLY = Jail(env=PATH_ONLY, network=False, write_fs=False, spawn=False)


class TestGrants(unittest.TestCase):
    def test_the_media_keys_and_the_exec_table_assemble_the_jail(self) -> None:
        p = program("grep", cwd=".", network=False, write_fs=False, env=["PATH"], spawn=False)
        self.assertEqual(p.jail, READ_ONLY)
        self.assertTrue(p.effect_free)  # neither medium: an empty write set
        self.assertEqual(program("ls", cwd=".").jail, UNJAILED)
        v = validation("v", argv=["t"], establishes={}, write_fs=False)
        self.assertEqual(v.jail, Jail(write_fs=False))
        self.assertFalse(v.effect_free)  # the network medium is still reached
        # writes = [] is the region-level claim: effect-free, and no jail
        w = validation("w", argv=["t"], establishes={}, writes=[])
        self.assertTrue(w.effect_free)
        self.assertEqual(w.jail, UNJAILED)

    def test_environment_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "an environment variable name, not an assignment"):
            program("git", cwd=".", env=["A=1"])
        p = program("git", cwd=".", env=["PATH", {"GIT_PAGER": "cat", "GIT_OPTIONAL_LOCKS": "0"}])
        self.assertEqual(p.jail.env, Environment(("PATH",), (("GIT_PAGER", "cat"), ("GIT_OPTIONAL_LOCKS", "0"))))

    def test_the_table_loads(self) -> None:
        policy = from_data({
            "policy-version": 1,
            "program": [
                {"name": "grep", "cwd": ".", "subcommand": "x", "network": False, "write-fs": False,
                 "exec": {"env": ["PATH"], "spawn": False}},
                {"name": "git", "cwd": ".", "subcommand": "log", "network": False},
                {"name": "ls", "cwd": "."},
                {"name": "cat", "cwd": ".", "exec": {"view": "policy"}},
            ],
            "validation": [
                {"name": "v", "argv": ["t"], "write-fs": False, "exec": {"env": []}},
                {"name": "w", "argv": ["t"], "exec": {"env": ["HOME", {"PYTHONDONTWRITEBYTECODE": "1"}]}},
            ],
        })
        grep, git, ls, cat = policy.programs
        self.assertEqual(grep.jail, READ_ONLY)
        self.assertEqual(git.jail, Jail(network=False))
        self.assertEqual(ls.jail, UNJAILED)
        self.assertEqual(cat.jail, Jail(view=View.POLICY))
        self.assertTrue(cat.jail.restricts and cat.jail.confined and policy.confines)
        self.assertEqual(policy.validations[0].jail, Jail(env=EMPTY, write_fs=False))
        self.assertEqual(policy.validations[1].jail, Jail(env=Environment(("HOME",), (("PYTHONDONTWRITEBYTECODE", "1"),))))

    def test_the_shape(self) -> None:
        def problems(keys: str) -> list[str]:
            text = f'policy-version = 1\n[[program]]\nname = "x"\ncwd = "."\n{keys}\n'
            try:
                parse_policy(tomllib.loads(text), "<t>")
            except SchemaError as e:
                return e.problems
            return []

        self.assertEqual(problems('exec.spawn = false'), [])
        self.assertEqual(problems('exec.network = false'), ["program[0].exec: unknown key 'network'"])
        self.assertEqual(problems('exec.spawn = "no"'), ["program[0].exec.spawn: expected true or false"])
        self.assertEqual(problems('exec.env = "PATH"'), [])  # one name stands for the list of one
        self.assertEqual(problems('exec.env = ["A=1"]'), ["program[0].exec.env: an environment variable name, not an assignment: 'A=1'"])
        self.assertEqual(problems('exec.env = ["PATH", { PATH = "/bin" }]'), ["program[0].exec.env: environment variable PATH is mentioned twice"])
        self.assertIn("program[0].exec.env[0].A: expected a string", problems('exec.env = [{ A = 1 }]'))
        self.assertEqual(problems('exec.env = ["PATH", { GIT_PAGER = "cat" }]'), [])
        self.assertEqual(problems('write-fs = "no"'), ["program[0].write-fs: expected true or false"])
        self.assertEqual(problems('exec.view = "policy"'), [])
        self.assertEqual(problems('exec.view = "host"'), [])
        self.assertEqual(len(problems('exec.view = "fuse"')), 1)
        self.assertEqual(problems('exec.view = "policy"\nexec.mount-read = ["/srv/keys/**"]\nexec.mount-write = [".git/**"]'), [])
        self.assertEqual(
            problems('exec.mount-read = ["/srv/keys/**"]'),
            ['program[0].exec: mount-read / mount-write widen the policy view: they need view = "policy"'],
        )
        self.assertEqual(
            problems('write-fs = false\nexec.view = "policy"\nexec.mount-write = [".git/**"]'),
            ["program[0]: exec.mount-write on a grant with write-fs = false: nothing it mounts could be written"],
        )
        self.assertEqual(len(problems('exec.view = "policy"\nexec.mount-read = ["a/../b"]')), 1)

    def test_the_constructors_hold_the_mount_rules_too(self) -> None:
        with self.assertRaisesRegex(ValueError, "need view = policy"):
            program("git", cwd=".", mount_read=["/srv/keys/**"])
        with self.assertRaisesRegex(ValueError, "write-fs = false"):
            program("git", cwd=".", view=View.POLICY, write_fs=False, mount_write=[".git/**"])
        with self.assertRaisesRegex(ValueError, "need view = policy"):
            validation("v", argv=["t"], establishes={}, mount_read=["/x/**"])
        p = program("git", cwd=".", view=View.POLICY, mount_read=["/srv/keys/**"], mount_write=[".git/**"])
        self.assertEqual(len(p.mount_read), 1)
        self.assertEqual(len(p.mount_write), 1)
        loaded = from_data({
            "policy-version": 1,
            "program": [{"name": "git", "cwd": ".", "exec": {"view": "policy", "mount-read": ["/srv/keys/**"]}}],
        })
        self.assertEqual(loaded.programs[0].mount_read, p.mount_read)

    def test_the_seatbelt_profile_of_a_policy_view(self) -> None:
        mounts = Mounts(reads=(pathlib.Path("/r/src"),), writes=(pathlib.Path("/r/out"),), no_write=(pathlib.Path("/r/out/final"),))
        profile = seatbelt_profile(CONFINED, "/tmp/scratch", mounts, "/usr/bin/cat")
        self.assertIn("(deny file-read-data file-write*)", profile)
        # every process reads the root directory's entries at startup (measured: without this
        # `ls` and `cat` abort before main); the top-level names are all it exposes
        self.assertIn('(allow file-read-data (literal "/"))', profile)
        self.assertIn('(subpath "/usr/bin/cat")', profile)
        self.assertIn('(subpath "/r/src")', profile)
        # under write-fs = false the write grant is readable, and only the scratch dir writable
        self.assertRegex(profile, r'\(allow file-write\* \(subpath "[^"]*scratch"\) \(literal "/dev/null"\)\)')
        self.assertIn('(deny file-write* (subpath "/r/out/final"))', profile)
        self.assertIn("(deny network*)", profile)
        self.assertIn("(deny process-fork)", profile)
        writer = Jail(write_fs=True, view=View.POLICY)
        self.assertIn('(allow file-write* (subpath "/r/out")', seatbelt_profile(writer, "/tmp/scratch", mounts, None))
        # patterns are regex filters
        patterned = Mounts(reads=(Regex("^/r/src/(.*/)?[^/]+\\.py$"),), no_write=(Regex("^/r/(.*/)?\\.git(/.*)?$"),))
        profile = seatbelt_profile(CONFINED, "/tmp/scratch", patterned, None)
        self.assertIn('(regex #"^/r/src/(.*/)?[^/]+\\.py$")', profile)
        self.assertIn('(deny file-write* (regex #"^/r/(.*/)?\\.git(/.*)?$"))', profile)
        # the host view: today's profile, untouched
        self.assertEqual(seatbelt_profile(Jail(network=False), None, None, None), "(version 1) (allow default) (deny network*)")

    def test_describe_says_what_is_enforced(self) -> None:
        policy = Policy.allow(
            programs=[
                program("grep", cwd=".", subcommand="x", network=False, write_fs=False, env=["PATH"], spawn=False),
                program("git", cwd=".", subcommand="log", network=False, env=["PATH", {"GIT_PAGER": "cat"}]),
            ],
            validations=[validation("v", argv=["t"], establishes={}, spawn=False, env=[])],
        )
        text = describe(policy, "p.toml", None)
        self.assertIn(
            "effects: none (effect-free: kills no facts)\n"
            "    jailed (enforced by the OS): no network; no filesystem writes (a private TMPDIR only); "
            "no subprocesses; environment: PATH",
            text,
        )
        self.assertIn("jailed (enforced by the OS): no network; environment: PATH; sets GIT_PAGER=cat\n", text)
        self.assertIn("jailed (enforced by the OS): no subprocesses; environment: empty", text)
        self.assertIn("effects: writes anything on the filesystem (no network)\n    jailed", text)
        confined_text = describe(Policy.allow(programs=[program("cat", cwd=".", view=View.POLICY)]), "p.toml", None)
        self.assertIn("jailed (enforced by the OS): sees only what the policy grants", confined_text)
        widened = program("git", cwd=".", view=View.POLICY, mount_read=["/srv/keys/**"], mount_write=[".git/**"])
        self.assertIn("also sees: /srv/keys/** (read), .git/** (write)", describe(Policy.allow(programs=[widened]), "p.toml", None))


@unittest.skipUnless(HAS_BWRAP, "bubblewrap is the Linux mechanism")
class TestBrokeredJail(unittest.TestCase):
    """Through the broker: a grant's tool and a validation's checker run confined to the media
    they declare, and a jail the platform cannot provide is a broker error, not an unjailed run."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.root = pathlib.Path(tempfile.mkdtemp())
        policy = Policy.allow(
            programs=[
                program(
                    "python3", cwd=markers.within("."), argv=["python3", "-c", hole("CODE")],
                    holes={"CODE": constraint(any=True)}, write_fs=False,
                ),
                program(
                    "cat", cwd=markers.within("."), argv=["cat", hole("FILE")],
                    holes={"FILE": constraint(any=True)}, network=False, write_fs=False, spawn=False,
                    view=View.POLICY,
                ),
            ],
            validations=[
                validation("clean", argv=["python3", "-c", "open('probe', 'w')"], establishes={}, write_fs=False),
            ],
            read=["src/**"],
        )
        (cls.root / "src").mkdir()
        (cls.root / "src" / "a.txt").write_text("granted\n")
        (cls.root / "b.txt").write_text("not granted\n")
        cls.sock = os.path.join(tempfile.mkdtemp(), "broker.sock")
        cls.server = build_server(cls.sock, policy, cls.root)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_the_tool_runs_jailed(self) -> None:
        # "python3 -c" are the template's leading words; CODE follows
        reply = exec_request(self.sock, "python3", ["-c", "open('probe', 'w'); print('wrote')"], cwd=".")
        self.assertTrue(reply["ok"], reply)
        self.assertNotEqual(reply["returncode"], 0)
        self.assertIn(b"Read-only file system", base64.b64decode(reply["stderr_b64"]))
        self.assertFalse((self.root / "probe").exists())
        reply = exec_request(self.sock, "python3", ["-c", "print('read only is fine')"], cwd=".")
        self.assertEqual((reply["ok"], reply["returncode"]), (True, 0), reply)

    def test_a_confined_tool_sees_the_policy_view(self) -> None:
        reply = exec_request(self.sock, "cat", ["src/a.txt"], cwd=".")
        self.assertEqual((reply["ok"], reply["returncode"]), (True, 0), reply)
        self.assertEqual(base64.b64decode(reply["stdout_b64"]), b"granted\n")
        reply = exec_request(self.sock, "cat", ["b.txt"], cwd=".")
        self.assertTrue(reply["ok"], reply)
        self.assertNotEqual(reply["returncode"], 0)
        self.assertIn(b"No such file or directory", base64.b64decode(reply["stderr_b64"]))

    def test_the_checker_runs_jailed(self) -> None:
        reply = _roundtrip(self.sock, {"kind": "check", "name": "clean", "params": {}})
        self.assertTrue(reply["ok"], reply)
        self.assertNotEqual(reply["returncode"], 0)
        self.assertFalse((self.root / "probe").exists())

    def test_no_mechanism_no_run(self) -> None:
        with mock.patch("certorail.childjail.shutil.which", return_value=None):
            reply = exec_request(self.sock, "python3", ["-c", "open('probe', 'w')"], cwd=".")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "broker_error")
        self.assertIn("bubblewrap", reply["detail"])
        self.assertFalse((self.root / "probe").exists())


class TestLiteralCheckerJail(unittest.TestCase):
    def test_a_literal_checker_runs_under_its_jail(self) -> None:
        if not HAS_BWRAP:
            self.skipTest("bubblewrap is the Linux mechanism")
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)

        # a literal checker is effect-free: here by reaching neither medium (enforced), there by
        # the region-level claim writes = []. This one "accepts" by writing a file: jailed it
        # cannot, so it vouches for nothing; under the claim alone it writes the probe and vouches
        def touching(**media: object) -> Policy:
            return Policy.allow(validations=[validation(
                "touching", params=["v"], argv=["python3", "-c", "open('probe', 'w')", Param(ParamName("v"))],
                establishes={"v": [pure("touched")]}, **media,  # type: ignore[arg-type]
            )])

        jailed = touching(network=False, write_fs=False)
        self.assertTrue(jailed.validations[0].effect_free)
        self.assertFalse(jailed.discharger(root)(CheckId("touched"), "anything"))
        self.assertFalse((root / "probe").exists())
        self.assertTrue(touching(writes=[]).discharger(root)(CheckId("touched"), "anything"))
        self.assertTrue((root / "probe").exists())


if __name__ == "__main__":
    unittest.main()
