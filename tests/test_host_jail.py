"""The OS jail the host puts around a confined run -- bubblewrap around the interpreter on Linux,
a Seatbelt profile the bootstrap installs on itself on macOS -- the self-jail's process-creation
denial, and the whole path end to end: a program inside the jail reaching the broker over the
inherited descriptor."""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import certorail
from certorail.policy import Policy, network
from certorail.sandbox import Backend, CompileError, Compiled, compile_jail
from certorail.sandbox.emit import Link, bwrap_command, seatbelt_profile
from certorail.sandbox.facts import Disk
from certorail.sandbox.front import program_host
from certorail.sandbox.place import BwrapPlan, HostBase, SeatbeltPlan, place_bubblewrap, place_seatbelt
from certorail.sandbox.program import ProgramJail, program_jail
from certorail.world import Floor, World


class Tree(unittest.TestCase):
    """A real directory for the program's jail: the front end and the placer look at what exists."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(os.path.realpath(tmp.name)) / "root"
        for d in ("out", "repos/a", "secrets", "src"):
            (self.root / d).mkdir(parents=True)
        self.outside = self.root.parent / "outside"
        for d in ("abs/data", "alt/data", "keys"):
            (self.outside / d).mkdir(parents=True)

    def jail(self, floor: Floor) -> ProgramJail | CompileError:
        return program_jail(TestHostWorld.POLICY, World(floor=floor), self.root, sys.executable, ())


class TestHostWorld(Tree):
    """Host mode: the host's ``/`` as unix permissions have it, whatever the policy and the floor
    say. The floor guard holds those, in the process (``test_floorguard``)."""

    POLICY = Policy.allow(write=["out/**", "/srv/{a,b}/**"], no_write=["secrets", "repos/*/.git"])

    def test_the_world_is_the_hosts(self) -> None:
        jail = self.jail(Floor.of(never_write=(self.outside / "keys",), never_visible=(self.root / "secrets",)))
        assert isinstance(jail, ProgramJail)
        self.assertEqual((jail.grants, jail.interpreter), (program_host(), None))
        self.assertEqual(place_bubblewrap(jail.grants, Disk()), BwrapPlan(HostBase(True), ()))
        self.assertEqual(place_seatbelt(jail.grants, Disk()), SeatbeltPlan(HostBase(True), ()))

    def test_a_missing_floor_path_is_held_by_name(self) -> None:
        self.assertIsInstance(self.jail(Floor.of(never_write=(self.root / "nope",), never_visible=(self.root / "gone",))), ProgramJail)

    def test_hiding_the_interpreter_refuses(self) -> None:
        prefix = pathlib.Path(os.path.realpath(sys.base_prefix))
        refused = self.jail(Floor.of(never_visible=(prefix,)))
        assert isinstance(refused, CompileError), refused
        self.assertIn(f"this machine's never-visible {prefix}: hides {prefix}, which the interpreter needs",
                      [r.describe() for r in refused.refusals])


class TestRefusedRun(unittest.TestCase):
    """What a jail cannot hold refuses the run before anything runs, with every reason: nothing is
    ever left out of a jail."""

    def test_a_jail_needing_a_view_this_machine_cannot_serve(self) -> None:
        if sys.platform != "linux":
            self.skipTest("views are bubblewrap's (Seatbelt spells a pattern as a rule)")
        from certorail.analysis import pretty_location
        from certorail.childjail import View
        from certorail.host import JailRefused, run
        from certorail.policy import program

        policy = Policy.allow(read=["**", "src/<x.*>"], programs=[program("cat", cwd=".", view=View.POLICY)])
        with tempfile.TemporaryDirectory() as tmp, mock.patch("certorail.viewdaemon.unavailable", return_value="a test says so"):
            refused = run("print('never')\n", "p.py", policy, pathlib.Path(tmp))
        assert isinstance(refused, JailRefused), refused
        pattern = pretty_location(policy.read[1])
        self.assertEqual(refused.reasons, (f"read grant {pattern}: needs a filesystem view, and none can be had: a test says so",))


class TestEnumerablePrefixes(unittest.TestCase):
    """An absolute grant must begin with literal names or {a,b} sets, which the jail explodes;
    one it could only widen to "/" is refused at load."""

    def test_a_pattern_first_component_is_refused(self) -> None:
        for spelling in ("/**", "/*/data", "/<t.*>/data", "/"):
            with self.subTest(spelling=spelling):
                with self.assertRaisesRegex(ValueError, "must begin with a literal name"):
                    Policy.allow(write=[spelling])
                with self.assertRaisesRegex(ValueError, "must begin with a literal name"):
                    Policy.allow(no_write=[spelling])

    def test_relative_locations_and_url_paths_are_not_affected(self) -> None:
        Policy.allow(read=["*/data"], write=["<t.*>/**"])
        Policy.allow(network=[network("api.example.com", path="/**")])


class TestTheJailAsWritten(Tree):
    """Host mode's jail as a run writes it: the host's ``/``, network and process creation off."""

    def compiled(self, backend: Backend) -> Compiled:
        jail = self.jail(Floor.of(never_visible=(self.outside / "keys",)))
        assert isinstance(jail, ProgramJail)
        compiled = compile_jail(jail.grants, backend, Disk(), view_unavailable=None)
        assert isinstance(compiled, Compiled)
        return compiled

    def test_bubblewrap(self) -> None:
        compiled = self.compiled(Backend.BUBBLEWRAP)
        assert isinstance(compiled.plan, BwrapPlan)
        self.assertEqual(bwrap_command(compiled.plan, compiled.grants.process, Link(self.root), {}, bwrap="/usr/bin/bwrap"), [
            "/usr/bin/bwrap", "--die-with-parent", "--bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-net", "--",
        ])

    def test_seatbelt(self) -> None:
        compiled = self.compiled(Backend.SEATBELT)
        assert isinstance(compiled.plan, SeatbeltPlan)
        self.assertEqual(seatbelt_profile(compiled.plan, compiled.grants.process, Link(self.root)).splitlines(), [
            "(version 1)", "(allow default)", "(deny network*)", "(deny process-fork)", "(deny process-exec*)",
        ])


class TestBootstrap(unittest.TestCase):
    """The child's bootstrap, run as the host runs it but unjailed, with a program the analysis
    would never admit, to look: the program sees none of the environment, and the markers still
    find the broker."""

    def test_the_program_sees_no_environment(self) -> None:
        from certorail.host import bootstrap

        parent = str(pathlib.Path(certorail.__file__).resolve().parent.parent)
        with tempfile.TemporaryFile() as program:
            program.write(b"import os\nprint(sorted(os.environ), sorted(os.environb), certora.BROKER_FD)\n")
            program.flush()
            program.seek(0)
            env = {"CERTORAIL_PROGRAM_FD": str(program.fileno()), "CERTORAIL_BROKER_FD": "7", "EXAMPLE_SETTING": "on"}
            done = subprocess.run([sys.executable, "-I", "-P", "-c", bootstrap(parent), "prog.py"], env=env,
                                  pass_fds=[program.fileno()], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), "[] [] 7")


class TestSelfJail(unittest.TestCase):
    def test_exec_is_denied_after_install(self) -> None:
        if sys.platform != "linux":
            self.skipTest("the seccomp self-jail is Linux; macOS installs a Seatbelt profile")
        probe = (
            "import certorail.selfjail, subprocess, sys\n"
            "warning = certorail.selfjail.install()\n"
            "assert warning is None, warning\n"
            "try:\n"
            '    subprocess.run(["/bin/true"], check=False)\n'
            "except PermissionError:\n"
            "    sys.exit(42)\n"
            "sys.exit(1)\n"
        )
        package_parent = pathlib.Path(certorail.__file__).resolve().parent.parent
        result = subprocess.run(
            [sys.executable, "-c", probe],
            env={**os.environ, "PYTHONPATH": str(package_parent)},
            capture_output=True,
        )
        self.assertEqual(result.returncode, 42, result.stderr.decode(errors="replace"))


class TestJailedRun(unittest.TestCase):
    """The whole path, jail on: the host spawns the interpreter (under bubblewrap on Linux), the
    bootstrap installs the self-jail, and the program's exec travels over the inherited socket to
    the broker, which runs the tool host-side and answers."""

    def test_an_exec_from_inside_the_jail_reaches_the_broker(self) -> None:
        if sys.platform == "linux" and shutil.which("bwrap") is None:
            self.skipTest("bubblewrap is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            policy = root / "policy.toml"
            policy.write_text('policy-version = 1\n\n[[program]]\nname = "pwd"\ncwd = "."\n', encoding="utf-8")
            source = 'r = certora.exec("pwd", cwd=".")\nprint("the tool ran in", r.stdout.decode("utf-8", "replace"))\n'
            result = subprocess.run(
                [sys.executable, "-m", "certorail.host", "run", "-c", source, "--root", str(root), "--policy", str(policy)],
                capture_output=True,
            )
        err = result.stderr.decode(errors="replace")
        self.assertEqual(result.returncode, 0, err)  # a jail that could not be had would refuse the run
        self.assertIn(f"the tool ran in {root}", result.stdout.decode(errors="replace"))

    def test_the_program_starts_with_none_of_the_hosts_environment(self) -> None:
        # /proc/self/environ is what the process was started with, whatever it clears later: the
        # host's own environment must never have reached it
        if sys.platform != "linux" or shutil.which("bwrap") is None:
            self.skipTest("/proc and bubblewrap are Linux's")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            policy = root / "policy.toml"
            policy.write_text('policy-version = 1\nbase = false\n[filesystem]\nread = ["/proc/self/environ"]\n', encoding="utf-8")
            source = 'for entry in open("/proc/self/environ").read().split("\\0"):\n    print(entry)\n'
            result = subprocess.run(
                [sys.executable, "-m", "certorail.host", "run", "-c", source, "--root", str(root), "--policy", str(policy)],
                env={**os.environ, "EXAMPLE_SETTING": "on", "LANG": "C.UTF-8"}, capture_output=True,
            )
        out = result.stdout.decode(errors="replace")
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertNotIn("EXAMPLE_SETTING", out)
        self.assertIn("LANG=C.UTF-8", out)  # the locale, kept


if __name__ == "__main__":
    unittest.main()
