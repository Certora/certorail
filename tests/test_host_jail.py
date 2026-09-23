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

import certorail
from certorail import markers
from certorail.analysis import pretty_location as pretty
from certorail.policy import Policy, network
from certorail.sandbox.lowering import Bind, RegexRule
from certorail.sandbox.program import bwrap_argv, lower_program, seatbelt_profile

ROOT = pathlib.Path("/work")
COMMAND = ["python3", "-I", "-P", "-c", "bootstrap", "prog.py"]


def writable(policy: Policy) -> list[str]:
    return [str(p) for p in lower_program(policy, ROOT, patterns=False).writable]


class TestWriteSurface(unittest.TestCase):
    def test_the_root_and_absolute_write_prefixes(self) -> None:
        policy = Policy.allow(
            write=[
                markers.within("repos"),                        # relative: the root covers it
                markers.within("/srv/checkouts"),               # absolute: its own allowance
                markers.within("/opt", leaf=markers.matches(r"\w+\.log")),  # concrete prefix
            ],
        )
        self.assertEqual(writable(policy), ["/work", "/srv/checkouts", "/opt"])

    def test_protections_lower_by_platform(self) -> None:
        policy = Policy.allow(write=["**"], no_write=["secrets", "repos/*/.git"])
        linux = lower_program(policy, ROOT, patterns=False)
        self.assertEqual(linux.protected, (Bind(ROOT / "secrets", "no-write"),))
        self.assertEqual([pretty(o.location) for o in linux.omitted], ["repos/*/.git"])
        mac = lower_program(policy, ROOT, patterns=True)
        self.assertEqual(len(mac.protected), 2)
        self.assertIsInstance(mac.protected[1], RegexRule)
        self.assertEqual(mac.omitted, ())


class TestStrict(unittest.TestCase):
    """``strict = true``: a confined grant whose jail cannot express the policy refuses the run,
    before anything runs, instead of warning."""

    def test_an_omission_refuses_a_strict_run(self) -> None:
        if sys.platform != "linux":
            self.skipTest("the omission here is bubblewrap's (Seatbelt spells the pattern)")
        from certorail.childjail import View
        from certorail.host import JailRefused, run
        from certorail.policy import program

        def policy(strict: bool) -> Policy:
            # an absolute pattern: no bind says it and no view serves it
            return Policy.allow(read=["**", "/srv/<x.*>"], programs=[program("cat", cwd=".", view=View.POLICY)], strict=strict)

        with tempfile.TemporaryDirectory() as tmp:
            refused = run("print('never')\n", "p.py", policy(True), pathlib.Path(tmp))
            assert isinstance(refused, JailRefused)
            self.assertEqual([o.role for o in refused.omitted], ["read"])
            self.assertIn("strict", refused.describe()[0])


class TestEnumerablePrefixes(unittest.TestCase):
    """An absolute grant must begin with literal names or {a,b} sets, which the jail explodes;
    one it could only widen to "/" is refused at load."""

    def test_sets_are_exploded(self) -> None:
        policy = Policy.allow(write=["/{srv,opt}/data/**", "/srv/data/<x.*>"])
        self.assertEqual(writable(policy), ["/work", "/opt/data", "/srv/data"])

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


class TestBubblewrap(unittest.TestCase):
    def test_the_world(self) -> None:
        policy = Policy.allow(write=[markers.within("repos")], no_write=[markers.within("secrets")])
        argv = bwrap_argv(lower_program(policy, ROOT, patterns=False), "/usr/bin/bwrap", COMMAND)
        text = " ".join(argv)
        self.assertTrue(text.startswith("/usr/bin/bwrap --ro-bind / / --dev /dev --proc /proc "))
        self.assertIn("--bind-try /work /work", text)
        self.assertIn("--ro-bind-try /work/secrets /work/secrets", text)
        # the protection is mounted after the writable root, so it wins
        self.assertLess(text.index("--bind-try /work /work"), text.index("--ro-bind-try /work/secrets"))
        self.assertIn("--unshare-net", argv)
        self.assertIn("--die-with-parent", argv)
        self.assertEqual(argv[-len(COMMAND) - 1:], ["--", *COMMAND])


class TestSeatbelt(unittest.TestCase):
    def test_the_profile(self) -> None:
        policy = Policy.allow(write=[markers.within("repos")], no_write=[markers.within("secrets")])
        lines = seatbelt_profile(lower_program(policy, ROOT, patterns=True)).splitlines()
        real = os.path.realpath
        self.assertEqual(lines[:3], ["(version 1)", "(allow default)", "(deny file-write*)"])
        allowed = f'(allow file-write* (subpath "{real("/work")}"))'
        protected = f'(deny file-write* (subpath "{real("/work/secrets")}"))'
        self.assertIn(allowed, lines)
        self.assertIn(protected, lines)
        self.assertLess(lines.index(allowed), lines.index(protected))  # later rules win: protections last
        self.assertEqual(lines[-3:], ["(deny network*)", "(deny process-fork)", "(deny process-exec*)"])


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
        self.assertEqual(result.returncode, 0, err)
        self.assertIn(f"the tool ran in {root}", result.stdout.decode(errors="replace"))
        self.assertNotIn("WITHOUT the OS jail", err)
        self.assertNotIn("self-jail not installed", err)


if __name__ == "__main__":
    unittest.main()
