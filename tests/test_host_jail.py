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
from certorail.host import _bwrap_command, _jail_write_paths, _seatbelt_profile
from certorail.policy import Policy

ROOT = pathlib.Path("/work")
COMMAND = ["python3", "-I", "-P", "-c", "bootstrap", "prog.py"]


class TestWriteSurface(unittest.TestCase):
    def test_the_root_and_absolute_write_prefixes(self) -> None:
        policy = Policy.allow(
            write=[
                markers.within("repos"),                        # relative: the root covers it
                markers.within("/srv/checkouts"),               # absolute: its own allowance
                markers.within("/opt", leaf=markers.matches(r"\w+\.log")),  # concrete prefix
            ],
        )
        self.assertEqual(_jail_write_paths(policy, ROOT), ["/work", "/srv/checkouts", "/opt"])


class TestBubblewrap(unittest.TestCase):
    def test_the_world(self) -> None:
        policy = Policy.allow(write=[markers.within("repos")], no_write=[markers.within("secrets")])
        argv = _bwrap_command("/usr/bin/bwrap", policy, ROOT, policy.mounts(ROOT), COMMAND)
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
        lines = _seatbelt_profile(policy, ROOT, policy.mounts(ROOT)).splitlines()
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
