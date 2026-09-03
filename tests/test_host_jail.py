"""The srt jail profile the host wraps around a confined run, and the self-jail the
bootstrap installs inside it."""
import os
import pathlib
import subprocess
import sys
import unittest

import certorail
from certorail import markers
from certorail.host import _srt_settings
from certorail.policy import Policy

ROOT = pathlib.Path("/work")
TMP = pathlib.Path("/tmp/run")


class TestJailProfile(unittest.TestCase):
    def test_deny_all_network_with_the_broker_as_the_single_door(self) -> None:
        settings = _srt_settings(Policy.allow(), ROOT, TMP, TMP / "broker.sock")
        self.assertEqual(settings["network"]["allowedDomains"], [])
        self.assertFalse(settings["network"]["allowLocalBinding"])
        self.assertEqual(settings["network"]["allowUnixSockets"], ["/tmp/run/broker.sock"])
        self.assertEqual(settings["filesystem"]["allowWrite"], ["/work", "/tmp/run"])

    def test_no_broker_means_no_doors(self) -> None:
        settings = _srt_settings(Policy.allow(), ROOT, TMP, None)
        self.assertEqual(settings["network"]["allowUnixSockets"], [])


class TestSelfJail(unittest.TestCase):
    def test_exec_is_denied_after_install(self) -> None:
        if sys.platform != "linux":
            self.skipTest("the seccomp self-jail is Linux; macOS uses sandbox_init")
        probe = (
            "import certorail.selfjail, subprocess, sys\n"
            "warning = certorail.selfjail.deny_process_creation()\n"
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

    def test_absolute_write_locations_are_lowered_into_the_profile(self) -> None:
        policy = Policy.allow(
            write=[
                markers.within("repos"),                        # relative: the root covers it
                markers.within("/srv/checkouts"),               # absolute: its own allowance
                markers.within("/opt", leaf=markers.matches(r"\w+\.log")),  # concrete prefix
            ],
        )
        settings = _srt_settings(policy, ROOT, TMP, None)
        self.assertEqual(
            settings["filesystem"]["allowWrite"],
            ["/work", "/tmp/run", "/srv/checkouts", "/opt"],
        )


if __name__ == "__main__":
    unittest.main()
