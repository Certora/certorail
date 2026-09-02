"""The srt jail profile the host wraps around a confined run."""
import pathlib
import unittest

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

    def test_absolute_write_locations_are_lowered_into_the_profile(self) -> None:
        policy = Policy.allow(
            write=[
                markers.within("repos"),                        # relative: the root covers it
                markers.within("/home/john/certora/verisafe"),  # absolute: its own allowance
                markers.within("/opt", leaf=markers.matches(r"\w+\.log")),  # concrete prefix
            ],
        )
        settings = _srt_settings(policy, ROOT, TMP, None)
        self.assertEqual(
            settings["filesystem"]["allowWrite"],
            ["/work", "/tmp/run", "/home/john/certora/verisafe", "/opt"],
        )


if __name__ == "__main__":
    unittest.main()
