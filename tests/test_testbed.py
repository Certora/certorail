"""The testbed's static half (testbed/scenario.toml): every probe gets the analysis' verdict the
scenario says, for the reason it says, and every policy that must not load does not. The run-time
half needs a built root, the jail and the local API: testbed/run.py."""
import pathlib
import tomllib
import unittest

from certorail.host import Accepted, check
from certorail.policy import Policy
from certorail.policyfile import PolicyFileError, load_policy_file

TESTBED = pathlib.Path(__file__).resolve().parent.parent / "testbed"
SCENARIO = tomllib.loads((TESTBED / "scenario.toml").read_text(encoding="utf-8"))


class TestTestbed(unittest.TestCase):
    def setUp(self) -> None:
        self.policies: dict[str, Policy] = {}

    def policy(self, name: str) -> Policy:
        if name not in self.policies:
            self.policies[name] = load_policy_file(TESTBED / name)
        return self.policies[name]

    def test_every_probe_gets_its_verdict(self) -> None:
        for probe in SCENARIO["probe"]:
            with self.subTest(probe=probe["name"]):
                program = probe["program"]
                outcome = check((TESTBED / program).read_text(encoding="utf-8"), program,
                                self.policy(probe.get("policy", "policy.toml")))
                report = "\n".join(outcome.describe(program))
                if probe["check"] == "accepted":
                    self.assertIsInstance(outcome, Accepted, report)
                    continue
                self.assertNotIsInstance(outcome, Accepted, report)
                kind = "violation" if probe["check"] == "violation" else "denied"
                self.assertIn(f": {kind}: ", report)
                self.assertIn(probe["because"], report)

    def test_every_refused_policy_is_refused(self) -> None:
        for refused in SCENARIO["refused"]:
            with self.subTest(policy=refused["policy"]):
                with self.assertRaises(PolicyFileError) as caught:
                    load_policy_file(TESTBED / refused["policy"])
                self.assertIn(refused["error"], str(caught.exception))

    def test_every_other_policy_loads(self) -> None:
        for name in ("policy.toml", "strict.toml", "lints.toml"):
            with self.subTest(policy=name):
                self.policy(name)


if __name__ == "__main__":
    unittest.main()
