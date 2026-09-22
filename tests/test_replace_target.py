"""``p.replace(target)``: the receiver is moved onto *target*, so both paths are write sinks.
The target used to go unaudited, which let a program lay a file it had written onto any path
at all -- the write grant was checked against the source only."""
import unittest

from certorail import markers
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policy import Policy
from certorail.walker import analyze

HEADER = "import pathlib\nimport sys\n"

# writes are permitted under repos/*/out only
OUT_ONLY = Policy.allow(
    read=[markers.within("repos")],
    write=[markers.within("repos/x/out")],
)


class TestReplaceTarget(unittest.TestCase):
    def test_a_target_outside_the_grant_is_denied(self) -> None:
        source = HEADER + (
            'src = pathlib.Path("repos/x/out/config")\n'
            'src.replace(pathlib.Path("repos/x/.git/config"))\n'
        )
        outcome = host_check(source, "<t>", OUT_ONLY)
        assert isinstance(outcome, Rejected), outcome
        reasons = "\n".join(d.reason for d in outcome.denials)
        self.assertIn("write of repos/x/.git/config is not permitted", reasons)

    def test_both_paths_within_the_grant_are_accepted(self) -> None:
        source = HEADER + (
            'src = pathlib.Path("repos/x/out/config.tmp")\n'
            'src.replace(target=pathlib.Path("repos/x/out/config"))\n'
        )
        self.assertIsInstance(host_check(source, "<t>", OUT_ONLY), Accepted)

    def test_an_unproven_target_is_rejected(self) -> None:
        source = HEADER + (
            'src = pathlib.Path("repos/x/out/config.tmp")\n'
            "src.replace(sys.argv[1])\n"
        )
        self.assertIsInstance(host_check(source, "<t>", OUT_ONLY), Rejected)

    def test_a_missing_target_is_a_violation(self) -> None:
        report = analyze(HEADER + 'pathlib.Path("repos/x/out/a").replace()\n')
        self.assertTrue(any("target argument is required" in what for _, what in report.violations))

    def test_str_replace_is_not_a_sink(self) -> None:
        source = HEADER + 'name = sys.argv[1].replace("/", "_")\nprint(name)\n'
        self.assertIsInstance(host_check(source, "<t>", OUT_ONLY), Accepted)


if __name__ == "__main__":
    unittest.main()
