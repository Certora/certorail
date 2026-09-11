"""Location slots (a rule's or a validation's ``cwd``) take one location or a list meaning
any-of; ``${checkers}/<name>`` heads a validation's argv and resolves against the config
directory's ``checkers/`` at load."""
import os
import pathlib
import stat
import tempfile
import unittest

from certorail import markers
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policy import Policy, program, validation
from certorail.policyfile import PolicyFileError, from_data

HEADER = "import pathlib\n"

TWO_ROOTS = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within(".")],
    listing=[markers.within(".")],
    programs=[program("git", subcommand="log", cwd=[markers.within("repos"), markers.within("data")])],
    validations=[
        validation(
            "probe",
            argv=("true",),
            cwd=[markers.within("repos"), markers.within("data")],
            establishes={"cwd": ["probed"]},
        )
    ],
)


class TestAnyOfCwd(unittest.TestCase):
    def outcome(self, body: str):
        return host_check(HEADER + body, "<t>", TWO_ROOTS)

    def test_either_location_is_permitted(self) -> None:
        for spot in ('pathlib.Path("repos") / "x"', 'pathlib.Path("data") / "y"'):
            with self.subTest(spot=spot):
                outcome = self.outcome(f'certora.exec("git", "log", cwd={spot})\n')
                if isinstance(outcome, Rejected):
                    self.fail("\n".join(outcome.describe("<t>")))

    def test_a_third_is_denied_naming_both(self) -> None:
        outcome = self.outcome('certora.exec("git", "log", cwd=pathlib.Path("other") / "z")\n')
        assert isinstance(outcome, Rejected)
        (denial,) = outcome.denials
        self.assertIn("one of repos/**, data/**", denial.reason)

    def test_a_check_runs_at_either(self) -> None:
        outcome = self.outcome('certora.check("probe", cwd=pathlib.Path("data") / "y")\n')
        self.assertIsInstance(outcome, Accepted)
        outcome = self.outcome('certora.check("probe", cwd=pathlib.Path("other"))\n')
        assert isinstance(outcome, Rejected)
        self.assertIn("one of", outcome.denials[0].reason)

    def test_an_empty_slot_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            program("git", cwd=[])

    def test_the_runtime_recheck_agrees(self) -> None:
        self.assertIsNone(TWO_ROOTS.exec_refusal("git", ["log"], "data/y"))
        refusal = TWO_ROOTS.exec_refusal("git", ["log"], "other/z")
        assert refusal is not None
        self.assertIn("one of", refusal)


class TestSlotsInTheDataFormat(unittest.TestCase):
    def test_a_list_and_a_string_both_load(self) -> None:
        policy = from_data({
            "policy-version": 1,
            "program": [
                {"name": "git", "cwd": ["repos/**", "data/**"]},
                {"name": "gh", "cwd": "."},
            ],
            "validation": [
                {"name": "v", "argv": ["true"], "cwd": ["repos/**", "/srv/x/**"], "establishes": {}},
            ],
        })
        git, gh = policy.programs
        self.assertEqual(len(git.cwd), 2)
        self.assertEqual(len(gh.cwd), 1)
        (v,) = policy.validations
        assert v.cwd is not None
        self.assertEqual(len(v.cwd), 2)

    def test_malformed_slots_are_reported(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            from_data({
                "policy-version": 1,
                "program": [{"name": "git", "cwd": []}, {"name": "gh", "cwd": ["ok", 3]}],
            })
        self.assertIn("program[0].cwd", str(cm.exception))
        self.assertIn("program[1].cwd", str(cm.exception))


class TestCheckersVariable(unittest.TestCase):
    def setUp(self) -> None:
        self.config = pathlib.Path(tempfile.mkdtemp())
        os.environ["CERTORAIL_CONFIG_DIR"] = str(self.config)
        self.addCleanup(os.environ.pop, "CERTORAIL_CONFIG_DIR", None)
        checkers = self.config / "checkers"
        checkers.mkdir()
        self.ok = checkers / "ok"
        self.ok.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.ok.chmod(self.ok.stat().st_mode | stat.S_IXUSR)
        (checkers / "not-executable").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

    def load(self, argv: list[str]) -> Policy:
        return from_data({
            "policy-version": 1,
            "validation": [{"name": "v", "argv": argv, "establishes": {}}],
        })

    def test_the_head_resolves_to_the_installed_checker(self) -> None:
        (v,) = self.load(["${checkers}/ok", "--strict"]).validations
        self.assertEqual(v.argv, (str(self.ok), "--strict"))

    def test_a_missing_or_unexecutable_checker_fails_at_load(self) -> None:
        for name in ("absent", "not-executable"):
            with self.subTest(name=name), self.assertRaises(PolicyFileError) as cm:
                self.load([f"${{checkers}}/{name}"])
            self.assertIn("not installed", str(cm.exception))

    def test_only_the_head_of_argv0(self) -> None:
        for argv in (["${checkers}"], ["${checkers}/"], ["test", "${checkers}/ok"], ["x/${checkers}/ok"]):
            with self.subTest(argv=argv), self.assertRaises(PolicyFileError) as cm:
                self.load(argv)
            self.assertIn("${checkers}", str(cm.exception))

    def test_no_escaping_the_checkers_directory(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            self.load(["${checkers}/../ok"])
        self.assertIn("'..'", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
