"""Two rule shapes and nothing between (TEMPLATES.md): a flat rule is exactly its words, a
template says what each argument is. The retired flat-rule argument keys are load errors that
name the replacement; the open flag vocabulary (``any = true``) is the explicit spelling of
"this tool is trusted with its options"; and ``not-option`` is the built-in atom behind the
leading-dash guard, which a checker may establish on text whose head the analysis cannot see."""
import unittest

from certorail import markers
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policy import Policy, constraint, flagset, hole, param, program, pure, splice, validation
from certorail.policyfile import PolicyFileError, from_data
from certorail.templates import Flags, Flagset, Token

HEADER = "import pathlib\n"
REPO = 'repo = pathlib.Path("repos") / "x"\n'


def loads(data: dict) -> Policy:
    return from_data({"policy-version": 1, **data}, "<t>")


class TestRetiredKeys(unittest.TestCase):
    def test_each_retired_key_names_the_replacement(self) -> None:
        for key, value in (
            ("unknown-arguments", True),
            ("argument-locations", ["repos/**"]),
            ("argument-atoms", []),
        ):
            with self.subTest(key=key):
                with self.assertRaises(PolicyFileError) as cm:
                    loads({"program": [{"name": "git", "cwd": ".", key: value}]})
                self.assertIn("template", str(cm.exception))

    def test_a_flat_rule_is_its_words(self) -> None:
        policy = loads({"program": [{"name": "git", "cwd": "repos/**", "subcommand": "status"}]})
        outcome = host_check(HEADER + REPO + 'certora.exec("git", "status", cwd=repo)\n', "<t>", policy)
        self.assertIsInstance(outcome, Accepted)
        outcome = host_check(HEADER + REPO + 'certora.exec("git", "status", "--short", cwd=repo)\n', "<t>", policy)
        assert isinstance(outcome, Rejected)
        self.assertTrue(any("takes no arguments beyond its words" in d.reason for d in outcome.denials))


class TestOpenFlags(unittest.TestCase):
    def test_the_open_vocabulary_admits_anything_in_flag_position(self) -> None:
        policy = loads({
            "program": [{
                "name": "cargo", "cwd": "repos/**", "network": False,
                "argv": ["cargo", "build", "${FLAGS...}"],
                "holes": {"FLAGS": {"kind": "flags", "any": True}},
            }],
        })
        source = HEADER + REPO + (
            "import sys\n"
            'certora.exec("cargo", "build", "--release", "--features", sys.argv[1], cwd=repo)\n'
        )
        outcome = host_check(source, "<t>", policy)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_it_stands_alone(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            loads({
                "program": [{
                    "name": "cargo", "cwd": ".", "argv": ["cargo", "${FLAGS...}"],
                    "holes": {"FLAGS": {"kind": "flags", "any": True, "bare": ["-q"]}},
                }],
            })
        self.assertIn("lists no flags", str(cm.exception))
        with self.assertRaises(ValueError):
            Flagset(any=True, bare=frozenset({"-q"}))  # type: ignore[arg-type]

    def test_it_cannot_say_what_it_writes(self) -> None:
        with self.assertRaises(ValueError) as cm:
            program(
                "cargo", cwd=".", writes=[], network=False,
                argv=["cargo", "build", splice("FLAGS")], holes={"FLAGS": Flags(flagset(any=True))},
            )
        self.assertIn("cannot say what it writes", str(cm.exception))

    def test_a_named_flagset_may_be_open(self) -> None:
        policy = loads({
            "flagset": [{"name": "trusted", "any": True}],
            "program": [{
                "name": "cargo", "cwd": ".", "argv": ["cargo", "${FLAGS...}"],
                "holes": {"FLAGS": {"kind": "flags", "flagset": "trusted"}},
            }],
        })
        (rule,) = policy.programs
        assert rule.template is not None
        flags = rule.template.holes[next(iter(rule.template.holes))]
        assert isinstance(flags, Flags)
        self.assertTrue(flags.flagset.any)


NOT_FORCE = validation(
    "not-force-check",
    argv=("test", param("value"), "!=", "--force"),
    params=("value",),
    establishes={"value": [pure("not-force"), "not-option"]},
    effect_free=True,
)


class TestNotOption(unittest.TestCase):
    def test_it_cannot_be_declared(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            loads({"atoms": {"not-option": {"pure": True}}})
        self.assertIn("built in", str(cm.exception))
        with self.assertRaises(ValueError):
            Policy.allow(atoms=[__import__("certorail.policy", fromlist=["atom"]).atom("not-option", markers.matches("x"))])

    def test_a_checker_may_establish_it(self) -> None:
        policy = loads({
            "atoms": {"not-force": {"pure": True}},
            "validation": [{
                "name": "not-force-check", "params": ["value"],
                "argv": ["test", "${value}", "!=", "--force"], "effect-free": True,
                "establishes": {"value": ["not-force", "not-option"]},
            }],
            "program": [{
                "name": "git", "cwd": "repos/**", "argv": ["git", "push", "origin", "${BRANCH}"],
                "holes": {"BRANCH": {"atoms": ["not-force"]}},
            }],
        })
        # a checked value of unknown text fills a hole no "--" precedes: the checker vouched for
        # its head; unchecked, the same value is denied on the dash guard
        checked = HEADER + REPO + (
            "import sys\n"
            'branch = certora.check_single("not-force-check", sys.argv[1])\n'
            'certora.exec("git", "push", "origin", branch, cwd=repo)\n'
        )
        outcome = host_check(checked, "<t>", policy)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_structure_saturates_it(self) -> None:
        policy = Policy.allow(
            programs=[program(
                "git", cwd=markers.within("repos"),
                argv=["git", "push", "origin", hole("BRANCH")],
                holes={"BRANCH": Token(constraint(atoms=["not-option"]))},  # the guard, spelled out
            )],
        )
        self.assertIsInstance(
            host_check(HEADER + REPO + 'certora.exec("git", "push", "origin", "main", cwd=repo)\n', "<t>", policy),
            Accepted,
        )
        outcome = host_check(
            HEADER + REPO + 'import sys\ncertora.exec("git", "push", "origin", sys.argv[1], cwd=repo)\n', "<t>", policy
        )
        assert isinstance(outcome, Rejected)
        self.assertTrue(any("not-option" in d.reason for d in outcome.denials))

    def test_the_vocabulary_counts_it_pure(self) -> None:
        policy = Policy.allow(validations=[NOT_FORCE])
        self.assertIn("not-option", policy.vocabulary().pure_atoms)


if __name__ == "__main__":
    unittest.main()
