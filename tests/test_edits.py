"""Lifts and edits in the root policy (REDLINES.md): a root policy lets one grant's process past the
machine's redlines (``exec.lift-read`` / ``lift-write``), on a rule it declares or through an
``[[edit]]`` of a rule an applied ruleset grants -- which amends that rule's ``exec`` table and
nothing else. A ruleset lifts nothing."""
import os
import pathlib
import tempfile
import tomllib
import unittest
from unittest import mock

from certorail.childjail import View
from certorail.describe import jail_line
from certorail.locations import parse_location
from certorail.policy import Policy, Program, Validation
from certorail.policyfile import PolicyFileError, from_data

HEAD = 'policy-version = 1\nbase = false\n[filesystem]\nread = ["**"]\nwrite = ["**"]\n'
CARGO = """ruleset-version = 1
[[program]]
name = "cargo"
subcommand = "build"
cwd = "."

[[program]]
name = "cargo"
subcommand = "fetch"
cwd = "."
exec.env = ["PATH"]

[[validation]]
name = "clean"
argv = ["test", "-d", "."]
establishes = {}
"""


class Case(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.config = pathlib.Path(tmp.name)
        self.enterContext(mock.patch.dict(os.environ, {"CERTORAIL_CONFIG_DIR": str(self.config)}))
        (self.config / "rulesets").mkdir()
        self.ruleset("cargo.toml", CARGO)

    def ruleset(self, name: str, text: str) -> None:
        (self.config / "rulesets" / name).write_text(text, encoding="utf-8")

    def load(self, text: str) -> Policy:
        return from_data(tomllib.loads(HEAD + text))

    def refused(self, text: str) -> str:
        with self.assertRaises(PolicyFileError) as caught:
            self.load(text)
        return str(caught.exception)

    def rule(self, text: str, words: tuple[str, ...]) -> Program:
        return next(p for p in self.load(text).programs if p.leading_words == words)


class TestLifts(Case):
    def test_a_rule_the_root_declares_may_lift(self) -> None:
        rule = self.rule('[[program]]\nname = "git"\ncwd = "."\nexec.lift-read = "/home/u/.ssh/known_hosts"\n', ("git",))
        self.assertEqual(rule.lift_read, (parse_location("/home/u/.ssh/known_hosts"),))
        self.assertIn("let past this machine's redlines at: /home/u/.ssh/known_hosts (readable, read-only)", jail_line(rule) or "")

    def test_a_ruleset_lifts_nothing(self) -> None:
        self.ruleset("lifts.toml", 'ruleset-version = 1\n[[program]]\nname = "git"\ncwd = "."\nexec.lift-read = "/home/u/.ssh"\n')
        self.assertIn("a ruleset lifts no redline", self.refused('[[apply]]\nruleset = "lifts.toml"\n'))

    def test_a_writable_lift_needs_the_medium(self) -> None:
        self.assertIn("nothing it lifts could be written",
                      self.refused('[[program]]\nname = "git"\ncwd = "."\nwrite-fs = false\nexec.lift-write = "/home/u/.ssh"\n'))


class TestEdits(Case):
    APPLY = '[[apply]]\nruleset = "cargo.toml"\n'

    def test_an_edit_runs_a_rulesets_tool_the_users_way(self) -> None:
        edited = self.rule(self.APPLY + (
            '[[edit]]\nprogram = "cargo build"\nfrom = "cargo"\n'
            'exec.view = "policy"\nexec.mount-write = "/home/u/.cargo/**"\n'
        ), ("cargo", "build"))
        self.assertIs(edited.view, View.POLICY)
        self.assertEqual(edited.mount_write, (parse_location("/home/u/.cargo/**"),))
        self.assertIn("edited by", edited.origin or "")
        self.assertIn("(widens and narrows)", edited.origin or "")  # a mount added, the host view left

    def test_the_rule_is_checked_as_merged(self) -> None:
        # the ruleset's host view refuses mounts: the edit alone does not make them legal
        self.assertIn("need view = policy", self.refused(self.APPLY + (
            '[[edit]]\nprogram = "cargo build"\nexec.mount-read = "/srv/**"\n'
        )))

    def test_a_list_is_added_to_and_a_value_replaced(self) -> None:
        edited = self.rule(self.APPLY + (
            '[[edit]]\nprogram = "cargo fetch"\nexec.env = ["HOME"]\nexec.spawn = false\n'
        ), ("cargo", "fetch"))
        assert edited.env is not None
        self.assertEqual(edited.env.passed, ("PATH", "HOME"))
        self.assertFalse(edited.spawn)

    def test_the_whole_environment_has_nothing_to_add_to(self) -> None:
        self.assertIn("none to add to", self.refused(self.APPLY + '[[edit]]\nprogram = "cargo build"\nexec.env = ["HOME"]\n'))

    def test_an_edit_that_matches_nothing_is_an_error(self) -> None:
        for text, message in (
            ('[[edit]]\nprogram = "cargo test"\nexec.spawn = false\n', "no applied ruleset grants it"),
            ('[[edit]]\nprogram = "cargo build"\nfrom = "other"\nexec.spawn = false\n', "from 'other': no applied ruleset grants it"),
            ('[[program]]\nname = "make"\ncwd = "."\n[[edit]]\nprogram = "make"\nexec.spawn = false\n', "declared by this policy"),
        ):
            with self.subTest(text=text):
                self.assertIn(message, self.refused(self.APPLY + text))

    def test_a_validation_by_its_name(self) -> None:
        policy = self.load(self.APPLY + '[[edit]]\nvalidation = "clean"\nexec.spawn = false\n')
        (clean,) = [v for v in policy.validations if v.name == "clean"]
        self.assertIsInstance(clean, Validation)
        self.assertFalse(clean.spawn)

    def test_an_edit_never_touches_the_media(self) -> None:
        self.assertIn("unknown key 'network'", self.refused(self.APPLY + '[[edit]]\nprogram = "cargo build"\nexec.network = false\n'))
        self.assertIn("unknown key 'network'", self.refused(self.APPLY + '[[edit]]\nprogram = "cargo build"\nnetwork = false\nexec = {}\n'))

    def test_a_ruleset_edits_nothing(self) -> None:
        self.ruleset("edits.toml", 'ruleset-version = 1\n[[edit]]\nprogram = "cargo build"\nexec.spawn = false\n')
        self.assertIn("unknown key 'edit'", self.refused('[[apply]]\nruleset = "edits.toml"\n'))

    def test_an_edit_lifts(self) -> None:
        edited = self.rule(self.APPLY + (
            '[[edit]]\nprogram = "cargo fetch"\nexec.lift-read = "/home/u/.cargo/credentials.toml"\n'
        ), ("cargo", "fetch"))
        self.assertEqual(edited.lift_read, (parse_location("/home/u/.cargo/credentials.toml"),))
        self.assertIn("(widens)", edited.origin or "")


if __name__ == "__main__":
    unittest.main()
