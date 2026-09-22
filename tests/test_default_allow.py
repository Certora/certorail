"""``default-allow = true``: a program no rule and no deny names runs with any arguments and the
user's authority; a named program keeps its shapes. Decided on the leading program name alone.
Root policies only; the filesystem kinds left unwritten become the whole root."""
import os
import pathlib
import tempfile
import threading
import unittest

from tests.brokerpath import build_server, exec_request
from certorail.describe import describe
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policy import Command, Refusal
from certorail.policyfile import PolicyFileError, from_data
from certorail.schema import SchemaError, parse_ruleset
from tests.test_rulesets import HEADER, RulesetCase

REPO = 'repo = pathlib.Path("repos") / "x"\n'


class TestDefaultAllow(RulesetCase):
    def setUp(self) -> None:
        super().setUp()
        self.policy = from_data({
            "policy-version": 1,
            "default-allow": True,
            "atoms": {"org-checkout": {}},
            "validation": [
                {"name": "org-repo", "argv": ["true"], "cwd": "repos/**", "writes": [],
                 "establishes": {"cwd": ["org-checkout"]}},
            ],
            "program": [
                {"name": "git", "subcommand": "log", "cwd": "repos/**"},
                {"name": "git", "argv": ["git", "push", "origin", "${BRANCH}"], "cwd": "repos/**",
                 "requires": ["org-checkout"], "holes": {"BRANCH": {"matches": "[a-z]+"}}},
            ],
            "deny": [{"argv": ["rm"]}, {"argv": ["curl"]}],
        })

    def check(self, body: str):
        return host_check(HEADER + REPO + body, "<t>", self.policy)

    def accept(self, body: str) -> None:
        outcome = self.check(body)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def denial(self, body: str) -> str:
        outcome = self.check(body)
        assert isinstance(outcome, Rejected), "expected a rejection"
        self.assertEqual(outcome.violations, [])
        return outcome.denials[0].reason

    def test_an_unnamed_program_runs_with_any_arguments(self) -> None:
        self.accept('certora.exec("cargo", "build", "--release", cwd=repo)\n')
        self.accept('certora.exec("jq", sys.argv[1], repo / "x.json", cwd=pathlib.Path("."))\n')  # even unknown text
        self.accept('certora.exec("make", cwd=repo)\n')

    def test_a_named_program_keeps_its_shapes(self) -> None:
        self.accept('certora.exec("git", "log", cwd=repo)\n')
        self.assertIn("fail closed", self.denial('certora.exec("git", "status", cwd=repo)\n'))
        self.assertIn("fail closed", self.denial('certora.exec("git", "-C", "x", "push", "origin", "main", cwd=repo)\n'))

    def test_a_denied_first_verb_is_refused(self) -> None:
        self.assertIn("not permitted", self.denial('certora.exec("rm", "-rf", "build", cwd=repo)\n'))
        self.assertIn("not permitted", self.denial('certora.exec("curl", "https://x", cwd=repo)\n'))
        self.assertEqual(self.policy.denied, frozenset({"rm", "curl"}))
        self.assertTrue(self.policy.governed("rm") and self.policy.governed("git") and not self.policy.governed("cargo"))

    def test_the_cwd_is_still_a_sink(self) -> None:
        self.assertIn("cwd is not proven", self.denial('certora.exec("cargo", "build", cwd=pathlib.Path(sys.argv[1]))\n'))

    def test_keywords_have_nothing_to_bind(self) -> None:
        self.assertIn("no holes to bind by keyword", self.denial('certora.exec("cargo", FLAGS=["--release"], cwd=repo)\n'))

    def test_an_unnamed_program_kills_every_environmental_fact(self) -> None:
        self.accept('certora.check("org-repo", cwd=repo)\ncertora.exec("git", "push", "origin", "main", cwd=repo)\n')
        reason = self.denial(
            'certora.check("org-repo", cwd=repo)\ncertora.exec("cargo", "build", cwd=repo)\n'
            'certora.exec("git", "push", "origin", "main", cwd=repo)\n'
        )
        self.assertIn("org-checkout", reason)

    def test_the_broker_agrees(self) -> None:
        command = self.policy.exec_command("cargo", ["build", "--release"], {}, "repos/x")
        assert isinstance(command, Command)
        self.assertEqual(command.argv, ["cargo", "build", "--release"])
        self.assertEqual(command.rule.origin, "default-allow")
        self.assertFalse(command.rule.jail.restricts)
        self.assertIsInstance(self.policy.exec_command("rm", ["-rf", "x"], {}, "repos/x"), Refusal)
        self.assertIsInstance(self.policy.exec_command("git", ["status"], {}, "repos/x"), Refusal)
        self.assertIsInstance(self.policy.exec_command("cargo", [], {"X": "1"}, "repos/x"), Refusal)
        self.assertIsInstance(self.policy.exec_command("cargo", [], {}, "../elsewhere"), Refusal)

    def test_end_to_end_through_the_broker(self) -> None:
        root = pathlib.Path(tempfile.mkdtemp())
        sock = os.path.join(tempfile.mkdtemp(), "broker.sock")
        server = build_server(sock, self.policy, root)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        reply = exec_request(sock, "echo", ["let", "it", "ride"], cwd=".")
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["returncode"], 0)
        reply = exec_request(sock, "rm", ["-rf", "x"], cwd=".")
        self.assertEqual((reply["ok"], reply["error"]), (False, "policy_denied"))

    def test_the_filesystem_defaults_to_the_root(self) -> None:
        self.assertEqual([str(loc) for loc in self.policy.read], [str(self.policy.write[0])])
        self.assertIsInstance(self.check('pathlib.Path("anything/at/all.txt").write_text("x")\n'), Accepted)
        self.assertIsInstance(self.check('pathlib.Path("/etc/passwd").read_text()\n'), Rejected)  # not absolute
        # a written kind stands, `[]` included
        narrow = from_data({"policy-version": 1, "default-allow": True, "filesystem": {"write": [], "read": ["src/**"]}})
        self.assertEqual(narrow.write, ())
        self.assertEqual(len(narrow.read), 1)
        # protections still bind
        protected = from_data({"policy-version": 1, "default-allow": True, "filesystem": {"no-write": ["secrets/**"]}})
        outcome = host_check(HEADER + 'pathlib.Path("secrets/k").write_text("x")\n', "<t>", protected)
        assert isinstance(outcome, Rejected)
        self.assertIn("protected", outcome.denials[0].reason)

    def test_without_the_key_nothing_changes(self) -> None:
        strict = from_data({"policy-version": 1, "program": [{"name": "git", "subcommand": "log", "cwd": "."}]})
        outcome = host_check(HEADER + 'certora.exec("cargo", "build", cwd=pathlib.Path("."))\n', "<t>", strict)
        assert isinstance(outcome, Rejected)
        self.assertIn("not permitted", outcome.denials[0].reason)
        self.assertEqual(strict.read, ())
        with self.assertRaises(PolicyFileError) as cm:
            from_data({"policy-version": 1, "deny": [{"argv": ["rm"]}]})
        self.assertIn("takes back nothing", str(cm.exception))

    def test_root_only(self) -> None:
        with self.assertRaises(SchemaError) as cm:
            parse_ruleset({"ruleset-version": 1, "default-allow": True}, "r.toml")
        self.assertEqual(cm.exception.problems, ["unknown key 'default-allow'"])

    def test_describe_says_so(self) -> None:
        text = describe(self.policy, "p.toml", None)
        self.assertIn("DEFAULT-ALLOW: any program not named above (and not denied: curl, rm) runs with any arguments and your authority", text)
        self.assertIn("Only the leading program name decides", text)


if __name__ == "__main__":
    unittest.main()
