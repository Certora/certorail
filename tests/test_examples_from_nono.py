"""The nono ports under ``examples/policies/from-nono``: every policy loads, and every example
program reaches the verdict its header claims -- for the reason its header claims. The denial
strings are asserted because they are the examples' whole point: each one names the mechanism
that stood in for a nono feature."""
import ast
import pathlib
import tomllib
import unittest

from certorail.host import Accepted, Rejected, check as host_check
from certorail.policyfile import load_policy_file

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "policies" / "from-nono"
ROOT = EXAMPLES / "sandbox"

ACCEPTED = [
    ("paths.toml", "paths_ok.py"),
    ("delegation.toml", "delegation_ok.py"),
    ("argv_gate.toml", "argv_gate_ok.py"),
    ("endpoints.toml", "endpoints_ok.py"),
    ("protection.toml", "protection_ok.py"),
]

# policy, program, the reason of every denial, in order
DENIED = [
    ("paths.toml", "paths_denied.py", [
        "write of config/settings.json is not permitted",
        "read of /etc/hosts is not permitted",
    ]),
    ("delegation.toml", "delegation_denied.py", [
        "arguments match no declared subcommand of 'git' (subcommands fail closed)",
        "program 'ssh' is not permitted",
    ]),
    ("argv_gate.toml", "argv_gate_denied.py", [
        "arguments match no declared subcommand of 'gh' (subcommands fail closed)",
        "argument 3 is not validated by: read-only-token",
        "argument 2 is not validated by: read-only-token",
        "argument 2 is not validated by: read-only-token",
        "argument 2 is not validated by: read-only-token",
    ]),
    ("endpoints.toml", "endpoints_denied.py", [
        "the URL is not validated by: issues-endpoint",
        "the URL is not validated by: issues-endpoint",
        "DELETE https://api.github.com:443 matches no network rule",
        "the URL is not proven",
        "the URL is not validated by: issues-endpoint",
    ]),
    ("protection.toml", "protection_denied.py", [
        "read of workspace/.env is not permitted",
        "program 'rm' is not permitted",
    ]),
]


def outcome(policy_name: str, program_name: str) -> tuple[Accepted | Rejected, str]:
    program = EXAMPLES / program_name
    return (
        host_check(program.read_text(), program.name, load_policy_file(EXAMPLES / policy_name), ROOT),
        program.name,
    )


class TestTheAcceptedExamples(unittest.TestCase):
    def test_each_one_is_accepted(self) -> None:
        for policy, program in ACCEPTED:
            with self.subTest(program=program):
                result, name = outcome(policy, program)
                if isinstance(result, Rejected):
                    self.fail("\n".join(result.describe(name)))


class TestTheDeniedExamples(unittest.TestCase):
    def test_each_one_is_denied_for_the_documented_reason(self) -> None:
        for policy, program, expected in DENIED:
            with self.subTest(program=program):
                result, name = outcome(policy, program)
                assert isinstance(result, Rejected), f"{name}: expected a rejection"
                self.assertEqual([], result.violations)
                reasons = [d.reason for d in result.denials]
                self.assertEqual(len(expected), len(reasons), reasons)
                for want, got in zip(expected, reasons):
                    self.assertIn(want, got)


class TestTheSubsetRemovesTheDeletionSinks(unittest.TestCase):
    """protection_deleted.py is the one example rejected by the subset rather than the policy:
    the program's own deletion sinks are not in the subset, so the rejection carries a violation
    and no denial at all, and no policy can hand one of those sinks back."""

    def test_unlink_is_a_violation_not_a_denial(self) -> None:
        result, _ = outcome("protection.toml", "protection_deleted.py")
        assert isinstance(result, Rejected), "expected a rejection"
        self.assertEqual([], result.denials)
        self.assertTrue(any("forbidden attribute unlink" in what for _, what in result.violations))


def assigned_string(source: str, name: str) -> str:
    """The value of a module-level ``name = "..."`` binding, read off the parse tree."""
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            assert isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
            return node.value.value
    raise AssertionError(f"no module-level {name} assignment")


class TestTheCheckerMatchesItsAtom(unittest.TestCase):
    """endpoints.toml's atom and checks/issues-endpoint are two spellings of one property: the
    analysis discharges the atom from text it can read, the checker establishes it on text it
    cannot. The checker's docstring says keeping them in step is the author's job; this is the
    one thing that can check it mechanically."""

    def test_the_pattern_is_the_atom(self) -> None:
        policy = tomllib.loads((EXAMPLES / "endpoints.toml").read_text())
        checker = (EXAMPLES / "checks" / "issues-endpoint").read_text()
        self.assertEqual(
            policy["atoms"]["issues-endpoint"]["matches"],
            assigned_string(checker, "PATTERN"),
        )


if __name__ == "__main__":
    unittest.main()
