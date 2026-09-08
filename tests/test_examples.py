"""The shipped example policies (``examples/policies/``): every conforming program is
accepted under its own policy, every probe is rejected with the reason its README quotes,
and every checker script answers correctly offline.

Nothing here needs a network, a cloud CLI or a git remote: the checkers that would otherwise
ask the world have a fixture mode, and it is the default.
"""
import os
import pathlib
import subprocess
import unittest

from certorail.host import Rejected, check as host_check
from certorail.policyfile import load_policy_file

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "policies"

# example -> the program that must be accepted
CONFORMING = {
    "cloud-account-guard": "deploy.py",
    "pinned-image": "run_report.py",
    "budget-gate": "submit_jobs.py",
    "revision-exists": "pin_dependency.py",
    "publishable-text": "publish_note.py",
}

# example -> probe -> the fragment of the denial its README quotes
PROBES = {
    "cloud-account-guard": {
        "no_check.py": "argument 4 is not validated by: credentials-verified",
        "stale_check.py": "argument 4 is not validated by: credentials-verified",
        "undeclared_subcommand.py":
            "arguments match no declared subcommand of 'cloudctl' (subcommands fail closed)",
    },
    "pinned-image": {
        "moving_tag.py": "argument 3 is not validated by: approved-image, pinned-by-digest",
        "unapproved_digest.py": "argument 3 is not validated by: approved-image",
        "computed_image.py": "argument 3 is of unknown provenance",
    },
    "budget-gate": {
        "no_gate.py": "cwd is not validated by: under-budget",
        "gate_hoisted.py": "cwd is not validated by: under-budget",
        "gate_at_wrong_cwd.py": "check 'budget-gate' may not run at jobs (permitted: .)",
    },
    "revision-exists": {
        "unknown_revision.py": "argument 3 is not validated by: revision-exists",
        "moving_ref.py": "argument 3 is not validated by: revision-exists",
        "revision_from_argv.py": "argument 3 is of unknown provenance",
    },
    "publishable-text": {
        "unscanned_text.py": "argument 2 is not validated by: text-scanned",
        "literal_leak.py": "argument 2 is not validated by: text-scanned",
        "write_then_publish.py": "argument 2 is not validated by: file-scanned",
        "rewrite_after_scan.py": "argument 2 is not validated by: file-scanned",
    },
}


def outcome(example: str, program: str):
    """``certorail --check`` on one example program, in process. The root is the example's own
    directory, which is what lets the literal checkers find their fixtures."""
    root = EXAMPLES / example
    policy = load_policy_file(root / "policy.toml")
    source = (root / program).read_text(encoding="utf-8")
    return host_check(source, program, policy, root)


def checker(example: str, script: str, *args: str, env=None) -> subprocess.CompletedProcess:
    """One checker script, run the way certorail runs it: no shell, the example directory as
    the working directory."""
    root = EXAMPLES / example
    return subprocess.run(
        ["/bin/sh", f"checkers/{script}", *args],
        cwd=root,
        env={**os.environ, **(env or {})},
        capture_output=True,
        check=False,
    )


class TestConformingPrograms(unittest.TestCase):
    def test_every_conforming_program_is_accepted(self) -> None:
        for example, program in CONFORMING.items():
            with self.subTest(example=example):
                result = outcome(example, program)
                if isinstance(result, Rejected):
                    self.fail("\n".join(result.describe(program)))


class TestProbes(unittest.TestCase):
    def test_every_probe_is_rejected_for_its_documented_reason(self) -> None:
        for example, probes in PROBES.items():
            for program, expected in probes.items():
                with self.subTest(example=example, probe=program):
                    result = outcome(example, f"probes/{program}")
                    self.assertIsInstance(result, Rejected)
                    rendered = "\n".join(result.describe(program))
                    self.assertIn(expected, rendered)


class TestCloudAccountChecker(unittest.TestCase):
    """The stub mode: EXAMPLE_CLOUD_ACCOUNT stands in for asking the provider."""

    def test_matching_account_passes(self) -> None:
        r = checker("cloud-account-guard", "cloud-account.sh", "staging",
                    env={"EXAMPLE_CLOUD_ACCOUNT": "000000000001"})
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_staging_name_over_production_credentials_is_refused(self) -> None:
        r = checker("cloud-account-guard", "cloud-account.sh", "staging",
                    env={"EXAMPLE_CLOUD_ACCOUNT": "000000000002"})
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"not the 'staging' account", r.stderr)

    def test_an_unrecorded_environment_is_a_distinct_failure(self) -> None:
        r = checker("cloud-account-guard", "cloud-account.sh", "sandbox",
                    env={"EXAMPLE_CLOUD_ACCOUNT": "000000000001"})
        self.assertEqual(r.returncode, 3)

    def test_an_absent_cli_never_reads_as_a_match(self) -> None:
        # no stub, and a PATH with no provider CLI on it: the checker must fail loudly
        r = checker("cloud-account-guard", "cloud-account.sh", "staging",
                    env={"EXAMPLE_CLOUD_ACCOUNT": "", "PATH": "/usr/bin:/bin"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"not on PATH", r.stderr)


class TestBudgetChecker(unittest.TestCase):
    def test_under_the_cap_passes(self) -> None:
        self.assertEqual(checker("budget-gate", "budget-gate.sh").returncode, 0)


class TestRevisionChecker(unittest.TestCase):
    def test_a_revision_in_the_fixture_passes(self) -> None:
        r = checker("revision-exists", "revision-exists.sh",
                    "0123456789abcdef0123456789abcdef01234567")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_an_unknown_revision_is_refused(self) -> None:
        r = checker("revision-exists", "revision-exists.sh", "f" * 40)
        self.assertEqual(r.returncode, 1)

    def test_a_branch_name_is_not_a_pin(self) -> None:
        r = checker("revision-exists", "revision-exists.sh", "main")
        self.assertEqual(r.returncode, 1)


class TestScanCheckers(unittest.TestCase):
    def test_clean_text_passes_and_a_denylisted_term_does_not(self) -> None:
        self.assertEqual(
            checker("publishable-text", "scan-text.sh", "a perfectly ordinary sentence").returncode, 0
        )
        self.assertEqual(
            checker("publishable-text", "scan-text.sh", "ship PROJECT-BLUEBOTTLE now").returncode, 1
        )

    def test_the_file_scan_reads_the_file(self) -> None:
        self.assertEqual(
            checker("publishable-text", "scan-file.sh", "drafts/release-note.md").returncode, 0
        )

    def test_a_missing_file_is_not_a_pass(self) -> None:
        r = checker("publishable-text", "scan-file.sh", "outbox/absent.md")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
