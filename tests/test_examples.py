"""The shipped example policies (``examples/policies/``): every conforming program is
accepted under its own policy, every probe is rejected with the reason its README quotes,
and every checker script answers correctly offline.

Nothing here needs a network, a cloud CLI or a git remote: the checkers that would otherwise
ask the world have a fixture mode, and it is the default.
"""
import contextlib
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from certorail.host import Rejected, check as host_check
from certorail.policyfile import load_policy_file

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples" / "policies"

# The variables the example checkers switch modes on. A developer or a CI runner with one of
# these exported would otherwise be testing a different example than the docstring describes,
# so they are stripped everywhere a checker can see them -- including the in-process path,
# where certorail spawns the literal checkers itself and they inherit os.environ.
MODE_VARS = ("EXAMPLE_UPSTREAM_MIRROR", "EXAMPLE_CLOUD_ACCOUNT")


def _fixture_environment() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in MODE_VARS}


@contextlib.contextmanager
def fixture_mode():
    """os.environ with the mode variables removed, restored on the way out."""
    saved = {k: os.environ.pop(k) for k in MODE_VARS if k in os.environ}
    try:
        yield
    finally:
        os.environ.update(saved)

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
    with fixture_mode():
        return host_check(source, program, policy, root)


def checker(example: str, script: str, *args: str, env=None) -> subprocess.CompletedProcess:
    """One checker script, run the way certorail runs it: no shell, the example directory as
    the working directory."""
    root = EXAMPLES / example
    return subprocess.run(
        ["/bin/sh", f"checkers/{script}", *args],
        cwd=root,
        env={**_fixture_environment(), **(env or {})},
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

    def test_a_name_that_is_not_an_environment_name_is_refused(self) -> None:
        # the name becomes a path component, so the checker validates its shape first
        for name in ("../accounts/staging", "Staging", "sand box"):
            with self.subTest(name=name):
                r = checker("cloud-account-guard", "cloud-account.sh", name,
                            env={"EXAMPLE_CLOUD_ACCOUNT": "000000000001"})
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn(b"not an environment name", r.stderr)

    def test_an_absent_cli_never_reads_as_a_match(self) -> None:
        # no stub, and a PATH with no provider CLI on it: the checker must fail loudly
        r = checker("cloud-account-guard", "cloud-account.sh", "staging",
                    env={"EXAMPLE_CLOUD_ACCOUNT": "", "PATH": "/usr/bin:/bin"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"not on PATH", r.stderr)


class TestBudgetChecker(unittest.TestCase):
    """The passing case runs against the committed fixture; every refusal runs against a copy,
    so the fixture the rest of the example depends on stays as it is."""

    def test_under_the_cap_passes(self) -> None:
        self.assertEqual(checker("budget-gate", "budget-gate.sh").returncode, 0)

    def budget(self, contents: str | None) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            shutil.copytree(EXAMPLES / "budget-gate" / "checkers", root / "checkers")
            if contents is not None:
                (root / "state").mkdir()
                (root / "state" / "budget").write_text(contents, encoding="utf-8")
            return subprocess.run(
                ["/bin/sh", "checkers/budget-gate.sh"],
                cwd=root, env=_fixture_environment(), capture_output=True, check=False,
            )

    def test_spending_up_to_the_cap_is_refused(self) -> None:
        r = self.budget("100 100\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"has reached the cap", r.stderr)

    def test_an_unparsable_fixture_is_not_a_pass(self) -> None:
        r = self.budget("x 100\n")
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"is not a number", r.stderr)

    def test_an_empty_fixture_is_not_a_pass(self) -> None:
        self.assertEqual(self.budget("").returncode, 2)

    def test_a_missing_fixture_is_not_a_budget_with_room_in_it(self) -> None:
        r = self.budget(None)
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"no budget fixture", r.stderr)


class TestRevisionChecker(unittest.TestCase):
    def test_a_revision_in_the_fixture_passes(self) -> None:
        r = checker("revision-exists", "revision-exists.sh",
                    "0123456789abcdef0123456789abcdef01234567")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_an_unknown_revision_is_refused(self) -> None:
        r = checker("revision-exists", "revision-exists.sh", "f" * 40)
        self.assertEqual(r.returncode, 1)

    def test_uppercase_hex_is_not_a_pin(self) -> None:
        # a case-pattern range is collation-dependent; the checker must not depend on it
        r = checker("revision-exists", "revision-exists.sh", "0123456789ABCDEF" + "0" * 24)
        self.assertEqual(r.returncode, 1)
        self.assertIn(b"lowercase hexadecimal", r.stderr)

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

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "root reads a mode-000 file, so there is nothing to refuse")
    def test_a_file_that_cannot_be_read_is_not_a_pass(self) -> None:
        # grep answers an unreadable file with an error, not with "no match". The whole
        # example rests on a predicate having been run, so that must not read as clean.
        with tempfile.TemporaryDirectory() as tmp:
            unreadable = pathlib.Path(tmp) / "leak.md"
            unreadable.write_text("PROJECT-BLUEBOTTLE ships tomorrow\n", encoding="utf-8")
            unreadable.chmod(0o000)
            r = checker("publishable-text", "scan-file.sh", str(unreadable))
            self.assertEqual(r.returncode, 2, r.stderr)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "root reads a mode-000 file, so there is nothing to refuse")
    def test_a_denylist_that_cannot_be_read_is_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "example"
            shutil.copytree(EXAMPLES / "publishable-text", root)
            (root / "denylist.txt").chmod(0o000)
            for script, argument in (("scan-text.sh", "we ship PROJECT-BLUEBOTTLE tomorrow"),
                                     ("scan-file.sh", "drafts/release-note.md")):
                with self.subTest(script=script):
                    r = subprocess.run(
                        ["/bin/sh", f"checkers/{script}", argument],
                        cwd=root, env=_fixture_environment(),
                        capture_output=True, check=False,
                    )
                    self.assertEqual(r.returncode, 2, r.stderr)
            (root / "denylist.txt").chmod(0o644)


class TestTheSuiteCoversTheTree(unittest.TestCase):
    def test_every_probe_on_disk_is_listed(self) -> None:
        for example in CONFORMING:
            with self.subTest(example=example):
                on_disk = {p.name for p in (EXAMPLES / example / "probes").glob("*.py")}
                self.assertEqual(on_disk, set(PROBES[example]))

    def test_every_example_directory_has_a_conforming_program(self) -> None:
        on_disk = {p.name for p in EXAMPLES.iterdir() if p.is_dir()}
        self.assertEqual(on_disk, set(CONFORMING))


class TestPolicyConfinement(unittest.TestCase):
    """The two holes the rules close on top of `argument-locations`, which binds only the
    arguments the analysis tracked as paths and so lets a literal through."""

    def check_source(self, example: str, source: str):
        root = EXAMPLES / example
        policy = load_policy_file(root / "policy.toml")
        with fixture_mode():
            return host_check(source, "probe.py", policy, root)

    def test_a_literal_path_outside_the_outbox_cannot_be_published(self) -> None:
        result = self.check_source("publishable-text", """import pathlib
def main() -> None:
    workdir = pathlib.Path(".")
    target = "../../../etc/passwd"
    certora.check("scan-file", path=target, cwd=workdir)
    certora.exec("post-note", "publish-file", target, cwd=workdir)
main()
""")
        self.assertIsInstance(result, Rejected)
        self.assertIn("is not validated by: outbox-path",
                      "\n".join(result.describe("probe.py")))

    def test_the_text_scan_cannot_be_moved_off_the_root(self) -> None:
        # A validation with no declared cwd lets the program choose where the checker runs,
        # and denylist.txt is resolved from there. `cwd = "."` is what forbids it.
        result = self.check_source("publishable-text", """import pathlib
def main() -> None:
    body = (pathlib.Path("drafts") / "release-note.md").read_text()
    scanned = certora.check_single("scan-text", body, cwd=pathlib.Path("outbox"))
    certora.exec("post-note", "publish-text", scanned, cwd=pathlib.Path("."))
main()
""")
        self.assertIsInstance(result, Rejected)
        self.assertIn("check 'scan-text' may not run at outbox",
                      "\n".join(result.describe("probe.py")))


if __name__ == "__main__":
    unittest.main()
