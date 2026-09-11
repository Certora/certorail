"""The kill by intersection (EFFECTS.md, step 2): an effect kills an environmental atom exactly
when what the effect's rule writes meets what the atom depends on. Exec and network sites take
their write set from the policy; a check from its signature; every other call, and every file
write, still writes everything."""
import unittest

from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policyfile import from_data

POLICY = from_data({
    "policy-version": 1,
    "filesystem": {"read": ["repos/**"], "write": ["repos/**"], "list": ["repos/**"]},
    "regions": {
        "git.config": {"footprint": ".git/config"},
        "git.index": {"footprint": ".git/index"},
        "git.refs": {"footprint": ".git/refs"},
        "git.remote": {"network": True},
    },
    "atoms": {
        "org-checkout": {"reads": ["git.config"]},
        "unprotected": {"reads": ["network"]},
    },
    "validation": [
        {"name": "org-repo", "argv": ["true"], "cwd": "repos/**", "effect-free": True,
         "establishes": {"cwd": ["org-checkout"]}},
        {"name": "main-unprotected", "argv": ["true"], "cwd": "repos/**", "write": False,
         "writes": [], "establishes": {"cwd": ["unprotected"]}},
    ],
    "program": [
        {"name": "git", "subcommand": "commit", "cwd": "repos/**", "network": False,
         "writes": ["git.refs", "git.index"]},
        {"name": "git", "subcommand": "status", "cwd": "repos/**", "effect-free": True},
        {"name": "git", "subcommand": "push", "cwd": "repos/**",
         "requires": ["org-checkout", "unprotected"], "writes": ["git.remote", "git.refs"]},
        {"name": "cargo", "subcommand": "build", "cwd": "repos/**"},
    ],
    "network": [
        {"host": "api.github.com", "methods": ["GET"]},
        {"host": "hooks.example.com", "methods": ["POST"]},
    ],
}, "<t>")

HEADER = "import pathlib\n"
REPO = 'repo = pathlib.Path("repos") / "x"\n'
CHECKS = 'certora.check("org-repo", cwd=repo)\ncertora.check("main-unprotected", cwd=repo)\n'
PUSH = 'certora.exec("git", "push", cwd=repo)\n'
COMMIT = 'certora.exec("git", "commit", "-m", "x", cwd=repo)\n'


def between(effect: str):
    return host_check(HEADER + REPO + CHECKS + effect + PUSH, "<t>", POLICY)


def denied_atoms(outcome: object) -> str:
    assert isinstance(outcome, Rejected), outcome
    return "\n".join(d.reason for d in outcome.denials)


class TestExecWriteSets(unittest.TestCase):
    def test_a_commit_preserves_what_it_does_not_write(self) -> None:
        outcome = between(COMMIT)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_an_effect_free_exec_preserves_everything(self) -> None:
        self.assertIsInstance(between('certora.exec("git", "status", cwd=repo)\n'), Accepted)

    def test_an_undeclared_rule_writes_everything(self) -> None:
        reason = denied_atoms(between('certora.exec("cargo", "build", cwd=repo)\n'))
        self.assertIn("cwd is not validated by: org-checkout, unprotected", reason)

    def test_a_loop_boundary_uses_the_same_write_sets(self) -> None:
        # the boundary rehearses one iteration, so a commit in a loop kills what a commit kills
        # and no more
        self.assertIsInstance(between("for i in [1]:\n    " + COMMIT), Accepted)
        reason = denied_atoms(between('for i in [1]:\n    certora.exec("cargo", "build", cwd=repo)\n'))
        self.assertIn("org-checkout", reason)


class TestNetworkWriteSets(unittest.TestCase):
    def test_a_get_writes_nothing(self) -> None:
        self.assertIsInstance(
            between('certora.network.get("https://api.github.com/repos")\n'), Accepted
        )

    def test_a_post_writes_the_network_and_only_that(self) -> None:
        reason = denied_atoms(
            between('certora.network.post("https://hooks.example.com/h", body=b"x")\n')
        )
        self.assertIn("cwd is not validated by: unprotected", reason)
        self.assertNotIn("org-checkout", reason)


class TestEverythingElse(unittest.TestCase):
    def test_a_file_write_still_kills_everything(self) -> None:
        reason = denied_atoms(between('(repo / "NOTICE.md").write_text("x")\n'))
        self.assertIn("org-checkout", reason)
        self.assertIn("unprotected", reason)

    def test_an_instantiation_still_kills_everything(self) -> None:
        reason = denied_atoms(between("class Box:\n    pass\nBox()\n"))
        self.assertIn("org-checkout", reason)
        self.assertIn("unprotected", reason)


if __name__ == "__main__":
    unittest.main()
