"""The kill by intersection (EFFECTS.md): an effect kills an environmental atom exactly when
what the effect writes meets what the atom depends on. Exec and network sites take their write
set from the policy, a check from its signature, and the program's own file writes are derived:
a write kills an atom when its proven location can lie at or below a footprint of a region the
atom reads, instantiated under the cwd of the validation that established it."""
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
        "tidy": {},                                  # undeclared: depends on everything
        "indexed": {"reads": ["git.index"]},
    },
    "validation": [
        {"name": "org-repo", "argv": ["true"], "cwd": "repos/**", "effect-free": True,
         "establishes": {"cwd": ["org-checkout"]}},
        {"name": "main-unprotected", "argv": ["true"], "cwd": "repos/**", "write": False,
         "writes": [], "establishes": {"cwd": ["unprotected"]}},
        {"name": "is-tidy", "argv": ["true"], "cwd": "repos/**", "effect-free": True,
         "establishes": {"cwd": ["tidy"]}},
        {"name": "has-index", "argv": ["true"], "cwd": "repos/**", "effect-free": True,
         "establishes": {"cwd": ["indexed"]}},
    ],
    "program": [
        {"name": "git", "subcommand": "commit", "cwd": "repos/**", "network": False,
         "writes": ["git.refs", "git.index"]},
        {"name": "git", "subcommand": "status", "cwd": "repos/**", "effect-free": True},
        {"name": "git", "subcommand": "push", "cwd": "repos/**",
         "requires": ["org-checkout", "unprotected"], "writes": ["git.remote", "git.refs"]},
        {"name": "git", "subcommand": "gc", "cwd": "repos/**", "requires": ["tidy", "indexed"],
         "network": False},
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
COMMIT = 'certora.exec("git", "commit", cwd=repo)\n'


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


GC_CHECKS = 'certora.check("is-tidy", cwd=repo)\ncertora.check("has-index", cwd=repo)\n'
GC = 'certora.exec("git", "gc", cwd=repo)\n'


def before_gc(effect: str):
    return host_check(HEADER + REPO + GC_CHECKS + effect + GC, "<t>", POLICY)


class TestFileWrites(unittest.TestCase):
    """A file write kills by footprint: ``org-checkout`` reads ``git.config`` at ``.git/config``
    under the check's cwd ``repos/**``, so only a write that can lie at or below
    ``repos/**/.git/config`` kills it; ``unprotected`` reads the network and survives every file
    write; ``tidy`` depends on everything and dies at any of them."""

    def test_a_write_beside_the_footprint_preserves(self) -> None:
        for effect in (
            '(repo / "NOTICE.md").write_text("x")\n',
            '(repo / "src" / "lib.rs").write_text("x")\n',
            '(repo / "docs").mkdir()\n',
            'with open(repo / "out.txt", "w") as f:\n    pass\n',
        ):
            with self.subTest(effect=effect):
                outcome = between(effect)
                if isinstance(outcome, Rejected):
                    self.fail("\n".join(outcome.describe("<t>")))

    def test_a_write_at_or_below_the_footprint_kills_its_readers_only(self) -> None:
        for effect in (
            '(repo / ".git" / "config").write_text("x")\n',
            '(repo / ".git" / "config" / "extra").write_text("x")\n',
            '(repo / ".GIT" / "config").write_text("x")\n',  # folded: one file on a case-folding mount
            '(repo / ".git" / "config").touch()\n',
            'with (repo / ".git" / "config").open("w") as f:\n    pass\n',
        ):
            with self.subTest(effect=effect):
                reason = denied_atoms(between(effect))
                self.assertIn("cwd is not validated by: org-checkout", reason)
                self.assertNotIn("unprotected", reason)

    def test_a_write_through_a_handle_is_a_write_at_its_location(self) -> None:
        # the open truncates (a write at open time); the later write through the handle is a
        # write at the same location, not a write to everything: beside the footprint it
        # preserves, at the footprint it kills, and print(file=) is the same write
        for effect in (
            'f = open(repo / "NOTICE.md", "w")\nf.write("x")\n',
            'f = open(repo / "NOTICE.md", "w")\nprint("x", file=f)\n',
            'with (repo / "NOTICE.md").open("w") as f:\n    f.writelines(["x"])\n',
        ):
            with self.subTest(effect=effect):
                outcome = between(effect)
                if isinstance(outcome, Rejected):
                    self.fail("\n".join(outcome.describe("<t>")))
        for effect in (
            'f = open(repo / ".git" / "config", "w")\ncertora.check("org-repo", cwd=repo)\nf.write("x")\n',
            'f = open(repo / ".git" / "config", "w")\ncertora.check("org-repo", cwd=repo)\nprint("x", file=f)\n',
            'f = open(repo / ".git" / "config", "w")\ncertora.check("org-repo", cwd=repo)\nf.truncate()\n',
        ):
            with self.subTest(effect=effect):
                reason = denied_atoms(between(effect))
                self.assertIn("cwd is not validated by: org-checkout", reason)
                self.assertNotIn("unprotected", reason)

    def test_a_handle_joined_over_two_locations_writes_either(self) -> None:
        # each open was checked against the grant with a precise path, and an open file cannot
        # be redirected, so the write through the joined handle is accepted; what the join lost
        # is *which* location, so the kill is conservative: the readers of either footprint die
        effect = (
            'if len("a") == 1:\n    f = open(repo / ".git" / "config", "w")\n'
            'else:\n    f = open(repo / "NOTICE.md", "w")\n'
            'certora.check("org-repo", cwd=repo)\nf.write("x")\n'
        )
        reason = denied_atoms(between(effect))
        self.assertNotIn("f.write", reason)  # the write itself stands
        self.assertIn("cwd is not validated by: org-checkout", reason)
        self.assertNotIn("unprotected", reason)  # still only by footprint
        # both branches beside the footprint: the joined handle preserves
        outcome = between(
            'if len("a") == 1:\n    f = open(repo / "src" / "a.rs", "w")\n'
            'else:\n    f = open(repo / "NOTICE.md", "w")\n'
            'f.write("x")\n'
        )
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_a_check_killed_on_one_branch_is_dead_after_the_join(self) -> None:
        killed_on_one = 'if len("a") == 1:\n    (repo / ".git" / "config").write_text("x")\n'
        self.assertIn("org-checkout", denied_atoms(between(killed_on_one)))
        # ... while what both branches carry survives, on the same variable
        kept_on_both = 'if len("a") == 1:\n    (repo / "NOTICE.md").write_text("x")\nelse:\n    pass\n'
        self.assertIsInstance(between(kept_on_both), Accepted)

    def test_a_write_on_a_read_handle_writes_nothing(self) -> None:
        # io raises before anything reaches the disk
        self.assertIsInstance(between('f = open(repo / ".git" / "config")\nf.write("x")\n'), Accepted)

    def test_a_replace_target_is_a_write_too(self) -> None:
        reason = denied_atoms(
            between('(repo / "tmp").replace(repo / ".git" / "config")\n')
        )
        self.assertIn("org-checkout", reason)

    def test_a_write_somewhere_below_the_repo_may_be_anywhere(self) -> None:
        # a location known only to lie at or below repo may be .git/config itself
        reason = denied_atoms(
            between('for p in repo.rglob("*"):\n    p.write_text("x")\n')
        )
        self.assertIn("org-checkout", reason)

    def test_an_atom_depending_on_everything_dies_at_any_write(self) -> None:
        reason = denied_atoms(before_gc('(repo / "NOTICE.md").write_text("x")\n'))
        self.assertIn("cwd is not validated by: tidy", reason)
        self.assertNotIn("indexed", reason)  # git.index is at .git/index: untouched

    def test_the_index_footprint(self) -> None:
        reason = denied_atoms(before_gc('(repo / ".git" / "index").write_bytes(b"")\n'))
        self.assertIn("indexed", reason)
        self.assertIn("tidy", reason)


class TestEverythingElse(unittest.TestCase):
    def test_an_instantiation_still_kills_everything(self) -> None:
        reason = denied_atoms(between("class Box:\n    pass\nBox()\n"))
        self.assertIn("org-checkout", reason)
        self.assertIn("unprotected", reason)


if __name__ == "__main__":
    unittest.main()
