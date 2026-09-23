"""Taking shapes back from an applied ruleset (``[[deny]]``), replacing one (``override = true``),
and a ruleset's obligation on the root's writes (``[filesystem] no-write``)."""
import pathlib
import unittest

from certorail import markers
from certorail.analysis import DirSplat, Named, StaticPath
from certorail.host import Accepted, Rejected
from certorail.sandbox.lowering import Bind
from certorail.sandbox.program import lower_program
from certorail.host import check as host_check
from certorail.policy import Policy
from certorail.policyfile import PolicyFileError, from_data
from certorail.schema import SchemaError, parse_policy, parse_ruleset
from tests.test_rulesets import HEADER, RulesetCase

# a rung with three shapes of one program, one of which a root will want back
GIT_LOCAL = """
ruleset-version = 1

[params]
where = { kind = "directory" }

[filesystem]
no-write = ["${where}/**/.git"]

[[program]]
name = "git"
subcommand = "add"
cwd = "${where}/**"

[[program]]
name = "git"
subcommand = "apply"
cwd = "${where}/**"

[[program]]
name = "git"
argv = ["git", "push", "origin", "${BRANCH}"]
cwd = "${where}/**"
holes.BRANCH = { matches = '[a-z]+' }
"""


def shapes(policy: Policy) -> list[str]:
    return sorted(" ".join(p.leading_words) for p in policy.programs)


class TestDeny(RulesetCase):
    def setUp(self) -> None:
        super().setUp()
        self.ruleset("git-local.toml", GIT_LOCAL)

    def apply(self, *extra_sections: tuple[str, object]) -> dict:
        return self.root({"ruleset": "git-local.toml", "where": "repos"}, **dict(extra_sections))

    def test_a_denied_shape_is_gone_and_fails_closed(self) -> None:
        policy = from_data(self.apply(("deny", [{"argv": ["git", "apply"]}])))
        self.assertEqual(shapes(policy), ["git add", "git push origin"])
        denied = host_check(HEADER + 'certora.exec("git", "apply", cwd=pathlib.Path("repos") / "x")\n', "<t>", policy)
        assert isinstance(denied, Rejected)
        self.assertIn("fail closed", denied.denials[0].reason)

    def test_a_denial_takes_back_every_shape_under_its_words(self) -> None:
        policy = from_data(self.apply(("deny", [{"argv": ["git"]}])))
        self.assertEqual(shapes(policy), [])

    def test_a_stale_denial_is_an_error(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.apply(("deny", [{"argv": ["git", "rebase"]}])))
        self.assertIn("deny[0]: deny 'git rebase' takes back nothing", str(cm.exception))

    def test_denying_the_roots_own_shape_is_a_contradiction(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.apply(
                ("deny", [{"argv": ["ls"]}]),
                ("program", [{"name": "ls", "cwd": "."}]),
            ))
        self.assertIn("names a shape this policy grants itself", str(cm.exception))

    def test_the_shape(self) -> None:
        with self.assertRaises(SchemaError) as cm:
            parse_policy({"policy-version": 1, "deny": [{"argv": []}, {"argv": ["git", "${X}"]}, {"words": ["git"]}]}, "<t>")
        self.assertEqual(sorted(cm.exception.problems), [
            "deny[0].argv: List should have at least 1 item after validation, not 0",
            "deny[1].argv[1]: the words of a shape are literal",
            "deny[2]: argv is required",
            "deny[2]: unknown key 'words'",
        ])
        # a ruleset cannot deny: composition is additive below the root
        with self.assertRaises(SchemaError) as cm:
            parse_ruleset({"ruleset-version": 1, "deny": [{"argv": ["git"]}]}, "r.toml")
        self.assertEqual(cm.exception.problems, ["unknown key 'deny'"])


class TestOverride(RulesetCase):
    def setUp(self) -> None:
        super().setUp()
        self.ruleset("git-local.toml", GIT_LOCAL)

    def push(self, **keys: object) -> dict:
        return {
            "name": "git", "argv": ["git", "push", "${REMOTE}", "${BRANCH}"], "cwd": "repos/*",
            "holes": {"REMOTE": {"one-of": ["origin", "fork"]}, "BRANCH": {"matches": "[a-z]+"}},
            **keys,
        }

    def test_an_override_replaces_the_overlapping_rule(self) -> None:
        policy = from_data(self.root({"ruleset": "git-local.toml", "where": "repos"}, program=[self.push(override=True)]))
        self.assertEqual(shapes(policy), ["git add", "git apply", "git push"])
        push = next(p for p in policy.programs if p.leading_words == ("git", "push"))
        self.assertIsNone(push.origin)  # the root's own
        accepted = host_check(HEADER + 'certora.exec("git", "push", "fork", "main", cwd=pathlib.Path("repos") / "x")\n', "<t>", policy)
        self.assertIsInstance(accepted, Accepted)

    def test_an_overlap_without_override_names_the_fix(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root({"ruleset": "git-local.toml", "where": "repos"}, program=[self.push()]))
        self.assertIn(
            "program[0]: 'git push' overlaps 'git push origin' from git-local.toml (where=repos); "
            "add override = true to replace it, or [[deny]] it",
            str(cm.exception),
        )

    def test_an_override_of_nothing_is_stale(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root({"ruleset": "git-local.toml", "where": "repos"}, program=[
                {"name": "ls", "cwd": ".", "override": True},
            ]))
        self.assertIn("program[0].override: 'ls' overrides nothing", str(cm.exception))

    def test_only_the_root_overrides(self) -> None:
        self.ruleset("bad.toml", 'ruleset-version = 1\n[[program]]\nname = "ls"\ncwd = "."\noverride = true\n')
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root({"ruleset": "bad.toml"}))
        self.assertIn("bad.toml: program[0].override: only the root policy overrides", str(cm.exception))

    def test_deny_and_override_on_one_shape_contradict(self) -> None:
        # the denial names the shape the root's own rule grants
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root(
                {"ruleset": "git-local.toml", "where": "repos"},
                deny=[{"argv": ["git", "push"]}], program=[self.push(override=True)],
            ))
        self.assertIn("deny 'git push' names a shape this policy grants itself", str(cm.exception))


class TestNoWrite(RulesetCase):
    def setUp(self) -> None:
        super().setUp()
        self.ruleset("git-local.toml", GIT_LOCAL)
        self.policy = from_data(self.root({"ruleset": "git-local.toml", "where": ["repos", "/srv/git"]}))

    def check(self, body: str) -> Accepted | Rejected:
        return host_check(HEADER + body, "<t>", self.policy)

    def test_the_protection_is_instantiated_per_directory(self) -> None:
        self.assertEqual(
            self.policy.no_write,
            (
                DirSplat((Named("repos"),), Named(".git")),
                DirSplat((Named("srv"), Named("git")), Named(".git"), absolute=True),
            ),
        )

    def test_a_write_that_may_touch_it_is_denied_within_a_grant(self) -> None:
        # write = ["**"] grants everything; the protection subtracts .git and everything below
        for body in (
            'pathlib.Path("repos/x/.git/config").write_text("x")\n',
            'pathlib.Path("repos/x/.git/hooks/pre-commit").write_text("x")\n',
            # a proven dynamic component may name anything, .git included
            'p = sys.argv[1]\nassert certora.pathmatch(p, "repos/x/*")\npathlib.Path(p).write_text("x")\n',
            # below src is still under repos/**/.git: a nested repository's .git
            'p = sys.argv[1]\nassert certora.pathmatch(p, "repos/x/src/*")\npathlib.Path(p).write_text("x")\n',
            # and a dynamic directory could itself be .git, whatever the literal leaf
            'p = sys.argv[1]\nassert certora.pathmatch(p, "repos/*/README.md")\npathlib.Path(p).write_text("x")\n',
            '(pathlib.Path("repos") / "x" / ".GIT" / "config").write_text("x")\n',  # folds equal
        ):
            with self.subTest(body=body):
                outcome = self.check(body)
                assert isinstance(outcome, Rejected), body
                self.assertIn("protected (no-write)", outcome.denials[0].reason)

    def test_a_write_provably_outside_it_is_fine(self) -> None:
        # under a `**/.git` protection a dynamic component is fine when its regex cannot spell
        # .git in any case; a bare `*` could be it
        for body in (
            'pathlib.Path("repos/x/README.md").write_text("x")\n',
            'pathlib.Path("repos/x/src/.gitignore").write_text("x")\n',
            'pathlib.Path("elsewhere/.git/config").write_text("x")\n',  # not under a protected root
            'p = sys.argv[1]\nassert certora.pathmatch(p, r"repos/x/<\\w+>")\npathlib.Path(p).write_text("x")\n',
            'p = sys.argv[1]\nassert certora.pathmatch(p, "repos/<[^.].*>/README.md")\npathlib.Path(p).write_text("x")\n',
        ):
            with self.subTest(body=body):
                outcome = self.check(body)
                if isinstance(outcome, Rejected):
                    self.fail("\n".join(outcome.describe("<t>")))

    def test_reads_are_untouched(self) -> None:
        self.assertIsInstance(self.check('pathlib.Path("repos/x/.git/config").read_text()\n'), Accepted)

    def test_the_root_may_protect_too_and_describe_says_so(self) -> None:
        policy = Policy.allow(write=[markers.within(".")], no_write=[markers.within("secrets")])
        outcome = host_check(HEADER + 'pathlib.Path("secrets/key").write_text("x")\n', "<t>", policy)
        self.assertIsInstance(outcome, Rejected)
        from certorail.describe import describe
        self.assertIn("- protected (no write may touch these", describe(policy, "p.toml", None))
        self.assertIn("): secrets/**", describe(policy, "p.toml", None))

    def test_concrete_protections_reach_the_jail(self) -> None:
        policy = Policy.allow(
            write=[markers.within(".")],
            no_write=[markers.within("secrets"), markers.within("/etc/certorail"), markers.within("repos", leaf=markers.matches(r"\.git"))],
        )
        # the wildcard one is the analysis' alone
        jail = lower_program(policy, pathlib.Path("/work"), patterns=False)
        self.assertEqual(
            [g.path for g in jail.protected if isinstance(g, Bind)],
            [pathlib.Path("/work/secrets"), pathlib.Path("/etc/certorail")],
        )
        self.assertEqual(len(jail.omitted), 1)  # the wildcard one is the analysis' alone

    def test_a_ruleset_spells_no_absolute_protection(self) -> None:
        self.ruleset("abs.toml", 'ruleset-version = 1\n[filesystem]\nno-write = ["/etc/**"]\n')
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root({"ruleset": "abs.toml"}))
        self.assertIn("a ruleset names no absolute locations", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
