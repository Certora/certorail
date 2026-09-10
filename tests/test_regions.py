"""Effect regions (EFFECTS.md, step 1): the ``[regions]`` vocabulary, the media a grant claims,
``writes`` on rules and ``reads`` on atoms, the write and read sets they induce, and the
computed "dies on" in ``--describe``. Nothing here touches the kill yet."""
import copy
import os
import pathlib
import tempfile
import unittest

from certorail.describe import describe
from certorail.effects import EVERYTHING, NOTHING, effects_of, whole
from certorail.ids import AtomId, ProgramName, RegionId, ValidationName
from certorail.policy import Policy, program, region, validation
from certorail.policyfile import PolicyFileError, from_data

REGIONS = {
    "git.head": {"footprint": ".git/HEAD", "about": "which branch HEAD names"},
    "git.config": {"footprint": ".git/config"},
    "git.index": {"footprint": ".git/index"},
    "git.refs": {"footprint": [".git/refs", ".git/packed-refs"]},
    "git.worktree": {"footprint": "."},
    "git.remote": {"network": True, "about": "the remote repository"},
}

ORG_CHECKOUT = AtomId("org-checkout")
ON_FEATURE = AtomId("on-feature")
UNPROTECTED = AtomId("unprotected")
CLEAN = AtomId("clean")


def policy_data() -> dict:
    return copy.deepcopy({
        "policy-version": 1,
        "filesystem": {"read": ["repos/**"], "write": ["repos/**"], "list": ["repos/**"]},
        "regions": REGIONS,
        "atoms": {
            "org-checkout": {"reads": ["git.config"]},
            "on-feature": {"reads": ["git.head"]},
            "unprotected": {"reads": ["network"]},
            "clean": {},
            "not-force": {"pure": True},
        },
        "validation": [
            {"name": "org-repo", "argv": ["true"], "cwd": "repos/**", "effect-free": True,
             "establishes": {"cwd": ["org-checkout"]}},
            {"name": "feature", "argv": ["true"], "cwd": "repos/**", "network": False, "writes": [],
             "establishes": {"cwd": ["on-feature"]}},
            {"name": "main-unprotected", "argv": ["true"], "cwd": "repos/**", "write": False,
             "writes": [], "establishes": {"cwd": ["unprotected"]}},
            {"name": "is-clean", "argv": ["true"], "cwd": "repos/**", "establishes": {"cwd": ["clean"]}},
            {"name": "not-force-check", "params": ["value"], "argv": ["test", "${value}", "!=", "--force"],
             "effect-free": True, "establishes": {"value": ["not-force"]}},
        ],
        "program": [
            {"name": "git", "subcommand": "add", "cwd": "repos/**", "network": False, "writes": ["git.index"]},
            {"name": "git", "subcommand": "commit", "cwd": "repos/**", "network": False,
             "writes": ["git.refs", "git.index"]},
            {"name": "git", "subcommand": "push", "cwd": "repos/**", "requires": ["org-checkout"],
             "writes": ["git.remote", "git.refs"]},
            {"name": "git", "subcommand": "checkout", "cwd": "repos/**", "network": False,
             "writes": ["git.head", "git.index", "git.worktree"]},
            {"name": "git", "subcommand": "status", "cwd": "repos/**", "effect-free": True},
            {"name": "cargo", "subcommand": "build", "cwd": "repos/**"},
            {"name": "gh", "cwd": ".", "unknown-arguments": True, "write": False},
        ],
        "network": [
            {"host": "api.github.com", "methods": ["GET"]},
            {"host": "uploads.github.com", "methods": ["PUT"], "writes": ["git.remote"]},
            {"host": "hooks.example.com", "methods": ["POST"]},
        ],
    })


def load(data: dict) -> Policy:
    return from_data(data, "<t>")


def rule(policy: Policy, *words: str):
    return next(p for p in policy.programs if p.leading_words == words)


def check(policy: Policy, name: str):
    return next(v for v in policy.validations if v.name == name)


def net(policy: Policy, host: str):
    return next(r for r in policy.network if r.host == host)


class TestWriteSets(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load(policy_data())

    def test_declared_writes(self) -> None:
        self.assertEqual(self.policy.write_set(rule(self.policy, "git", "add")), effects_of(["git.index"]))
        self.assertEqual(
            self.policy.write_set(rule(self.policy, "git", "push")), effects_of(["git.remote", "git.refs"])
        )

    def test_undeclared_writes_are_the_media(self) -> None:
        self.assertEqual(self.policy.write_set(rule(self.policy, "cargo", "build")), EVERYTHING)
        self.assertEqual(self.policy.write_set(rule(self.policy, "gh")), whole(["network"]))
        self.assertEqual(self.policy.write_set(check(self.policy, "is-clean")), EVERYTHING)

    def test_effect_free_is_no_media(self) -> None:
        status = rule(self.policy, "git", "status")
        self.assertFalse(status.network)
        self.assertFalse(status.write)
        self.assertTrue(status.effect_free)
        self.assertEqual(self.policy.write_set(status), NOTHING)
        self.assertTrue(check(self.policy, "org-repo").effect_free)
        self.assertFalse(check(self.policy, "feature").effect_free)  # fs claimed, writes nothing

    def test_network_rules(self) -> None:
        self.assertEqual(self.policy.write_set(net(self.policy, "api.github.com")), NOTHING)  # GET only
        self.assertEqual(self.policy.write_set(net(self.policy, "uploads.github.com")), effects_of(["git.remote"]))
        self.assertEqual(self.policy.write_set(net(self.policy, "hooks.example.com")), whole(["network"]))


class TestReadSetsAndKills(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load(policy_data())

    def test_read_sets(self) -> None:
        self.assertEqual(self.policy.read_set(ORG_CHECKOUT), effects_of(["git.config"]))
        self.assertEqual(self.policy.read_set(UNPROTECTED), whole(["network"]))
        self.assertEqual(self.policy.read_set(CLEAN), EVERYTHING)

    def test_kills_are_the_meeting(self) -> None:
        p = self.policy
        cases = [
            (rule(p, "git", "commit"), ORG_CHECKOUT, False),
            (rule(p, "git", "push"), ORG_CHECKOUT, False),
            (rule(p, "git", "checkout"), ON_FEATURE, True),
            (rule(p, "git", "commit"), ON_FEATURE, False),
            (rule(p, "cargo", "build"), ORG_CHECKOUT, True),     # writes everything
            (rule(p, "git", "add"), UNPROTECTED, False),          # no network
            (rule(p, "git", "push"), UNPROTECTED, True),          # git.remote is network
            (rule(p, "gh"), ORG_CHECKOUT, False),                 # no filesystem writes
            (rule(p, "gh"), UNPROTECTED, True),
            (rule(p, "git", "status"), CLEAN, False),             # effect-free
            (rule(p, "git", "add"), CLEAN, True),                 # clean depends on everything
            (check(p, "is-clean"), ORG_CHECKOUT, True),           # undeclared writes
            (check(p, "feature"), ORG_CHECKOUT, False),           # writes nothing
            (net(p, "api.github.com"), UNPROTECTED, False),       # GET
            (net(p, "hooks.example.com"), UNPROTECTED, True),
            (net(p, "hooks.example.com"), ORG_CHECKOUT, False),   # a request writes no fs region
        ]
        for grant, atom_name, expected in cases:
            with self.subTest(grant=getattr(grant, "name", None) or getattr(grant, "host", None), atom=atom_name):
                self.assertIs(p.kills(grant, atom_name), expected)

    def test_the_vocabulary_carries_it(self) -> None:
        vocab = self.policy.vocabulary()
        self.assertEqual(vocab.reads[ORG_CHECKOUT], effects_of(["git.config"]))
        self.assertNotIn(CLEAN, vocab.reads)
        self.assertEqual(vocab.signatures[ValidationName("is-clean")].writes, EVERYTHING)
        self.assertEqual(vocab.signatures[ValidationName("org-repo")].writes, NOTHING)
        self.assertTrue(vocab.signatures[ValidationName("org-repo")].effect_free)
        self.assertEqual(vocab.medium_of[RegionId("git.remote")], "network")
        self.assertIn((ProgramName("git"), ("add",), effects_of(["git.index"])), vocab.writes.exec)


class TestLoadErrors(unittest.TestCase):
    def rejects(self, data: dict, *fragments: str) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            load(data)
        for fragment in fragments:
            self.assertIn(fragment, str(cm.exception))

    def test_undeclared_region(self) -> None:
        data = policy_data()
        data["program"][0]["writes"] = ["git.stash"]
        self.rejects(data, "region 'git.stash' is not declared")

    def test_writes_outside_the_media(self) -> None:
        data = policy_data()
        data["program"][0]["writes"] = ["git.remote"]  # network = false
        self.rejects(data, "says it writes 'git.remote' (network) but does not reach that medium")
        data = policy_data()
        data["program"][0]["write"] = False  # git add: neither medium left for a filesystem claim
        data["program"][0]["writes"] = ["fs"]
        self.rejects(data, "whole fs medium but does not reach it")

    def test_a_network_rule_writes_only_remote_state(self) -> None:
        data = policy_data()
        data["network"][1]["writes"] = ["git.index"]
        self.rejects(data, "network rule 'uploads.github.com' says it writes 'git.index' (fs)")

    def test_reads_on_a_pure_atom(self) -> None:
        data = policy_data()
        data["atoms"]["not-force"]["reads"] = ["git.head"]
        self.rejects(data, "a pure atom depends on no state")

    def test_reads_of_nothing_is_pure(self) -> None:
        data = policy_data()
        data["atoms"]["clean"]["reads"] = []
        self.rejects(data, "depends on nothing is pure")

    def test_reads_for_an_atom_nobody_establishes(self) -> None:
        data = policy_data()
        data["atoms"]["orphan"] = {"reads": ["git.head"]}
        self.rejects(data, "reads declared for atom 'orphan', which no validation establishes")

    def test_a_region_has_one_medium(self) -> None:
        data = policy_data()
        data["regions"]["both"] = {"footprint": "x", "network": True}
        self.rejects(data, "one medium")
        data = policy_data()
        data["regions"]["neither"] = {"about": "?"}
        self.rejects(data, "one medium")
        data = policy_data()
        data["regions"]["fs"] = {"network": True}
        self.rejects(data, "names a medium and is reserved")

    def test_unknown_arguments_cannot_say_what_they_write(self) -> None:
        data = policy_data()
        data["program"][6]["writes"] = ["git.remote"]  # gh: unknown-arguments = true
        self.rejects(data, "cannot say what it writes")

    def test_effect_free_disagrees_with_a_claimed_medium(self) -> None:
        data = policy_data()
        data["program"][4]["network"] = True  # git status: effect-free = true
        self.rejects(data, "effect-free means no network and no writes")

    def test_an_any_hole_the_tool_could_read_as_an_option(self) -> None:
        templated = {
            "name": "tool", "cwd": ".", "argv": ["tool", "${X}"], "holes": {"X": {"any": True}},
            "writes": ["git.index"],
        }
        data = policy_data()
        data["program"].append(templated)
        self.rejects(data, "hole 'X' admits anything where the tool could read it as an option")
        # after a literal -- the tool treats it as data, so the claim stands
        data = policy_data()
        data["program"].append({**templated, "argv": ["tool", "--", "${X}"]})
        policy = load(data)
        self.assertEqual(policy.write_set(rule(policy, "tool", "--")), effects_of(["git.index"]))
        # a flag's value is exempt too
        data = policy_data()
        data["program"].append({
            "name": "tool2", "cwd": ".", "argv": ["tool2", "${FLAGS...}"],
            "holes": {"FLAGS": {"kind": "flags", "-m": {"any": True}}},
            "writes": ["git.index"],
        })
        policy = load(data)
        self.assertEqual(policy.write_set(rule(policy, "tool2")), effects_of(["git.index"]))


class TestRulesets(unittest.TestCase):
    def setUp(self) -> None:
        self.config = pathlib.Path(tempfile.mkdtemp())
        os.environ["CERTORAIL_CONFIG_DIR"] = str(self.config)
        self.addCleanup(os.environ.pop, "CERTORAIL_CONFIG_DIR", None)
        (self.config / "rulesets").mkdir()

    def ruleset(self, name: str, text: str) -> None:
        (self.config / "rulesets" / name).write_text(text, encoding="utf-8")

    def root(self, *applies: dict) -> dict:
        data = policy_data()
        data["apply"] = list(applies)
        return data

    def test_the_same_region_declared_twice_is_one_region(self) -> None:
        self.ruleset("git.toml", (
            'ruleset-version = 1\n'
            '[params]\nwhere = { kind = "directory" }\n'
            '[regions]\n"git.head" = { footprint = ".git/HEAD" }\n"git.stash" = { footprint = ".git/refs/stash" }\n'
            '[[program]]\nname = "git"\ncwd = "${where}/**"\nargv = ["git", "stash"]\n'
            'network = false\nwrites = ["git.stash", "git.worktree"]\n'
        ))
        policy = load(self.root({"ruleset": "git.toml", "where": "repos"}))
        self.assertEqual(len([r for r in policy.regions if r.name == "git.head"]), 1)
        stash = rule(policy, "git", "stash")
        self.assertEqual(policy.write_set(stash), effects_of(["git.stash", "git.worktree"]))
        self.assertTrue(policy.kills(stash, CLEAN))
        self.assertFalse(policy.kills(stash, ORG_CHECKOUT))

    def test_a_differing_declaration_is_an_error(self) -> None:
        self.ruleset("git.toml", (
            'ruleset-version = 1\n'
            '[regions]\n"git.head" = { footprint = "HEAD" }\n'
        ))
        with self.assertRaises(PolicyFileError) as cm:
            load(self.root({"ruleset": "git.toml"}))
        self.assertIn("declared differently", str(cm.exception))

    def test_a_ruleset_footprint_is_relative(self) -> None:
        self.ruleset("git.toml", (
            'ruleset-version = 1\n'
            '[regions]\n"git.global" = { footprint = "/etc/gitconfig" }\n'
        ))
        with self.assertRaises(PolicyFileError) as cm:
            load(self.root({"ruleset": "git.toml"}))
        self.assertIn("a ruleset names no absolute locations", str(cm.exception))


class TestDescribe(unittest.TestCase):
    def test_regions_effects_and_dies_on(self) -> None:
        text = describe(load(policy_data()), "<t>")
        self.assertIn("## Regions", text)
        self.assertIn("git.config (on disk at .git/config below the check's cwd, and everything under it)", text)
        self.assertIn("git.remote (remote): the remote repository", text)
        self.assertIn("effects: writes git.index (no network)", text)
        self.assertIn("effects: none (effect-free: kills no facts)", text)
        self.assertIn("effects: writes anything on the filesystem, anything remote", text)
        feature = next(line for line in text.splitlines() if line.startswith("- on-feature:"))
        self.assertIn("depends on git.head; dies on: git checkout; cargo build; check is-clean; "
                      "file writes under .git/HEAD (below the check's cwd)", feature)
        org = next(line for line in text.splitlines() if line.startswith("- org-checkout:"))
        self.assertNotIn("git commit", org)
        self.assertNotIn("git push", org)
        clean = next(line for line in text.splitlines() if line.startswith("- clean:"))
        self.assertIn("dies at any effectful call, so check immediately before the use", clean)
        self.assertIn("- PUT https://uploads.github.com; writes git.remote", text)


class TestPythonApi(unittest.TestCase):
    def test_constructors(self) -> None:
        policy = Policy.allow(
            regions=[region("git.config", footprint=".git/config"), region("gh.pr", network=True)],
            reads={"org-checkout": ["git.config"]},
            validations=[validation("org-repo", argv=["true"], cwd="repos/**",
                                    establishes={"cwd": ["org-checkout"]}, effect_free=True)],
            programs=[program("git", cwd="repos/**", subcommand="commit", network=False, writes=["fs"])],
        )
        self.assertEqual(policy.write_set(policy.programs[0]), whole(["fs"]))
        self.assertTrue(policy.kills(policy.programs[0], ORG_CHECKOUT))
        with self.assertRaises(ValueError):
            Policy.allow(regions=[region("git.config", footprint=".git/config")], reads={"x": []})
        with self.assertRaises(ValueError):
            region("both", footprint="x", network=True)
        with self.assertRaises(ValueError):
            program("git", cwd=".", effect_free=True, network=True)


if __name__ == "__main__":
    unittest.main()
