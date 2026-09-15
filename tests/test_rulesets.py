"""Rulesets and ``[[apply]]`` (TEMPLATES.md): parameterised bundles of exec-side vocabulary in
the config directory, applied once with set-valued directory parameters, identified by
(file, hash, bindings), restricted in what executables they may name."""
import os
import pathlib
import stat
import tempfile
import unittest

from certorail import markers
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.ids import HoleName
from certorail.policy import Policy
from certorail.policyfile import PolicyFileError, from_data
from certorail.templates import Constraint, Each, Flags, Token

UNIX = """
ruleset-version = 1

[params]
where = { kind = "directory" }

[atoms]
"unix.no-flag" = { matches = '[^-].*' }

[[flagset]]
name = "grep-ro"
bare = ["-r", "-n"]
"--include" = { matches = '[^/]+' }

[[program]]
name  = "grep"
cwd   = "${where}"
argv  = ["grep", "${FLAGS...}", "--", "${PATTERN}", "${FILES...}"]
holes.FLAGS   = { kind = "flags", flagset = "grep-ro" }
holes.PATTERN = { any = true }
holes.FILES   = { kind = "each", location = "${where}/**", min = 1 }

[[program]]
name  = "ls"
cwd   = "."
argv  = ["ls", "${WHERE}"]
holes.WHERE = { location = ["${where}/**", "shared/**"] }
"""

GIT_ORG = """
ruleset-version = 1

[params]
where = { kind = "directory" }
org   = { kind = "atom" }

[[validation]]
name        = "org-repo"
argv        = ["${checkers}/org-checkout"]
cwd         = "${where}/**"
writes      = []
establishes = { cwd = ["${org}"] }

[[program]]
name     = "git"
cwd      = "${where}/**"
argv     = ["git", "push", "origin", "${BRANCH}"]
requires = ["${org}"]
holes.BRANCH = { atoms = ["unix.no-flag"] }
"""

HEADER = "import pathlib\nimport sys\n"


class RulesetCase(unittest.TestCase):
    def setUp(self) -> None:
        self.config = pathlib.Path(tempfile.mkdtemp())
        os.environ["CERTORAIL_CONFIG_DIR"] = str(self.config)
        self.addCleanup(os.environ.pop, "CERTORAIL_CONFIG_DIR", None)
        (self.config / "rulesets").mkdir()
        (self.config / "checkers").mkdir()
        checker = self.config / "checkers" / "org-checkout"
        checker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        checker.chmod(checker.stat().st_mode | stat.S_IXUSR)
        self.ruleset("unix.toml", UNIX)
        self.ruleset("git-org.toml", GIT_ORG)

    def ruleset(self, name: str, text: str) -> None:
        (self.config / "rulesets" / name).write_text(text, encoding="utf-8")

    def root(self, *applies: dict, **extra) -> dict:
        return {
            "policy-version": 1,
            "filesystem": {"read": ["**"], "write": ["**"], "list": ["**"]},
            "apply": list(applies),
            **extra,
        }


class TestApply(RulesetCase):
    def test_a_set_valued_directory_maps_over_every_location_slot(self) -> None:
        policy = from_data(self.root({"ruleset": "unix.toml", "where": ["repos", "/srv/data"]}))
        grep, ls = policy.programs
        self.assertEqual(len(grep.cwd), 2)  # cwd = "${where}" -> two directories
        assert grep.template is not None and ls.template is not None
        files = grep.template.holes[HoleName("FILES")]
        self.assertEqual(
            [str(loc.absolute) for loc in getattr(files, "constraint").locations], ["False", "True"]
        )
        where = ls.template.holes[HoleName("WHERE")]
        assert isinstance(where, Token)
        self.assertEqual(len(where.constraint.locations), 3)  # two mapped + shared/**
        self.assertEqual(grep.origin, "unix.toml (where=repos,/srv/data)")
        self.assertIn("unix.no-flag", {a.name for a in policy.atoms})

    def test_the_instantiated_rules_govern_programs(self) -> None:
        policy = from_data(self.root({"ruleset": "unix.toml", "where": ["repos", "data"]}))
        source = HEADER + (
            'certora.exec("grep", FLAGS=["-r"], PATTERN="x", '
            'FILES=[pathlib.Path("repos") / "a", pathlib.Path("data") / "b"], cwd=pathlib.Path("data"))\n'
        )
        outcome = host_check(source, "<t>", policy)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))
        denied = host_check(
            HEADER + 'certora.exec("grep", FLAGS=["-R"], PATTERN="x", FILES=[pathlib.Path("repos") / "a"], cwd=pathlib.Path("repos"))\n',
            "<t>", policy,
        )
        assert isinstance(denied, Rejected)
        self.assertIn("unix.toml (where=repos,data): FLAGS: '-R' is not a declared flag", denied.denials[0].reason)

    def test_atom_parameters_and_restricted_validations(self) -> None:
        policy = from_data(self.root(
            {"ruleset": "unix.toml", "where": "repos"},
            {"ruleset": "git-org.toml", "where": "repos", "org": "org-checkout"},
            atoms={"org-checkout": {}},
        ))
        (v,) = policy.validations
        self.assertEqual(v.establishes, {"cwd": frozenset({"org-checkout"})})
        self.assertTrue(v.argv[0].endswith("/checkers/org-checkout"))
        git = next(p for p in policy.programs if p.name == "git")
        self.assertEqual(git.requires, frozenset({"org-checkout"}))
        source = HEADER + (
            'repo = pathlib.Path("repos") / "x"\n'
            'certora.check("org-repo", cwd=repo)\n'
            'certora.exec("git", "push", "origin", "feature", cwd=repo)\n'
        )
        self.assertIsInstance(host_check(source, "<t>", policy), Accepted)

    def test_the_same_application_twice_is_one_document(self) -> None:
        # a diamond: the root applies unix.toml, and so does a ruleset it applies, identically
        self.ruleset(
            "tools.toml",
            'ruleset-version = 1\n[params]\nwhere = { kind = "directory" }\n'
            '[[apply]]\nruleset = "unix.toml"\nwhere = "${where}"\n',
        )
        policy = from_data(self.root(
            {"ruleset": "tools.toml", "where": "repos"},
            {"ruleset": "unix.toml", "where": "repos"},
        ))
        self.assertEqual([p.name for p in policy.programs], ["grep", "ls"])

    def test_different_bindings_for_one_ruleset_is_an_error(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root(
                {"ruleset": "unix.toml", "where": "repos"},
                {"ruleset": "unix.toml", "where": "data"},
            ))
        self.assertIn("different bindings", str(cm.exception))
        self.assertIn("union", str(cm.exception))

    def test_a_cycle_is_an_error(self) -> None:
        self.ruleset("a.toml", 'ruleset-version = 1\n[[apply]]\nruleset = "b.toml"\n')
        self.ruleset("b.toml", 'ruleset-version = 1\n[[apply]]\nruleset = "a.toml"\n')
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root({"ruleset": "a.toml"}))
        self.assertIn("applies itself", str(cm.exception))

    def test_binding_errors(self) -> None:
        cases = [
            ({"ruleset": "unix.toml"}, "not bound"),
            ({"ruleset": "unix.toml", "where": []}, "non-empty list"),
            ({"ruleset": "unix.toml", "where": "repos/**"}, "not a directory"),
            ({"ruleset": "unix.toml", "where": "repos", "extra": 1}, "not a parameter"),
            ({"ruleset": "nope.toml", "where": "repos"}, "cannot read"),
            ({"ruleset": "../unix.toml", "where": "repos"}, "name of a .toml file"),
        ]
        for apply, expected in cases:
            with self.subTest(apply=apply), self.assertRaises(PolicyFileError) as cm:
                from_data(self.root(apply))
            self.assertIn(expected, str(cm.exception))


class TestRulesetWellFormedness(RulesetCase):
    def load(self, text: str, **bindings) -> Policy:
        self.ruleset("r.toml", text)
        return from_data(self.root({"ruleset": "r.toml", **bindings}))

    def test_exec_side_vocabulary_only(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            self.load('ruleset-version = 1\n[filesystem]\nread = ["**"]\n')
        self.assertIn("unknown key 'filesystem'", str(cm.exception))

    def test_version_is_required(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            self.load('[[program]]\nname = "x"\ncwd = "."\n')
        self.assertIn("ruleset-version = 1 is required", str(cm.exception))

    def test_no_absolute_locations(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            self.load('ruleset-version = 1\n[[program]]\nname = "x"\ncwd = "/etc"\n')
        self.assertIn("no absolute locations", str(cm.exception))

    def test_a_parameter_heads_a_location(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            self.load(
                'ruleset-version = 1\n[params]\nw = { kind = "directory" }\n'
                '[[program]]\nname = "x"\ncwd = "a/${w}"\n',
                w="repos",
            )
        self.assertIn("may only head a location", str(cm.exception))

    def test_parameter_kinds_are_checked(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            self.load(
                'ruleset-version = 1\n[params]\nw = { kind = "atom" }\n'
                '[[program]]\nname = "x"\ncwd = "${w}"\n',
                w="some-atom",
            )
        self.assertIn("not a directory parameter", str(cm.exception))

    def test_validation_argv_is_restricted(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            self.load(
                'ruleset-version = 1\n[[validation]]\nname = "v"\nargv = ["/usr/bin/curl", "x"]\nestablishes = {}\n'
            )
        self.assertIn("${checkers}/<name> or one of test", str(cm.exception))
        # the stock predicate is fine
        policy = self.load(
            'ruleset-version = 1\n[[validation]]\nname = "v"\nparams = ["value"]\n'
            'argv = ["test", "${value}", "!=", "x"]\nestablishes = {}\n'
        )
        self.assertEqual(policy.validations[0].argv[0], "test")

    def test_atom_names_are_unique_across_files(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root(
                {"ruleset": "unix.toml", "where": "repos"},
                atoms={"unix.no-flag": {"matches": "[^-].*"}},  # the same definition: still an error
            ))
        self.assertIn("atom names are unique", str(cm.exception))

    def test_a_root_rule_may_reference_a_ruleset_atom(self) -> None:
        policy = from_data(self.root(
            {"ruleset": "unix.toml", "where": "repos"},
            program=[{"name": "echo", "cwd": ".", "argv": ["echo", "${WORDS...}"],
                      "holes": {"WORDS": {"kind": "each", "atoms": ["unix.no-flag"]}}}],
        ))
        echo = next(p for p in policy.programs if p.name == "echo")
        assert echo.template is not None
        words = echo.template.holes[HoleName("WORDS")]
        assert isinstance(words, Each)
        self.assertEqual(words.constraint.atoms, frozenset({"unix.no-flag"}))

    def test_flagsets_are_private_to_their_document(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root(
                {"ruleset": "unix.toml", "where": "repos"},
                program=[{
                    "name": "rg", "cwd": ".", "argv": ["rg", "${FLAGS...}"],
                    "holes": {"FLAGS": {"kind": "flags", "flagset": "grep-ro"}},
                }],
            ))
        self.assertIn("flagset 'grep-ro' is not declared", str(cm.exception))


# A push rung in the shape of rulesets/git-remote.toml: every parameter kind, a bool-gated flag
# whose demand reaches another hole, a bool-gated rule, and a rule-level requires table that
# conjoins the pack's own atom with whatever constraint the root bound.
PUSH = """
ruleset-version = 1

[params]
where      = { kind = "directory" }
remote     = { kind = "constraint" }
branch     = { kind = "constraint" }
push-gate  = { kind = "atom" }
force      = { kind = "bool" }
force-gate = { kind = "atom" }
history    = { kind = "bool" }

[atoms]
"push.ref-name" = { matches = '[A-Za-z][A-Za-z0-9/_-]*' }
"push.feature"  = { matches = 'feature/.*' }

[[flagset]]
name  = "push"
holes = ["BRANCH"]
bare  = ["-u"]
"--force" = { value = false, when = "${force}", requires = { BRANCH = ["${force-gate}"] } }
"-o"      = { any = true }

[[program]]
name = "git"
argv = ["git", "push", "${REMOTE}", "${BRANCH}", "${FLAGS...}"]
cwd  = "${where}/**"
holes.REMOTE = "${remote}"
holes.BRANCH = "${branch}"
holes.FLAGS  = { kind = "flags", flagset = "push" }
requires = { cwd = ["${push-gate}"], REMOTE = ["push.ref-name"], BRANCH = ["push.ref-name"] }

[[program]]
name = "git"
when = "${history}"
argv = ["git", "log", "${FLAGS...}"]
cwd  = "${where}/**"
holes.FLAGS = { kind = "flags", bare = ["--oneline"] }
"""

UMBRELLA = """
ruleset-version = 1

[params]
where      = { kind = "directory" }
branch     = { kind = "constraint" }
force      = { kind = "bool" }
force-gate = { kind = "atom" }

[[apply]]
ruleset    = "push.toml"
where      = "${where}"
remote     = { one-of = ["origin"] }
branch     = "${branch}"
push-gate  = []
force      = "${force}"
force-gate = "${force-gate}"
"""

REPO = 'repo = pathlib.Path("repos") / "x"\n'


class TestParameterKinds(RulesetCase):
    def setUp(self) -> None:
        super().setUp()
        self.ruleset("push.toml", PUSH)
        self.ruleset("umbrella.toml", UMBRELLA)

    BASE = {
        "ruleset": "push.toml", "where": "repos",
        "remote": {"one-of": ["origin"]}, "branch": {"matches": "[a-z/]+"}, "push-gate": [],
    }

    def push(self, args: str, policy: Policy, prelude: str = "") -> object:
        return host_check(HEADER + REPO + prelude + f'certora.exec("git", "push", {args}, cwd=repo)\n', "<t>", policy)

    def accept(self, args: str, policy: Policy, prelude: str = "") -> None:
        result = self.push(args, policy, prelude)
        if isinstance(result, Rejected):
            self.fail("\n".join(result.describe("<t>")))

    def denial(self, args: str, policy: Policy, prelude: str = "") -> str:
        result = self.push(args, policy, prelude)
        assert isinstance(result, Rejected), "expected a rejection"
        return result.denials[0].reason

    def test_an_unbound_bool_is_false(self) -> None:
        # history and force unbound: no log rule, no --force flag, and force-gate -- referenced
        # only from the dropped flag -- needs no binding
        policy = from_data(self.root(self.BASE))
        self.assertEqual([p.leading_words for p in policy.programs], [("git", "push")])
        self.accept('"origin", "feature/x", "-u"', policy)
        self.assertIn("'--force' is not a declared flag", self.denial('"origin", "feature/x", "--force"', policy))
        self.assertIn("force=false", policy.programs[0].origin or "")

    def test_a_bool_enables_a_flag_and_a_rule(self) -> None:
        policy = from_data(self.root({
            **self.BASE, "force": True, "force-gate": ["push.feature"], "history": True,
        }))
        self.assertEqual([p.leading_words for p in policy.programs], [("git", "push"), ("git", "log")])
        self.accept('"origin", "feature/x", "--force"', policy)
        self.accept('"origin", "main"', policy)
        self.assertIn(
            "--force requires BRANCH validated by: push.feature",
            self.denial('"origin", "main", "--force"', policy),
        )

    def test_an_enabled_flag_needs_its_bindings(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root({**self.BASE, "force": True}))
        self.assertIn("parameter 'force-gate' is not bound", str(cm.exception))

    def test_an_atom_list_splices_into_requires(self) -> None:
        policy = from_data(self.root(
            {**self.BASE, "push-gate": ["org-checkout"]},
            atoms={"org-checkout": {}},
            validation=[{"name": "org-repo", "argv": ["true"], "cwd": "repos/**",
                         "establishes": {"cwd": ["org-checkout"]}}],
        ))
        self.assertEqual(policy.programs[0].requires, frozenset({"org-checkout"}))
        self.assertIn("cwd is not validated by: org-checkout", self.denial('"origin", "feature/x"', policy))
        self.accept('"origin", "feature/x"', policy, 'certora.check("org-repo", cwd=repo)\n')

    def test_a_constraint_binding_is_conjoined_with_the_pack_requirement(self) -> None:
        # the root says anything; the pack still insists a branch is a ref name, not a refspec
        policy = from_data(self.root({**self.BASE, "branch": {"any": True}}))
        assert policy.programs[0].template is not None
        branch = policy.programs[0].template.holes[HoleName("BRANCH")]
        assert isinstance(branch, Token)
        self.assertEqual(branch.constraint, Constraint(atoms=frozenset({"push.ref-name"})))
        self.accept('"origin", "feature/x"', policy)
        self.assertIn("not validated by: push.ref-name", self.denial('"origin", "feature:main"', policy))
        # and a binding with its own shape keeps it, the pack's atom added
        policy = from_data(self.root({**self.BASE, "branch": {"matches": "feature/.*", "literal": True}}))
        assert policy.programs[0].template is not None
        branch = policy.programs[0].template.holes[HoleName("BRANCH")]
        assert isinstance(branch, Token)
        self.assertTrue(branch.constraint.literal)
        self.assertIsNotNone(branch.constraint.regex)
        self.assertEqual(branch.constraint.atoms, frozenset({"push.ref-name"}))
        self.assertIn("BRANCH", self.denial('"origin", sys.argv[1]', policy))

    def test_bindings_pass_through_an_umbrella(self) -> None:
        policy = from_data(self.root({
            "ruleset": "umbrella.toml", "where": "repos", "branch": {"matches": "[a-z/]+"},
            "force": True, "force-gate": ["push.feature"],
        }))
        self.accept('"origin", "feature/x", "--force"', policy)
        self.assertIn("push.toml (", policy.programs[0].origin or "")
        # an unbound bool passes down as false
        policy = from_data(self.root({"ruleset": "umbrella.toml", "where": "repos", "branch": {"any": True}}))
        self.assertIn("not a declared flag", self.denial('"origin", "feature/x", "--force"', policy))

    def test_binding_errors(self) -> None:
        cases = [
            ({**self.BASE, "force": "yes"}, "expected true or false"),
            ({**self.BASE, "branch": "any"}, "expected a constraint table"),
            ({**self.BASE, "push-gate": 3}, "expected an atom name or a list"),
            ({**self.BASE, "branch": {"any": True, "atoms": ["push.feature"]}}, "combines with nothing"),
            ({k: v for k, v in self.BASE.items() if k != "branch"}, "parameter 'branch' is not bound"),
        ]
        for apply, expected in cases:
            with self.subTest(expected=expected), self.assertRaises(PolicyFileError) as cm:
                from_data(self.root(apply))
            self.assertIn(expected, str(cm.exception))

    def test_when_is_a_bool_parameter_or_a_literal(self) -> None:
        def load(text: str) -> None:
            self.ruleset("w.toml", 'ruleset-version = 1\n[params]\nwhere = { kind = "directory" }\n' + text)
            from_data(self.root({"ruleset": "w.toml", "where": "repos"}))

        with self.assertRaises(PolicyFileError) as cm:
            load('[[program]]\nname = "x"\ncwd = "."\nwhen = "${where}"\n')
        self.assertIn("'where' is not a bool parameter", str(cm.exception))
        with self.assertRaises(PolicyFileError) as cm:
            load('[[program]]\nname = "x"\ncwd = "."\nwhen = "maybe"\n')
        self.assertIn("expected true, false, or a bool parameter", str(cm.exception))
        # a root file toggles with a literal
        policy = from_data(self.root(program=[
            {"name": "x", "cwd": ".", "when": False},
            {"name": "y", "cwd": ".", "when": True},
        ]))
        self.assertEqual([p.name for p in policy.programs], ["y"])
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root(program=[{"name": "x", "cwd": ".", "when": "${x}"}]))
        self.assertIn("'x' is not a parameter", str(cm.exception))

    def test_parameters_have_no_defaults(self) -> None:
        self.ruleset("d.toml", 'ruleset-version = 1\n[params]\nforce = { kind = "bool", default = true }\n')
        with self.assertRaises(PolicyFileError) as cm:
            from_data(self.root({"ruleset": "d.toml"}))
        self.assertIn("params.force: unknown key 'default'", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
