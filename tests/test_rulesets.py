"""Rulesets and ``[[apply]]`` (TEMPLATES.md): parameterised bundles of exec-side vocabulary in
the config directory, applied once with set-valued directory parameters, identified by
(file, hash, bindings), restricted in what executables they may name."""
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

from certorail import markers
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.ids import HoleName
from certorail.install import install_pack
from certorail.policy import Command, Policy
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
        # this test's own config directory; the suite-wide isolated one comes back after (conftest)
        self.enterContext(mock.patch.dict(os.environ, {"CERTORAIL_CONFIG_DIR": str(self.config)}))
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


BASE = """
ruleset-version = 1

[filesystem]
no-write = ["**/.secret"]

[[program]]
name = "cat"
cwd  = "**"
argv = ["cat", "${FILES...}"]
holes.FILES = { kind = "each", location = "**", min = 1 }
network  = false
write-fs = false

[[apply]]                      # a pack the base carries, bound to the root itself
ruleset = "unix.toml"
where   = "."
"""


class TestBase(RulesetCase):
    """``rulesets/base.toml``: a ruleset applied to every root by its fixed name."""

    def setUp(self) -> None:
        super().setUp()
        self.ruleset("base.toml", BASE)

    def test_the_base_applies_to_every_root(self) -> None:
        policy = from_data({"policy-version": 1})
        self.assertEqual(sorted(p.name for p in policy.programs), ["cat", "grep", "ls"])
        self.assertEqual(sorted({p.origin for p in policy.programs}), ["base.toml", "unix.toml (where=.)"])
        # never silent: the policy records what was composed in, and describe says so
        self.assertEqual(policy.applied, ("base.toml", "unix.toml (where=.)"))
        from certorail.describe import describe
        self.assertIn("Rulesets composed into this policy: base.toml, unix.toml (where=.) (base.toml is the config directory's base ruleset; base = false opts out)", describe(policy, "p.toml", None))
        self.assertEqual(from_data({"policy-version": 1, "base": False}).applied, ())
        self.assertEqual([str(loc.absolute) for loc in policy.no_write], ["False"])  # the protection travels
        grep = next(p for p in policy.programs if p.name == "grep")
        self.assertEqual(len(grep.cwd), 1)  # ${where} with where = ".": the root

    def test_the_default_policy_carries_it_too(self) -> None:
        from certorail.policyfile import default_policy
        policy = default_policy()
        self.assertEqual(sorted(p.name for p in policy.programs), ["cat", "grep", "ls"])
        self.assertEqual(len(policy.read), 1)

    def test_no_base_file_means_no_base(self) -> None:
        (self.config / "rulesets" / "base.toml").unlink()
        self.assertEqual(from_data({"policy-version": 1}).programs, ())

    def test_base_false_opts_out(self) -> None:
        policy = from_data({"policy-version": 1, "base": False, "program": [{"name": "ls", "cwd": "."}]})
        self.assertEqual([(p.name, p.origin) for p in policy.programs], [("ls", None)])

    def test_a_root_rule_overlapping_the_base_needs_override(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            from_data({"policy-version": 1, "program": [{"name": "cat", "cwd": "."}]})
        self.assertIn("'cat' overlaps 'cat' from base.toml; add override = true to replace it, or [[deny]] it", str(cm.exception))
        policy = from_data({"policy-version": 1, "program": [{"name": "cat", "cwd": ".", "override": True}]})
        cat = [p for p in policy.programs if p.name == "cat"]
        self.assertEqual([p.origin for p in cat], [None])

    def test_deny_takes_a_base_shape_back(self) -> None:
        policy = from_data({"policy-version": 1, "deny": [{"argv": ["cat"]}]})
        self.assertEqual(sorted(p.name for p in policy.programs), ["grep", "ls"])

    def test_applying_the_base_explicitly_is_the_same_document(self) -> None:
        policy = from_data({"policy-version": 1, "apply": [{"ruleset": "base.toml"}]})
        self.assertEqual(sorted(p.name for p in policy.programs), ["cat", "grep", "ls"])
        # and applying a pack the base already carries, identically, is the same document too
        policy = from_data({"policy-version": 1, "apply": [{"ruleset": "unix.toml", "where": "."}]})
        self.assertEqual(sorted(p.name for p in policy.programs), ["cat", "grep", "ls"])

    def test_a_base_with_a_parameter_to_bind_is_an_error(self) -> None:
        self.ruleset("base.toml", 'ruleset-version = 1\n[params]\nwhere = { kind = "directory" }\n[[program]]\nname = "ls"\ncwd = "${where}"\n')
        with self.assertRaises(PolicyFileError) as cm:
            from_data({"policy-version": 1})
        self.assertIn("base.toml: program[0].cwd: parameter 'where' is not bound", str(cm.exception))

    def test_the_base_grants_run(self) -> None:
        policy = from_data({"policy-version": 1, "filesystem": {"read": ["**"]}})
        source = HEADER + 'certora.exec("cat", pathlib.Path("src") / "x.py", cwd=pathlib.Path("src") / "pkg")\n'
        outcome = host_check(source, "<t>", policy)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))
        # the protection the base carries applies to the root's own writes
        denied = host_check(HEADER + 'pathlib.Path("x/.secret").write_text("k")\n', "<t>", from_data({"policy-version": 1, "filesystem": {"write": ["**"]}}))
        assert isinstance(denied, Rejected)
        self.assertIn("protected (no-write)", denied.denials[0].reason)


SHIPPED = pathlib.Path(__file__).resolve().parent.parent / "rulesets"
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


@unittest.skipUnless((SHIPPED / "git").is_dir(), "the shipped git pack is not in this tree")
class TestGitPack(RulesetCase):
    """The shipped git pack loads, through a root policy that applies it (the fixture)."""

    def setUp(self) -> None:
        super().setUp()
        install_pack(SHIPPED / "git")  # the real install path: rulesets, notes, checkers made executable

    def test_the_fixture_root_policy_loads(self) -> None:
        import tomllib
        data = tomllib.loads((FIXTURES / "git-policy.toml").read_text(encoding="utf-8"))
        policy = from_data(data, "git-policy.toml")
        shapes = sorted(" ".join(p.leading_words) for p in policy.programs)
        self.assertIn("git log", shapes)
        self.assertIn("git add", shapes)
        self.assertNotIn("git apply", shapes)          # denied by the root
        self.assertIn("git push", shapes)              # the root's override
        self.assertNotIn("git push origin", shapes)    # the pack's shape it replaced
        self.assertNotIn("git rebase", shapes)         # rewrite = false: the rung is not applied
        push = next(p for p in policy.programs if p.leading_words == ("git", "push"))
        self.assertIsNone(push.origin)
        self.assertIn("git.ref-name", {a for v in policy.validations for atoms in v.establishes.values() for a in atoms})
        # the vocabulary's protection reaches the root: no program write may touch a .git
        self.assertTrue(any(".git" in str(loc) for loc in policy.no_write))

    def test_every_rung_applies(self) -> None:
        policy = from_data({
            "policy-version": 1,
            "filesystem": {"read": ["repos/**"], "write": ["repos/*/**"]},
            "atoms": {"my-branch": {"matches": "agent/.*"}},
            "apply": [{
                "ruleset": "git.toml", "where": "repos", "remote": {"one-of": ["origin", "fork"]},
                "branch": {"atoms": ["my-branch"]}, "push-gate": [],
                "rewrite": True, "force": True, "force-gate": ["git.not-default-branch"], "delete": True,
                "rebase-pull": True, "skip-hooks": True, "clone": True, "clone-from": {"atoms": ["git.remote-url"]},
            }],
        })
        shapes = sorted(" ".join(p.leading_words) for p in policy.programs)
        for shape in ("git log", "git commit", "git rebase", "git push", "git clone"):
            self.assertIn(shape, shapes)


@unittest.skipUnless((SHIPPED / "coreutils").is_dir(), "the shipped coreutils pack is not in this tree")
class TestCoreutilsRo(RulesetCase):
    """The shipped read rung of coreutils, as a base.toml would apply it: every rule jailed, the
    common spellings bind, the excluded operations are unspellable."""

    def setUp(self) -> None:
        super().setUp()
        install_pack(SHIPPED / "coreutils")
        self.ruleset("base.toml", 'ruleset-version = 1\n[[apply]]\nruleset = "coreutils-ro.toml"\nwhere = "."\n')
        self.policy = from_data({"policy-version": 1, "filesystem": {"read": ["**"]}})

    def test_every_rule_is_jailed(self) -> None:
        self.assertGreaterEqual(len(self.policy.programs), 14)
        for p in self.policy.programs:
            with self.subTest(program=p.name):
                self.assertEqual((p.network, p.write_fs, p.spawn), (False, False, False))
                self.assertTrue(p.effect_free)

    def check(self, body: str):
        return host_check(HEADER + body, "<t>", self.policy)

    def test_the_common_spellings_bind(self) -> None:
        for body in (
            'certora.exec("ls", "-la", pathlib.Path("src"), cwd=pathlib.Path("."))\n',
            'certora.exec("ls", cwd=pathlib.Path("src") / "pkg")\n',
            'certora.exec("cat", "-n", pathlib.Path("README.md"), cwd=pathlib.Path("."))\n',
            'certora.exec("head", "-n", "20", pathlib.Path("README.md"), cwd=pathlib.Path("."))\n',
            'certora.exec("tail", "-n", "+5", pathlib.Path("log.txt"), cwd=pathlib.Path("."))\n',
            'certora.exec("grep", "-rn", "TODO", pathlib.Path("src"), cwd=pathlib.Path("."))\n',
            'certora.exec("grep", "-rn", "--include", "*.py", "TODO", pathlib.Path("src"), cwd=pathlib.Path("."))\n',
            'certora.exec("grep", FLAGS=["-r", "-e", "-x", "-e", "-y"], PATTERN="z", FILES=[pathlib.Path("src")], cwd=pathlib.Path("."))\n',
            'certora.exec("find", pathlib.Path("src"), "-name", "*.py", "-type", "f", "-not", "-path", "*/tests/*", cwd=pathlib.Path("."))\n',
            'certora.exec("diff", "-u", pathlib.Path("a.txt"), pathlib.Path("b.txt"), cwd=pathlib.Path("."))\n',
            'certora.exec("wc", "-l", pathlib.Path("a.txt"), cwd=pathlib.Path("."))\n',
            'certora.exec("sort", "-rn", "-k", "2,2", pathlib.Path("a.txt"), cwd=pathlib.Path("."))\n',
            'certora.exec("du", "-sh", pathlib.Path("src"), cwd=pathlib.Path("."))\n',
            'certora.exec("stat", "-c", "%s", pathlib.Path("a.txt"), cwd=pathlib.Path("."))\n',
            'certora.exec("cut", "-d", ",", "-f", "1,3", pathlib.Path("a.csv"), cwd=pathlib.Path("."))\n',
        ):
            with self.subTest(body=body):
                outcome = self.check(body)
                if isinstance(outcome, Rejected):
                    self.fail("\n".join(outcome.describe("<t>")))

    def test_paths_come_after_a_host_inserted_double_dash(self) -> None:
        # every rule but find spells "--" before its paths: a file named "-R" is a file, and no
        # path the program passes can be read as an option -- so the dash guard need not apply
        for name in ("ls", "cat", "head", "tail", "stat", "file", "diff", "wc", "du", "sort", "uniq", "cut", "tree"):
            rule = next(p for p in self.policy.programs if p.name == name)
            assert rule.template is not None
            self.assertIn("--", rule.template.pieces, name)
        find = next(p for p in self.policy.programs if p.name == "find")
        assert find.template is not None
        self.assertNotIn("--", find.template.pieces)
        # a dash-shaped file name binds by keyword and reaches the tool after the "--" (-Q is
        # no flag of the rung's ls; -R is, and is a recursive listing, which is fine)
        outcome = self.check('certora.exec("ls", "-l", FILES=[pathlib.Path("-Q")], cwd=pathlib.Path("."))\n')
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))
        command = self.policy.exec_command("ls", ["-l"], {"FILES": ["-Q"]}, ".")
        assert isinstance(command, Command), command
        self.assertEqual(command.argv, ["ls", "-l", "--", "-Q"])
        # positionally it is refused as a non-flag, with the keyword named as the fix
        outcome = self.check('certora.exec("ls", "-l", "-Q", cwd=pathlib.Path("."))\n')
        assert isinstance(outcome, Rejected)
        self.assertIn("'-Q' is not a flag of FLAGS; if it is the value of FILES, bind FILES by keyword", outcome.denials[0].reason)

    def test_the_script_tools_are_absent(self) -> None:
        # sed and awk scripts can name files the flag list never sees; not portable to close
        for program in ("sed", "awk"):
            self.assertNotIn(program, {p.name for p in self.policy.programs})

    def test_the_excluded_operations_are_unspellable(self) -> None:
        for body, why in (
            ('certora.exec("find", pathlib.Path("src"), "-exec", "rm", "{}", ";", cwd=pathlib.Path("."))\n', "-exec"),
            ('certora.exec("find", pathlib.Path("src"), "-delete", cwd=pathlib.Path("."))\n', "-delete"),
            ('certora.exec("tail", "-f", pathlib.Path("log.txt"), cwd=pathlib.Path("."))\n', "-f"),
            ('certora.exec("sort", "-o", pathlib.Path("out.txt"), pathlib.Path("a.txt"), cwd=pathlib.Path("."))\n', "-o"),
            ('certora.exec("grep", "-r", "x", pathlib.Path("/etc"), cwd=pathlib.Path("."))\n', "not a proven path"),
            ('certora.exec("grep", "-rf", pathlib.Path("/etc/passwd"), "x", pathlib.Path("src"), cwd=pathlib.Path("."))\n', "valued flag"),
            ('certora.exec("diff", "-X", pathlib.Path("/etc/shadow"), pathlib.Path("a"), pathlib.Path("b"), cwd=pathlib.Path("."))\n', "not a proven path"),
            ('certora.exec("cat", cwd=pathlib.Path("."))\n', "at least 1"),
            ('certora.exec("grep", "-r", sys.argv[1], pathlib.Path("src"), cwd=pathlib.Path("."))\n', "could be a flag"),
        ):
            with self.subTest(body=body):
                outcome = self.check(body)
                assert isinstance(outcome, Rejected), body
                self.assertIn(why, outcome.denials[0].reason)


class TestRulesetWellFormedness(RulesetCase):
    def load(self, text: str, **bindings) -> Policy:
        self.ruleset("r.toml", text)
        return from_data(self.root({"ruleset": "r.toml", **bindings}))

    def test_exec_side_vocabulary_only(self) -> None:
        with self.assertRaises(PolicyFileError) as cm:
            self.load('ruleset-version = 1\n[filesystem]\nread = ["**"]\n')
        self.assertIn("filesystem: unknown key 'read'", str(cm.exception))  # only no-write: a ruleset grants nothing

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
