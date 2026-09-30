"""The policy's filesystem section as the jails hold it: the one path a bind can say,
the ERE a Seatbelt filter takes, and each location as the front end states it and a backend
places it. Pure, no jail."""
import os
import pathlib
import re
import unittest
from collections.abc import Sequence

from certorail.childjail import View
from certorail.locations import parse_location as loc
from certorail.locations import single_path as bind_path
from certorail.policy import Policy, Program, program
from certorail.sandbox.front import tool
from certorail.sandbox.grants import Access, Exactly, Grant, Narrowing, Pattern, PolicyGrants, Restriction, Subtree
from certorail.sandbox.place import (
    CompileError, LiteralRule, RegexRule, Rule, SeatbeltPlan, SubpathRule, place_bubblewrap, place_seatbelt,
)
from certorail.sandbox.seatbelt import NOT_ERE, ere_of, pattern_regex
from tests.test_jail_compiler import FakeFS

ROOT = pathlib.Path("/sandbox")
REAL = re.escape(os.path.realpath(ROOT))  # what a regex over canonical paths starts with
FS = FakeFS(dirs=("/sandbox/src", "/sandbox/docs", "/sandbox/repos", "/sandbox/out", "/srv/alpha", "/srv/beta"),
            files=("/sandbox/README.md",))
CAT = program("cat", cwd=".", view=View.POLICY)


def jail(rule: Program = CAT, *, read: Sequence[str] = (), write: Sequence[str] = (), no_write: Sequence[str] = ()) -> PolicyGrants:
    """*rule*'s jail at ROOT under a policy of this section, as the front end states it."""
    grants = tool(Policy.allow(read=read, write=write, no_write=no_write, programs=[rule]), rule, ROOT, ())
    assert isinstance(grants, PolicyGrants)
    return grants


class TestBindPath(unittest.TestCase):
    def test_a_subtree_and_a_literal_path_are_bindable(self) -> None:
        self.assertEqual(bind_path(loc("src/**"), ROOT), ROOT / "src")
        self.assertEqual(bind_path(loc("**"), ROOT), ROOT)
        self.assertEqual(bind_path(loc("."), ROOT), ROOT)
        self.assertEqual(bind_path(loc("README.md"), ROOT), ROOT / "README.md")
        self.assertEqual(bind_path(loc("a/b/c"), ROOT), ROOT / "a" / "b" / "c")

    def test_absolute_locations_anchor_at_the_filesystem_root(self) -> None:
        self.assertEqual(bind_path(loc("/opt/data/**"), ROOT), pathlib.Path("/opt/data"))
        self.assertEqual(bind_path(loc("/etc/hosts"), ROOT), pathlib.Path("/etc/hosts"))

    def test_patterns_have_no_bind(self) -> None:
        for text in ("src/**/*.py", "repos/*/**", "repos/*", "src/**/<.*\\.txt>", "<x.*>/**", "**/.git"):
            with self.subTest(text=text):
                self.assertIsNone(bind_path(loc(text), ROOT))


class TestEreOf(unittest.TestCase):
    """A policy <regex> as ERE, rendered from Python's parse of it: equivalent or refused."""

    def test_the_shared_subset_renders(self) -> None:
        for pattern, expected in (
            ("abc", "abc"),
            ("a\\.b", "a\\.b"),
            ("a+b*c?", "a+b*c?"),
            ("[a-z0-9_]+\\.txt", "[a-z0-9_]+\\.txt"),
            ("[^/]+", "[^/]+"),
            ("[^.]", "[^./]"),         # a component never holds "/": a negated class excludes it
            ("[!-~]", "[!-.0-~]"),     # ... and a positive one loses it, split around it
            ("(ab|cd)*", "(ab|cd)*"),
            ("a{2}b{3,}c{1,4}", "a{2}b{3,}c{1,4}"),
            (".*", "[^/]*"),           # "." is any character of one name
            ("^x$", "x"),              # edge anchors say nothing under fullmatch
            ("\\Ax\\Z", "x"),
            ("[]a]", "[]a]"),          # a leading ] is literal in both dialects
            ("[a-]", "[a-]"),          # a trailing - too
            ("[a^]", "[a^]"),          # ^ is literal when not leading
            ("[^^]", "[^/^]"),         # with "/" leading, a lone ^ can be placed
            ("\\*\\+\\?", "\\*\\+\\?"),
            ("(?:ab)+", "(ab)+"),      # a non-capturing group is a plain group
            ("(?:a+)*", "(a+)*"),      # a quantified quantifier is grouped first
            # rendered from the parse, not the text: Python read these as {a, z, -} and as A
            ("[a\\-z]", "[az-]"),
            ("\\x41", "A"),
        ):
            with self.subTest(pattern=pattern):
                self.assertEqual(ere_of(pattern), expected)
                re.compile(pattern)  # the Python side is well-formed too

    def test_what_python_says_that_ere_cannot_is_refused(self) -> None:
        for pattern in (
            "\\d+", "\\w", "\\s", "x\\d", "[\\d]", "\\bx", "a*?", "a+?", "a??", "a{2,}?",
            "(?i)x", "(?i:x)y", "(?=a)b", "(?!a)b", "(?<=a)b", "(a)\\1", "(?P<n>a)(?P=n)",
            "a++", "(?>a)", "[^]", "é", "[à-ÿ]", "\\n",
            "\\/", "a/b",              # a component never holds "/"
            "a^b", "a$b", "(^a)",      # an anchor anywhere but the edges
        ):
            with self.subTest(pattern=pattern):
                self.assertIsNone(ere_of(pattern))

    def test_a_regex_seatbelt_cannot_spell_refuses_the_jail(self) -> None:
        refused = place_seatbelt(jail(read=["logs/**/<\\d+\\.log>"], no_write=["<(?i)secret>"]), FS)
        assert isinstance(refused, CompileError)
        self.assertEqual([r.reason for r in refused.refusals], [NOT_ERE, NOT_ERE])
        # the same shape spelled in the shared subset is a rule
        placed = place_seatbelt(jail(read=["logs/**/<[0-9]+\\.log>"]), FS)
        assert isinstance(placed, SeatbeltPlan)
        self.assertEqual(placed.rules, (Rule(RegexRule(f"^{ROOT}/logs/(.*/)?([0-9]+\\.log)$"), Grant(Access.READ_ONLY)),))


class TestPatternRegex(unittest.TestCase):
    """What Seatbelt gets for a pattern: anchored ERE over canonical absolute paths."""

    def regex(self, text: str, below: bool = False) -> str:
        r = pattern_regex(loc(text), ROOT, below=below)
        assert r is not None
        return r

    def test_the_shapes(self) -> None:
        self.assertEqual(self.regex("src/**/<.*\\.py>"), f"^{REAL}/src/(.*/)?([^/]*\\.py)$")
        # `*.py` is a literal name in the micro-syntax (only a bare `*` is a wildcard): escaped
        self.assertEqual(self.regex("src/**/*.py"), f"^{REAL}/src/(.*/)?\\*\\.py$")
        self.assertEqual(self.regex("repos/*/**"), f"^{REAL}/repos/[^/]+(/.*)?$")
        self.assertEqual(self.regex("repos/*"), f"^{REAL}/repos/[^/]+$")
        self.assertEqual(self.regex("**/.git"), f"^{REAL}/(.*/)?\\.git$")
        self.assertEqual(self.regex("src/**/<[a-z]+\\.txt>"), f"^{REAL}/src/(.*/)?([a-z]+\\.txt)$")
        self.assertEqual(self.regex("/srv/*/data/**"), "^/srv/[^/]+/data(/.*)?$")
        # a literal path renders too (a caller may want everything as regex)
        self.assertEqual(self.regex("src/**"), f"^{REAL}/src(/.*)?$")
        self.assertEqual(self.regex("a+b/**"), f"^{REAL}/a\\+b(/.*)?$")

    def test_a_protection_guards_the_subtree(self) -> None:
        self.assertEqual(self.regex("repos/**/.git", below=True), f"^{REAL}/repos/(.*/)?\\.git(/.*)?$")
        self.assertEqual(self.regex("repos/*", below=True), f"^{REAL}/repos/[^/]+(/.*)?$")

    def test_the_regex_accepts_what_the_location_denotes(self) -> None:
        r = re.compile(self.regex("src/**/<.*\\.py>"))
        real = os.path.realpath(ROOT)
        self.assertTrue(r.search(f"{real}/src/a.py"))
        self.assertTrue(r.search(f"{real}/src/pkg/deep/b.py"))
        self.assertFalse(r.search(f"{real}/src/a.pyc"))
        self.assertFalse(r.search(f"{real}/srcs/a.py"))
        self.assertFalse(r.search(f"{real}/a.py"))
        guard = re.compile(self.regex("repos/**/.git", below=True))
        self.assertTrue(guard.search(f"{real}/repos/x/.git"))
        self.assertTrue(guard.search(f"{real}/repos/x/.git/config"))
        self.assertFalse(guard.search(f"{real}/repos/x/.gitignore"))


class TestTheSectionAsLayers(unittest.TestCase):
    """Each location as the front end states it -- the paths it is exactly the union of, or one
    pattern -- and what each backend does with it. Nothing is rounded: a location no backend here
    can hold refuses the jail."""

    def test_without_a_view_what_no_bind_says_refuses_the_jail(self) -> None:
        grants = jail(read=["src/**/<.*\\.py>", "docs/**"], write=["repos/*/**"], no_write=["repos/**/.git"])
        refused = place_bubblewrap(grants, FS, view_unavailable="a test attaches no view")
        assert isinstance(refused, CompileError)
        # docs/** is a bind; the patterns and the protection are a view's
        self.assertEqual([r.origin.describe().split()[0] for r in refused.refusals], ["read", "write", "no-write"])

    def test_seatbelt_spells_everything_as_rules(self) -> None:
        placed = place_seatbelt(jail(read=["src/**/<.*\\.py>", "docs/**", "README.md"], write=["repos/*/**"],
                                     no_write=["repos/**/.git", "out/final"]), FS)
        assert isinstance(placed, SeatbeltPlan)
        rules = [(rule.filter, rule.effect) for rule in placed.rules]
        self.assertIn((RegexRule(f"^{ROOT}/src/(.*/)?([^/]*\\.py)$"), Grant(Access.READ_ONLY)), rules)
        self.assertIn((SubpathRule(ROOT / "docs"), Grant(Access.READ_ONLY)), rules)
        self.assertIn((LiteralRule(ROOT / "README.md"), Grant(Access.READ_ONLY)), rules)   # a literal is that path alone
        # a protection guards what lies below what it names, and the jail alone stops a tool
        self.assertIn((SubpathRule(ROOT / "out" / "final"), Restriction(Narrowing.NO_WRITE, sole=True)), rules)

    def test_a_set_of_names_is_one_region_per_name(self) -> None:
        # {a,b} is exactly two paths; a pattern after it is not, and a grant is never widened
        grants = jail(read=["/srv/{alpha,beta}/**", "/srv/{alpha,beta}/<x.*>"], no_write=["{out,dist}/final"])
        self.assertEqual([layer.region for layer in grants.layers], [
            Subtree(pathlib.Path("/srv/alpha")), Subtree(pathlib.Path("/srv/beta")),
            Pattern(loc("/srv/{alpha,beta}/<x.*>"), pathlib.Path("/")),
            Subtree(ROOT / "dist" / "final"), Subtree(ROOT / "out" / "final"),
        ])

    def test_a_rules_additions_are_layers_under_their_own_names(self) -> None:
        git = program("git", cwd=".", view=View.POLICY, mount_read=["/srv/keys/**", "cfg/*"], mount_write=[".git/**"])
        grants = jail(git, read=["src/**"])
        self.assertEqual([(layer.origin.describe(), layer.effect) for layer in grants.layers[1:]], [
            ("git's mount-read /srv/keys/**", Grant(Access.READ_ONLY)),
            ("git's mount-read cfg/*", Grant(Access.READ_ONLY)),
            ("git's mount-write .git/**", Grant(Access.WRITABLE)),
        ])

    def test_a_path_named_exactly_is_a_views_under_bubblewrap(self) -> None:
        # what is there may change kind, or not be there yet: a bind of it would say too much
        grants = jail(read=["src", "README.md"])
        self.assertEqual([layer.region for layer in grants.layers], [Exactly(ROOT / "src"), Exactly(ROOT / "README.md")])
        refused = place_bubblewrap(grants, FS, view_unavailable="a test attaches no view")
        assert isinstance(refused, CompileError)
        self.assertEqual([r.origin.describe() for r in refused.refusals], ["read grant src", "read grant README.md"])


if __name__ == "__main__":
    unittest.main()
