"""The policy filesystem section lowered for the jails (MOUNTS.md): the one path a bind can say,
the ERE a Seatbelt filter takes, and each spawner's typed lowering. Pure, no jail."""
import os
import pathlib
import re
import tempfile
import unittest

from certorail.analysis import pretty_location
from certorail.childjail import View
from certorail.confinement import Additions, FilesystemSection, PolicyFilesystem
from certorail.locations import parse_location as loc
from certorail.locations import single_path as bind_path
from certorail.policy import Policy, program
from certorail.sandbox import NoView
from certorail.sandbox.bubblewrap import BubblewrapSpawner
from certorail.sandbox.lowering import Bind, Omitted, RegexRule
from certorail.sandbox.seatbelt import NOT_ERE, SeatbeltSpawner, ere_of, pattern_regex

ROOT = pathlib.Path("/sandbox")
REAL = re.escape(os.path.realpath(ROOT))  # what a regex over canonical paths starts with


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

    def test_a_refused_regex_is_omitted_with_the_reason_under_patterns(self) -> None:
        section = FilesystemSection(read=(loc("logs/**/<\\d+\\.log>"),), no_write=(loc("<(?i)secret>"),))
        lowered = SeatbeltSpawner().lower(PolicyFilesystem(ROOT, section), write_fs=False)
        self.assertEqual([(o.role, o.reason) for o in lowered if isinstance(o, Omitted)],
                         [("read", NOT_ERE), ("no-write", NOT_ERE)])
        self.assertEqual(len(lowered), 2)
        # the same shape spelled in the shared subset lowers
        ok = SeatbeltSpawner().lower(PolicyFilesystem(ROOT, FilesystemSection(read=(loc("logs/**/<[0-9]+\\.log>"),))), write_fs=False)
        self.assertEqual(ok, (RegexRule(f"^{os.path.realpath(ROOT)}/logs/(.*/)?([0-9]+\\.log)$", "read"),))


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


def fs(read: tuple = (), write: tuple = (), no_write: tuple = (), additions: Additions = Additions()) -> PolicyFilesystem:
    return PolicyFilesystem(ROOT, FilesystemSection(read, write, no_write), additions)


class TestLowering(unittest.TestCase):
    """What each mechanism does with each location: a typed ``Lowered`` value per location, with
    its role, never a string."""

    def test_without_patterns_what_no_bind_expresses_is_omitted_not_rounded(self) -> None:
        lowered = BubblewrapSpawner(NoView("a test serves no view")).lower(fs(
            read=(loc("src/**/<.*\\.py>"), loc("docs/**")), write=(loc("repos/*/**"),), no_write=(loc("repos/**/.git"),),
        ), write_fs=True)
        self.assertEqual([x for x in lowered if isinstance(x, Bind)], [Bind(ROOT / "docs", "read")])
        self.assertEqual([(o.role, pretty_location(o.location)) for o in lowered if isinstance(o, Omitted)],
                         [("read", "src/**/</.*\\.py/>"), ("write", "repos/*/**"), ("no-write", "repos/**/.git")])

    def test_seatbelt_lowers_everything_it_can_spell(self) -> None:
        lowered = SeatbeltSpawner().lower(fs(
            read=(loc("src/**/<.*\\.py>"), loc("docs/**"), loc("README.md")), write=(loc("repos/*/**"),),
            no_write=(loc("repos/**/.git"), loc("out/final")),
        ), write_fs=True)
        self.assertIn(RegexRule(f"^{os.path.realpath(ROOT)}/src/(.*/)?([^/]*\\.py)$", "read"), lowered)
        self.assertIn(Bind(ROOT / "docs", "read", subtree=True), lowered)
        self.assertIn(Bind(ROOT / "README.md", "read", subtree=False), lowered)  # a literal is that path alone
        self.assertIn(Bind(ROOT / "out" / "final", "no-write", subtree=True), lowered)  # a protection guards below
        self.assertFalse([x for x in lowered if isinstance(x, Omitted)])

    def test_a_set_of_names_is_one_bind_per_name(self) -> None:
        # {a,b} is exactly two paths; a pattern after it is not, and a grant is never widened
        lowered = BubblewrapSpawner(NoView("a test serves no view")).lower(fs(
            read=(loc("/srv/{alpha,beta}/**"), loc("/srv/{alpha,beta}/<x.*>")), no_write=(loc("{out,dist}/final"),),
        ), write_fs=True)
        self.assertEqual([x for x in lowered if isinstance(x, Bind)], [
            Bind(pathlib.Path("/srv/alpha"), "read"), Bind(pathlib.Path("/srv/beta"), "read"),
            Bind(ROOT / "dist" / "final", "no-write"), Bind(ROOT / "out" / "final", "no-write"),
        ])
        self.assertEqual([pretty_location(o.location) for o in lowered if isinstance(o, Omitted)], ["/srv/{alpha,beta}/</x.*/>"])

    def test_a_rules_additions_lower_under_their_own_names(self) -> None:
        lowered = BubblewrapSpawner(NoView("a test serves no view")).lower(fs(
            read=(loc("src/**"),), additions=Additions(read=(loc("/srv/keys/**"), loc("cfg/*")), write=(loc(".git/**"),)),
        ), write_fs=True)
        self.assertIn(Bind(pathlib.Path("/srv/keys"), "mount-read"), lowered)
        self.assertIn(Bind(ROOT / ".git", "mount-write"), lowered)
        self.assertEqual([(o.role, pretty_location(o.location)) for o in lowered if isinstance(o, Omitted)],
                         [("mount-read", "cfg/*")])

    def test_a_literal_directory_is_the_views_or_nothing_under_bubblewrap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "README.md").write_text("x\n")
            section = FilesystemSection(read=(loc("src"), loc("README.md")))
            lowered = BubblewrapSpawner(NoView("a test serves no view")).lower(PolicyFilesystem(root, section), write_fs=False)
            # a file binds exactly; a directory named alone cannot be bound without its contents
            self.assertIn(Bind(root / "README.md", "read"), lowered)
            self.assertEqual([pretty_location(o.location) for o in lowered if isinstance(o, Omitted)], ["src"])

    def test_the_policy_builds_the_confinement_the_lowering_reads(self) -> None:
        rule = program("git", cwd=".", view=View.POLICY, mount_read=["/srv/keys/**"], mount_write=[".git/**"])
        policy = Policy.allow(read=["src/**"], write=["out/**"], no_write=["out/final"], programs=[rule])
        c = policy.confinement(rule, ROOT)
        assert isinstance(c.filesystem, PolicyFilesystem)
        self.assertEqual(c.filesystem.section, FilesystemSection(policy.read, policy.write, policy.no_write))
        self.assertEqual(c.filesystem.additions, Additions(rule.mount_read, rule.mount_write))


if __name__ == "__main__":
    unittest.main()
