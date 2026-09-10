"""The policy filesystem section lowered to mounts (fsview, MOUNTS.md): pure, no jail."""
import os
import pathlib
import re
import unittest

from certorail.childjail import Mounts, Regex, View
from certorail.fsview import additions, mounts
from certorail.locations import parse_location as loc
from certorail.locations import single_path as bind_path
from certorail.policy import Policy, program
from certorail.sandbox.seatbelt import NOT_ERE, ere_of, pattern_regex

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
            ("[^.]", "[^.]"),
            ("(ab|cd)*", "(ab|cd)*"),
            ("a{2}b{3,}c{1,4}", "a{2}b{3,}c{1,4}"),
            (".*", ".*"),
            ("^x$", "^x$"),
            ("\\Ax\\Z", "^x$"),
            ("[]a]", "[]a]"),          # a leading ] is literal in both dialects
            ("[a-]", "[a-]"),          # a trailing - too
            ("[a^]", "[a^]"),          # ^ is literal when not leading
            ("\\*\\+\\?", "\\*\\+\\?"),
            ("\\/", "/"),              # an escaped non-special is the character
            ("(?:ab)+", "(ab)+"),      # a non-capturing group is a plain group
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
            "a++", "(?>a)", "[^]", "[^^]", "é", "[à-ÿ]", "\\n",
        ):
            with self.subTest(pattern=pattern):
                self.assertIsNone(ere_of(pattern))

    def test_a_refused_regex_is_omitted_with_the_reason_under_patterns(self) -> None:
        m = mounts(ROOT, read=(loc("logs/**/<\\d+\\.log>"),), write=(), no_write=(loc("<(?i)secret>"),), patterns=True)
        self.assertEqual(m.reads, ())
        self.assertEqual(m.no_write, ())
        self.assertEqual(len(m.omitted), 2)
        self.assertTrue(all(NOT_ERE in entry for entry in m.omitted), m.omitted)
        self.assertTrue(m.omitted[0].startswith("read logs/**/<"))
        self.assertTrue(m.omitted[1].startswith("no-write <"))
        # the same shape spelled in the shared subset lowers
        ok = mounts(ROOT, read=(loc("logs/**/<[0-9]+\\.log>"),), write=(), no_write=(), patterns=True)
        self.assertEqual(ok.reads, (Regex(f"^{REAL}/logs/(.*/)?([0-9]+\\.log)$"),))
        self.assertEqual(ok.omitted, ())


class TestPatternRegex(unittest.TestCase):
    """What Seatbelt gets for a pattern: anchored ERE over canonical absolute paths."""

    def regex(self, text: str, below: bool = False) -> str:
        r = pattern_regex(loc(text), ROOT, below=below)
        assert r is not None
        return r

    def test_the_shapes(self) -> None:
        self.assertEqual(self.regex("src/**/<.*\\.py>"), f"^{REAL}/src/(.*/)?(.*\\.py)$")
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


class TestMounts(unittest.TestCase):
    def test_grants_and_protections_are_kept_apart_and_deduplicated(self) -> None:
        m = mounts(
            ROOT,
            read=(loc("**"), loc("/usr/share/data/**"), loc(".")),
            write=(loc("build/**"),),
            no_write=(loc("build/keep.txt"),),
            patterns=False,
        )
        self.assertEqual(m, Mounts(
            reads=(ROOT, pathlib.Path("/usr/share/data")),
            writes=(ROOT / "build",),
            no_write=(ROOT / "build" / "keep.txt",),
        ))

    def test_without_patterns_what_no_bind_expresses_is_reported_not_rounded(self) -> None:
        m = mounts(
            ROOT,
            read=(loc("src/**/<.*\\.py>"), loc("docs/**")),
            write=(loc("repos/*/**"),),
            no_write=(loc("repos/**/.git"),),
            listing=(loc("."), loc("src/*")),
            patterns=False,
        )
        self.assertEqual(m.reads, (ROOT / "docs",))
        self.assertEqual(m.writes, ())
        self.assertEqual(m.no_write, ())
        self.assertEqual(m.listings, ())  # a bind cannot say "this directory, not its files"
        self.assertEqual(m.omitted, ("read src/**/</.*\\.py/>", "write repos/*/**", "no-write repos/**/.git"))

    def test_with_patterns_everything_lowers(self) -> None:
        m = mounts(
            ROOT,
            read=(loc("src/**/<.*\\.py>"), loc("docs/**")),
            write=(loc("repos/*/**"),),
            no_write=(loc("repos/**/.git"),),
            listing=(loc("."), loc("src/*")),
            patterns=True,
        )
        self.assertEqual(m.reads, (Regex(f"^{REAL}/src/(.*/)?(.*\\.py)$"), ROOT / "docs"))
        self.assertEqual(m.writes, (Regex(f"^{REAL}/repos/[^/]+(/.*)?$"),))
        self.assertEqual(m.no_write, (Regex(f"^{REAL}/repos/(.*/)?\\.git(/.*)?$"),))
        self.assertEqual(m.listings, (ROOT, Regex(f"^{REAL}/src/[^/]+$")))
        self.assertEqual(m.omitted, ())
        # the bind-mountable part drops the regexes and the listings
        self.assertEqual(m.paths, Mounts(reads=(ROOT / "docs",)))

    def test_a_rules_additions_join_the_view_under_their_own_names(self) -> None:
        base = mounts(ROOT, read=(loc("src/**"),), write=(loc("out/**"),), no_write=(loc("out/final"),), patterns=False)
        extra = additions(ROOT, mount_read=(loc("/srv/keys/**"), loc("src/**"), loc("cfg/*")), mount_write=(loc(".git/**"),), patterns=False)
        self.assertEqual(extra.omitted, ("mount-read cfg/*",))
        joined = base | extra
        self.assertEqual(joined.reads, (ROOT / "src", pathlib.Path("/srv/keys")))  # src once
        self.assertEqual(joined.writes, (ROOT / "out", ROOT / ".git"))
        self.assertEqual(joined.no_write, (ROOT / "out" / "final",))
        self.assertEqual(joined.omitted, ("mount-read cfg/*",))
        rule = program("git", cwd=".", view=View.POLICY, mount_read=["/srv/keys/**"], mount_write=[".git/**"])
        policy = Policy.allow(read=["src/**"], write=["out/**"], no_write=["out/final"], programs=[rule])
        self.assertEqual(policy.mounts(ROOT, rule).writes, (ROOT / "out", ROOT / ".git"))
        self.assertEqual(policy.mounts(ROOT).writes, (ROOT / "out",))  # the base alone, without a rule

    def test_the_policy_lowers_its_own_section(self) -> None:
        policy = Policy.allow(read=["src/**"], write=["out/**"], no_write=["out/final"], programs=[program("cat", cwd=".")])
        m = policy.mounts(ROOT)
        self.assertEqual((m.reads, m.writes, m.no_write), ((ROOT / "src",), (ROOT / "out",), (ROOT / "out" / "final",)))
        self.assertFalse(policy.confines)


if __name__ == "__main__":
    unittest.main()
