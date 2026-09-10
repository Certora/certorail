"""Location overlap (``certorail/footprints.py``): a location as a component sequence, and
whether a write's proven location can lie at or below another location -- the ``no-write``
protection's test -- with folded component equality."""
import unittest

from certorail.analysis import ANY_NAME, DirSplat, Matching, Named, OneOf, RegexLit, StaticPath
from certorail.footprints import SPLAT, Footprint, fold, footprint_of, items_of, overlaps


def static(*names: str, absolute: bool = False) -> StaticPath:
    return StaticPath(tuple(Named(n) for n in names), absolute)


def below(*names: str, leaf=None, absolute: bool = False) -> DirSplat:
    """``names/**`` (the prefix and everything below it), or ``names/**/leaf``."""
    return DirSplat(tuple(Named(n) for n in names), leaf, absolute)


# repos/**/.git/config: a splat followed by a tail of two components, which the location grammar
# cannot spell but a footprint can hold
ORG = Footprint((Named("repos"), SPLAT, Named(".git"), Named("config")))


class TestItems(unittest.TestCase):
    def test_items_of_a_leaf_splat(self) -> None:
        self.assertEqual(items_of(below("a", leaf=Named("b"))), (Named("a"), SPLAT, Named("b")))

    def test_a_footprint_keeps_its_anchor(self) -> None:
        fp = footprint_of(static("etc", "hosts", absolute=True))
        self.assertTrue(fp.absolute)
        self.assertEqual(fp.items, (Named("etc"), Named("hosts")))

    def test_reflexive_and_strict_descent_differ(self) -> None:
        # a/** denotes a itself; a/**/* demands one component below it
        self.assertEqual(items_of(below("a")), (Named("a"), SPLAT))
        self.assertEqual(items_of(below("a", leaf=ANY_NAME)), (Named("a"), SPLAT, ANY_NAME))
        strict = footprint_of(below("repos", leaf=ANY_NAME))
        self.assertFalse(overlaps(static("repos"), strict))
        self.assertTrue(overlaps(static("repos", "x"), strict))
        reflexive = footprint_of(below("repos"))
        self.assertTrue(overlaps(static("repos"), reflexive))


class TestOverlaps(unittest.TestCase):
    def test_the_worked_examples(self) -> None:
        self.assertFalse(overlaps(static("repos", "x", "NOTICE.md"), ORG))
        slug = Matching(RegexLit(r"[a-z]+"))
        self.assertFalse(overlaps(StaticPath((Named("repos"), slug, Named("NOTICE.md"))), ORG))
        # but at any depth below the slug, NOTICE.md may sit inside .git/config
        self.assertTrue(overlaps(DirSplat((Named("repos"), slug), Named("NOTICE.md")), ORG))
        self.assertTrue(overlaps(static("repos", "x", ".git", "config"), ORG))
        self.assertTrue(overlaps(static("repos", "x", ".git", "config", "anything"), ORG))
        self.assertTrue(overlaps(static("repos", "x", ".GIT", "config"), ORG))
        self.assertTrue(overlaps(below("repos"), ORG))  # somewhere under repos: may be it
        self.assertTrue(overlaps(below("repos", "x"), ORG))

    def test_nested_repositories(self) -> None:
        # the splat may be any depth under repos, so a nested checkout's config is covered
        self.assertTrue(overlaps(static("repos", "a", "vendor", "b", ".git", "config"), ORG))

    def test_a_write_above_the_footprint_does_not_reach_it(self) -> None:
        self.assertFalse(overlaps(static("repos"), ORG))
        self.assertFalse(overlaps(static("repos", "x", ".git"), ORG))  # .git itself, not config

    def test_anchors_never_relate(self) -> None:
        self.assertFalse(overlaps(static("repos", "x", ".git", "config", absolute=True), ORG))
        etc = footprint_of(static("etc", absolute=True))
        self.assertFalse(overlaps(static("etc", "hosts"), etc))
        self.assertTrue(overlaps(static("etc", "hosts", absolute=True), etc))

    def test_a_wildcard_may_name_anything_but_a_regex_is_read(self) -> None:
        wild = DirSplat((Named("repos"),), Matching(RegexLit(r"\w+")))  # repos/**/<\w+>
        self.assertTrue(overlaps(wild, ORG))  # \w+ spells "config"
        digits = DirSplat((Named("repos"),), Matching(RegexLit(r"\d+")))  # repos/**/<\d+>
        self.assertTrue(overlaps(digits, ORG))  # repos/.git/config/123 lies below the footprint
        self.assertFalse(overlaps(StaticPath((Named("repos"), Named("x"), Matching(RegexLit(r"\d+")))), ORG))  # neither .git nor below
        any_config = Footprint((Named("repos"), SPLAT, ANY_NAME, Named("config")))
        self.assertTrue(overlaps(static("repos", "x", "a", "config"), any_config))
        self.assertTrue(overlaps(StaticPath((Named("repos"), ANY_NAME, Named(".git"), Named("config"))), ORG))

    def test_a_regex_is_read_against_every_spelling_of_the_name(self) -> None:
        git = Footprint((Named("repos"), SPLAT, Named(".git")))  # repos/**/.git and below
        for regex, may in (
            (r"\w+", False),           # cannot spell the dot
            (r"[^-].*", True),         # .git itself
            (r"[^.].*", False),        # not a dotfile: neither .git nor .GIT
            (r"\.GIT", True),          # folds to .git
            (r"\.g[iI]t", True),
            (r"(?i)\.git", True),
            (r"[a-z]+\.git", False),   # needs a prefix
            (r"x|\.Git", True),
        ):
            with self.subTest(regex=regex):
                self.assertIs(overlaps(StaticPath((Named("repos"), Named("x"), Matching(RegexLit(regex)))), git), may)
        # a name whose spellings are many (ligatures, long s, sharp s) is still enumerated
        stuff = Footprint((Named("repos"), SPLAT, Named("assist")))
        self.assertTrue(overlaps(StaticPath((Named("repos"), Named("x"), Matching(RegexLit("aſſiﬆ")))), stuff))
        self.assertTrue(overlaps(StaticPath((Named("repos"), Named("x"), Matching(RegexLit("Aßiﬅ")))), stuff))
        self.assertFalse(overlaps(StaticPath((Named("repos"), Named("x"), Matching(RegexLit("assis")))), stuff))
        # a name this cannot enumerate falls back to the conservative answer
        cafe = Footprint((Named("repos"), SPLAT, Named("café")))
        self.assertTrue(overlaps(StaticPath((Named("repos"), Matching(RegexLit(r"\d+")))), cafe))

    def test_one_of(self) -> None:
        either = StaticPath((Named("repos"), Named("x"), OneOf(frozenset({".git", "src"})), Named("config")))
        self.assertTrue(overlaps(either, ORG))
        neither = StaticPath((Named("repos"), Named("x"), OneOf(frozenset({"docs", "src"})), Named("config")))
        self.assertFalse(overlaps(neither, ORG))


class TestFold(unittest.TestCase):
    def test_case(self) -> None:
        self.assertEqual(fold(".GIT"), fold(".git"))

    def test_normalisation(self) -> None:
        self.assertEqual(fold("café"), fold("café"))  # NFC vs decomposed

    def test_format_code_points_are_not_ignored(self) -> None:
        # HFS+ ignored a zero-width joiner; APFS does not, and no sandbox root is on HFS+
        self.assertNotEqual(fold("con‍fig"), fold("config"))

    def test_the_kelvin_sign_and_the_long_s_are_spellings(self) -> None:
        self.assertEqual(fold("Key"), fold("key"))
        self.assertEqual(fold("ſ"), fold("s"))


if __name__ == "__main__":
    unittest.main()
