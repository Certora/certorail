"""The footprint derivation (EFFECTS.md, "File writes: derived"; ``certorail/footprints.py``):
instantiating a region's footprint under a validation's cwd, and deciding whether a write's
proven location can lie at or below it -- with folded component equality."""
import unittest

from certorail.analysis import ANY_NAME, DirSplat, Matching, Named, OneOf, RegexLit, StaticPath
from certorail.footprints import ANYWHERE, SPLAT, Footprint, fold, instantiate, items_of, overlaps


def static(*names: str, absolute: bool = False) -> StaticPath:
    return StaticPath(tuple(Named(n) for n in names), absolute)


def below(*names: str, leaf=None, absolute: bool = False) -> DirSplat:
    """``names/**`` (the prefix and everything below it), or ``names/**/leaf``."""
    return DirSplat(tuple(Named(n) for n in names), leaf, absolute)


REPOS = below("repos")  # repos/**: the check's cwd
GIT_CONFIG = static(".git", "config")
ORG = instantiate(REPOS, GIT_CONFIG)  # repos/**/.git/config


class TestInstantiate(unittest.TestCase):
    def test_a_splat_then_a_tail_longer_than_one_component(self) -> None:
        # the location grammar cannot spell this; the footprint sequence can
        self.assertEqual(ORG.items, (Named("repos"), SPLAT, Named(".git"), Named("config")))
        self.assertFalse(ORG.absolute)

    def test_a_static_cwd(self) -> None:
        self.assertEqual(
            instantiate(static("repos", "x"), GIT_CONFIG).items,
            (Named("repos"), Named("x"), Named(".git"), Named("config")),
        )

    def test_an_absolute_footprint_takes_no_base(self) -> None:
        fp = instantiate(REPOS, static("etc", "hosts", absolute=True))
        self.assertTrue(fp.absolute)
        self.assertEqual(fp.items, (Named("etc"), Named("hosts")))

    def test_the_whole_tree(self) -> None:
        # footprint "." under repos/**: the cwd itself and everything below
        self.assertEqual(instantiate(REPOS, StaticPath(())).items, (Named("repos"), SPLAT))

    def test_items_of_a_leaf_splat(self) -> None:
        self.assertEqual(items_of(below("a", leaf=Named("b"))), (Named("a"), SPLAT, Named("b")))

    def test_reflexive_and_strict_descent_differ(self) -> None:
        # a/** denotes a itself; a/**/* demands one component below it
        self.assertEqual(items_of(below("a")), (Named("a"), SPLAT))
        self.assertEqual(items_of(below("a", leaf=ANY_NAME)), (Named("a"), SPLAT, ANY_NAME))
        strict = instantiate(below("repos", leaf=ANY_NAME), StaticPath(()))  # repos/**/* then "."
        self.assertFalse(overlaps(static("repos"), strict))
        self.assertTrue(overlaps(static("repos", "x"), strict))
        reflexive = instantiate(below("repos"), StaticPath(()))
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
        # the cwd may be any depth under repos, so a nested checkout's config is covered
        self.assertTrue(overlaps(static("repos", "a", "vendor", "b", ".git", "config"), ORG))

    def test_a_write_above_the_footprint_does_not_reach_it(self) -> None:
        self.assertFalse(overlaps(static("repos"), ORG))
        self.assertFalse(overlaps(static("repos", "x", ".git"), ORG))  # .git itself, not config

    def test_anchors_never_relate(self) -> None:
        self.assertFalse(overlaps(static("repos", "x", ".git", "config", absolute=True), ORG))
        etc = instantiate(None, static("etc", absolute=True))
        self.assertFalse(overlaps(static("etc", "hosts"), etc))
        self.assertTrue(overlaps(static("etc", "hosts", absolute=True), etc))

    def test_wildcards_may_name_anything(self) -> None:
        wild = DirSplat((Named("repos"),), Matching(RegexLit(r"\d+")))  # repos/**/<\d+>
        self.assertTrue(overlaps(wild, ORG))  # conservatively: the regex may spell "config"
        self.assertTrue(overlaps(static("repos", "x", "a", "config"), instantiate(REPOS, StaticPath((ANY_NAME, Named("config"))))))

    def test_one_of(self) -> None:
        either = StaticPath((Named("repos"), Named("x"), OneOf(frozenset({".git", "src"})), Named("config")))
        self.assertTrue(overlaps(either, ORG))
        neither = StaticPath((Named("repos"), Named("x"), OneOf(frozenset({"docs", "src"})), Named("config")))
        self.assertFalse(overlaps(neither, ORG))

    def test_anywhere(self) -> None:
        for fp in ANYWHERE:
            with self.subTest(absolute=fp.absolute):
                self.assertTrue(overlaps(static("a", "b", absolute=fp.absolute), fp))


class TestFold(unittest.TestCase):
    def test_case(self) -> None:
        self.assertEqual(fold(".GIT"), fold(".git"))

    def test_normalisation(self) -> None:
        self.assertEqual(fold("café"), fold("café"))  # NFC vs decomposed

    def test_ignorable_code_points(self) -> None:
        self.assertEqual(fold("con‍fig"), fold("config"))  # a zero-width joiner hides nothing


if __name__ == "__main__":
    unittest.main()
