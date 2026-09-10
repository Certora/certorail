"""A constant collection of literals, iterated: the loop variable carries the one fact covering
every element, by a one-shot fold over the display (``join_fact`` / ``join_loc``). Exact where
the literals agree, a splat where they do not, ``**`` at worst for one anchor, nothing across
anchors. Ad-hoc precision for literal containers only: the walker's control-flow join is not
involved (the join decision)."""
import unittest

from certorail import markers
from certorail.analysis import (
    ANY_NAME,
    DirSplat,
    Exact,
    Located,
    Named,
    OneOf,
    StaticPath,
    StrFact,
    alternation,
    join_fact,
    join_loc,
    locate,
    location_le,
)
from certorail.host import Rejected
from certorail.host import check as host_check
from certorail.policy import Policy, constraint, program, splice
from certorail.templates import Each

HEADER = "import pathlib\nimport sys\n"


def named(*parts: str) -> StaticPath:
    return StaticPath(tuple(Named(p) for p in parts))


def one_of(*names: str) -> OneOf:
    return OneOf(frozenset(names))


class TestJoinLoc(unittest.TestCase):
    """Total on one anchor, an upper bound of both arguments."""

    def both_below(self, a: StaticPath | DirSplat, b: StaticPath | DirSplat, expected: StaticPath | DirSplat) -> None:
        got = join_loc(a, b)
        self.assertEqual(got, expected)
        assert got is not None
        self.assertTrue(location_le(a, got), f"{a} not within {got}")
        self.assertTrue(location_le(b, got), f"{b} not within {got}")

    def test_pointwise_where_the_shapes_agree(self) -> None:
        self.both_below(named("a", "x.py"), named("a", "y.py"), StaticPath((Named("a"), one_of("x.py", "y.py"))))

    def test_depth_mismatch_degrades_to_a_strict_splat_with_the_leaf(self) -> None:
        self.both_below(named("a", "b", "x.py"), named("a", "y.py"), DirSplat((Named("a"),), one_of("x.py", "y.py")))
        self.both_below(named("a", "b", "foo.py"), named("c", "blah.py"), DirSplat((one_of("a", "c"),), one_of("foo.py", "blah.py")))

    def test_the_worst_case_is_everything(self) -> None:
        # foo.py, a/b/bar.py, c/baz.py: no shared head at all
        step = join_loc(named("foo.py"), named("a", "b", "bar.py"))
        assert step is not None
        got = join_loc(step, named("c", "baz.py"))
        self.assertEqual(got, DirSplat((), one_of("foo.py", "bar.py", "baz.py")))
        # and once a leaf disagrees with a reflexive splat there is nothing left to say but **
        self.both_below(DirSplat((), None), named("q", "r"), DirSplat((), None))

    def test_a_splat_and_a_path_outside_its_prefix(self) -> None:
        # previously None; now the covering splat
        self.both_below(DirSplat((Named("a"),), ANY_NAME), named("b", "x"), DirSplat((one_of("a", "b"),), ANY_NAME))
        self.both_below(DirSplat((Named("a"), Named("b")), None), named("a", "c"), DirSplat((Named("a"), one_of("b", "c")), None))
        self.both_below(DirSplat((Named("a"), Named("b")), None), named("a"), DirSplat((Named("a"),), None))
        # the path ends at the splat's prefix: only the reflexive form denotes the prefix
        self.both_below(DirSplat((Named("a"),), ANY_NAME), named("a"), DirSplat((Named("a"),), None))

    def test_anchors_never_join(self) -> None:
        self.assertIsNone(join_loc(named("a"), StaticPath((Named("a"),), absolute=True)))


class TestLocateAnAlternationOfLiterals(unittest.TestCase):
    def test_same_directory_is_exact(self) -> None:
        got = locate(StrFact(regex=alternation(Exact("certorail/x.py"), Exact("certorail/y.py"))))
        self.assertEqual(got, Located(StaticPath((Named("certorail"), one_of("x.py", "y.py"))), "str"))

    def test_different_depths_widen(self) -> None:
        got = locate(StrFact(regex=alternation(Exact("a/b/foo.py"), Exact("c/blah.py"))))
        assert got is not None
        self.assertEqual(got.location, DirSplat((one_of("a", "c"),), one_of("foo.py", "blah.py")))

    def test_an_unsafe_literal_or_mixed_anchors_give_nothing(self) -> None:
        self.assertIsNone(locate(StrFact(regex=alternation(Exact("a/x"), Exact("/etc/x")))))
        self.assertIsNone(locate(StrFact(regex=alternation(Exact("a/x"), Exact("../x")))))


class TestJoinFact(unittest.TestCase):
    def test_text_joins_to_the_alternation_and_common_atoms(self) -> None:
        a = StrFact(regex=Exact("x"), atoms=frozenset({"no-slash", "p"}))
        b = StrFact(regex=Exact("y"), atoms=frozenset({"no-slash"}))
        self.assertEqual(join_fact(a, b), StrFact(regex=alternation(Exact("x"), Exact("y")), atoms=frozenset({"no-slash"})))

    def test_paths_join_by_location(self) -> None:
        got = join_fact(Located(named("a", "x"), "path"), Located(named("a", "y"), "path"))
        self.assertEqual(got, Located(StaticPath((Named("a"), one_of("x", "y"))), "path"))
        self.assertIsNone(join_fact(Located(named("a"), "path"), Located(named("a"), "str")))  # spellings differ
        self.assertIsNone(join_fact(Located(named("a"), "path"), StrFact(regex=Exact("a"))))  # readings differ


POLICY = Policy.allow(
    read=[markers.within(".")],
    programs=[
        program(
            "grep", cwd=".", argv=["grep", "x", splice("FILES")],
            holes={"FILES": Each(constraint(location=[markers.within("certorail"), markers.within("tests")]))},
        ),
        program(
            "wc", cwd=".", argv=["wc", splice("FILES")],
            holes={"FILES": Each(constraint(location=markers.within("src")))},
        ),
    ],
)


class TestIteratingADisplay(unittest.TestCase):
    def check(self, body: str):
        return host_check(HEADER + body, "<t>", POLICY)

    def accept(self, body: str) -> None:
        outcome = self.check(body)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_literal_paths_in_one_directory(self) -> None:
        self.accept(
            'for f in ["certorail/a.py", "certorail/b.py"]:\n'
            '    certora.exec("grep", "x", FILES=[pathlib.Path(f)], cwd=pathlib.Path("."))\n'
        )
        self.accept(
            'for p in [pathlib.Path("certorail/a.py"), pathlib.Path("certorail/b.py")]:\n'
            '    certora.exec("grep", "x", FILES=[p], cwd=pathlib.Path("."))\n'
        )

    def test_across_directories_the_splat_needs_a_grant_covering_it(self) -> None:
        # src/**/{a.py,b.py} is within src/**
        self.accept(
            'for f in ["src/a.py", "src/lib/b.py"]:\n'
            '    certora.exec("wc", FILES=[pathlib.Path(f)], cwd=pathlib.Path("."))\n'
        )
        # {certorail,tests}/{a.py,b.py} is within neither certorail/** nor tests/** by itself: the
        # any-of is per value, and the widened value fits no single alternative (the known limit)
        outcome = self.check(
            'for f in ["certorail/a.py", "tests/b.py"]:\n'
            '    certora.exec("grep", "x", FILES=[pathlib.Path(f)], cwd=pathlib.Path("."))\n'
        )
        assert isinstance(outcome, Rejected)
        self.assertIn("not a proven path within", outcome.denials[0].reason)

    def test_an_unreadable_element_yields_nothing(self) -> None:
        outcome = self.check(
            'for f in ["certorail/a.py", sys.argv[1]]:\n'
            '    certora.exec("grep", "x", FILES=[pathlib.Path(f)], cwd=pathlib.Path("."))\n'
        )
        self.assertIsInstance(outcome, Rejected)

    def test_a_tuple_and_a_set_work_too(self) -> None:
        self.accept(
            'for f in ("certorail/a.py", "certorail/b.py"):\n'
            '    certora.exec("grep", "x", FILES=[pathlib.Path(f)], cwd=pathlib.Path("."))\n'
        )
        self.accept(
            'for f in {"certorail/a.py"}:\n'
            '    certora.exec("grep", "x", FILES=[pathlib.Path(f)], cwd=pathlib.Path("."))\n'
        )


if __name__ == "__main__":
    unittest.main()
