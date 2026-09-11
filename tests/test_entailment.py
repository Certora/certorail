"""The rely/guarantee check: ``entails(actual, required)``.

Relies are written as annotation source and parsed with ``parse_annotation``; actuals are written
as expressions and interpreted with ``operand_value`` -- the same two routes the walker takes at a
call site. ``within("foo")`` etc. are the ``certora`` markers.
"""
import ast
import unittest

from certorail.analysis import (
    ANY_NAME,
    DirSplat,
    Located,
    Matching,
    Named,
    PathFact,
    RegexLit,
    StaticPath,
    StrFact,
    ValidationFact,
    entails,
    location_le,
    operand_value,
)
from certorail.annotations import parse_annotation

type State = dict[str, ValidationFact]


def rely(annotation: str) -> ValidationFact:
    fact = parse_annotation(ast.parse(annotation, mode="eval").body)
    assert isinstance(fact, (StrFact, PathFact, Located)), fact
    return fact


def value(src: str, st: State | None = None) -> str | ValidationFact | None:
    return operand_value(ast.parse(src, mode="eval").body, st if st is not None else {})


def static(*parts: str) -> StaticPath:
    return StaticPath(tuple(Named(p) for p in parts))


WITHIN_FOO_STR = 'typing.Annotated[str, certora.within("foo")]'
WITHIN_FOO_PATH = 'typing.Annotated[pathlib.Path, certora.within("foo")]'
TXT_UNDER_FOO_STR = r'typing.Annotated[str, certora.within("foo", leaf=certora.matches(r"\w+\.txt"))]'


class TestLiteralAgainstLocation(unittest.TestCase):
    def test_literal_below_the_prefix_is_within(self) -> None:
        for src in ('"foo/bar"', '"foo/bar/baz"', '"foo/bar.txt"', '"./foo/bar"', '"foo//bar"'):
            with self.subTest(src=src):
                self.assertTrue(entails(value(src), rely(WITHIN_FOO_STR)))

    def test_the_prefix_itself_is_within_when_the_leaf_is_unconstrained(self) -> None:
        self.assertTrue(entails(value('"foo"'), rely(WITHIN_FOO_STR)))

    def test_the_prefix_itself_is_not_within_a_constrained_leaf(self) -> None:
        self.assertFalse(entails(value('"foo"'), rely(TXT_UNDER_FOO_STR)))

    def test_leaf_constraint_is_checked_against_the_literal(self) -> None:
        self.assertTrue(entails(value('"foo/bar.txt"'), rely(TXT_UNDER_FOO_STR)))
        self.assertTrue(entails(value('"foo/sub/bar.txt"'), rely(TXT_UNDER_FOO_STR)))
        self.assertFalse(entails(value('"foo/bar.csv"'), rely(TXT_UNDER_FOO_STR)))

    def test_literal_outside_the_prefix_is_not_within(self) -> None:
        for src in ('"other/bar"', '"foobar/x"', '"/foo/bar"', '"../foo/bar"', '"foo/../etc"', '""'):
            with self.subTest(src=src):
                self.assertFalse(entails(value(src), rely(WITHIN_FOO_STR)))

    def test_exactly_requires_the_exact_path(self) -> None:
        exact = 'typing.Annotated[str, certora.exactly("foo/bar")]'
        self.assertTrue(entails(value('"foo/bar"'), rely(exact)))
        self.assertFalse(entails(value('"foo/bar/baz"'), rely(exact)))
        self.assertFalse(entails(value('"foo"'), rely(exact)))

    def test_exactly_with_a_choice_of_component(self) -> None:
        choice = 'typing.Annotated[str, certora.exactly("foo", certora.one_of("bar", "qux"))]'
        self.assertTrue(entails(value('"foo/bar"'), rely(choice)))
        self.assertTrue(entails(value('"foo/qux"'), rely(choice)))
        self.assertFalse(entails(value('"foo/zzz"'), rely(choice)))


class TestRepresentationMustAgree(unittest.TestCase):
    def test_a_str_literal_does_not_meet_a_path_rely(self) -> None:
        self.assertFalse(entails(value('"foo/bar"'), rely(WITHIN_FOO_PATH)))

    def test_a_constructed_path_meets_a_path_rely(self) -> None:
        self.assertTrue(entails(value('pathlib.Path("foo/bar")'), rely(WITHIN_FOO_PATH)))
        self.assertTrue(entails(value('pathlib.Path("foo") / "bar"'), rely(WITHIN_FOO_PATH)))

    def test_a_constructed_path_does_not_meet_a_str_rely(self) -> None:
        self.assertFalse(entails(value('pathlib.Path("foo/bar")'), rely(WITHIN_FOO_STR)))

    def test_str_of_a_path_meets_the_str_rely(self) -> None:
        self.assertTrue(entails(value('str(pathlib.Path("foo/bar"))'), rely(WITHIN_FOO_STR)))


class TestLocatedAgainstLocation(unittest.TestCase):
    def test_a_splat_below_the_prefix_is_within(self) -> None:
        # the reflexive form denotes its prefix; the strict form (an unconstrained leaf) does not
        self.assertTrue(location_le(static("foo"), DirSplat((Named("foo"),), None)))
        self.assertFalse(location_le(static("foo"), DirSplat((Named("foo"),), ANY_NAME)))
        self.assertTrue(location_le(static("foo", "x"), DirSplat((Named("foo"),), ANY_NAME)))
        self.assertTrue(location_le(DirSplat((Named("foo"),), ANY_NAME), DirSplat((Named("foo"),), None)))
        self.assertFalse(location_le(DirSplat((Named("foo"),), None), DirSplat((Named("foo"),), ANY_NAME)))
        deeper = Located(DirSplat((Named("foo"), Named("sub")), None), "path")
        self.assertTrue(entails(deeper, rely(WITHIN_FOO_PATH)))

    def test_a_splat_above_the_prefix_is_not_within(self) -> None:
        shallower = Located(DirSplat((Named("foo"),), None), "path")
        self.assertFalse(entails(shallower, rely('typing.Annotated[pathlib.Path, certora.within("foo/sub")]')))

    def test_an_unconstrained_leaf_does_not_meet_a_constrained_one(self) -> None:
        anything = Located(DirSplat((Named("foo"),), None), "str")
        self.assertFalse(entails(anything, rely(TXT_UNDER_FOO_STR)))

    def test_a_matching_component_meets_the_same_leaf_constraint(self) -> None:
        txt = Located(StaticPath((Named("foo"), Matching(RegexLit(r"\w+\.txt")))), "str")
        self.assertTrue(entails(txt, rely(TXT_UNDER_FOO_STR)))
        csv = Located(StaticPath((Named("foo"), Matching(RegexLit(r"\w+\.csv")))), "str")
        self.assertFalse(entails(csv, rely(TXT_UNDER_FOO_STR)))

    def test_a_splat_never_meets_an_exact_location(self) -> None:
        self.assertFalse(
            location_le(DirSplat((Named("foo"),), Named("bar")), static("foo", "bar"))
        )

    def test_a_variable_with_a_located_fact(self) -> None:
        st: State = {"p": Located(static("foo", "bar"), "path")}
        self.assertTrue(entails(value("p", st), rely(WITHIN_FOO_PATH)))
        self.assertTrue(entails(value('p / "baz"', st), rely(WITHIN_FOO_PATH)))


class TestTextRelies(unittest.TestCase):
    def test_literal_against_atoms(self) -> None:
        no_slash = "typing.Annotated[str, certora.no_slash]"
        self.assertTrue(entails(value('"abc"'), rely(no_slash)))
        self.assertFalse(entails(value('"a/b"'), rely(no_slash)))

    def test_literal_against_regex(self) -> None:
        txt = r'typing.Annotated[str, certora.matches(r"\w+\.txt")]'
        self.assertTrue(entails(value('"abc.txt"'), rely(txt)))
        self.assertFalse(entails(value('"abc.csv"'), rely(txt)))

    def test_validated_string_against_atoms(self) -> None:
        both = "typing.Annotated[str, certora.no_slash, certora.no_parent_traversal]"
        self.assertTrue(entails(StrFact(atoms=frozenset({"no-slash", "no-parent-traversal"})), rely(both)))
        self.assertTrue(entails(StrFact(atoms=frozenset({"no-slash", "not-dot-dot"})), rely(both)))  # derived
        self.assertFalse(entails(StrFact(atoms=frozenset({"no-slash"})), rely(both)))

    def test_validated_string_does_not_meet_a_regex_it_was_not_checked_against(self) -> None:
        txt = r'typing.Annotated[str, certora.matches(r"\w+\.txt")]'
        self.assertFalse(entails(StrFact(atoms=frozenset({"no-slash"})), rely(txt)))

    def test_located_str_meets_only_an_unconstrained_text_rely(self) -> None:
        located = Located(static("foo", "bar"), "str")
        self.assertTrue(entails(located, rely("str")))
        self.assertFalse(entails(located, rely("typing.Annotated[str, certora.no_slash]")))


class TestTypeRelies(unittest.TestCase):
    def test_plain_path(self) -> None:
        self.assertTrue(entails(PathFact(), rely("pathlib.Path")))
        self.assertTrue(entails(Located(static("foo"), "path"), rely("pathlib.Path")))
        self.assertFalse(entails(value('"foo"'), rely("pathlib.Path")))

    def test_path_atoms(self) -> None:
        relative = "typing.Annotated[pathlib.Path, certora.not_absolute]"
        self.assertTrue(entails(PathFact(atoms=frozenset({"not-absolute"})), rely(relative)))
        self.assertFalse(entails(PathFact(), rely(relative)))
        self.assertFalse(entails(Located(static("foo"), "path"), rely(relative)))  # nothing lexical is tracked

    def test_unknown_establishes_nothing(self) -> None:
        for annotation in ("str", "pathlib.Path", WITHIN_FOO_STR):
            with self.subTest(annotation=annotation):
                self.assertFalse(entails(None, rely(annotation)))


if __name__ == "__main__":
    unittest.main()
