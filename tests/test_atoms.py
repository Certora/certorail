"""One atom domain (ATOMS.md): a fact carries a ``frozenset[AtomId | CheckId | SourceId]``, and
``Vocabulary.missing`` is the one answer to "does this value carry X" -- structure for the
built-ins, the regex for a defined atom, a literal checker for a checkable one, nothing for a
source. The dash guard is ``not-option`` asked that way; the annotation kinds are checked."""
import pathlib
import stat
import tempfile
import unittest

from certorail import markers
from certorail.analysis import (
    ANY_STR,
    DirSplat,
    Exact,
    Located,
    Named,
    PathFact,
    RegexLit,
    StaticPath,
    StrFact,
    entails,
    holds,
    may_start_with_dash,
)
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.ids import (
    BUILTIN_ATOMS,
    NO_PARENT_TRAVERSAL,
    NO_SLASH,
    NOT_ABSOLUTE,
    NOT_DOT_DOT,
    NOT_OPTION,
    CheckId,
    SourceId,
    spelled,
)
from certorail.policy import Policy, atom, constraint, hole, param, program, pure, validation
from certorail.walker import analyze

HEADER = "import pathlib\nimport sys\n"
REPO = 'repo = pathlib.Path("repos") / "x"\n'


class TestIds(unittest.TestCase):
    def test_the_kinds_are_strings_equal_by_name(self) -> None:
        self.assertEqual(CheckId("x"), "x")
        self.assertEqual(SourceId("x"), CheckId("x"))  # one namespace: the kind table decides
        self.assertIs(spelled("no-slash"), NO_SLASH)
        self.assertIsInstance(spelled("safe"), CheckId)
        self.assertIsInstance(spelled(SourceId("gh-api")), SourceId)  # a kinded id is kept

    def test_a_demand_is_met_by_name_whatever_the_label(self) -> None:
        # the Python API labels a bare name CheckId; a value carrying the source still meets it
        vocabulary = Policy.allow(programs=[program("gh", cwd=".", subcommand="api", source="gh-api")]).vocabulary()
        value = StrFact(atoms=frozenset({SourceId("gh-api")}))
        self.assertEqual(vocabulary.missing(value, frozenset({spelled("gh-api")})), frozenset())
        self.assertEqual(vocabulary.missing(value, frozenset({SourceId("gh-api")})), frozenset())
        self.assertEqual(vocabulary.missing("gh-api", frozenset({SourceId("gh-api")})), frozenset({"gh-api"}))
        self.assertEqual(set(BUILTIN_ATOMS), {"no-slash", "no-parent-traversal", "not-absolute", "not-dot-dot", "not-option"})


class TestHolds(unittest.TestCase):
    """The structural rules and the implication table."""

    def test_no_parent_traversal_implies_not_dot_dot(self) -> None:
        # the row that was missing: a string with no ".." part is not the string ".."
        self.assertTrue(holds(NOT_DOT_DOT, StrFact(atoms=frozenset({NO_PARENT_TRAVERSAL}))))
        self.assertTrue(holds(NOT_DOT_DOT, PathFact(atoms=frozenset({NO_PARENT_TRAVERSAL}))))
        self.assertFalse(holds(NOT_DOT_DOT, StrFact()))
        # and still the other way: no-slash and not-dot-dot give no-parent-traversal
        self.assertTrue(holds(NO_PARENT_TRAVERSAL, StrFact(atoms=frozenset({NO_SLASH, NOT_DOT_DOT}))))
        self.assertTrue(holds(NOT_ABSOLUTE, StrFact(atoms=frozenset({NO_SLASH}))))

    def test_not_option_from_text(self) -> None:
        self.assertTrue(holds(NOT_OPTION, StrFact(regex=Exact("main"))))
        self.assertFalse(holds(NOT_OPTION, StrFact(regex=Exact("-f"))))
        self.assertTrue(holds(NOT_OPTION, StrFact(regex=RegexLit(r"[a-z]+"))))
        self.assertFalse(holds(NOT_OPTION, StrFact(regex=RegexLit(r"[a-z-]+"))))
        self.assertFalse(holds(NOT_OPTION, StrFact(regex=ANY_STR)))
        self.assertTrue(holds(NOT_OPTION, StrFact(atoms=frozenset({NOT_OPTION}))))  # stated: a checker vouched
        self.assertFalse(holds(NOT_OPTION, PathFact()))

    def test_not_option_from_a_location(self) -> None:
        self.assertTrue(holds(NOT_OPTION, Located(StaticPath((Named("repos"),)), "str")))
        self.assertTrue(holds(NOT_OPTION, Located(StaticPath((), absolute=True), "str")))
        self.assertTrue(holds(NOT_OPTION, Located(StaticPath(()), "str")))  # "." itself
        self.assertFalse(holds(NOT_OPTION, Located(DirSplat((), None), "str")))  # first component unknown
        self.assertFalse(holds(NOT_OPTION, Located(StaticPath((Named("-rf"),)), "str")))
        # the path atoms are not derived of a located value: its text is not tracked
        self.assertFalse(holds(NO_SLASH, Located(StaticPath((Named("a"),)), "str")))

    def test_may_start_with_dash_is_the_negation(self) -> None:
        self.assertTrue(may_start_with_dash("-x"))
        self.assertFalse(may_start_with_dash("x"))
        self.assertTrue(may_start_with_dash(None))
        self.assertFalse(may_start_with_dash(Located(StaticPath((Named("repos"),)), "str")))

    def test_a_policy_atom_holds_only_as_stated(self) -> None:
        self.assertTrue(holds(CheckId("safe"), StrFact(atoms=frozenset({CheckId("safe")}))))
        self.assertFalse(holds(CheckId("safe"), StrFact(regex=Exact("anything"))))

    def test_entails_asks_holds(self) -> None:
        # a rely on not-dot-dot is met by a value known to have no parent traversal
        self.assertTrue(entails(StrFact(atoms=frozenset({NO_PARENT_TRAVERSAL})), StrFact(atoms=frozenset({NOT_DOT_DOT}))))
        # a rely on a check atom is met only when stated
        self.assertFalse(entails(StrFact(regex=Exact("x")), StrFact(atoms=frozenset({CheckId("safe")}))))


class TestMissing(unittest.TestCase):
    """``Vocabulary.missing``, per kind, with and without a discharger."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.config = pathlib.Path(tempfile.mkdtemp())
        checker = cls.config / "is-lower"
        checker.write_text('#!/bin/sh\ncase "$1" in *[!a-z]*) exit 1;; *) exit 0;; esac\n', encoding="utf-8")
        checker.chmod(checker.stat().st_mode | stat.S_IXUSR)
        cls.policy = Policy.allow(
            atoms=[atom("slug", markers.matches(r"[a-z-]+"))],
            validations=[
                validation("lower", argv=(str(checker), param("value")), params=("value",),
                           establishes={"value": [pure("lower")]}, writes=[]),
                validation("org-repo", argv=("true",), cwd=markers.within("repos"),
                           establishes={"cwd": ["org-checkout"]}),
            ],
            programs=[program("gh", cwd=".", subcommand="api", source="gh-api")],
        )
        cls.vocabulary = cls.policy.vocabulary()

    def missing(self, value, *names: str, discharge=None):
        return self.vocabulary.missing(value, frozenset(spelled(n) for n in names), discharge)

    def test_stated_atoms_are_carried_whatever_their_kind(self) -> None:
        fact = StrFact(atoms=frozenset({CheckId("org-checkout"), SourceId("gh-api"), NOT_OPTION}))
        self.assertEqual(self.missing(fact, "org-checkout", "gh-api", "not-option"), frozenset())

    def test_a_builtin_by_structure(self) -> None:
        self.assertEqual(self.missing("main", "not-option", "no-slash"), frozenset())
        self.assertEqual(self.missing("-f", "not-option"), frozenset({NOT_OPTION}))
        self.assertEqual(self.missing(Located(StaticPath((Named("repos"),)), "path"), "not-option"), frozenset())
        self.assertEqual(self.missing(StrFact(), "not-option"), frozenset({NOT_OPTION}))

    def test_a_defined_atom_by_its_regex(self) -> None:
        self.assertEqual(self.missing("feature-x", "slug"), frozenset())
        # a guard with the atom's own regex text (regex inclusion between different texts is
        # not reasoned about: a known gap of _regex_subsumes)
        self.assertEqual(self.missing(StrFact(regex=RegexLit("[a-z-]+")), "slug"), frozenset())
        self.assertEqual(self.missing("Feature", "slug"), frozenset({"slug"}))
        self.assertEqual(self.missing(StrFact(), "slug"), frozenset({"slug"}))

    def test_a_checkable_atom_needs_the_discharger(self) -> None:
        self.assertEqual(self.missing("abc", "lower"), frozenset({"lower"}))  # weaker, never wrong
        discharge = self.policy.discharger(self.config)
        self.assertEqual(self.missing("abc", "lower", discharge=discharge), frozenset())
        self.assertEqual(self.missing("ABC", "lower", discharge=discharge), frozenset({"lower"}))
        self.assertEqual(self.missing(StrFact(regex=RegexLit("[a-z]+")), "lower", discharge=discharge), frozenset({"lower"}))  # not exact text

    def test_an_environmental_atom_and_a_source_are_never_inferred(self) -> None:
        discharge = self.policy.discharger(self.config)
        self.assertEqual(self.missing("repos/x", "org-checkout", discharge=discharge), frozenset({"org-checkout"}))
        self.assertEqual(self.missing("main", "gh-api", discharge=discharge), frozenset({"gh-api"}))

    def test_an_unknown_value_lacks_everything(self) -> None:
        self.assertEqual(self.missing(None, "slug", "not-option"), frozenset({"slug", NOT_OPTION}))

    def test_what_a_string_can_decide(self) -> None:
        decidable = self.vocabulary.decidable_from_text()
        self.assertTrue(frozenset(BUILTIN_ATOMS.values()) <= decidable)
        self.assertIn("slug", decidable)
        self.assertIn("lower", decidable)
        self.assertNotIn("org-checkout", decidable)
        self.assertNotIn("gh-api", decidable)

    def test_the_kill_never_touches_a_builtin(self) -> None:
        # a value that carries not-option by a guard keeps it across an effectful call
        source = HEADER + REPO + (
            "b = sys.argv[1]\n"
            'assert not b.startswith("-")\n'
            'certora.exec("git", "log", cwd=repo)\n'
            'certora.exec("git", "push", "origin", b, cwd=repo)\n'
        )
        policy = Policy.allow(
            programs=[
                program("git", subcommand="log", cwd=markers.within("repos")),
                program("git", cwd=markers.within("repos"), argv=["git", "push", "origin", hole("B")],
                        holes={"B": __import__("certorail.templates", fromlist=["Token"]).Token(constraint(any=True))}),
            ],
        )
        outcome = host_check(source, "<t>", policy)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))


class TestGuardsEstablishNotOption(unittest.TestCase):
    POLICY = Policy.allow(
        programs=[program("ls", cwd=".", argv=["ls", hole("P")],
                          holes={"P": __import__("certorail.templates", fromlist=["Token"]).Token(constraint(any=True))})],
    )

    def outcome(self, guard: str):
        return host_check(HEADER + 'here = pathlib.Path(".")\np = sys.argv[1]\n' + guard + 'certora.exec("ls", p, cwd=here)\n', "<t>", self.POLICY)

    def test_the_recognised_shapes(self) -> None:
        for guard in (
            'assert not p.startswith("-")\n',
            'assert p[0] != "-"\n',
            'assert p[:1] != "-"\n',
            'assert re.fullmatch(r"[a-z]+", p)\n',
            "assert p.isalnum()\n",
        ):
            with self.subTest(guard=guard):
                outcome = host_check(
                    HEADER + "import re\n" + 'here = pathlib.Path(".")\np = sys.argv[1]\n' + guard + 'certora.exec("ls", p, cwd=here)\n',
                    "<t>", self.POLICY,
                )
                if isinstance(outcome, Rejected):
                    self.fail("\n".join(outcome.describe("<t>")))

    def test_without_a_guard_the_dash_guard_denies(self) -> None:
        outcome = self.outcome("")
        assert isinstance(outcome, Rejected)
        self.assertIn("lacks not-option", outcome.denials[0].reason)

    def test_the_annotation(self) -> None:
        source = HEADER + (
            "import typing\n"
            "def run(p: typing.Annotated[str, certora.not_option]) -> None:\n"
            '    certora.exec("ls", p, cwd=pathlib.Path("."))\n'
            'run("main")\n'
            "run(sys.argv[1])\n"
        )
        report = analyze(source, "<t>", self.POLICY.vocabulary())
        self.assertEqual(len(report.violations), 1)  # the argv value: not shown
        self.assertIn("run", report.violations[0][1])


class TestAnnotationKinds(unittest.TestCase):
    POLICY = Policy.allow(
        validations=[validation("safe", argv=("true",), params=("value",), establishes={"value": [pure("safe")]}, writes=[])],
        programs=[program("gh", cwd=".", subcommand="api", source="gh-api")],
    )

    def problems(self, annotation: str) -> list[str]:
        source = HEADER + f"import typing\ndef f(x: typing.Annotated[str, {annotation}]) -> None:\n    pass\n"
        return [what for _, what in analyze(source, "<t>", self.POLICY.vocabulary()).violations]

    def test_validated_may_not_name_a_source(self) -> None:
        (problem,) = self.problems('certora.validated("gh-api")')
        self.assertIn("is a source atom; spell it certora.source", problem)

    def test_source_names_a_source(self) -> None:
        self.assertEqual(self.problems('certora.source("gh-api")'), [])
        (problem,) = self.problems('certora.source("safe")')
        self.assertIn("no rule of the policy yields that source atom", problem)

    def test_validated_names_a_check(self) -> None:
        self.assertEqual(self.problems('certora.validated("safe")'), [])
        self.assertEqual(self.problems("certora.not_option"), [])


if __name__ == "__main__":
    unittest.main()
