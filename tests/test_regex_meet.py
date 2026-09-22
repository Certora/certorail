"""The meet of the string domain (``analysis.both`` / ``Both``): two readings of one value's text
-- the shape an f-string gave it and the regex a ``re.fullmatch`` guard asserted -- are kept
together, so a regex guarantee, a regex-leaf location or a defined atom can be discharged on a
value the analysis already knew something about."""
import ast
import unittest

from certorail import markers
from certorail.analysis import (
    ANY_STR,
    Alternation,
    Both,
    Exact,
    RegexLit,
    StrFact,
    _regex_subsumes,
    alternation,
    both,
    concat,
    pretty_regex,
)
from certorail.guards import apply, recognize
from certorail.host import Rejected
from certorail.host import check as host_check
from certorail.policy import Policy, atom, constraint, hole, program
from certorail.templates import Token
from certorail.walker import analyze

A, B, C = RegexLit("a"), RegexLit("b"), RegexLit("c")
DOT_MD = concat(ANY_STR, Exact(".md"))  # the shape of f"{slug}.md"
WORD_MD = RegexLit(r"\w+\.md")


def refine(fact, cond: str, name: str = "u"):
    """Mirror ``walker._refine``: apply the guards *cond* establishes, in source order."""
    out = {name: fact}
    for g in recognize(ast.parse(cond, mode="eval").body, out):
        refined = apply(out.get(g.subject), g.refinement)
        if refined is not None:
            out[g.subject] = refined
    return out[name]


class TestBoth(unittest.TestCase):
    def test_flattens_dedupes_and_drops_the_wildcard(self) -> None:
        got = both(ANY_STR, A, both(B, A))
        self.assertIsInstance(got, Both)
        assert isinstance(got, Both)
        self.assertEqual(len(got.all_of), 2)
        self.assertEqual(got, both(A, B))

    def test_is_canonical_in_order(self) -> None:
        self.assertEqual(both(A, B), both(B, A))

    def test_a_single_survivor_is_itself(self) -> None:
        self.assertEqual(both(ANY_STR, A), A)
        self.assertEqual(both(ANY_STR, ANY_STR), ANY_STR)

    def test_finite_parts_intersect_exactly(self) -> None:
        abc = alternation(Exact("a"), Exact("b"), Exact("c"))
        bcd = alternation(Exact("b"), Exact("c"), Exact("d"))
        self.assertEqual(both(abc, bcd), Alternation([Exact("b"), Exact("c")]))
        # against an infinite part: the survivors are the strings it accepts
        self.assertEqual(both(abc, RegexLit("[ab]")), Alternation([Exact("a"), Exact("b")]))

    def test_an_exact_absorbs(self) -> None:
        self.assertEqual(both(DOT_MD, Exact("x.md")), Exact("x.md"))

    def test_a_dead_path_keeps_the_finite_part(self) -> None:
        # x == "abc" and re.fullmatch(r"\d+", x): the fall-through is unreachable, the claim vacuous
        self.assertEqual(both(Exact("abc"), RegexLit(r"\d+")), Exact("abc"))

    def test_pretty(self) -> None:
        self.assertEqual(pretty_regex(both(A, B)), "(/a/&/b/)")


class TestSubsumption(unittest.TestCase):
    def test_a_conjunct_suffices_on_the_specific_side(self) -> None:
        self.assertTrue(_regex_subsumes(WORD_MD, both(DOT_MD, WORD_MD)))
        self.assertTrue(_regex_subsumes(DOT_MD, both(DOT_MD, WORD_MD)))
        self.assertFalse(_regex_subsumes(C, both(A, B)))

    def test_every_conjunct_is_needed_on_the_general_side(self) -> None:
        self.assertTrue(_regex_subsumes(both(A, B), both(A, B, C)))  # extra conjuncts narrow
        self.assertFalse(_regex_subsumes(both(A, B, C), both(A, B)))
        self.assertTrue(_regex_subsumes(both(B, A), both(A, B)))

    def test_a_general_conjunction_accepts_by_every_part(self) -> None:
        g = both(RegexLit("[ab]"), RegexLit("[bc]"))
        self.assertTrue(_regex_subsumes(g, Exact("b")))
        self.assertFalse(_regex_subsumes(g, Exact("a")))


class TestGuardMeet(unittest.TestCase):
    def test_a_fullmatch_guard_survives_an_fstring_shape(self) -> None:
        got = refine(StrFact(regex=DOT_MD), 're.fullmatch(r"\\w+\\.md", u)')
        assert isinstance(got, StrFact)
        self.assertTrue(_regex_subsumes(WORD_MD, got.regex))
        self.assertTrue(_regex_subsumes(DOT_MD, got.regex))

    def test_an_equality_guard_still_pins_the_text(self) -> None:
        got = refine(StrFact(regex=DOT_MD), 'u == "x.md"')
        self.assertEqual(got, StrFact(regex=Exact("x.md")))

    def test_membership_guards_intersect(self) -> None:
        got = refine(StrFact(regex=alternation(Exact("a"), Exact("b"))), 'u in ("b", "c")')
        self.assertEqual(got, StrFact(regex=Exact("b")))


HEADER = "import pathlib\nimport re\nimport typing\n"

REPORT_NAME = (
    "def report_name(slug: str) -> typing.Annotated["
    'str, certora.matches(r"\\w+\\.md"), certora.no_slash, certora.not_dot_dot]:\n'
    '    fname = f"{slug}.md"\n'
    '    assert re.fullmatch(r"\\w+\\.md", fname) and "/" not in fname and fname not in (".", "..")\n'
    "    return fname\n"
)

REPORTS_POLICY = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within("reports", leaf=markers.matches(r"\w+\.md"))],
)


class TestEndToEnd(unittest.TestCase):
    def test_a_regex_guarantee_on_a_built_name(self) -> None:
        self.assertEqual(analyze(HEADER + REPORT_NAME).violations, [])

    def test_the_guard_is_still_required(self) -> None:
        source = HEADER + REPORT_NAME.replace('re.fullmatch(r"\\w+\\.md", fname) and ', "")
        self.assertTrue(any("guarantee" in what for _, what in analyze(source).violations))

    def test_a_regex_leaf_write_is_permitted(self) -> None:
        source = HEADER + REPORT_NAME + (
            'fname = report_name("x")\n'
            '(pathlib.Path("reports") / fname).write_text("ok")\n'
        )
        outcome = host_check(source, "<t>", REPORTS_POLICY)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_a_defined_atom_guard_on_a_built_value(self) -> None:
        policy = Policy.allow(
            read=[markers.within(".")],
            write=[markers.within(".")],
            atoms=[atom("no-flag", markers.matches(r"[^-].*"))],
            programs=[
                program(
                    "git",
                    cwd=markers.within("repos"),
                    argv=["git", "push", "origin", hole("BRANCH")],
                    holes={"BRANCH": Token(constraint(atoms=["no-flag"]))},
                )
            ],
        )
        source = HEADER + (
            "import sys\n"
            'branch = f"release-{sys.argv[1]}"\n'
            'assert re.fullmatch(r"[^-].*", branch)\n'
            'certora.exec("git", "push", "origin", branch, cwd=pathlib.Path("repos") / "x")\n'
        )
        outcome = host_check(source, "<t>", policy)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))


if __name__ == "__main__":
    unittest.main()
