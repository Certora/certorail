"""Absolute locations: a leading "/" anchors a location at the *filesystem* root instead of the
sandbox root. The two anchors never relate -- no relative location lies within an absolute one or
vice versa, even when the sandbox root itself sits under the absolute prefix -- so an absolute
allowance in a policy says nothing about sandbox-relative paths and vice versa.
"""
import ast
import unittest

from certorail import markers
from certorail.analysis import (
    ANY_COMPONENT,
    ANY_NAME,
    PATH_ATOMS,
    Alternation,
    DirSplat,
    Exact,
    Located,
    Named,
    StaticPath,
    StrFact,
    interpret_expr,
    known_text,
    locate,
    location_le,
    pretty_location,
)
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.ids import NO_PARENT_TRAVERSAL, NO_SLASH
from certorail.policy import Policy, location_of, program
from certorail.policyfile import parse_location


def evaluate(src: str, st: dict | None = None):
    return interpret_expr(ast.parse(src, mode="eval").body, st if st is not None else {})


def rel(*names: str) -> StaticPath:
    return StaticPath(tuple(Named(n) for n in names))


def absolute(*names: str) -> StaticPath:
    return StaticPath(tuple(Named(n) for n in names), absolute=True)


class TestAnchorSeparation(unittest.TestCase):
    def test_anchors_never_relate(self) -> None:
        under_abs = DirSplat((Named("repos"),), None, absolute=True)
        under_rel = DirSplat((Named("repos"),), None)
        self.assertFalse(location_le(rel("repos", "x"), under_abs))
        self.assertFalse(location_le(absolute("repos", "x"), under_rel))

    def test_absolute_within_absolute(self) -> None:
        under = DirSplat((Named("srv"), Named("work")), None, absolute=True)
        self.assertTrue(location_le(absolute("srv", "work", "x"), under))
        self.assertFalse(location_le(absolute("srv", "other", "x"), under))


class TestRendering(unittest.TestCase):
    def test_known_text(self) -> None:
        self.assertEqual(known_text(Located(absolute("a", "b"), "path")), "/a/b")
        self.assertEqual(known_text(Located(StaticPath((), absolute=True), "path")), "/")

    def test_pretty_location_round_trips_through_parse(self) -> None:
        for spelling in (".", "/", "/a/b", "/srv/work/**", "/a/{b,c}", "repos/**"):
            with self.subTest(spelling=spelling):
                self.assertEqual(pretty_location(parse_location(spelling)), spelling)

    def test_parse_rejects_malformed_absolute(self) -> None:
        for bad in ("//a", "/.."):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_location(bad)


class TestPythonSpelling(unittest.TestCase):
    def test_literal_string_location(self) -> None:
        self.assertEqual(location_of("/srv/work/x"), absolute("srv", "work", "x"))

    def test_within_absolute_prefix(self) -> None:
        self.assertEqual(
            location_of(markers.within("/srv/work")),
            DirSplat((Named("srv"), Named("work")), None, absolute=True),
        )

    def test_traversal_in_an_absolute_prefix_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            location_of(markers.within("/srv/../etc"))


class TestTransfer(unittest.TestCase):
    def test_absolute_literal_is_located(self) -> None:
        self.assertEqual(
            evaluate('pathlib.Path("/opt/data")'), Located(absolute("opt", "data"), "path")
        )

    def test_join_stays_absolute(self) -> None:
        st = {"base": Located(absolute("opt", "data"), "path")}
        self.assertEqual(evaluate('base / "x"', st), Located(absolute("opt", "data", "x"), "path"))

    def test_absolute_right_operand_wins(self) -> None:
        # pathlib: joining onto an absolute path discards the left side
        st = {"p": Located(rel("a"), "path"), "q": Located(absolute("etc"), "path")}
        self.assertEqual(evaluate("p / q", st), Located(absolute("etc"), "path"))

    def test_literal_concatenation_locates_absolutely(self) -> None:
        got = evaluate('"/etc/" + "passwd"')
        self.assertEqual(got, StrFact(regex=Exact("/etc/passwd")))
        self.assertEqual(locate(got), Located(absolute("etc", "passwd"), "str"))

    def test_leading_slash_spelling_is_absolute(self) -> None:
        name = StrFact(regex=ANY_COMPONENT, atoms=PATH_ATOMS)  # one listed name: never "" or "."
        self.assertEqual(
            evaluate('f"/var/data/{name}"', {"name": name}),
            Located(StaticPath((Named("var"), Named("data"), ANY_NAME), absolute=True), "str"),
        )

    def test_empty_text_before_a_leading_slash_stays_absolute(self) -> None:
        # "" names nothing, so "" + "/srv/x" is the absolute /srv/x -- not srv/x under the root
        empty = {"e": StrFact(regex=Exact(""))}
        self.assertEqual(evaluate('e + "/srv/x"', empty), Located(absolute("srv", "x"), "str"))
        self.assertEqual(evaluate('f"{e}/srv/x"', empty), Located(absolute("srv", "x"), "str"))
        # a value that may be "" has no single reading: no location, and not "not-absolute"
        maybe = {"e": StrFact(regex=Alternation([Exact(""), Exact("docs")]))}
        got = evaluate('e + "/srv/x"', maybe)
        self.assertIsNone(locate(got))
        assert isinstance(got, StrFact)
        self.assertNotIn("not-absolute", got)
        # a name that may be "" joined onto a leading "/" is no component either
        loose = {"n": StrFact(atoms=frozenset({NO_SLASH, NO_PARENT_TRAVERSAL}))}
        self.assertIsNone(locate(evaluate('n + "/srv/x"', loose)))

    def test_absolute_path_replayed_in_an_f_string(self) -> None:
        st = {"base": Located(absolute("opt", "data"), "path")}
        self.assertEqual(evaluate('f"{base}/x"', st), Located(absolute("opt", "data", "x"), "str"))

    def test_absolute_replayed_mid_string_is_just_text(self) -> None:
        # "x" + "/opt/data" spells the *relative* path "x/opt/data"
        st = {"base": Located(absolute("opt", "data"), "path")}
        self.assertEqual(evaluate('f"x{base}"', st), Located(rel("x", "opt", "data"), "str"))


HEADER = "import pathlib\n"

ABS_POLICY = Policy.allow(
    read=[markers.within("/opt/data")],
    programs=[program("git", subcommand="log", cwd=markers.within("/opt/repos"))],
)


class TestPolicyEnforcement(unittest.TestCase):
    def accept(self, body: str) -> None:
        outcome = host_check(HEADER + body, "<t>", ABS_POLICY)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def denials(self, body: str) -> list[str]:
        outcome = host_check(HEADER + body, "<t>", ABS_POLICY)
        assert isinstance(outcome, Rejected), "expected a rejection"
        return [d.reason for d in outcome.denials]

    def test_absolute_read_within_the_allowance(self) -> None:
        self.accept('print(pathlib.Path("/opt/data/x.txt").read_text())\n')

    def test_absolute_read_outside_is_denied(self) -> None:
        reasons = self.denials('print(pathlib.Path("/etc/passwd").read_text())\n')
        self.assertTrue(any("read of /etc/passwd is not permitted" in r for r in reasons))

    def test_relative_reads_are_not_covered_by_an_absolute_allowance(self) -> None:
        reasons = self.denials('print(pathlib.Path("data/x.txt").read_text())\n')
        self.assertTrue(any("is not permitted" in r for r in reasons))

    def test_exec_with_an_absolute_cwd(self) -> None:
        self.accept('certora.exec("git", "log", cwd=pathlib.Path("/opt/repos/proj"))\n')

    def test_exec_cwd_anchors_do_not_mix(self) -> None:
        reasons = self.denials('certora.exec("git", "log", cwd=pathlib.Path("repos"))\n')
        self.assertTrue(any("not within" in r for r in reasons))


if __name__ == "__main__":
    unittest.main()
