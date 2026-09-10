"""``certora.pathmatch(text, "<location>")``: the policy's location spelling as a guard -- the
same grammar (``locspec``) read by the loader, the analysis and the runtime."""
import ast
import unittest

from certorail import locspec, markers
from certorail.analysis import (
    ANY_NAME,
    DirSplat,
    Located,
    Matching,
    Named,
    RegexLit,
    StaticPath,
    StrFact,
    UrlString,
)
from certorail.guards import apply, recognize
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.locations import parse_location
from certorail.policy import Policy, network
from certorail.walker import analyze


def refine(fact, cond: str, name: str = "u"):
    out = {name: fact}
    for g in recognize(ast.parse(cond, mode="eval").body, out):
        refined = apply(out.get(g.subject), g.refinement)
        if refined is not None:
            out[g.subject] = refined
    return out[name]


class TestRuntimeMatcher(unittest.TestCase):
    def test_matches(self) -> None:
        cases = [
            ("repos/**", "repos/a/b", True),
            ("repos/**", "repos", True),
            ("repos/**", "./repos/a", True),
            ("repos/**", "data/x", False),
            ("repos/**", "/repos/a", False),          # anchors must agree
            ("/repos/**", "repos/a", False),
            ("repos/**", "repos/../etc/passwd", False),
            (r"repos/**/<\w+\.json>", "repos/a/x.json", True),
            (r"repos/**/<\w+\.json>", "repos/x.json", True),
            (r"repos/**/<\w+\.json>", "repos", False),
            (r"repos/**/<\w+\.json>", "repos/a/x.txt", False),
            ("repos/*/foundry.toml", "repos/a/foundry.toml", True),
            ("repos/*/foundry.toml", "repos/a/b/foundry.toml", False),
            (r"/repos/*/*/issues/<\d+>/comments", "/repos/o/r/issues/12/comments", True),
            (r"/repos/*/*/issues/<\d+>/comments", "/repos/o/r/issues/x/comments", False),
            ("{a,b}/x", "b/x", True),
            ("{a,b}/x", "c/x", False),
            (".", ".", True),
            (".", "", True),
            ("**", "anything/at/all", True),
            ("/", "/", True),
        ]
        for spec, text, expected in cases:
            with self.subTest(spec=spec, text=text):
                self.assertIs(markers.pathmatch(text, spec), expected)

    def test_arguments(self) -> None:
        with self.assertRaises(TypeError):
            markers.pathmatch(3, "repos/**")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            markers.pathmatch("x", "a/**/b/**")

    def test_one_grammar(self) -> None:
        # the loader's LocationFact and the runtime's Spec come from the same parse
        self.assertEqual(
            parse_location(r"/repos/*/*/issues/<\d+>/comments"),
            StaticPath(
                (Named("repos"), ANY_NAME, ANY_NAME, Named("issues"), Matching(RegexLit(r"\d+")), Named("comments")),
                absolute=True,
            ),
        )
        self.assertEqual(
            locspec.parse("repos/**/<x>"),
            locspec.Spec((locspec.Lit("repos"),), splat=True, leaf=locspec.Regex("x")),
        )


class TestGuard(unittest.TestCase):
    def test_a_filesystem_location(self) -> None:
        got = refine(StrFact(), 'certora.pathmatch(u, "repos/*/foundry.toml")')
        self.assertEqual(
            got, Located(StaticPath((Named("repos"), ANY_NAME, Named("foundry.toml"))), "str")
        )
        got = refine(StrFact(), 'certora.pathmatch(u, "repos/**")')
        self.assertEqual(got, Located(DirSplat((Named("repos"),), None), "str"))

    def test_a_url_path(self) -> None:
        got = refine(
            StrFact(),
            'certora.pathmatch(urllib.parse.urlsplit(u).path, r"/repos/*/*/issues/<\\d+>/comments")',
        )
        self.assertEqual(
            got,
            UrlString(
                path=StaticPath(
                    (Named("repos"), ANY_NAME, ANY_NAME, Named("issues"), Matching(RegexLit(r"\d+")), Named("comments")),
                    absolute=True,
                )
            ),
        )

    def test_what_establishes_nothing(self) -> None:
        for cond in (
            'certora.pathmatch(urllib.parse.urlsplit(u).path, "repos/**")',   # a URL path is absolute
            'certora.pathmatch(urllib.parse.urlparse(u).path, "/repos/**")',  # urlparse's path is not trusted
            'certora.pathmatch(u, "a/**/b/**")',                              # malformed
            'not certora.pathmatch(u, "repos/**")',                           # the negative says nothing
            'certora.pathmatch(os.path.normpath(u), "repos/**")',             # a collapsing view
        ):
            with self.subTest(cond=cond):
                self.assertEqual(refine(StrFact(), cond), StrFact())

    def test_through_a_str_view(self) -> None:
        # pathlib values are matched through str(p); the containment lands on p
        got = refine(StrFact(), 'certora.pathmatch(str(u), "repos/**")')
        self.assertEqual(got, Located(DirSplat((Named("repos"),), None), "str"))


# NB: the Python API reads a plain string as a literal path ("*" would be a directory named "*");
# the micro-syntax is the loader's, so spell these through parse_location / the markers
NET = Policy.allow(
    network=[
        network(
            "api.github.com", methods=["GET"],
            path=parse_location(r"/repos/*/*/issues/<\d+>/comments"),
        )
    ],
)
FS = Policy.allow(read=[markers.within("repos")], listing=[markers.within("repos")])
HEADER = "import os\nimport pathlib\nimport sys\nimport urllib.parse\n"


class TestEndToEnd(unittest.TestCase):
    def test_a_dynamic_url_proves_the_policy_path(self) -> None:
        source = HEADER + (
            "url = sys.argv[1]\n"
            'if (urllib.parse.urlsplit(url).scheme == "https" and urllib.parse.urlsplit(url).netloc == "api.github.com"\n'
            '        and certora.pathmatch(urllib.parse.urlsplit(url).path, r"/repos/*/*/issues/<\\d+>/comments")):\n'
            "    certora.network.get(url)\n"
        )
        outcome = host_check(source, "<t>", NET)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))
        without = host_check(source.replace(
            '\n        and certora.pathmatch(urllib.parse.urlsplit(url).path, r"/repos/*/*/issues/<\\d+>/comments")', ""
        ), "<t>", NET)
        assert isinstance(without, Rejected)
        self.assertIn("path is not proven", without.denials[0].reason)

    def test_a_dynamic_file_path(self) -> None:
        source = HEADER + (
            "p = sys.argv[1]\n"
            'assert certora.pathmatch(p, "repos/*/foundry.toml")\n'
            "with open(p) as f:\n"
            "    body = f.read()\n"
        )
        self.assertIsInstance(host_check(source, "<t>", FS), Accepted)
        too_wide = host_check(source.replace('"repos/*/foundry.toml"', '"**"'), "<t>", FS)
        assert isinstance(too_wide, Rejected)
        self.assertIn("not permitted", too_wide.denials[0].reason)

    def test_shape_violations(self) -> None:
        cases = {
            'p = sys.argv[1]\nspec = sys.argv[2]\nassert certora.pathmatch(p, spec)\n': "string literal",
            'p = sys.argv[1]\nassert certora.pathmatch(p, "a/**/b/**")\n': "'**' may appear once",
            'p = sys.argv[1]\nassert certora.pathmatch(p, "repos/**", 1)\n': "exactly two",
        }
        for body, expected in cases.items():
            with self.subTest(expected=expected):
                got = [what for _, what in analyze(HEADER + body).violations]
                self.assertTrue(any(expected in v for v in got), got)


if __name__ == "__main__":
    unittest.main()
