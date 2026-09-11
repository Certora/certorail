"""URL facts: strings read as URLs (``UrlString``) -- claims about their urlsplit reading --
established by guards on ``urllib.parse.urlsplit(u).<component>`` and by exactly-known text.
"""
import ast
import unittest

from certorail.analysis import (
    ANY_NAME,
    Alternation,
    DirSplat,
    Exact,
    Named,
    StaticPath,
    StrFact,
    UrlString,
    url_of,
)
from certorail.guards import apply, recognize
from certorail.walker import analyze


def refine(fact, cond: str, name: str = "u"):
    """Mirror ``walker._refine``: apply the guards *cond* establishes, in source order."""
    out = {name: fact}
    for g in recognize(ast.parse(cond, mode="eval").body, out):
        refined = apply(out.get(g.subject), g.refinement)
        if refined is not None:
            out[g.subject] = refined
    return out[name]


def abs_path(*names: str) -> StaticPath:
    return StaticPath(tuple(Named(n) for n in names), absolute=True)


class TestUrlGuards(unittest.TestCase):
    def test_netloc_equality(self) -> None:
        got = refine(StrFact(), 'urllib.parse.urlsplit(u).netloc == "api.github.com"')
        self.assertEqual(got, UrlString(netloc=Exact("api.github.com")))

    def test_urlparse_netloc_is_also_trusted(self) -> None:
        got = refine(StrFact(), 'urllib.parse.urlparse(u).netloc == "api.github.com"')
        self.assertEqual(got, UrlString(netloc=Exact("api.github.com")))

    def test_conjuncts_accumulate(self) -> None:
        got = refine(
            StrFact(),
            'urllib.parse.urlsplit(u).scheme == "https"'
            ' and urllib.parse.urlsplit(u).netloc == "api.github.com"',
        )
        self.assertEqual(got, UrlString(netloc=Exact("api.github.com"), scheme="https"))

    def test_exact_path(self) -> None:
        got = refine(StrFact(), 'urllib.parse.urlsplit(u).path == "/v1/users"')
        self.assertEqual(got, UrlString(path=abs_path("v1", "users")))

    def test_urlparse_path_is_not_trusted(self) -> None:
        # urlparse shears ';params' off the last segment: its .path is weaker than urlsplit's
        got = refine(StrFact(), 'urllib.parse.urlparse(u).path == "/v1/users"')
        self.assertEqual(got, StrFact())

    def test_path_prefix_needs_dot_dot_excluded(self) -> None:
        cond = 'urllib.parse.urlsplit(u).path.startswith("/repos/")'
        # dot-segments not excluded: "/repos/../admin" passes the prefix test, so no claim
        self.assertEqual(refine(StrFact(), cond), StrFact())
        got = refine(StrFact(), f'".." not in u and {cond}')
        self.assertEqual(
            got, UrlString(path=DirSplat((Named("repos"),), None, absolute=True))
        )

    def test_netloc_alternation(self) -> None:
        got = refine(StrFact(), 'urllib.parse.urlsplit(u).netloc in ("a.com", "b.com")')
        self.assertEqual(
            got, UrlString(netloc=Alternation([Exact("a.com"), Exact("b.com")]))
        )

    def test_checks_survive_the_url_reading(self) -> None:
        got = refine(
            StrFact(checks=frozenset({"c"})), 'urllib.parse.urlsplit(u).netloc == "x"'
        )
        self.assertEqual(got, UrlString(netloc=Exact("x"), checks=frozenset({"c"})))

    def test_a_normalizing_view_says_nothing(self) -> None:
        # PurePath rewrites the text ("h://a" becomes "h:/a"): claims about the view are void
        got = refine(StrFact(), 'urllib.parse.urlsplit(str(pathlib.Path(u))).netloc == "x"')
        self.assertEqual(got, StrFact())


class TestUrlOf(unittest.TestCase):
    def test_exact_text_parses(self) -> None:
        fact = StrFact(regex=Exact("https://api.github.com/repos/certora?page=2"))
        self.assertEqual(
            url_of(fact),
            UrlString(
                netloc=Exact("api.github.com"),
                path=abs_path("repos", "certora"),
                scheme="https",
            ),
        )

    def test_dot_segments_have_no_path_claim(self) -> None:
        fact = StrFact(regex=Exact("https://h/a/../b"))
        self.assertEqual(
            url_of(fact), UrlString(netloc=Exact("h"), path=None, scheme="https")
        )

    def test_a_literal(self) -> None:
        self.assertEqual(
            url_of("http://localhost:8080/"),
            UrlString(
                netloc=Exact("localhost:8080"),
                path=StaticPath((), absolute=True),
                scheme="http",
            ),
        )

    def test_unknown_text_has_no_url_reading(self) -> None:
        self.assertIsNone(url_of(StrFact()))


class TestUrlContracts(unittest.TestCase):
    """certora.url(...) in contracts: URL facts crossing function boundaries."""

    RELY = (
        "import typing\n"
        "def fetch(u: typing.Annotated[str, certora.url("
        'scheme="https", netloc="api.github.com", path_within="/repos")]) -> None:\n'
        "    pass\n"
    )

    def test_a_literal_discharges_a_url_rely(self) -> None:
        report = analyze(self.RELY + 'fetch("https://api.github.com/repos/certora")\n')
        self.assertEqual(report.violations, [])

    def test_the_wrong_host_does_not(self) -> None:
        report = analyze(self.RELY + 'fetch("https://evil.com/repos/certora")\n')
        self.assertTrue(any("does not establish" in what for _, what in report.violations))

    def test_the_wrong_path_does_not(self) -> None:
        report = analyze(self.RELY + 'fetch("https://api.github.com/admin")\n')
        self.assertTrue(any("does not establish" in what for _, what in report.violations))

    def test_a_guarded_value_discharges(self) -> None:
        # conjunct order matters (guards apply in source order, no fixpoint): the text facts
        # -- the ".." exclusion and the gated path prefix -- must precede the scheme/netloc
        # guards, whose upgrade to the (textless) URL reading would strand them
        report = analyze(
            "import sys\n"
            "import urllib.parse\n"
            + self.RELY
            + "u = sys.argv[1]\n"
            + 'if ".." not in u and '
            'urllib.parse.urlsplit(u).path.startswith("/repos/") and '
            'urllib.parse.urlsplit(u).scheme == "https" and '
            'urllib.parse.urlsplit(u).netloc == "api.github.com":\n'
            "    fetch(u)\n"
        )
        self.assertEqual(report.violations, [])

    def test_a_guarantee_is_established_by_a_literal(self) -> None:
        source = (
            "import typing\n"
            "def endpoint() -> typing.Annotated[str, certora.url("
            'scheme="https", netloc="api.github.com")]:\n'
            '    return "https://api.github.com/graphql"\n'
        )
        self.assertEqual(analyze(source).violations, [])

    def test_a_guarantee_is_not_established_by_the_wrong_literal(self) -> None:
        source = (
            "import typing\n"
            "def endpoint() -> typing.Annotated[str, certora.url("
            'scheme="https", netloc="api.github.com")]:\n'
            '    return "https://evil.com/graphql"\n'
        )
        self.assertTrue(any("guarantee" in what for _, what in analyze(source).violations))


class TestUrllibCarveOut(unittest.TestCase):
    def test_urllib_parse_is_importable(self) -> None:
        self.assertEqual(analyze("import urllib.parse\n").violations, [])

    def test_the_rest_of_urllib_is_not(self) -> None:
        for src in ("import urllib\n", "import urllib.request\n"):
            with self.subTest(src=src):
                report = analyze(src)
                self.assertTrue(
                    any("forbidden module" in what for _, what in report.violations)
                )


if __name__ == "__main__":
    unittest.main()
