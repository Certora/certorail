"""Source provenance (PROVENANCE.md): source atoms yielded by rules, bound to handles, established
only by the extractors, dying at the first derivation, consumed as any atom."""
import io
import unittest

from certorail import jqpath, markers
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.markers import ExecResult, ExtractError, NetworkResponse
from certorail.policy import (
    Policy,
    atom,
    constraint,
    hole,
    network,
    program,
    source,
    validation,
)
from certorail.policyfile import PolicyFileError, from_data
from certorail.templates import Token, may_start_with_dash
from certorail.analysis import RegexLit, StrFact
from certorail.walker import analyze

HEADER = "import pathlib\nimport re\nimport sys\nimport typing\n"
REPOS = markers.within("repos")

POLICY = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within(".")],
    listing=[markers.within(".")],
    network=[network("api.github.com", methods=["GET"], source="gh-api")],
    programs=[
        program(
            "git", cwd=REPOS, argv=["git", "branch", "--format=%(refname:short)"], holes={},
            source="git-branches",
        ),
        program(
            "git", cwd=REPOS, argv=["git", "push", "origin", hole("BRANCH")],
            holes={"BRANCH": Token(constraint(atoms=["gh-api"]))},
        ),
        program(
            "git", cwd=REPOS, argv=["git", "checkout", hole("BRANCH")],
            holes={"BRANCH": Token(constraint(atoms=["git-branches"]))},
        ),
        program(
            "cat", cwd=".", argv=["cat", hole("NAME")],
            holes={"NAME": Token(constraint(atoms=["approved"]))},
        ),
    ],
    sources=[source("approved", "platform/approved.json")],
)

SETUP = HEADER + 'repo = pathlib.Path("repos") / "x"\nhere = pathlib.Path(".")\n'
GET = 'resp = certora.network.get("https://api.github.com/repos/certora/x/branches")\n'
GUARD = 'assert re.fullmatch(r"[^-].*", b)\n'


class Base(unittest.TestCase):
    def accept(self, body: str) -> Accepted:
        result = host_check(SETUP + body, "<t>", POLICY)
        if isinstance(result, Rejected):
            self.fail("\n".join(result.describe("<t>")))
        return result

    def denial(self, body: str) -> str:
        result = host_check(SETUP + body, "<t>", POLICY)
        assert isinstance(result, Rejected), "expected a rejection"
        self.assertEqual(result.violations, [], result.describe("<t>"))
        return "; ".join(d.reason for d in result.denials)

    def violations(self, body: str) -> list[str]:
        return [what for _, what in analyze(SETUP + body, vocabulary=POLICY.vocabulary()).violations]


class TestExtraction(Base):
    def test_an_extracted_value_reaches_the_hole(self) -> None:
        self.accept(GET + 'b = certora.extract(resp, ".[0].name")\n' + GUARD
                    + 'certora.exec("git", "push", "origin", b, cwd=repo)\n')

    def test_a_literal_has_no_provenance(self) -> None:
        self.assertIn(
            "not validated by: gh-api",
            self.denial('certora.exec("git", "push", "origin", "feature", cwd=repo)\n'),
        )

    def test_a_derivation_drops_it(self) -> None:
        self.assertIn(
            "not validated by: gh-api",
            self.denial(GET + 'b0 = certora.extract(resp, ".[0].name")\nb = b0.strip()\n' + GUARD
                        + 'certora.exec("git", "push", "origin", b, cwd=repo)\n'),
        )

    def test_effects_do_not(self) -> None:
        self.accept(
            GET + 'b = certora.extract(resp, ".[0].name")\n'
            + 'certora.exec("git", "branch", "--format=%(refname:short)", cwd=repo)\n'  # effectful
            + GUARD + 'certora.exec("git", "push", "origin", b, cwd=repo)\n'
        )

    def test_the_wrong_source_is_not_the_right_one(self) -> None:
        self.assertIn(
            "not validated by: gh-api",
            self.denial(
                'listing = certora.exec("git", "branch", "--format=%(refname:short)", cwd=repo)\n'
                'local: list[typing.Annotated[str, certora.validated("git-branches")]] = certora.lines(listing)\n'
                "for b in local:\n    " + GUARD + '    certora.exec("git", "push", "origin", b, cwd=repo)\n'
            ),
        )

    def test_a_handle_used_inline(self) -> None:
        self.accept(
            'b = certora.extract(certora.network.get("https://api.github.com/x"), ".name")\n' + GUARD
            + 'certora.exec("git", "push", "origin", b, cwd=repo)\n'
        )


class TestContainers(Base):
    def test_extract_all_constructs_and_the_loop_consumes(self) -> None:
        self.accept(
            GET
            + 'branches: list[typing.Annotated[str, certora.validated("gh-api")]] = certora.extract_all(resp, ".[].name")\n'
            + "for b in branches:\n    " + GUARD + '    certora.exec("git", "push", "origin", b, cwd=repo)\n'
        )

    def test_lines_from_an_exec(self) -> None:
        self.accept(
            'listing = certora.exec("git", "branch", "--format=%(refname:short)", cwd=repo)\n'
            'local: list[typing.Annotated[str, certora.validated("git-branches")]] = certora.lines(listing)\n'
            "for b in local:\n    " + GUARD + '    certora.exec("git", "checkout", b, cwd=repo)\n'
        )

    def test_the_annotation_must_match_the_source(self) -> None:
        got = self.violations(
            GET + 'xs: list[typing.Annotated[str, certora.validated("git-branches")]] = certora.extract_all(resp, ".[].name")\n'
        )
        self.assertTrue(any("extracted elements do not establish" in v for v in got))


class TestFileSources(Base):
    def test_for_line_in_f_under_a_source(self) -> None:
        self.accept(
            'with open("platform/approved.json") as f:\n'
            "    for line in f:\n"
            '        assert re.fullmatch(r"[^-].*", line)\n'
            '        certora.exec("cat", line, cwd=here)\n'
        )

    def test_read_text_then_extract(self) -> None:
        self.accept(
            'text = pathlib.Path("platform/approved.json").read_text()\n'
            'b = certora.extract(text, ".packages[0]")\n'
            'assert re.fullmatch(r"[^-].*", b)\n'
            'certora.exec("cat", b, cwd=here)\n'
        )

    def test_a_read_outside_the_source_yields_nothing(self) -> None:
        self.assertIn(
            "not validated by: approved",
            self.denial(
                'text = pathlib.Path("notes.json").read_text()\n'
                'b = certora.extract(text, ".x")\n'
                'assert re.fullmatch(r"[^-].*", b)\n'
                'certora.exec("cat", b, cwd=here)\n'
            ),
        )

    def test_readlines_and_field(self) -> None:
        self.accept(
            'with open("platform/approved.json") as f:\n'
            '    rows: list[typing.Annotated[str, certora.validated("approved")]] = f.readlines()\n'
            "for row in rows:\n"
            '    b = certora.field(row, 0, sep=",")\n'
            '    assert re.fullmatch(r"[^-].*", b)\n'
            '    certora.exec("cat", b, cwd=here)\n'
        )

    def test_f_read_is_the_handle_too(self) -> None:
        self.accept(
            'with open("platform/approved.json") as f:\n'
            "    text = f.read()\n"
            'b = certora.extract(text, ".packages[0]")\n'
            'assert re.fullmatch(r"[^-].*", b)\n'
            'certora.exec("cat", b, cwd=here)\n'
        )


class TestShape(Base):
    def test_extractor_violations(self) -> None:
        cases = {
            GET + "p = sys.argv[1]\nb = certora.extract(resp, p)\n": "string literal",
            GET + 'b = certora.extract(resp, ".[].name")\n': "needs extract_all",
            GET + 'xs = certora.extract_all(resp, ".name")\n': "needs one []",
            GET + 'xs = certora.extract_all(resp, ".a[].b[]")\n': "at most one []",
            GET + 'b = certora.extract(resp, "name")\n': "begins with '.'",
            'b = certora.extract(sys.argv[1], ".a")\n': "must be a source",
            'xs = certora.lines("text")\n': "must be a source",
            GET + 'b = certora.extract(resp, ".a", "b")\n': "exactly two",
        }
        for body, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertTrue(any(expected in v for v in self.violations(body)), self.violations(body))


class TestPolicySide(unittest.TestCase):
    def test_the_vocabulary_carries_the_sources(self) -> None:
        vocabulary = POLICY.vocabulary()
        self.assertIn(("git", ("branch", "--format=%(refname:short)"), "git-branches"), vocabulary.sources.exec)
        self.assertIn(("api.github.com", (), "gh-api"), vocabulary.sources.network)
        self.assertEqual(len(vocabulary.sources.read), 1)
        self.assertTrue({"gh-api", "git-branches", "approved"} <= vocabulary.pure_atoms)

    def test_source_atoms_are_never_textual_at_runtime(self) -> None:
        # the broker cannot see provenance: the hole's source atom is the static check's alone
        self.assertEqual(
            POLICY.exec_command("git", ["push", "origin", "feature"], {}, "repos/x"),
            ["git", "push", "origin", "feature"],
        )

    def test_only_extraction_establishes_a_source_atom(self) -> None:
        with self.assertRaises(ValueError):
            Policy.allow(
                atoms=[atom("gh-api", markers.matches(".*"))],
                network=[network("api.github.com", source="gh-api")],
            )
        with self.assertRaises(ValueError):
            Policy.allow(
                validations=[validation("v", argv=("true",), establishes={"cwd": ["gh-api"]}, cwd=".")],
                network=[network("api.github.com", source="gh-api")],
            )

    def test_the_data_format(self) -> None:
        policy = from_data({
            "policy-version": 1,
            "atoms": {"gh-api": {"pure": True}, "manifest": {"pure": True}},
            "network": [{"host": "api.github.com", "methods": ["GET"], "source": "gh-api"}],
            "program": [{"name": "gh", "cwd": ".", "source": "gh-api"}],
            "source": [{"name": "manifest", "location": ["dist/manifest.json", "build/**"]}],
        })
        self.assertEqual(policy.network[0].source, "gh-api")
        self.assertEqual(policy.programs[0].source, "gh-api")
        (src,) = policy.sources
        self.assertEqual((src.name, len(src.locations)), ("manifest", 2))

    def test_a_source_atom_must_be_declared_pure(self) -> None:
        for atoms, expected in (
            ({"gh-api": {}}, "pure = true"),
            ({}, "not declared"),
        ):
            with self.subTest(atoms=atoms), self.assertRaises(PolicyFileError) as cm:
                from_data({
                    "policy-version": 1,
                    "atoms": atoms,
                    "network": [{"host": "api.github.com", "source": "gh-api"}],
                })
            self.assertIn(expected, str(cm.exception))


class TestDashGuardOnRegexHeads(unittest.TestCase):
    def test_sound_heads(self) -> None:
        for reg in (
            r"[^-].*", r"\w+", r"feature/.*", r"dev-\w+", r"[abc]+", r"^v\d+", r"[a-z]+",
            r"(?:re|fea)ture", r"x?y", r"(?=.)\w+", r"[^\W-]+",
        ):
            with self.subTest(reg=reg):
                self.assertFalse(may_start_with_dash(StrFact(regex=RegexLit(reg))))
        for reg in (
            r".*", r"-.*", r"(a|-b)", r"[-a]+", r"[^a-z]+", r"\-x", r"[!-/]", r"x?-", r"\W+",
            r"[^\d]", r"(x)?\1", r"(",
        ):
            with self.subTest(reg=reg):
                self.assertTrue(may_start_with_dash(StrFact(regex=RegexLit(reg))))


class TestJqPath(unittest.TestCase):
    def test_parse(self) -> None:
        self.assertEqual(jqpath.parse("."), ())
        self.assertEqual(jqpath.parse(".a.b"), (jqpath.Key("a"), jqpath.Key("b")))
        self.assertEqual(jqpath.parse('."x y"[0]'), (jqpath.Key("x y"), jqpath.Index(0)))
        self.assertEqual(jqpath.parse(".[]"), (jqpath.Each(),))
        self.assertEqual(jqpath.parse(".data[].name"), (jqpath.Key("data"), jqpath.Each(), jqpath.Key("name")))
        self.assertTrue(jqpath.plural(jqpath.parse(".a[]")))
        self.assertFalse(jqpath.plural(jqpath.parse(".a[0]")))
        for bad in ("a", ".a..b", ".a[x]", ".[].b[]", ".a.", '."open', ".a[", ".a b"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                jqpath.parse(bad)

    def test_walk(self) -> None:
        doc = {"data": [{"name": "a", "n": 1}, {"name": "b", "n": 2}], "x": {"y": True}}
        self.assertEqual(jqpath.walk(jqpath.parse(".data[].name"), doc), ["a", "b"])
        self.assertEqual(jqpath.walk(jqpath.parse(".data[-1].n"), doc), 2)
        self.assertIs(jqpath.walk(jqpath.parse(".x.y"), doc), True)
        for missing in (".nope", ".data[5]", ".x[]", ".data.name"):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                jqpath.walk(jqpath.parse(missing), doc)


class TestRuntimeExtractors(unittest.TestCase):
    def test_extract_from_an_exec_result(self) -> None:
        r = ExecResult(["gh"], 0, b'{"a": {"b": 1, "t": true}}', b"")
        self.assertEqual(markers.extract(r, ".a.b"), "1")
        self.assertEqual(markers.extract(r, ".a.t"), "true")
        with self.assertRaises(ExtractError):
            markers.extract(r, ".a")  # an object, not a scalar
        with self.assertRaises(ExtractError):
            markers.extract(r, ".a.zzz")
        with self.assertRaises(ExtractError):
            markers.extract(r, ".a[].b")  # plural path in extract

    def test_a_failed_child_raises_first(self) -> None:
        with self.assertRaises(markers.CalledProcessError):
            markers.extract(ExecResult(["gh"], 1, b"{}", b"boom"), ".a")

    def test_extract_all_lines_and_field(self) -> None:
        r = ExecResult(["gh"], 0, b'[{"name": "a"}, {"name": "b"}]', b"")
        self.assertEqual(markers.extract_all(r, ".[].name"), ["a", "b"])
        with self.assertRaises(ExtractError):
            markers.extract_all(r, ".[0].name")
        self.assertEqual(markers.lines(ExecResult(["ls"], 0, b"a\nb\n", b"")), ["a", "b"])
        self.assertEqual(markers.field("a,b,c", 1, sep=","), "b")
        with self.assertRaises(ExtractError):
            markers.field("a", 3)

    def test_responses_text_and_files(self) -> None:
        ok = NetworkResponse(200, "OK", (), b'{"k": "v"}', "https://x")
        self.assertEqual(markers.extract(ok, ".k"), "v")
        with self.assertRaises(ExtractError):
            markers.extract(NetworkResponse(404, "Not Found", (), b"{}", "https://x"), ".k")
        self.assertEqual(markers.extract('{"k": 2.5}', ".k"), "2.5")
        with self.assertRaises(ExtractError):
            markers.extract('{"k": null}', ".k")
        self.assertEqual(markers.lines(io.StringIO("x\ny\n")), ["x", "y"])
        with self.assertRaises(ExtractError):
            markers.extract("not json", ".k")


if __name__ == "__main__":
    unittest.main()
