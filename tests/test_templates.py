"""Command templates (TEMPLATES.md): a template binds like a signature -- the fast path stays
positional -- holes are relies, flags are a vocabulary, and the broker composes the argv."""
import os
import pathlib
import tempfile
import threading
import unittest

from certorail import markers
from certorail.analysis import ANY_NAME, DirSplat, Exact, Located, Named, StaticPath, StrFact
from certorail.broker import build_server, exec_request
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.ids import HoleName
from certorail.policy import Policy, Refusal, atom, constraint, flagset, hole, program, splice
from certorail.policyfile import PolicyFileError, from_data
from certorail.templates import (
    BindError,
    Bound,
    Constraint,
    Each,
    Flags,
    Flagset,
    HoleRef,
    Many,
    Template,
    Token,
    bind,
    instantiate,
    may_start_with_dash,
)
from certorail.walker import analyze

HEADER = "import pathlib\nimport sys\nimport typing\n"
REPOS = markers.within("repos")

FIND_FLAGS = flagset(
    bare=["-print", "-print0"],
    valued={
        "-mindepth": constraint(matches=r"\d+"),
        "-name": constraint(matches=r"[^/]+"),
        "-newer": constraint(location=REPOS),
    },
)

POLICY = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within(".")],
    listing=[markers.within(".")],
    atoms=[atom("no-flag", markers.matches(r"[^-].*"))],
    programs=[
        program(
            "git", cwd=REPOS, argv=["git", "push", "origin", hole("BRANCH")],
            holes={"BRANCH": Token(constraint(atoms=["no-flag"]))},
        ),
        program("git", cwd=REPOS, subcommand="log"),  # a flat rule beside a template: prefix-free
        program(
            "find", cwd=".", argv=["find", hole("WHERE"), splice("FLAGS")],
            holes={"WHERE": Token(constraint(location=REPOS)), "FLAGS": Flags(FIND_FLAGS)},
        ),
        program(
            "tar", cwd=".", argv=["tar", splice("FLAGS"), "-f", hole("ARCHIVE"), splice("FILES")],
            holes={
                "FLAGS": Flags(flagset(bare=["-c", "-z"])),
                "ARCHIVE": Token(
                    constraint(location=markers.within("archives", leaf=markers.matches(r"\w+\.tgz")))
                ),
                "FILES": Each(constraint(location=REPOS), min=1),
            },
        ),
        program(
            "grep", cwd=".", argv=["grep", splice("FLAGS"), "--", hole("PATTERN"), splice("FILES")],
            holes={
                "FLAGS": Flags(flagset(bare=["-r", "-n"])),
                "PATTERN": Token(constraint(any=True)),
                "FILES": Each(constraint(location=REPOS), min=1),
            },
        ),
        program(
            "ls", cwd=".", argv=["ls", hole("WHERE")],
            holes={"WHERE": Token(constraint(location=markers.within(".")))},
        ),
        # the intent gate: only a database the program itself named, of the dev shape
        program(
            "dropdb", cwd=".", argv=["dropdb", hole("NAME")],
            holes={"NAME": Token(constraint(matches=r"dev-\w+", literal=True))},
        ),
    ],
)


def outcome(body: str):
    return host_check(HEADER + body, "<t>", POLICY)


class Base(unittest.TestCase):
    def accept(self, body: str) -> Accepted:
        result = outcome(body)
        if isinstance(result, Rejected):
            self.fail("\n".join(result.describe("<t>")))
        return result

    def denial(self, body: str) -> str:
        result = outcome(body)
        assert isinstance(result, Rejected), "expected a rejection"
        self.assertEqual(result.violations, [], result.describe("<t>"))
        (d,) = result.denials
        return d.reason


REPO = 'repo = pathlib.Path("repos") / "x"\n'


class TestFastPath(Base):
    def test_positional_binding_is_the_default(self) -> None:
        self.accept(REPO + 'certora.exec("git", "push", "origin", "feature", cwd=repo)\n')

    def test_the_hole_is_a_rely(self) -> None:
        reason = self.denial(REPO + 'certora.exec("git", "push", "origin", "--force", cwd=repo)\n')
        self.assertIn("BRANCH", reason)
        self.assertIn("not validated by: no-flag", reason)

    def test_keyword_binding_also_works(self) -> None:
        self.accept(REPO + 'certora.exec("git", "push", "origin", BRANCH="feature", cwd=repo)\n')

    def test_the_flat_rule_beside_it_still_works(self) -> None:
        self.accept(REPO + 'certora.exec("git", "log", cwd=repo)\n')
        self.assertIn(
            "takes no arguments beyond its words",
            self.denial(REPO + 'certora.exec("git", "log", "--oneline", cwd=repo)\n'),
        )
        self.assertIn(
            "no declared subcommand", self.denial(REPO + 'certora.exec("git", "rebase", cwd=repo)\n')
        )

    def test_binding_errors(self) -> None:
        cases = {
            'certora.exec("git", "push", "origin", "a", BRANCH="b", cwd=repo)\n': "bound twice",
            'certora.exec("git", "push", "origin", "a", FOO="b", cwd=repo)\n': "not a hole",
            'certora.exec("git", "push", "origin", cwd=repo)\n': "unbound",
            'certora.exec("git", "push", "origin", "a", "b", cwd=repo)\n': "too many",
            'certora.exec("git", "log", X="1", cwd=repo)\n': "takes no keyword arguments",
        }
        for body, expected in cases.items():
            with self.subTest(body=body):
                self.assertIn(expected, self.denial(REPO + body))


class TestTrailingFlags(Base):
    HERE = 'here = pathlib.Path(".")\n'

    def test_flags_ride_the_positional_tail(self) -> None:
        self.accept(
            REPO + self.HERE
            + 'certora.exec("find", repo, "-mindepth", "1", "-name", "*.py", "-print", cwd=here)\n'
        )

    def test_the_vocabulary_is_closed(self) -> None:
        reason = self.denial(REPO + self.HERE + 'certora.exec("find", repo, "-delete", cwd=here)\n')
        self.assertIn("'-delete' is not a declared flag", reason)

    def test_valued_flags_need_and_check_their_value(self) -> None:
        self.assertIn(
            "needs a value",
            self.denial(REPO + self.HERE + 'certora.exec("find", repo, "-mindepth", cwd=here)\n'),
        )
        self.assertIn(
            "not known to match",
            self.denial(REPO + self.HERE + 'certora.exec("find", repo, "-mindepth", "x", cwd=here)\n'),
        )
        reason = self.denial(
            REPO + self.HERE
            + 'other = pathlib.Path("etc") / "x"\n'
            + 'certora.exec("find", repo, "-newer", other, cwd=here)\n'
        )
        self.assertIn("'-newer'", reason)
        self.assertIn("not a proven path within repos/**", reason)

    def test_unknown_values_fail_closed(self) -> None:
        # sys.argv[1] is a str of unknown text: not a proven path, so the location rely fails
        self.assertIn(
            "WHERE is not a proven path within repos/**",
            self.denial(self.HERE + 'certora.exec("find", sys.argv[1], cwd=here)\n'),
        )
        # a value of unknown type altogether
        self.assertIn(
            "WHERE is of unknown provenance",
            self.denial(self.HERE + 'x = {"a": "b"}\ncertora.exec("find", x["a"], cwd=here)\n'),
        )
        self.assertIn(
            "flag position",
            self.denial(REPO + self.HERE + 'certora.exec("find", repo, sys.argv[1], cwd=here)\n'),
        )


class TestKeywordOnlyShapes(Base):
    HERE = 'here = pathlib.Path(".")\n'
    TAR_OK = (
        'certora.exec("tar", FLAGS=["-c", "-z"], ARCHIVE=pathlib.Path("archives") / "out.tgz", '
        'FILES=[pathlib.Path("repos") / "a", pathlib.Path("repos") / "b"], cwd=here)\n'
    )

    def test_a_non_last_splice_makes_the_rest_keyword_only(self) -> None:
        reason = self.denial(
            self.HERE
            + 'certora.exec("tar", "-c", ARCHIVE=pathlib.Path("archives") / "out.tgz", '
            'FILES=[pathlib.Path("repos") / "a"], cwd=here)\n'
        )
        self.assertIn("keyword-only", reason)

    def test_the_keyword_form(self) -> None:
        self.accept(self.HERE + self.TAR_OK)

    def test_each_holes_check_every_element_and_min(self) -> None:
        self.assertIn(
            "FILES needs at least 1",
            self.denial(
                self.HERE
                + 'certora.exec("tar", FLAGS=["-c"], ARCHIVE=pathlib.Path("archives") / "out.tgz", '
                "FILES=[], cwd=here)\n"
            ),
        )
        self.assertIn(
            "FILES[1] is not a proven path within repos/**",
            self.denial(
                self.HERE
                + 'certora.exec("tar", FLAGS=["-c"], ARCHIVE=pathlib.Path("archives") / "out.tgz", '
                'FILES=[pathlib.Path("repos") / "a", pathlib.Path("etc") / "b"], cwd=here)\n'
            ),
        )

    def test_any_after_a_double_dash_admits_the_unknown(self) -> None:
        self.accept(
            REPO + self.HERE
            + 'certora.exec("grep", FLAGS=["-r", "-n"], PATTERN=sys.argv[1], FILES=[repo], cwd=here)\n'
        )
        self.assertIn(
            "'-R' is not a declared flag",
            self.denial(
                REPO + self.HERE
                + 'certora.exec("grep", FLAGS=["-R"], PATTERN="x", FILES=[repo], cwd=here)\n'
            ),
        )


class TestContainers(Base):
    HERE = 'here = pathlib.Path(".")\n'
    FILES = 'files: list[typing.Annotated[pathlib.Path, certora.within("repos")]] = [pathlib.Path("repos") / "a"]\n'

    def test_a_typed_container_splices_into_an_each_hole(self) -> None:
        self.accept(
            self.HERE + self.FILES
            + 'certora.exec("tar", FLAGS=["-c"], ARCHIVE=pathlib.Path("archives") / "out.tgz", FILES=files, cwd=here)\n'
        )

    def test_the_element_fact_must_entail_the_constraint(self) -> None:
        loose = 'files: list[typing.Annotated[pathlib.Path, certora.within(".")]] = [pathlib.Path("repos") / "a"]\n'
        reason = self.denial(
            self.HERE + loose
            + 'certora.exec("tar", FLAGS=["-c"], ARCHIVE=pathlib.Path("archives") / "out.tgz", FILES=files, cwd=here)\n'
        )
        self.assertIn("the elements of FILES", reason)

    def test_a_flags_hole_takes_no_container(self) -> None:
        reason = self.denial(
            self.HERE + self.FILES
            + 'certora.exec("tar", FLAGS=files, ARCHIVE=pathlib.Path("archives") / "out.tgz", '
            'FILES=[pathlib.Path("repos") / "a"], cwd=here)\n'
        )
        self.assertIn("not a container", reason)

    def test_a_positional_container_is_still_an_escape(self) -> None:
        report = analyze(HEADER + self.HERE + self.FILES + 'certora.exec("tar", files, cwd=here)\n')
        self.assertTrue(any("escapes" in what for _, what in report.violations))


class TestDashGuard(Base):
    HERE = 'here = pathlib.Path(".")\n'

    def test_a_value_that_may_be_an_option_is_denied(self) -> None:
        reason = self.denial(
            self.HERE
            + "p = sys.argv[1]\n"
            + 'assert ".." not in p and not p.startswith("/")\n'
            + 'certora.exec("ls", p, cwd=here)\n'
        )
        self.assertIn("may begin with '-'", reason)

    def test_a_named_directory_cannot_be_an_option(self) -> None:
        self.accept(REPO + self.HERE + 'certora.exec("ls", repo, cwd=here)\n')

    def test_the_predicate(self) -> None:
        self.assertTrue(may_start_with_dash("-x"))
        self.assertFalse(may_start_with_dash("x"))
        self.assertTrue(may_start_with_dash(None))
        self.assertTrue(may_start_with_dash(StrFact()))
        self.assertTrue(may_start_with_dash(StrFact(regex=Exact("-a"))))
        self.assertFalse(may_start_with_dash(Located(StaticPath((Named("repos"),)), "str")))
        self.assertFalse(may_start_with_dash(Located(StaticPath((), absolute=True), "str")))
        self.assertFalse(may_start_with_dash(Located(StaticPath(()), "str")))  # "." itself
        self.assertTrue(may_start_with_dash(Located(DirSplat((), None), "str")))

    def test_the_report_shows_the_bindings(self) -> None:
        accepted = self.accept(
            REPO + self.HERE
            + 'certora.exec("grep", FLAGS=["-r"], PATTERN="x", FILES=[repo], cwd=here)\n'
        )
        (line,) = accepted.describe("<t>")
        self.assertIn("FLAGS=['-r']", line)
        self.assertIn("FILES=[path at repos/x]", line)


class TestIntent(Base):
    """``literal`` is provenance, not shape: the value must come from the program's own text."""

    HERE = 'here = pathlib.Path(".")\n'

    def test_a_named_database_may_be_dropped(self) -> None:
        self.accept(self.HERE + 'certora.exec("dropdb", "dev-scratch", cwd=here)\n')
        self.accept(self.HERE + 'TARGET = "dev-scratch"\ncertora.exec("dropdb", TARGET, cwd=here)\n')

    def test_a_database_read_from_input_may_not_even_if_well_shaped(self) -> None:
        reason = self.denial(
            self.HERE
            + "import re\nname = sys.argv[1]\n"
            + 'assert re.fullmatch(r"dev-\\w+", name)\n'
            + 'certora.exec("dropdb", name, cwd=here)\n'
        )
        self.assertIn("NAME is not statically known text", reason)

    def test_the_shape_still_applies_to_literals(self) -> None:
        self.assertIn(
            "not known to match", self.denial(self.HERE + 'certora.exec("dropdb", "prod-main", cwd=here)\n')
        )

    def test_at_runtime_every_string_is_literal(self) -> None:
        # the broker sees text with no provenance: the shape is what it can re-check
        self.assertEqual(POLICY.exec_command("dropdb", ["dev-x"], {}, "."), ["dropdb", "dev-x"])


class TestTemplateWellFormedness(unittest.TestCase):
    def test_template_errors(self) -> None:
        good = Token(constraint(any=True))
        with self.assertRaises(ValueError):
            Template(("x", HoleRef(HoleName("A"))), {})  # used, not declared
        with self.assertRaises(ValueError):
            Template(("x",), {HoleName("A"): good})  # declared, not used
        with self.assertRaises(ValueError):
            Template(("x", HoleRef(HoleName("A"), variadic=True)), {HoleName("A"): good})  # ${A...} on a token
        with self.assertRaises(ValueError):
            Template(("x", HoleRef(HoleName("A"))), {HoleName("A"): Each(constraint(any=True))})  # ${A} on an each
        with self.assertRaises(ValueError):
            Template(("x", HoleRef(HoleName("cwd"))), {HoleName("cwd"): good})
        with self.assertRaises(ValueError):
            Template((HoleRef(HoleName("A")),), {HoleName("A"): good})

    def test_constraint_errors(self) -> None:
        with self.assertRaises(ValueError):
            Constraint()
        with self.assertRaises(ValueError):
            constraint(any=True, atoms=["a"])
        with self.assertRaises(ValueError):
            constraint(location=REPOS, matches="x")
        with self.assertRaises(ValueError):
            constraint(matches="x", one_of=["a"])
        # provenance is orthogonal to shape: both of these are meaningful
        constraint(literal=True, matches="x")
        constraint(literal=True, location=REPOS)

    def test_flagset_errors(self) -> None:
        with self.assertRaises(ValueError):
            Flagset()
        with self.assertRaises(ValueError):
            flagset(bare=["q"])
        with self.assertRaises(ValueError):
            flagset(bare=["-q"], valued={"-q": constraint(any=True)})

    def test_rule_errors(self) -> None:
        with self.assertRaises(ValueError):
            program("x", cwd=".", argv=["x"], holes={}, subcommand="y")
        with self.assertRaises(ValueError):
            program("x", cwd=".", argv=["y"], holes={})
        with self.assertRaises(ValueError):
            program("x", cwd=".", argv=["x"])

    def test_forms_of_one_program_are_prefix_free(self) -> None:
        with self.assertRaises(ValueError):
            Policy.allow(programs=[
                program("find", cwd=".", argv=["find", hole("A")], holes={"A": Token(constraint(any=True))}),
                program("find", cwd=".", argv=["find", hole("B")], holes={"B": Token(constraint(any=True))}),
            ])
        with self.assertRaises(ValueError):
            Policy.allow(programs=[
                program("git", cwd="."),
                program("git", cwd=".", argv=["git", "push", hole("B")], holes={"B": Token(constraint(any=True))}),
            ])


GREP = POLICY.programs[4].template
assert GREP is not None


class TestBind(unittest.TestCase):
    def test_leading_words_and_keyword_only(self) -> None:
        self.assertEqual(GREP.leading_words, ("grep",))
        self.assertEqual(GREP.keyword_only, ("FLAGS", "PATTERN", "FILES"))
        self.assertTrue(GREP.dash_exempt(HoleName("PATTERN")))
        self.assertFalse(GREP.dash_exempt(HoleName("FLAGS")))

    def test_instantiate_emits_interior_literals(self) -> None:
        bound = bind(GREP, [], {"FLAGS": Many(("-r",)), "PATTERN": "x", "FILES": Many(("repos/a",))})
        assert isinstance(bound, Bound)
        self.assertEqual(instantiate(bound), ["grep", "-r", "--", "x", "repos/a"])

    def test_an_omitted_splice_is_empty(self) -> None:
        bound = bind(GREP, [], {"PATTERN": "x", "FILES": Many(("repos/a",))})
        assert isinstance(bound, Bound)
        self.assertEqual(bound.bindings[HoleName("FLAGS")], Many(()))

    def test_positionals_reaching_keyword_only_holes(self) -> None:
        result = bind(GREP, ["-r"], {})
        assert isinstance(result, BindError)
        self.assertTrue(any("keyword-only" in r for r in result.reasons))


class TestRuntime(unittest.TestCase):
    def test_the_broker_composes_the_argv(self) -> None:
        self.assertEqual(
            POLICY.exec_command("grep", [], {"FLAGS": ["-r"], "PATTERN": "x", "FILES": ["repos/a"]}, "."),
            ["grep", "-r", "--", "x", "repos/a"],
        )
        self.assertEqual(
            POLICY.exec_command("git", ["push", "origin", "feature"], {}, "repos/x"),
            ["git", "push", "origin", "feature"],
        )
        self.assertEqual(POLICY.exec_command("git", ["log"], {}, "repos/x"), ["git", "log"])

    def test_the_same_checks_run_on_strings(self) -> None:
        cases = [
            (("find", ["repos/x", "-delete"], {}, "."), "not a declared flag"),
            (("git", ["push", "origin", "--force"], {}, "repos/x"), "not validated by: no-flag"),
            (("git", ["log"], {"X": "1"}, "repos/x"), "takes no keyword arguments"),
            (("ls", ["-la"], {}, "."), "may begin with '-'"),
            (("tar", [], {"FLAGS": ["-c"], "ARCHIVE": "archives/out.tgz", "FILES": []}, "."), "at least 1"),
            (("tar", [], {"FLAGS": ["-c"], "ARCHIVE": "etc/out.tgz", "FILES": ["repos/a"]}, "."), "ARCHIVE"),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                result = POLICY.exec_command(*args)
                assert isinstance(result, Refusal), result
                self.assertIn(expected, result.reason)


class TestBrokerRoundTrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = pathlib.Path(tempfile.mkdtemp())
        policy = Policy.allow(
            programs=[
                program(
                    "printf", cwd=".", argv=["printf", hole("FORMAT"), splice("ARGS")],
                    holes={"FORMAT": Token(constraint(literal=True)), "ARGS": Each(constraint(literal=True))},
                )
            ]
        )
        cls.sock = os.path.join(tempfile.mkdtemp(), "broker.sock")
        cls.server = build_server(cls.sock, policy, cls.root)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_a_templated_exec_runs_the_composed_argv(self) -> None:
        reply = exec_request(self.sock, "printf", ["%s-%s\\n"], cwd=".", kwargs={"ARGS": ["a", "b"]})
        self.assertTrue(reply["ok"], reply)
        import base64

        self.assertEqual(base64.b64decode(reply["stdout_b64"]), b"a-b\n")

    def test_markers_exec_sends_the_bindings(self) -> None:
        os.environ["CERTORAIL_BROKER_SOCKET"] = self.sock
        self.addCleanup(os.environ.pop, "CERTORAIL_BROKER_SOCKET", None)
        result = markers.exec("printf", "%s+%s\\n", ARGS=["x", "y"], cwd=".")
        self.assertEqual(result.stdout_lines(), ["x+y"])
        with self.assertRaises(TypeError):
            markers.exec("printf", "%s", ARGS=[1], cwd=".")

    def test_an_undeclared_hole_is_refused_unspawned(self) -> None:
        reply = exec_request(self.sock, "printf", ["%s"], cwd=".", kwargs={"NOPE": "x"})
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")
        self.assertIn("not a hole", reply["detail"])


class TestDataFormat(unittest.TestCase):
    def test_templates_load(self) -> None:
        policy = from_data({
            "policy-version": 1,
            "atoms": {"no-flag": {"matches": "[^-].*"}},
            "flagset": [{
                "name": "find-ro",
                "bare": ["-print"],
                "-mindepth": {"matches": r"\d+"},
                "-newer": {"location": "repos/**"},
            }],
            "program": [
                {
                    "name": "find", "cwd": ".",
                    "argv": ["find", "${WHERE}", "${FLAGS...}"],
                    "holes": {"WHERE": {"location": "repos/**"}, "FLAGS": {"kind": "flags", "flagset": "find-ro"}},
                },
                {
                    "name": "git", "cwd": ["repos/**", "data/**"],
                    "argv": ["git", "push", "origin", "${BRANCH}"],
                    "holes": {"BRANCH": {"atoms": ["no-flag"]}},
                },
                {
                    "name": "tar", "cwd": ".",
                    "argv": ["tar", "${FLAGS...}", "-f", "${ARCHIVE}", "${FILES...}"],
                    "holes": {
                        "FLAGS": {"kind": "flags", "bare": ["-c", "-z"], "-C": {"location": "repos/**"}},
                        "ARCHIVE": {"location": r"archives/<\w+\.tgz>"},
                        "FILES": {"kind": "each", "location": ["repos/**", "data/**"], "min": 1},
                    },
                },
            ],
        })
        find, git, tar = policy.programs
        assert find.template is not None and git.template is not None and tar.template is not None
        self.assertEqual(find.leading_words, ("find",))
        self.assertEqual(git.leading_words, ("git", "push", "origin"))
        self.assertEqual(tar.template.keyword_only, ("FLAGS", "ARCHIVE", "FILES"))
        flags = find.template.holes[HoleName("FLAGS")]
        assert isinstance(flags, Flags)
        self.assertEqual(flags.flagset.bare, frozenset({"-print"}))
        inline = tar.template.holes[HoleName("FLAGS")]
        assert isinstance(inline, Flags)
        self.assertIn("-C", inline.flagset.valued)
        files = tar.template.holes[HoleName("FILES")]
        assert isinstance(files, Each)
        self.assertEqual(files.min, 1)
        self.assertEqual(len(files.constraint.locations), 2)

    def test_the_load_catalogue(self) -> None:
        def rule(**extra):
            return {"policy-version": 1, "program": [{"name": "x", "cwd": ".", **extra}]}

        cases = [
            (rule(argv=["x", "${A}"], holes={"A": {"any": True}}, subcommand="y"), "carries no subcommand"),
            (rule(argv=["x", "${A}"], holes={}), "used but not declared"),
            (rule(argv=["x"], holes={"A": {"any": True}}), "declared but not used"),
            (rule(argv=["x", "${A...}"], holes={"A": {"any": True}}), "disagrees with its kind"),
            (rule(argv=["x", "${A}"], holes={"A": {"kind": "flags", "flagset": "nope"}}), "not declared"),
            (rule(argv=["x", "${A...}"], holes={"A": {"kind": "flags", "bare": ["-q"], "flagset": "f"}}), "exclude each other"),
            (rule(argv=["x", "${A...}"], holes={"A": {"kind": "flags", "-q": {}}}), "not a bare flag"),
            (rule(argv=["x", "${A}"], holes={"A": {}}), "says nothing"),
            (rule(argv=["x", "${A}"], holes={"A": {"location": "**", "matches": "x"}}), "textless"),
            (rule(argv=["x", "a${A}"], holes={"A": {"any": True}}), "whole words"),
            (rule(holes={"A": {"any": True}}), "need an argv template"),
            (rule(argv=["x", "${A}"], holes={"A": {"kind": "each", "any": True}}), "disagrees with its kind"),
            (rule(argv=["x", "${A}"], holes={"A": {"any": True, "min": 1}}), "min applies to each"),
        ]
        for data, expected in cases:
            with self.subTest(expected=expected), self.assertRaises(PolicyFileError) as cm:
                from_data(data)
            self.assertIn(expected, str(cm.exception))


if __name__ == "__main__":
    unittest.main()
