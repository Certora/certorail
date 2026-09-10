"""Pluggable runtime validations: ``certora.check`` gen, the kill discipline (pure vs
environment atoms, effect-free checkers), contracts, and policy consumption.

The vocabulary (which checks exist, what they establish, what is pure) is policy-side data
threaded into ``analyze``; the dataflow tests use a hand-built ``Vocabulary``, the end-to-end
tests go through ``host.check`` with a real ``Policy``.
"""
import os
import pathlib
import tempfile
import threading
import unittest

from certorail import markers
from certorail.broker import build_server
from certorail.analysis import RegexLit, checks_of
from certorail.effects import NOTHING
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.markers import CheckFailed
from certorail.policy import Policy, atom, param, program, pure, validation
from certorail.ids import AtomId, ParamName, ValidationName
from certorail.walker import CheckSignature, CheckSite, ExecSite, Report, Vocabulary, analyze

CWD = ParamName("cwd")
VOCAB = Vocabulary(
    signatures={
        # environmental atom, effectful evaluator (the conservative default)
        ValidationName("org-repo"): CheckSignature(
            ValidationName("org-repo"), (), {CWD: frozenset({AtomId("org-checkout")})}
        ),
        # environmental atom, effect-free evaluator: kills nothing, so checkers stack
        ValidationName("clean-tree"): CheckSignature(
            ValidationName("clean-tree"), (), {CWD: frozenset({AtomId("clean")})}, writes=NOTHING
        ),
        # pure atom on a string parameter
        ValidationName("repo-url"): CheckSignature(
            ValidationName("repo-url"), (ParamName("url"),),
            {ParamName("url"): frozenset({AtomId("good-url")})}, writes=NOTHING,
        ),
    },
    pure_atoms=frozenset({AtomId("good-url"), AtomId("no-flag")}),
    # a regex-defined atom: its meaning is a text property, established by saturation
    defined={AtomId("no-flag"): RegexLit(r"[^-].*")},
)

HEADER = "import pathlib\nimport typing\n"
REPO = 'repo = pathlib.Path("repos") / "x"\n'
CHECK = 'certora.check("org-repo", cwd=repo)\n'
EXEC = 'certora.exec("git", "log", cwd=repo)\n'


def run(body: str) -> Report:
    return analyze(HEADER + body, vocabulary=VOCAB)


def exec_sites(report: Report) -> list[ExecSite]:
    return [s for s in report.sinks if isinstance(s, ExecSite)]


def check_sites(report: Report) -> list[CheckSite]:
    return [s for s in report.sinks if isinstance(s, CheckSite)]


class TestGen(unittest.TestCase):
    def test_check_establishes_on_cwd(self) -> None:
        report = run(REPO + CHECK + EXEC)
        self.assertEqual(report.violations, [])
        (site,) = exec_sites(report)
        self.assertEqual(checks_of(site.cwd), frozenset({"org-checkout"}))

    def test_the_check_site_itself_is_reported(self) -> None:
        report = run(REPO + CHECK)
        (site,) = check_sites(report)
        self.assertEqual(site.name, "org-repo")
        self.assertTrue(site.confined)

    def test_check_must_be_a_statement(self) -> None:
        report = run(REPO + 'ok = certora.check("org-repo", cwd=repo)\n')
        self.assertTrue(any("bare statement" in what for _, what in report.violations))

    def test_unknown_validation_is_a_violation(self) -> None:
        report = run(REPO + 'certora.check("nope", cwd=repo)\n')
        self.assertTrue(any("declares no validation" in what for _, what in report.violations))

    def test_keywords_must_match_the_signature(self) -> None:
        report = run('certora.check("repo-url", cwd=pathlib.Path("repos"))\n')
        self.assertTrue(any("url= is required" in what for _, what in report.violations))
        report = run(REPO + 'certora.check("org-repo", extra="x", cwd=repo)\n')
        self.assertTrue(any("not part of validation" in what for _, what in report.violations))

    def test_cwd_is_required(self) -> None:
        report = run('certora.check("org-repo")\n')
        self.assertTrue(any("cwd= is required" in what for _, what in report.violations))


class TestKill(unittest.TestCase):
    def test_a_program_call_kills_environment_atoms(self) -> None:
        report = run("def helper():\n    return 1\n" + REPO + CHECK + "helper()\n" + EXEC)
        (site,) = exec_sites(report)
        self.assertEqual(checks_of(site.cwd), frozenset())

    def test_effect_free_calls_do_not_kill(self) -> None:
        report = run(REPO + CHECK + "msg = str(repo)\nprint(msg)\nxs = sorted([3, 1])\n" + EXEC)
        (site,) = exec_sites(report)
        self.assertEqual(checks_of(site.cwd), frozenset({"org-checkout"}))

    def test_effect_free_checkers_stack(self) -> None:
        report = run(REPO + CHECK + 'certora.check("clean-tree", cwd=repo)\n' + EXEC)
        (site,) = exec_sites(report)
        self.assertEqual(checks_of(site.cwd), frozenset({"org-checkout", "clean"}))

    def test_an_effectful_checker_kills_prior_environment_atoms(self) -> None:
        report = run(REPO + 'certora.check("clean-tree", cwd=repo)\n' + CHECK + EXEC)
        (site,) = exec_sites(report)
        self.assertEqual(checks_of(site.cwd), frozenset({"org-checkout"}))

    def test_reassignment_kills(self) -> None:
        report = run(REPO + CHECK + REPO + EXEC)
        (site,) = exec_sites(report)
        self.assertEqual(checks_of(site.cwd), frozenset())

    def test_loop_boundary_kills_environment_atoms(self) -> None:
        report = run(REPO + CHECK + "for i in [1]:\n    " + EXEC)
        (site,) = exec_sites(report)
        self.assertEqual(checks_of(site.cwd), frozenset())

    def test_check_inside_the_loop_survives_to_its_use(self) -> None:
        report = run(REPO + "for i in [1]:\n    " + CHECK.replace("\n", "\n    ") + EXEC)
        (site,) = exec_sites(report)
        self.assertEqual(checks_of(site.cwd), frozenset({"org-checkout"}))

    def test_a_branch_only_check_does_not_survive_the_join(self) -> None:
        report = run(REPO + 'if "a" in "ab":\n    ' + CHECK + EXEC)
        (site,) = exec_sites(report)
        self.assertEqual(checks_of(site.cwd), frozenset())

    def test_the_handler_does_not_see_the_check(self) -> None:
        report = run(REPO + "try:\n    " + CHECK + "except Exception:\n    " + EXEC)
        (site,) = exec_sites(report)
        self.assertEqual(checks_of(site.cwd), frozenset())


CLONE = (
    'def clone(url: typing.Annotated[str, certora.validated("good-url")]) -> None:\n'
    "    pass\n"
)
URL_CHECK = 'url = "https://example.test/x"\ncertora.check("repo-url", url=url, cwd=pathlib.Path("repos"))\n'


class TestPureAtoms(unittest.TestCase):
    def test_a_pure_atom_survives_effectful_calls(self) -> None:
        report = run(CLONE + URL_CHECK + "xs = sorted([3, 1])\nclone(url)\n")
        self.assertEqual(report.violations, [])

    def test_a_pure_atom_dies_with_the_value(self) -> None:
        report = run(CLONE + URL_CHECK + 'url = url + ""\nclone(url)\n')
        self.assertTrue(any("does not establish" in what for _, what in report.violations))

    def test_without_the_check_the_rely_fails(self) -> None:
        report = run(CLONE + 'url = "https://example.test/x"\nclone(url)\n')
        self.assertTrue(any("does not establish" in what for _, what in report.violations))


PUSH = (
    "def push(repo: typing.Annotated[pathlib.Path, "
    'certora.within("repos"), certora.validated("org-checkout")]) -> None:\n'
    '    certora.exec("git", "push", cwd=repo)\n'
)


class TestContracts(unittest.TestCase):
    def test_rely_discharged_by_a_check(self) -> None:
        report = run(PUSH + REPO + CHECK + "push(repo)\n")
        self.assertEqual(report.violations, [])

    def test_rely_not_discharged_without_a_check(self) -> None:
        report = run(PUSH + REPO + "push(repo)\n")
        self.assertTrue(any("does not establish" in what for _, what in report.violations))

    def test_the_rely_seeds_the_body(self) -> None:
        report = run(PUSH + REPO + CHECK + "push(repo)\n")
        self.assertTrue(
            any(checks_of(s.cwd) == frozenset({"org-checkout"}) for s in exec_sites(report))
        )

    def test_guarantee_established_by_a_check(self) -> None:
        report = run(
            "def make() -> typing.Annotated[pathlib.Path, "
            'certora.within("repos"), certora.validated("org-checkout")]:\n'
            '    repo = pathlib.Path("repos") / "x"\n'
            '    certora.check("org-repo", cwd=repo)\n'
            "    return repo\n"
        )
        self.assertEqual(report.violations, [])

    def test_guarantee_not_established_without_the_check(self) -> None:
        report = run(
            "def make() -> typing.Annotated[pathlib.Path, "
            'certora.within("repos"), certora.validated("org-checkout")]:\n'
            '    repo = pathlib.Path("repos") / "x"\n'
            "    return repo\n"
        )
        self.assertTrue(any("guarantee" in what for _, what in report.violations))


ORG_POLICY = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within(".")],
    listing=[markers.within(".")],
    programs=[program("git", cwd=markers.within("repos"), requires=["org-checkout"])],
    validations=[
        validation(
            "org-repo",
            argv=("check-org", "certora"),
            cwd=markers.within("repos"),
            establishes={"cwd": ["org-checkout"]},
        )
    ],
)


class TestPolicy(unittest.TestCase):
    def test_checked_exec_is_accepted(self) -> None:
        outcome = host_check(HEADER + REPO + CHECK + EXEC, "<t>", ORG_POLICY)
        self.assertIsInstance(outcome, Accepted)

    def test_unchecked_exec_is_denied(self) -> None:
        outcome = host_check(HEADER + REPO + EXEC, "<t>", ORG_POLICY)
        assert isinstance(outcome, Rejected)
        self.assertTrue(any("not validated" in d.reason for d in outcome.denials))

    def test_check_outside_its_permitted_location_is_denied(self) -> None:
        source = HEADER + 'other = pathlib.Path("elsewhere")\ncertora.check("org-repo", cwd=other)\n'
        outcome = host_check(source, "<t>", ORG_POLICY)
        assert isinstance(outcome, Rejected)
        self.assertTrue(any("may not run at" in d.reason for d in outcome.denials))

    def test_the_vocabulary_is_derived_from_the_policy(self) -> None:
        self.assertEqual(
            ORG_POLICY.vocabulary(),
            Vocabulary(
                signatures={
                    ValidationName("org-repo"): CheckSignature(
                        ValidationName("org-repo"), (), {CWD: frozenset({AtomId("org-checkout")})}
                    )
                },
                pure_atoms=frozenset(),
            ),
        )

    def test_conflicting_purity_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Policy.allow(
                validations=[
                    validation("a", argv=("x",), cwd=".", establishes={"cwd": [pure("atom-1")]}),
                    validation("b", argv=("y",), cwd=".", establishes={"cwd": ["atom-1"]}),
                ]
            )

    def test_duplicate_validation_names_are_rejected(self) -> None:
        v = validation("a", argv=("x",), cwd=".", establishes={"cwd": ["atom-1"]})
        with self.assertRaises(ValueError):
            Policy.allow(validations=[v, v])


class TestDefinedAtoms(unittest.TestCase):
    FLAGLESS = (
        'def push_to(branch: typing.Annotated[str, certora.validated("no-flag")]) -> None:\n'
        "    pass\n"
    )

    def test_a_literal_discharges_a_defined_atom_rely(self) -> None:
        report = run(self.FLAGLESS + 'push_to("master")\n')
        self.assertEqual(report.violations, [])

    def test_a_flag_literal_does_not(self) -> None:
        report = run(self.FLAGLESS + 'push_to("--force")\n')
        self.assertTrue(any("does not establish" in what for _, what in report.violations))


# "not equal to --force" is trivially executable and miserable as a regex: the literal checker
# (effect-free, pure atom, exactly one parameter) is what lets a plain literal discharge it.
SUB_POLICY = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within(".")],
    listing=[markers.within(".")],
    validations=[
        validation(
            "not-force-check",
            argv=("test", param("value"), "!=", "--force"),
            cwd=markers.within("."),
            params=("value",),
            establishes={"value": [pure("not-force")]},
            effect_free=True,
        )
    ],
    programs=[
        program(
            "git",
            subcommand="push origin",
            cwd=markers.within("repos"),
            argument_atoms=["not-force"],
            unknown_arguments=True,  # branch names are checked values, not literals: the opt-in
        ),
        program("git", subcommand="log", cwd=markers.within("repos")),
    ],
)

ROOT = pathlib.Path(".")


class TestSubcommands(unittest.TestCase):
    def accept(self, body: str) -> None:
        outcome = host_check(HEADER + body, "<t>", SUB_POLICY, ROOT)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def denials(self, body: str) -> list[str]:
        outcome = host_check(HEADER + body, "<t>", SUB_POLICY, ROOT)
        assert isinstance(outcome, Rejected), "expected a rejection"
        return [d.reason for d in outcome.denials]

    def test_a_listed_subcommand_is_accepted(self) -> None:
        self.accept(REPO + 'certora.exec("git", "log", cwd=repo)\n')

    def test_an_unlisted_subcommand_fails_closed(self) -> None:
        reasons = self.denials(REPO + 'certora.exec("git", "rebase", "-i", cwd=repo)\n')
        self.assertTrue(any("no declared subcommand" in r for r in reasons))

    def test_a_computed_subcommand_fails_closed(self) -> None:
        reasons = self.denials(
            "import sys\n" + REPO + 'sub = sys.argv[1]\ncertora.exec("git", sub, cwd=repo)\n'
        )
        self.assertTrue(any("no declared subcommand" in r for r in reasons))

    def test_a_literal_argument_is_discharged_by_running_the_checker(self) -> None:
        # the point of literal checkers: no assert dance around a plain literal
        self.accept(REPO + 'certora.exec("git", "push", "origin", "master", cwd=repo)\n')

    def test_a_flag_argument_is_denied(self) -> None:
        reasons = self.denials(REPO + 'certora.exec("git", "push", "origin", "--force", cwd=repo)\n')
        self.assertTrue(any("not validated by: not-force" in r for r in reasons))

    def test_an_unknown_argument_is_denied(self) -> None:
        reasons = self.denials(
            "import sys\n"
            + REPO
            + 'branch = sys.argv[1]\ncertora.exec("git", "push", "origin", branch, cwd=repo)\n'
        )
        self.assertTrue(any("not validated by: not-force" in r for r in reasons))

    def test_overlapping_subcommands_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Policy.allow(
                programs=[
                    program("git", subcommand="push", cwd="."),
                    program("git", subcommand="push origin", cwd="."),
                ]
            )

    def test_mixing_bare_and_subcommand_rules_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Policy.allow(
                programs=[
                    program("git", cwd="."),
                    program("git", subcommand="log", cwd="."),
                ]
            )

    def test_a_constant_cwd_discharges_via_the_checker(self) -> None:
        # "cwd is an org checkout" has no regex; for a constant cwd the evaluator itself runs at
        # check time, so the program needs no certora.check at all
        policy = Policy.allow(
            read=[markers.within(".")],
            write=[markers.within(".")],
            listing=[markers.within(".")],
            programs=[
                program("git", subcommand="log", cwd=markers.within("repos"), requires=["org-checkout"])
            ],
            validations=[
                validation(
                    "org-repo",
                    argv=("true",),
                    cwd=markers.within("repos"),
                    establishes={"cwd": [pure("org-checkout")]},
                    effect_free=True,
                )
            ],
        )
        source = HEADER + REPO + 'certora.exec("git", "log", cwd=repo)\n'
        with tempfile.TemporaryDirectory() as tmp:
            (pathlib.Path(tmp) / "repos" / "x").mkdir(parents=True)
            outcome = host_check(source, "<t>", policy, pathlib.Path(tmp))
        self.assertIsInstance(outcome, Accepted)

    def test_a_rely_is_discharged_by_running_the_checker(self) -> None:
        source = HEADER + (
            'def push_to(branch: typing.Annotated[str, certora.validated("not-force")]) -> None:\n'
            "    pass\n"
            'push_to("master")\n'
        )
        self.assertIsInstance(host_check(source, "<t>", SUB_POLICY, ROOT), Accepted)
        self.assertIsInstance(
            host_check(source.replace('"master"', '"--force"'), "<t>", SUB_POLICY, ROOT), Rejected
        )


# a cwd-free validation: not-force-check is a pure text predicate, so it declares no cwd --
# callers omit cwd=, no location is proven, and the policy asks nothing of the site
CWD_FREE_POLICY = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within(".")],
    listing=[markers.within(".")],
    validations=[
        validation(
            "not-force-check",
            argv=("test", param("value"), "!=", "--force"),
            params=("value",),
            establishes={"value": [pure("not-force")]},
            effect_free=True,
        )
    ],
    programs=[
        program(
            "git",
            subcommand="push origin",
            cwd=markers.within("repos"),
            argument_atoms=["not-force"],
            unknown_arguments=True,  # branch names are checked values, not literals: the opt-in
        )
    ],
)


class TestCwdFreeChecks(unittest.TestCase):
    def test_check_without_cwd_is_accepted_and_establishes(self) -> None:
        source = HEADER + (
            "import sys\n"
            "branch = sys.argv[1]\n"
            'certora.check("not-force-check", value=branch)\n'
            + REPO
            + 'certora.exec("git", "push", "origin", branch, cwd=repo)\n'
        )
        outcome = host_check(source, "<t>", CWD_FREE_POLICY, ROOT)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_the_vocabulary_marks_cwd_free_checks(self) -> None:
        self.assertFalse(
            CWD_FREE_POLICY.vocabulary().signatures[ValidationName("not-force-check")].needs_cwd
        )
        self.assertTrue(ORG_POLICY.vocabulary().signatures[ValidationName("org-repo")].needs_cwd)

    def test_a_cwd_free_check_cannot_establish_on_cwd(self) -> None:
        with self.assertRaises(ValueError):
            validation("v", argv=("true",), establishes={"cwd": ["atom-1"]})


class TestCheckSingle(unittest.TestCase):
    """certora.check_single: the functional check. The atoms ride the RESULT value."""

    def test_the_result_carries_the_atoms(self) -> None:
        source = HEADER + (
            "import sys\n"
            'branch = certora.check_single("not-force-check", sys.argv[1])\n'
            + REPO
            + 'certora.exec("git", "push", "origin", branch, cwd=repo)\n'
        )
        outcome = host_check(source, "<t>", CWD_FREE_POLICY, ROOT)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_the_argument_itself_gains_nothing(self) -> None:
        # the fact rides the returned value; a discarded result vouches for nobody
        source = HEADER + (
            "import sys\n"
            "raw = sys.argv[1]\n"
            'certora.check_single("not-force-check", raw)\n'
            + REPO
            + 'certora.exec("git", "push", "origin", raw, cwd=repo)\n'
        )
        outcome = host_check(source, "<t>", CWD_FREE_POLICY, ROOT)
        assert isinstance(outcome, Rejected)
        self.assertTrue(any("not validated" in d.reason for d in outcome.denials))

    def test_check_single_in_a_comprehension(self) -> None:
        source = HEADER + (
            "import sys\n"
            'branches: list[typing.Annotated[str, certora.validated("not-force")]] = '
            '[certora.check_single("not-force-check", s) for s in sys.argv[1:]]\n'
        )
        outcome = host_check(source, "<t>", CWD_FREE_POLICY, ROOT)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_an_effectful_check_establishes_nothing_in_a_comprehension(self) -> None:
        # iteration i+1's effectful evaluator kills what iteration i established: only
        # pure atoms accumulate across a comprehension (CONTAINERS.md)
        vocabulary = Policy.allow(
            validations=[
                validation(
                    "env-single",
                    argv=("probe", param("value")),
                    params=("value",),
                    establishes={"value": ["env-mark"]},
                )
            ]
        ).vocabulary()
        report = analyze(
            HEADER
            + "import sys\n"
            'ms: list[typing.Annotated[str, certora.validated("env-mark")]] = '
            '[certora.check_single("env-single", s) for s in sys.argv[1:]]\n',
            vocabulary=vocabulary,
        )
        self.assertTrue(
            any("comprehension element does not establish" in what for _, what in report.violations)
        )

    def test_shape_violations(self) -> None:
        report = analyze(
            HEADER + 'x = certora.check_single("nope", "v")\n',
            vocabulary=CWD_FREE_POLICY.vocabulary(),
        )
        self.assertTrue(
            any("declares no validation" in what for _, what in report.violations)
        )
        report = analyze(
            HEADER + 'x = certora.check_single("org-repo", "v")\n',
            vocabulary=ORG_POLICY.vocabulary(),
        )
        self.assertTrue(any("exactly one" in what for _, what in report.violations))


# unknown_arguments=False admits only vouched-for arguments: exactly-known text or a proven
# path. A computed str is a StrFact, not the None sentinel, and must not slip past the gate.
STRICT_POLICY = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within(".")],
    listing=[markers.within(".")],
    programs=[
        program(
            "git",
            cwd=markers.within("repos"),
            unknown_arguments=False,
            argument_locations=[markers.within("repos")],
        )
    ],
)


class TestUnknownArguments(unittest.TestCase):
    def accept(self, body: str) -> None:
        outcome = host_check(HEADER + body, "<t>", STRICT_POLICY, ROOT)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def denials(self, body: str) -> list[str]:
        outcome = host_check(HEADER + body, "<t>", STRICT_POLICY, ROOT)
        assert isinstance(outcome, Rejected), "expected a rejection"
        return [d.reason for d in outcome.denials]

    def test_a_proven_path_argument_is_vouched_for(self) -> None:
        self.accept(REPO + 'certora.exec("git", "log", repo / "src", cwd=repo)\n')

    def test_a_str_spelled_proven_path_is_vouched_for(self) -> None:
        self.accept(REPO + 'certora.exec("git", "log", str(repo), cwd=repo)\n')

    def test_a_laundered_string_is_denied(self) -> None:
        # str(p).strip() builds a fresh StrFact -- not None -- and used to slip past the gate
        reasons = self.denials(REPO + 'certora.exec("git", "log", str(repo).strip(), cwd=repo)\n')
        self.assertTrue(any("unknown provenance" in r for r in reasons))

    def test_an_f_string_is_denied(self) -> None:
        reasons = self.denials(
            "import sys\n"
            + REPO
            + 'certora.exec("git", "log", f"--author={sys.argv[1]}", cwd=repo)\n'
        )
        self.assertTrue(any("unknown provenance" in r for r in reasons))

    def test_locations_still_confine_paths_that_pass_the_gate(self) -> None:
        # orthogonality: a Located argument satisfies the gate but must lie within the
        # permitted argument locations
        reasons = self.denials(
            'other = pathlib.Path("elsewhere") / "y"\n'
            + REPO
            + 'certora.exec("git", "log", other, cwd=repo)\n'
        )
        self.assertTrue(any("outside the permitted locations" in r for r in reasons))


class TestRuntimeCheck(unittest.TestCase):
    """The runtime half of certora.check: tunneled to the broker, run host-side -- outside
    the jail, where whatever a validation consults actually lives."""

    @classmethod
    def setUpClass(cls) -> None:
        policy = Policy.allow(
            validations=[
                validation("always", argv=("true",), establishes={}),
                validation("never", argv=("false",), establishes={}),
                validation(
                    "nonempty",
                    argv=("test", "-n", param("what")),
                    params=("what",),
                    establishes={},
                ),
            ]
        )
        cls.root = pathlib.Path(tempfile.mkdtemp())
        cls.sock = os.path.join(tempfile.mkdtemp(), "broker.sock")
        cls.server = build_server(cls.sock, policy, cls.root)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        os.environ["CERTORAIL_BROKER_SOCKET"] = cls.sock

    @classmethod
    def tearDownClass(cls) -> None:
        os.environ.pop("CERTORAIL_BROKER_SOCKET", None)
        cls.server.shutdown()
        cls.server.server_close()

    def test_success_returns_none(self) -> None:
        self.assertIsNone(markers.check("always", cwd="."))

    def test_failure_raises(self) -> None:
        with self.assertRaises(CheckFailed):
            markers.check("never", cwd=".")

    def test_parameters_substitute_into_the_argv(self) -> None:
        self.assertIsNone(markers.check("nonempty", what="x"))
        with self.assertRaises(CheckFailed):
            markers.check("nonempty", what="")

    def test_unknown_validation_raises(self) -> None:
        with self.assertRaises(CheckFailed):
            markers.check("unregistered")

    def test_wrong_keywords_raise(self) -> None:
        with self.assertRaises(TypeError):
            markers.check("always", extra="x")

    def test_check_single_returns_the_value(self) -> None:
        self.assertEqual(markers.check_single("nonempty", "x"), "x")
        with self.assertRaises(CheckFailed):
            markers.check_single("nonempty", "")

    def test_check_single_demands_a_single_parameter(self) -> None:
        with self.assertRaises(TypeError):
            markers.check_single("always", "x")  # zero declared parameters


if __name__ == "__main__":
    unittest.main()
