"""``certorail explain``: the account a rejected program gives of itself.

The angle is the structure, not the printed text -- ``explain()`` is a pure function from a source
and a policy to an ``Explanation``, so almost nothing here captures stdout. What is asserted is
the cause each denial carries, the schema path each policy remedy names, and the two channels
every finding offers.
"""
import contextlib
import io
import json
import os
import pathlib
import tempfile
import tomllib
import unittest

from certorail import markers
from certorail.analysis import (
    Concat,
    DirSplat,
    Exact,
    Matching,
    Named,
    RegexLit,
    StaticPath,
    location_le,
)
from certorail.explain import (
    Edit,
    Explanation,
    enclosing_spelling,
    explain,
    policy_spelling,
    remedies_for,
    render,
    to_json,
)
from certorail.host import main
from certorail.policy import (
    ArgumentMissingAtoms,
    CheckCwdOutside,
    CwdMissingAtoms,
    CwdOutside,
    EndpointUnmatched,
    ExecDenied,
    NotPermitted,
    Policy,
    UndeclaredValidation,
    UnknownProgram,
    Unproven,
    atom,
    network,
    program,
    validation,
)
from certorail.policyfile import from_data, parse_location
from certorail.walker import CheckSite, analyze

HEADER = "import pathlib\nimport sys\n"
REPO = 'repo = pathlib.Path("repos") / "x"\n'
ELSEWHERE = 'y = pathlib.Path("elsewhere") / "y"\n'

ROOT = pathlib.Path(tempfile.mkdtemp()).resolve()
(ROOT / "data").mkdir(exist_ok=True)
(ROOT / "repos" / "x").mkdir(parents=True, exist_ok=True)

POLICY = Policy.allow(
    read=[markers.within("data")],
    write=[markers.within("reports")],
    listing=[markers.within("data")],
    atoms=[atom("no-flag", markers.matches(r"[^-].*"))],
    programs=[
        program(
            "git",
            cwd=markers.within("repos"),
            subcommand="log",
            argument_atoms=["no-flag"],
        )
    ],
    validations=[
        validation(
            "org-repo",
            argv=("true",),
            cwd=markers.within("repos"),
            establishes={"cwd": ["org-checkout"]},
        )
    ],
    network=[network("api.example.com", methods=["GET"])],
)

# a second policy whose exec rule wants an opaque atom on its cwd -- one no regex can define, so
# only a live certora.check establishes it
OPAQUE_POLICY = Policy.allow(
    read=[markers.within("data")],
    programs=[program("git", cwd=markers.within("repos"), requires=["org-checkout"])],
    validations=[
        validation(
            "org-repo",
            argv=("true",),
            cwd=markers.within("repos"),
            establishes={"cwd": ["org-checkout"]},
        )
    ],
)


def explained(body: str, policy: Policy = POLICY) -> Explanation:
    return explain(body, "<t>", policy, ROOT)


def policy_edits(explanation: Explanation) -> list[Edit]:
    return [
        r.edit
        for f in explanation.findings
        for r in f.remedies
        if r.channel == "policy" and r.edit is not None
    ]


def channel_text(explanation: Explanation, channel: str) -> str:
    return " | ".join(
        r.text for f in explanation.findings for r in f.remedies if r.channel == channel
    )


class TestViolations(unittest.TestCase):
    def test_a_subset_violation_is_explained(self) -> None:
        e = explained("from os import path\n")
        self.assertFalse(e.accepted)
        self.assertEqual(len(e.findings), 1)
        finding = e.findings[0]
        self.assertEqual(finding.kind, "violation")
        self.assertEqual(finding.what, "imports")
        self.assertEqual(finding.reason, "import from")
        self.assertEqual(finding.span.source, "from os import path")
        # a subset rule is not configurable, so the policy channel offers no edit at all
        self.assertEqual(policy_edits(e), [])
        self.assertEqual({r.channel for r in finding.remedies}, {"policy", "program"})

    def test_each_pass_names_itself(self) -> None:
        # the phase is plumbed at six different early returns; three of them, spot-checked
        for source, phase in (
            ("def f():\n    global x\n    x = 1\n", "lexical"),
            (HEADER + "class A(pathlib.Path):\n    pass\n", "inheritance"),
            (HEADER + REPO + 'certora.check("nope", cwd=repo)\n', "dataflow"),
        ):
            with self.subTest(phase=phase):
                e = explained(source)
                self.assertEqual(e.phase, phase)
                self.assertEqual(e.findings[0].what, phase)

    def test_the_render_says_the_policy_never_ran(self) -> None:
        self.assertIn("the policy was not evaluated", render(explained("from os import path\n")))


class TestDenials(unittest.TestCase):
    def test_an_unproven_location_names_no_policy_edit(self) -> None:
        e = explained(HEADER + "p = pathlib.Path(sys.argv[1])\np.read_text()\n")
        self.assertEqual(e.findings[0].cause, Unproven("path"))
        self.assertEqual(policy_edits(e), [])
        self.assertIn("guard", channel_text(e, "program"))

    def test_a_denied_read_gives_the_smallest_allowance(self) -> None:
        e = explained(HEADER + 'pathlib.Path("elsewhere").read_text()\n')
        cause = e.findings[0].cause
        assert isinstance(cause, NotPermitted)
        self.assertEqual(cause.kind, "read")
        self.assertEqual(policy_edits(e), [Edit("filesystem.read", "elsewhere", widens=False)])

    def test_an_unknown_program_is_a_new_rule(self) -> None:
        e = explained(HEADER + REPO + 'certora.exec("gh", "repo", "view", cwd=repo)\n')
        self.assertEqual(e.findings[0].cause, UnknownProgram("gh"))
        edit = policy_edits(e)[0]
        self.assertEqual(edit.path, "program")
        self.assertIn('name       = "gh"', edit.add)
        self.assertIn("git", channel_text(e, "policy"))

    def test_a_program_rule_denial_names_the_rule(self) -> None:
        e = explained(HEADER + ELSEWHERE + 'certora.exec("git", "log", cwd=y)\n')
        cause = e.findings[0].cause
        assert isinstance(cause, ExecDenied)
        self.assertEqual(len(cause.mismatches), 1)
        self.assertEqual(cause.mismatches[0].rule_index, 0)
        self.assertIsInstance(cause.mismatches[0].detail, CwdOutside)
        self.assertEqual(policy_edits(e)[0].path, "program[0].cwd")

    def test_an_undischarged_defined_atom_names_its_regex(self) -> None:
        e = explained(HEADER + REPO + 'certora.exec("git", "log", "--oneline", cwd=repo)\n')
        cause = e.findings[0].cause
        assert isinstance(cause, ExecDenied)
        detail = cause.mismatches[0].detail
        self.assertEqual(detail, ArgumentMissingAtoms(2, frozenset({"no-flag"})))
        self.assertIn(r"[^-].*", channel_text(e, "program"))
        self.assertEqual(policy_edits(e)[0].path, "program[0].argument-atoms")

    def test_an_undischarged_opaque_atom_names_its_validation(self) -> None:
        e = explained(HEADER + REPO + 'certora.exec("git", cwd=repo)\n', OPAQUE_POLICY)
        cause = e.findings[0].cause
        assert isinstance(cause, ExecDenied)
        self.assertEqual(
            cause.mismatches[0].detail, CwdMissingAtoms(frozenset({"org-checkout"}))
        )
        self.assertIn('certora.check("org-repo"', channel_text(e, "program"))
        self.assertEqual(policy_edits(e)[0].path, "program[0].requires")

    def test_an_unmatched_endpoint_proposes_a_network_rule(self) -> None:
        e = explained(HEADER + 'certora.network.get("https://api.other.com/x")\n')
        self.assertEqual(
            e.findings[0].cause, EndpointUnmatched("GET", "https", "api.other.com", 443)
        )
        edit = policy_edits(e)[0]
        self.assertEqual(edit.path, "network")
        self.assertIn('host    = "api.other.com"', edit.add)
        # https on 443 is what a rule means by default, so neither line is emitted
        self.assertNotIn("schemes", edit.add)
        self.assertNotIn("ports", edit.add)

    def test_a_near_miss_network_rule_names_the_failing_clause(self) -> None:
        e = explained(HEADER + 'certora.network.post("https://api.example.com/x", body=b"")\n')
        paths = [edit.path for edit in policy_edits(e)]
        self.assertIn("network[0]", paths)
        self.assertIn("methods", channel_text(e, "policy"))

    def test_a_check_outside_its_cwd_widens_the_validation(self) -> None:
        e = explained(HEADER + ELSEWHERE + 'certora.check("org-repo", cwd=y)\n')
        cause = e.findings[0].cause
        assert isinstance(cause, CheckCwdOutside)
        self.assertEqual(cause.name, "org-repo")
        self.assertEqual(policy_edits(e)[0].path, "validation[0].cwd")


# a validation that takes one parameter and declares a cwd: check_single must then be called with
# cwd=, so the snippet a remedy prints has to carry it
VETTING_POLICY = Policy.allow(
    read=[markers.within("repos")],
    programs=[
        program("cat", cwd=markers.within("repos"), argument_atoms=["vetted"])
    ],
    validations=[
        validation(
            "vet",
            params=("value",),
            argv=("true", "${value}"),
            cwd=markers.within("repos"),
            establishes={"value": ["vetted"]},
        )
    ],
)


class TestRemediesAreRunnable(unittest.TestCase):
    """A program-channel snippet is advice a model pastes, so it has to survive the next run."""

    def test_check_single_carries_the_cwd_its_validation_declares(self) -> None:
        body = HEADER + REPO + 'value = "notes.txt"\ncertora.exec("cat", value, cwd=repo)\n'
        e = explained(body, VETTING_POLICY)
        self.assertIn("check_single(\"vet\", value, cwd=", channel_text(e, "program"))

        followed = (
            HEADER
            + REPO
            + 'value = "notes.txt"\n'
            + 'value = certora.check_single("vet", value, cwd=repo)\n'
            + 'certora.exec("cat", value, cwd=repo)\n'
        )
        self.assertTrue(explained(followed, VETTING_POLICY).accepted)

    def test_a_new_network_rule_names_the_method_the_site_used(self) -> None:
        # an omitted "methods" reads as any method, which is not what one POST asked for
        e = explained(HEADER + 'certora.network.post("https://api.other.com/x", body=b"")\n')
        edit = next(edit for edit in policy_edits(e) if edit.path == "network")
        self.assertIn('methods = ["POST"]', edit.add)
        self.assertEqual(edit.op, "add")

    def test_every_edit_says_what_to_do_with_its_text(self) -> None:
        # a consumer applies edit.add at edit.path according to edit.op, and never reads English
        # out of add; "remove" carries names, "note" carries nothing
        removal = explained(
            HEADER + REPO + 'certora.exec("git", "log", "--oneline", cwd=repo)\n'
        )
        edit = next(e for e in policy_edits(removal) if e.path == "program[0].argument-atoms")
        self.assertEqual((edit.op, edit.add), ("remove", "no-flag"))

        near_miss = explained(
            HEADER + 'certora.network.post("https://api.example.com/x", body=b"")\n'
        )
        note = next(e for e in policy_edits(near_miss) if e.path == "network[0]")
        self.assertEqual((note.op, note.add), ("note", ""))


SUBCOMMAND_DOCUMENT = """policy-version = 1

[filesystem]
read = ["data/**"]

[[program]]
name       = "git"
subcommand = "log"
cwd        = "repos/**"
"""


class TestSuggestedBlocksLoad(unittest.TestCase):
    """A ``[[program]]`` block a remedy prints is only a remedy if the policy loader accepts it.

    ``Policy.allow`` refuses the whole document when one program name mixes a bare rule with
    subcommand rules, or when two of its subcommands are prefix-related -- so a suggestion that
    trips either would stop every program under that policy from being checked."""

    def setUp(self) -> None:
        self.base = from_data(tomllib.loads(SUBCOMMAND_DOCUMENT), "<base>")

    def emitted_block(self, body: str, policy: Policy) -> str | None:
        edits = [edit for edit in policy_edits(explained(body, policy)) if edit.path == "program"]
        return edits[0].add if edits else None

    def test_the_block_it_prints_parses_and_permits_the_site(self) -> None:
        body = HEADER + REPO + 'certora.exec("git", "status", cwd=repo)\n'
        block = self.emitted_block(body, self.base)
        assert block is not None
        # raises if the suggested rule cannot coexist with the one already declared
        amended = from_data(tomllib.loads(SUBCOMMAND_DOCUMENT + "\n" + block), "<amended>")
        self.assertIn("status", [" ".join(r.subcommand) for r in amended.programs])
        self.assertTrue(explained(body, amended).accepted)

    def test_a_computed_subcommand_gets_prose_and_no_block(self) -> None:
        # the leading argument is not literal, and a rule with subcommand = "" is a bare rule,
        # which the loader refuses to mix with the declared subcommands
        body = HEADER + REPO + 'certora.exec("git", sys.argv[1], cwd=repo)\n'
        self.assertIsNone(self.emitted_block(body, self.base))
        self.assertIn("not literals", channel_text(explained(body, self.base), "policy"))

    def test_a_subcommand_that_would_overlap_gets_prose_and_no_block(self) -> None:
        overlapping = Policy.allow(
            read=[markers.within("data")],
            programs=[program("git", cwd=markers.within("repos"), subcommand="remote add")],
        )
        e = explained(HEADER + REPO + 'certora.exec("git", "remote", cwd=repo)\n', overlapping)
        self.assertEqual(policy_edits(e), [])
        self.assertIn("overlap", channel_text(e, "policy"))


class TestUndeclaredValidation(unittest.TestCase):
    """The lexical pass rejects an undeclared ``certora.check`` before the policy is consulted, so
    this denial is unreachable through ``check``; its remedy is exercised directly."""

    def test_the_remedy_proposes_a_validation_block(self) -> None:
        report = analyze(
            HEADER + REPO + 'certora.check("org-repo", cwd=repo)\n',
            "<t>",
            POLICY.vocabulary(),
        )
        site = next(s for s in report.sinks if isinstance(s, CheckSite))
        remedies = remedies_for(POLICY, site, UndeclaredValidation("missing"))
        edit = next(r.edit for r in remedies if r.channel == "policy")
        assert edit is not None
        self.assertEqual(edit.path, "validation")
        self.assertIn('name = "missing"', edit.add)
        self.assertIn("org-repo", next(r.text for r in remedies if r.channel == "policy"))


class TestAccepted(unittest.TestCase):
    def test_an_accepted_program_says_so(self) -> None:
        e = explained(HEADER + '(pathlib.Path("data") / "f.txt").read_text()\n')
        self.assertTrue(e.accepted)
        self.assertEqual(e.findings, ())
        self.assertTrue(e.sites)
        self.assertTrue(render(e).splitlines()[0].endswith(": accepted"))


class TestSites(unittest.TestCase):
    def test_the_site_inventory_survives_a_rejection(self) -> None:
        e = explained(HEADER + ELSEWHERE + 'certora.exec("git", "log", cwd=y)\n')
        self.assertEqual(len(e.sites), 1)
        # the cwd IS proven, so the analysis confined it; the policy denied it anyway
        self.assertTrue(e.sites[0].confined)
        self.assertTrue(e.sites[0].denied)

    def test_a_lexical_rejection_has_no_sites_at_all(self) -> None:
        e = explained("from os import path\n")
        self.assertEqual(e.sites, ())
        self.assertIn("sites (0):", render(e))


class TestSpelling(unittest.TestCase):
    def test_the_spelling_round_trips(self) -> None:
        for text in (
            ".",
            "data/x",
            "repos/**",
            "repos/*/foundry.toml",
            "/srv/data/**",
            "{a,b}/x",
            r"repos/**/<\w+\.tar>",
        ):
            with self.subTest(text=text):
                self.assertEqual(policy_spelling(parse_location(text)), text)

    def test_an_unspellable_component_falls_back_to_a_wider_splat(self) -> None:
        built = Matching(Concat([Exact("a"), RegexLit(r"\d+")]))
        loc = StaticPath((Named("repos"), built))
        self.assertIsNone(policy_spelling(loc))
        enclosing = enclosing_spelling(loc)
        self.assertTrue(enclosing.endswith("**"))
        self.assertTrue(location_le(loc, parse_location(enclosing)))

    def test_a_splat_leaf_the_grammar_cannot_write_is_unspellable(self) -> None:
        loc = DirSplat((Named("repos"),), Matching(Concat([Exact("a"), RegexLit(r"\d+")])))
        self.assertIsNone(policy_spelling(loc))
        self.assertTrue(location_le(loc, parse_location(enclosing_spelling(loc))))


class TestJson(unittest.TestCase):
    def test_the_document_is_serialisable_and_stable(self) -> None:
        e = explained(HEADER + REPO + 'certora.exec("git", "log", "--oneline", cwd=repo)\n')
        first = json.dumps(to_json(e), indent=2)
        self.assertEqual(first, json.dumps(to_json(e), indent=2))
        self.assertNotIn("ast.", first)
        self.assertNotIn("frozenset", first)

    def test_the_json_carries_one_entry_per_finding(self) -> None:
        e = explained(HEADER + 'pathlib.Path("elsewhere").read_text()\n')
        doc = to_json(e)
        self.assertEqual(len(doc["findings"]), len(e.findings))
        for entry in doc["findings"]:
            self.assertIn("where", entry)
            self.assertIn("operation", entry)
            self.assertIn("reason", entry)
            self.assertIn("kind", entry["cause"])
            self.assertTrue(entry["remedies"])

    def test_atom_sets_are_sorted_lists(self) -> None:
        e = explained(HEADER + REPO + 'certora.exec("git", "log", "--oneline", cwd=repo)\n')
        detail = to_json(e)["findings"][0]["cause"]["mismatches"][0]["detail"]
        self.assertEqual(detail["missing"], ["no-flag"])


class TestExplainCli(unittest.TestCase):
    def setUp(self) -> None:
        # without this the run picks up whatever ambient policy the developer has installed
        self.config = tempfile.TemporaryDirectory()
        self.addCleanup(self.config.cleanup)
        os.environ["CERTORAIL_CONFIG_DIR"] = self.config.name
        self.addCleanup(os.environ.pop, "CERTORAIL_CONFIG_DIR", None)

    def test_explain_accepts(self) -> None:
        self.assertEqual(main(["explain", "-c", "x = 1 + 1\n"]), 0)

    def test_explain_rejects(self) -> None:
        self.assertEqual(main(["explain", "-c", "from os import path\n"]), 1)

    def test_explain_reports_a_syntax_error(self) -> None:
        self.assertEqual(main(["explain", "-c", "def (\n"]), 2)

    def test_explain_refuses_run_only_flags(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            main(["explain", "-c", "x = 1\n", "--no-jail"])
        self.assertEqual(cm.exception.code, 2)

    def test_explain_needs_exactly_one_source(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            main(["explain"])
        self.assertEqual(cm.exception.code, 2)

    def test_a_file_argument_works(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            prog = pathlib.Path(tmp) / "p.py"
            prog.write_text("x = 1\n", encoding="utf-8")
            self.assertEqual(main(["explain", str(prog), "--root", tmp]), 0)

    def test_the_ordinary_cli_still_works(self) -> None:
        # guards the hand-rolled subcommand dispatch
        self.assertEqual(main(["-c", "x = 1 + 1\n", "--check"]), 0)

    def test_json_puts_one_document_on_stdout(self) -> None:
        # the one stdout-capturing test here: "one document on stdout, in both verdicts" is the
        # contract a consuming tool relies on, and it cannot be checked any other way
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = main(["explain", "-c", "from os import path\n", "--json"])
        self.assertEqual(code, 1)
        doc = json.loads(captured.getvalue())
        self.assertFalse(doc["accepted"])
        self.assertEqual(doc["certorail"], 1)


if __name__ == "__main__":
    unittest.main()
