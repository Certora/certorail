"""The TOML/JSON policy documents: the location micro-syntax, the strict schema, and the
host's loader dispatch. The full-document test pins the equivalence between a document and its
Python-API spelling."""
import json
import pathlib
import tempfile
import textwrap
import tomllib
import unittest

from certorail import markers
from certorail.analysis import (
    ANY_NAME,
    DirSplat,
    Matching,
    Named,
    OneOf,
    RegexLit,
    StaticPath,
    pretty_location,
)
from certorail.host import load_policy
from certorail.policy import (
    Policy,
    RequiredAtom,
    atom,
    network,
    param,
    program,
    pure,
    validation,
)
from certorail.policyfile import PolicyFileError, from_data, load_policy_file, parse_location


def loads(text: str) -> Policy:
    return from_data(tomllib.loads(textwrap.dedent(text)), "<test>")


class TestParseLocation(unittest.TestCase):
    CASES = {
        ".": StaticPath(()),
        "**": DirSplat((), ANY_NAME),
        "data/x": StaticPath((Named("data"), Named("x"))),
        "repos/**": DirSplat((Named("repos"),), ANY_NAME),
        "repos/**/x.tar": DirSplat((Named("repos"),), Named("x.tar")),
        r"repos/**/<\w+\.tar>": DirSplat((Named("repos"),), Matching(RegexLit(r"\w+\.tar"))),
        "repos/{2025,2026}/x": StaticPath(
            (Named("repos"), OneOf(frozenset({"2025", "2026"})), Named("x"))
        ),
        "*/x": StaticPath((ANY_NAME, Named("x"))),
        "<a/b>/x": StaticPath((Matching(RegexLit("a/b")), Named("x"))),
    }

    def test_the_compact_spellings(self) -> None:
        for text, expected in self.CASES.items():
            with self.subTest(text=text):
                self.assertEqual(parse_location(text), expected)

    def test_round_trip_with_the_report_spelling(self) -> None:
        # regex components print differently in reports; everything else round-trips
        for text, loc in self.CASES.items():
            if "<" in text:
                continue
            with self.subTest(text=text):
                self.assertEqual(parse_location(pretty_location(loc)), loc)

    def test_malformed_spellings(self) -> None:
        for text in (
            "//abs", "a//b", "a/../b", "..", "**/a/b", "a/**/**",
            "<unclosed", "{}/x", "{a,/b}/x",
        ):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    parse_location(text)


DOCUMENT = """\
policy-version = 1

[filesystem]
read  = ["**"]
write = ["repos/**"]
list  = ["repos/**"]

[atoms]
org-checkout = {}
not-force    = { pure = true }
no-flag      = { matches = '[^-].*' }

[[validation]]
name        = "not-force-check"
params      = ["value"]
argv        = ["test", "${value}", "!=", "--force"]
cwd         = "**"
effect-free = true
establishes = { value = ["not-force"] }

[[validation]]
name        = "org-repo"
argv        = ["check-org", "certora"]
cwd         = "repos/**"
establishes = { cwd = ["org-checkout"] }

[[program]]
name           = "git"
subcommand     = "push origin"
cwd            = "repos/**"
requires       = ["org-checkout"]
argument-atoms = ["not-force"]

[[program]]
name       = "git"
subcommand = "log"
cwd        = "repos/**"
"""

EXPECTED = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within("repos")],
    listing=[markers.within("repos")],
    atoms=[atom("no-flag", markers.matches(r"[^-].*"))],
    validations=[
        validation(
            "not-force-check",
            argv=("test", param("value"), "!=", "--force"),
            cwd=markers.within("."),
            params=("value",),
            establishes={"value": [pure("not-force")]},
            effect_free=True,
        ),
        validation(
            "org-repo",
            argv=("check-org", "certora"),
            cwd=markers.within("repos"),
            establishes={"cwd": ["org-checkout"]},
        ),
    ],
    programs=[
        program(
            "git",
            subcommand="push origin",
            cwd=markers.within("repos"),
            requires=["org-checkout"],
            argument_atoms=["not-force"],
            unknown_arguments=False,
        ),
        program("git", subcommand="log", cwd=markers.within("repos"), unknown_arguments=False),
    ],
)


class TestPolicyDocument(unittest.TestCase):
    def test_the_document_equals_its_python_spelling(self) -> None:
        self.assertEqual(from_data(tomllib.loads(DOCUMENT), "<test>"), EXPECTED)

    def test_json_is_the_same_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "policy.json"
            p.write_text(json.dumps(tomllib.loads(DOCUMENT)))
            self.assertEqual(load_policy_file(p), EXPECTED)

    def test_the_host_loads_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "policy.toml"
            p.write_text(DOCUMENT)
            self.assertEqual(load_policy(p), EXPECTED)


class TestStrictness(unittest.TestCase):
    def err(self, text: str) -> str:
        with self.assertRaises(PolicyFileError) as caught:
            loads(text)
        return str(caught.exception)

    def test_version_is_required(self) -> None:
        self.assertIn("policy-version", self.err("[filesystem]\nread = []\n"))

    def test_unknown_keys_fail_closed(self) -> None:
        msg = self.err(
            'policy-version = 1\n[[program]]\nname = "git"\ncwd = "."\nrequries = ["x"]\n'
        )
        self.assertIn("requries", msg)

    def test_undeclared_atoms_are_errors(self) -> None:
        msg = self.err(
            'policy-version = 1\n[[program]]\nname = "git"\ncwd = "."\nrequires = ["org-chekout"]\n'
        )
        self.assertIn("org-chekout", msg)

    def test_embedded_parameter_references_are_errors(self) -> None:
        msg = self.err(
            "policy-version = 1\n"
            "[atoms]\nok = { pure = true }\n"
            '[[validation]]\nname = "v"\nparams = ["x"]\n'
            'argv = ["p", "--flag=${x}"]\ncwd = "."\nestablishes = { x = ["ok"] }\n'
        )
        self.assertIn("whole arguments", msg)

    def test_a_defined_atom_cannot_be_declared_impure(self) -> None:
        msg = self.err("policy-version = 1\n[atoms]\nbad = { pure = false, matches = 'x' }\n")
        self.assertIn("pure by construction", msg)

    def test_every_problem_is_reported(self) -> None:
        # "/abs" is a valid (absolute) location these days; ".." is still malformed
        msg = self.err('policy-version = 3\n[[program]]\nname = "git"\ncwd = ".."\n')
        self.assertIn("unsupported", msg)
        self.assertIn("cwd", msg)

    def test_bad_toml_is_wrapped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / "policy.toml"
            p.write_text("policy-version = \n")
            with self.assertRaises(PolicyFileError):
                load_policy_file(p)


class TestNetworkTables(unittest.TestCase):
    def test_network_rules_load(self) -> None:
        pol = loads("""
            policy-version = 1

            [[network]]
            host    = "api.github.com"
            methods = ["get"]

            [[network]]
            host            = "*.example.com"
            schemes         = ["http", "https"]
            ports           = [8080]
            allow-nonpublic = true
            read-timeout    = 30
        """)
        self.assertEqual(
            pol.network,
            (
                network("api.github.com", methods=["GET"]),
                network(
                    "*.example.com",
                    schemes=["http", "https"],
                    ports=[8080],
                    allow_nonpublic=True,
                    read_timeout=30.0,
                ),
            ),
        )

    def test_unknown_network_keys_are_errors(self) -> None:
        with self.assertRaises(PolicyFileError):
            loads('policy-version = 1\n[[network]]\nhost = "a.com"\nmethod = ["GET"]\n')

    def test_network_requires_with_redirect_modes(self) -> None:
        pol = loads("""
            policy-version = 1

            [atoms]
            not-prod = { matches = 'https://x.com/db/(dev|staging)' }
            vetted   = { pure = true }

            [[network]]
            host     = "x.com"
            requires = ["not-prod", { atom = "vetted", on-redirect = "waive" }]
        """)
        (rule,) = pol.network
        self.assertEqual(
            rule.requires,
            frozenset({RequiredAtom("not-prod", "recheck"), RequiredAtom("vetted", "waive")}),
        )

    def test_a_bad_redirect_mode_is_an_error(self) -> None:
        with self.assertRaises(PolicyFileError):
            loads(
                "policy-version = 1\n"
                "[atoms]\nvetted = { pure = true }\n"
                '[[network]]\nhost = "a.com"\n'
                'requires = [{ atom = "vetted", on-redirect = "sometimes" }]\n'
            )


class TestCwdFreeValidations(unittest.TestCase):
    def test_a_validation_without_cwd_is_cwd_free(self) -> None:
        pol = loads("""
            policy-version = 1

            [atoms]
            not-force = { pure = true }

            [[validation]]
            name        = "not-force-check"
            params      = ["value"]
            argv        = ["test", "${value}", "!=", "--force"]
            effect-free = true
            establishes = { value = ["not-force"] }
        """)
        (v,) = pol.validations
        self.assertIsNone(v.cwd)
        self.assertFalse(pol.vocabulary().signatures["not-force-check"].needs_cwd)


if __name__ == "__main__":
    unittest.main()
