"""The network sink: ``certora.network.<method>(url, ...)`` sites, checked against the
policy's ``network`` rules -- statically here, and again by the broker at runtime."""
import unittest

from certorail import markers
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policy import (
    Policy,
    atom,
    network,
    param,
    program,
    pure,
    rechecked,
    validation,
)
from certorail.walker import analyze

HEADER = "import pathlib\n"

NET_POLICY = Policy.allow(
    network=[
        network("api.github.com", methods=["GET"]),
        network("uploads.github.com"),
    ],
)

# a policy where a network call sits between an environmental check and its use
KILL_POLICY = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within(".")],
    validations=[
        validation(
            "org-repo",
            argv=("check-org",),
            cwd=markers.within("repos"),
            establishes={"cwd": ["org-checkout"]},
        )
    ],
    programs=[program("git", subcommand="log", cwd=markers.within("repos"), requires=["org-checkout"])],
    network=[network("api.github.com")],
)


class TestNetworkSites(unittest.TestCase):
    def accept(self, body: str) -> None:
        outcome = host_check(HEADER + body, "<t>", NET_POLICY)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def denials(self, body: str) -> list[str]:
        outcome = host_check(HEADER + body, "<t>", NET_POLICY)
        assert isinstance(outcome, Rejected), "expected a rejection"
        return [d.reason for d in outcome.denials]

    def test_a_literal_url_is_accepted(self) -> None:
        self.accept('certora.network.get("https://api.github.com/repos/certora")\n')

    def test_an_explicit_default_port_is_the_default_port(self) -> None:
        self.accept('certora.network.get("https://api.github.com:443/repos")\n')

    def test_a_guarded_url_is_accepted(self) -> None:
        self.accept(
            "import sys\n"
            "import urllib.parse\n"
            "u = sys.argv[1]\n"
            'if urllib.parse.urlsplit(u).scheme == "https" and '
            'urllib.parse.urlsplit(u).netloc == "api.github.com":\n'
            "    certora.network.get(u)\n"
        )

    def test_an_unproven_url_is_denied(self) -> None:
        reasons = self.denials("import sys\ncertora.network.get(sys.argv[1])\n")
        self.assertTrue(any("not proven" in r for r in reasons))

    def test_an_unlisted_host_is_denied(self) -> None:
        reasons = self.denials('certora.network.get("https://evil.com/x")\n')
        self.assertTrue(any("matches no network rule" in r for r in reasons))

    def test_the_method_is_policed(self) -> None:
        reasons = self.denials('certora.network.post("https://api.github.com/x")\n')
        self.assertTrue(any("POST" in r and "matches no network rule" in r for r in reasons))
        # the uploads rule names no methods: any method goes
        self.accept('certora.network.post("https://uploads.github.com/x")\n')

    def test_an_off_port_is_denied(self) -> None:
        reasons = self.denials('certora.network.get("https://api.github.com:8443/x")\n')
        self.assertTrue(any("matches no network rule" in r for r in reasons))

    def test_http_needs_its_own_grant(self) -> None:
        reasons = self.denials('certora.network.get("http://api.github.com/")\n')
        self.assertTrue(any("matches no network rule" in r for r in reasons))

    def test_keywords_are_closed(self) -> None:
        report = analyze(
            HEADER + 'certora.network.get("https://api.github.com/", verify=False)\n',
            vocabulary=NET_POLICY.vocabulary(),
        )
        self.assertTrue(any("not admissible" in what for _, what in report.violations))

    def test_body_rides_only_body_methods(self) -> None:
        report = analyze(
            HEADER + 'certora.network.get("https://api.github.com/", body=b"x")\n',
            vocabulary=NET_POLICY.vocabulary(),
        )
        self.assertTrue(any("not admissible for get" in what for _, what in report.violations))

    def test_a_network_call_kills_environment_checks(self) -> None:
        request = 'certora.network.get("https://api.github.com/z")\n'
        source = HEADER + (
            'repo = pathlib.Path("repos") / "x"\n'
            'certora.check("org-repo", cwd=repo)\n'
            + request
            + 'certora.exec("git", "log", cwd=repo)\n'
        )
        outcome = host_check(source, "<t>", KILL_POLICY)
        assert isinstance(outcome, Rejected), "expected a rejection"
        self.assertTrue(any("not validated" in d.reason for d in outcome.denials))
        # without the network call in between, the check survives to the exec
        self.assertIsInstance(
            host_check(source.replace(request, ""), "<t>", KILL_POLICY), Accepted
        )


# atom-gated network access: the endpoint alone is not enough, the URL value must carry the
# atom -- discharged from an exactly-known URL's text, or established by a live check
REQ_POLICY = Policy.allow(
    atoms=[
        atom(
            "not-prod-db",
            markers.matches(r"https://cloud-api\.provider\.com/db/(dev|staging)(/[\w/.]*)?"),
        )
    ],
    validations=[
        validation(
            "not-prod-check",
            argv=("test-not-prod", param("value")),
            params=("value",),
            establishes={"value": ["not-prod-db"]},
            writes=[],
        )
    ],
    network=[network("cloud-api.provider.com", requires=["not-prod-db"])],
)


class TestNetworkRequires(unittest.TestCase):
    def outcome(self, body: str):
        return host_check(HEADER + body, "<t>", REQ_POLICY)

    def test_a_literal_url_discharges_the_atom(self) -> None:
        outcome = self.outcome(
            'certora.network.get("https://cloud-api.provider.com/db/staging/tables")\n'
        )
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_a_literal_url_outside_the_atom_is_denied(self) -> None:
        outcome = self.outcome(
            'certora.network.get("https://cloud-api.provider.com/db/prod/tables")\n'
        )
        assert isinstance(outcome, Rejected)
        self.assertTrue(
            any("not validated by: not-prod-db" in d.reason for d in outcome.denials)
        )

    def test_a_checked_dynamic_url_is_accepted(self) -> None:
        outcome = self.outcome(
            "import sys\n"
            "import urllib.parse\n"
            "u = sys.argv[1]\n"
            'if urllib.parse.urlsplit(u).scheme == "https" and '
            'urllib.parse.urlsplit(u).netloc == "cloud-api.provider.com":\n'
            '    certora.check("not-prod-check", value=u)\n'
            "    certora.network.get(u)\n"
        )
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))

    def test_an_unchecked_dynamic_url_is_denied(self) -> None:
        outcome = self.outcome(
            "import sys\n"
            "import urllib.parse\n"
            "u = sys.argv[1]\n"
            'if urllib.parse.urlsplit(u).scheme == "https" and '
            'urllib.parse.urlsplit(u).netloc == "cloud-api.provider.com":\n'
            "    certora.network.get(u)\n"
        )
        assert isinstance(outcome, Rejected)
        self.assertTrue(
            any("not validated by: not-prod-db" in d.reason for d in outcome.denials)
        )

    def test_textual_atoms_default_to_recheck(self) -> None:
        (rule,) = REQ_POLICY.network
        (ra,) = rule.requires
        self.assertEqual(ra.on_redirect, "recheck")

    def test_non_textual_atoms_default_to_stopping_redirects(self) -> None:
        # "not a production database" needs the inventory: nothing the broker re-checks
        pol = Policy.allow(
            validations=[
                validation(
                    "prod-inventory-check",
                    argv=("query-inventory", param("value")),
                    params=("value",),
                    establishes={"value": [pure("vetted")]},
                )
            ],
            network=[network("cloud-api.provider.com", requires=["vetted"])],
        )
        (rule,) = pol.network
        (ra,) = rule.requires
        self.assertEqual(ra.on_redirect, "stop")

    def test_explicit_recheck_of_a_non_textual_atom_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Policy.allow(
                validations=[
                    validation(
                        "envcheck",
                        argv=("probe",),
                        cwd=".",
                        establishes={"cwd": ["env-atom"]},
                    )
                ],
                network=[network("a.com", requires=[rechecked("env-atom")])],
            )


if __name__ == "__main__":
    unittest.main()
