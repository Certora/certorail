"""``path`` on a network rule: the URL's path, which the analysis already tracks (``UrlString``),
becomes a policy constraint -- statically on the proven path, and per hop at the broker,
percent-decoded."""
import unittest

from certorail import markers
from certorail.broker import PolicyDenied, _check
from certorail.describe import describe
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policy import Policy, network, path_permitted
from certorail.policyfile import PolicyFileError, from_data

HEADER = "import sys\nimport urllib.parse\n"

POLICY = Policy.allow(
    network=[
        network("api.github.com", methods=["GET"], path=markers.within("/repos")),
        network("uploads.github.com"),
    ],
)


class TestStatic(unittest.TestCase):
    def outcome(self, body: str):
        return host_check(HEADER + body, "<t>", POLICY)

    def accept(self, body: str) -> None:
        result = self.outcome(body)
        if isinstance(result, Rejected):
            self.fail("\n".join(result.describe("<t>")))

    def denial(self, body: str) -> str:
        result = self.outcome(body)
        assert isinstance(result, Rejected)
        return result.denials[0].reason

    def test_a_literal_inside_the_path(self) -> None:
        self.accept('certora.network.get("https://api.github.com/repos/certora/x")\n')

    def test_a_literal_outside_it(self) -> None:
        self.assertIn(
            "path /admin is outside the permitted /repos/**",
            self.denial('certora.network.get("https://api.github.com/admin")\n'),
        )

    def test_an_unproven_path_is_denied_when_the_rule_restricts(self) -> None:
        reason = self.denial(
            "u = sys.argv[1]\n"
            'if urllib.parse.urlsplit(u).scheme == "https" and urllib.parse.urlsplit(u).netloc == "api.github.com":\n'
            "    certora.network.get(u)\n"
        )
        self.assertIn("path is not proven", reason)
        self.assertIn("/repos/**", reason)

    def test_a_guarded_path_is_proven(self) -> None:
        # text guards first, then the URL reading: the ".." exclusion gates the prefix claim
        self.accept(
            "u = sys.argv[1]\n"
            'if ".." not in u and urllib.parse.urlsplit(u).path.startswith("/repos/") '
            'and urllib.parse.urlsplit(u).scheme == "https" '
            'and urllib.parse.urlsplit(u).netloc == "api.github.com":\n'
            "    certora.network.get(u)\n"
        )

    def test_a_rule_without_paths_admits_any(self) -> None:
        self.accept('certora.network.post("https://uploads.github.com/anything/at/all")\n')
        self.assertIsInstance(
            self.outcome(
                "u = sys.argv[1]\n"
                'if urllib.parse.urlsplit(u).scheme == "https" and urllib.parse.urlsplit(u).netloc == "uploads.github.com":\n'
                "    certora.network.get(u)\n"
            ),
            Accepted,
        )


class TestRuntime(unittest.TestCase):
    def test_the_broker_checks_the_decoded_path(self) -> None:
        _, host, _, _ = _check(POLICY, "GET", "https://api.github.com/repos/certora/x", True, None)
        self.assertEqual(host, "api.github.com")
        for url in (
            "https://api.github.com/admin",
            "https://api.github.com/repos/%2e%2e/admin",   # decodes to a ".." that escapes
            "https://api.github.com/",
        ):
            with self.subTest(url=url), self.assertRaises(PolicyDenied) as cm:
                _check(POLICY, "GET", url, True, None)
            self.assertIn("outside the permitted", str(cm.exception))
        _check(POLICY, "GET", "https://uploads.github.com/whatever", False, None)  # a hop, no paths

    def test_path_permitted(self) -> None:
        rule = POLICY.network[0]
        self.assertFalse(path_permitted(rule, None))
        self.assertTrue(path_permitted(POLICY.network[1], None))


class TestPolicySide(unittest.TestCase):
    def test_paths_are_server_absolute(self) -> None:
        with self.assertRaises(ValueError) as cm:
            network("api.github.com", path=markers.within("repos"))
        self.assertIn("server-absolute", str(cm.exception))

    def test_the_data_format(self) -> None:
        policy = from_data({
            "policy-version": 1,
            "network": [{"host": "api.github.com", "path": ["/repos/**", "/orgs/**"]}],
        })
        self.assertEqual(len(policy.network[0].paths), 2)
        with self.assertRaises(PolicyFileError) as cm:
            from_data({"policy-version": 1, "network": [{"host": "api.github.com", "path": "repos/**"}]})
        self.assertIn("server-absolute", str(cm.exception))

    def test_describe_shows_the_path(self) -> None:
        self.assertIn("- GET https://api.github.com; path within /repos/**", describe(POLICY, "p"))

    def test_a_path_scoped_source(self) -> None:
        # PROVENANCE.md's deferred item: a network source scoped by path
        policy = Policy.allow(
            network=[network("api.github.com", path=markers.within("/repos"), source="gh-repos")],
        )
        (entry,) = policy.vocabulary().sources.network
        self.assertEqual(entry[0], "api.github.com")
        self.assertEqual(entry[2], "gh-repos")
        self.assertEqual(len(entry[1]), 1)


if __name__ == "__main__":
    unittest.main()
