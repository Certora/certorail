"""A response's source atoms come from the one rule governing the request -- scheme, port,
method and path included -- never from a different rule that merely shares the host."""
import unittest

from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policyfile import from_data

POLICY = from_data({
    "policy-version": 1,
    "filesystem": {"read": ["**"]},
    "atoms": {"trusted": {"pure": True}},
    "network": [
        {"host": "api.example.com", "methods": ["GET"], "path": "/data/**", "source": "trusted"},
        {"host": "api.example.com", "schemes": ["http"], "ports": [8080], "methods": ["GET"]},
    ],
})


def reveal(url: str) -> str:
    got = host_check(
        f'r = certora.network.get("{url}")\nb = certora.extract(r, ".name")\ncertora.reveal_fact(b)\n',
        "<t>",
        POLICY,
    )
    assert isinstance(got, (Accepted, Rejected))
    return "\n".join(got.describe("<t>"))


class TestSources(unittest.TestCase):
    def test_the_governing_rule_tags_the_response(self) -> None:
        self.assertIn("validated: trusted", reveal("https://api.example.com/data/x"))

    def test_another_rule_for_the_same_host_does_not(self) -> None:
        self.assertNotIn("trusted", reveal("http://api.example.com:8080/data/x"))


if __name__ == "__main__":
    unittest.main()
