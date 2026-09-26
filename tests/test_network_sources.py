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


class TestASourceAtomFillsAHole(unittest.TestCase):
    """A value extracted from a sourced response carries the source's atom, which a program
    rule's hole may require -- but an argv hole also wants ``not-option``, which a source cannot
    vouch for: the extracted text could be ``-e`` (a report from the field, 2026-09-25)."""

    POLICY = """
policy-version = 1
base = false
[atoms]
vetted = { pure = true }
[[network]]
host    = "api.example.com"
schemes = ["https"]
source  = "vetted"
[[program]]
name = "echo"
argv = ["echo", "${WORD}"]
cwd  = "."
holes.WORD = { atoms = ["vetted"] }
"""

    def check(self, guard: str) -> Accepted | Rejected:
        import tomllib

        source = (
            'r = certora.network.get("https://api.example.com/x")\n'
            'word = certora.extract(r, ".field")\n'
            f"{guard}"
            'certora.exec("echo", word, cwd=".")\n'
        )
        return host_check(source, "<t>", from_data(tomllib.loads(self.POLICY)))

    def test_unguarded_the_word_may_be_an_option(self) -> None:
        got = self.check("")
        assert isinstance(got, Rejected), got
        self.assertIn("WORD may begin with '-' and be read as an option", "\n".join(got.describe("<t>")))

    def test_guarded_it_is_echoed(self) -> None:
        for guard in ('assert not word.startswith("-")\n', 'if word.startswith("-"):\n    raise SystemExit(1)\n'):
            with self.subTest(guard=guard):
                got = self.check(guard)
                self.assertIsInstance(got, Accepted, "\n".join(got.describe("<t>")))


if __name__ == "__main__":
    unittest.main()
