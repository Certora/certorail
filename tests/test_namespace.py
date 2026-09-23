"""The ``certora`` namespace is closed. At run time it is the whole ``certorail.markers`` module, so
anything that module imports or keeps private would be reachable through it, unanalysed; only
the vocabulary the analysis models may be named."""
import unittest

from certorail.walker import analyze

HEADER = "import typing\nimport sys\n"


def violations(body: str) -> list[str]:
    return [what for _, what in analyze(HEADER + body).violations]


class TestClosedNamespace(unittest.TestCase):
    def test_what_the_runtime_module_happens_to_hold_is_out_of_reach(self) -> None:
        for body, member in (
            ("certora.os.getcwd()\n", "certora.os"),
            ("certora.json.dumps(1)\n", "certora.json"),
            ("certora._broker.available()\n", "certora._broker"),
            ('certora.network._request("GET", "https://example.com/", None, None, None)\n', "certora.network._request"),
        ):
            with self.subTest(body=body):
                self.assertIn(f"{member} is not an allowed member", violations(body))

    def test_the_modelled_vocabulary_stays_available(self) -> None:
        body = (
            "x: typing.Annotated[str, certora.validated('t')] = sys.argv[1]\n"
            "certora.reveal_fact(x)\n"
            "try:\n"
            '    certora.network.get("https://example.com/")\n'
            "except certora.NetworkError:\n"
            "    pass\n"
        )
        self.assertFalse([v for v in violations(body) if "allowed member" in v])


if __name__ == "__main__":
    unittest.main()
