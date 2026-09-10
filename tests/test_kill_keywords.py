"""The effect-free allowlist is conditional on how the call is spelled: a keyword outside the
callee's admitted set (``json.loads(object_hook=f)``, ``json.dumps(default=f)``,
``print(file=obj)``) or a ``*``/``**`` splat runs program code inside the call, so the call kills
environmental atoms like any other. Plain spellings keep their exemption."""
import unittest

from certorail.analysis import checks_of
from certorail.ids import AtomId, ParamName, ValidationName
from certorail.walker import CheckSignature, ExecSite, Report, Vocabulary, analyze

ORG_REPO = ValidationName("org-repo")
VOCAB = Vocabulary(
    signatures={ORG_REPO: CheckSignature(ORG_REPO, (), {ParamName("cwd"): frozenset({AtomId("org-checkout")})})},
    pure_atoms=frozenset(),
    defined={},
)

HEADER = (
    "import json\n"
    "import pathlib\n"
    "\n"
    "def hook(d):\n"
    "    return d\n"
    "\n"
    "class Sink:\n"
    "    def write(self, s):\n"
    "        return None\n"
    "\n"
    "sink = Sink()\n"
    "xs = [1, 2]\n"
    'repo = pathlib.Path("repos") / "x"\n'
    'certora.check("org-repo", cwd=repo)\n'
)
EXEC = 'certora.exec("git", "log", cwd=repo)\n'


def atoms_at_exec(between: str) -> frozenset[str]:
    report: Report = analyze(HEADER + between + EXEC, vocabulary=VOCAB)
    assert report.violations == [], report.violations
    (site,) = [s for s in report.sinks if isinstance(s, ExecSite)]
    return checks_of(site.cwd)


LIVE = frozenset({"org-checkout"})
DEAD: frozenset[str] = frozenset()


class TestKeywordsKill(unittest.TestCase):
    def test_hooks_and_callables_kill(self) -> None:
        for call in (
            'json.loads("{}", object_hook=hook)\n',
            'json.loads("{}", parse_int=hook)\n',
            'json.dumps({"a": 1}, default=hook)\n',
            'print("x", file=sink)\n',
        ):
            with self.subTest(call=call):
                self.assertEqual(atoms_at_exec(call), DEAD)

    def test_splats_kill(self) -> None:
        for call in ('print(*xs)\n', 'opts = {"indent": 2}\njson.dumps({"a": 1}, **opts)\n'):
            with self.subTest(call=call):
                self.assertEqual(atoms_at_exec(call), DEAD)

    def test_admitted_keywords_do_not_kill(self) -> None:
        for call in (
            'json.loads("{}")\n',
            'json.dumps({"a": 1}, indent=2, sort_keys=True)\n',
            'print("a", "b", sep=", ", end="")\n',
            'n = int("10", base=16)\n',
        ):
            with self.subTest(call=call):
                self.assertEqual(atoms_at_exec(call), LIVE)

    def test_the_loop_boundary_agrees(self) -> None:
        # _may_effect scans the body without a state: the same spelling rule applies there
        self.assertEqual(atoms_at_exec('for i in xs:\n    json.loads("{}")\n'), LIVE)
        self.assertEqual(atoms_at_exec('for i in xs:\n    json.loads("{}", object_hook=hook)\n'), DEAD)


if __name__ == "__main__":
    unittest.main()
