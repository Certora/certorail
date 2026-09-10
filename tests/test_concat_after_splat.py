"""Text glued onto a value located somewhere under a directory has no location: ``data/**``
stands for ``data``, ``data/x``, ``data/x/y``, so ``p + ".bak"`` is ``data.bak`` or ``data/x.bak``
-- not a file named ``.bak`` below data, which is what the concatenation automaton used to
answer (found live through ``certora.reveal_fact``). A ``/`` in between opens a component
below, as before. Also: a reveal inside a loop reports once, for the state that holds."""
import unittest

from certorail.host import Rejected
from certorail.host import check as host_check
from certorail.policy import Policy
from certorail.walker import analyze

HEADER = "import pathlib\nimport sys\n"
LOCATED = HEADER + (
    "p = sys.argv[1]\n"
    'assert certora.pathmatch(p, "data/**")\n'
)


def reveals(source: str) -> list[str]:
    return [f"{r.name}: {r.fact}" for r in analyze(source, "<t>").reveals]


class TestTextAfterASplat(unittest.TestCase):
    def test_a_suffix_has_no_location(self) -> None:
        got = reveals(LOCATED + 'q = p + ".bak"\ncertora.reveal_fact(q)\nr = f"{p}.bak"\ncertora.reveal_fact(r)\n')
        for line in got:
            self.assertTrue(line.startswith(("q: text", "r: text")), line)
            self.assertNotIn(" at ", line)

    def test_a_separator_opens_a_component_below(self) -> None:
        got = reveals(LOCATED + 'q = p + "/" + "notes.txt"\ncertora.reveal_fact(q)\nr = f"{p}/x"\ncertora.reveal_fact(r)\n')
        self.assertEqual(got, ["q: str at data/**/notes.txt", "r: str at data/**/x"])

    def test_the_sink_is_denied_not_confined(self) -> None:
        policy = Policy.allow(read=["data/**"])
        outcome = host_check(LOCATED + 'open(p + ".bak").read()\n', "<t>", policy)
        assert isinstance(outcome, Rejected), "a suffixed path is text of unknown location"
        self.assertTrue(any("denied" in line for line in outcome.describe("<t>")))
        fine = host_check(LOCATED + 'open(p + "/" + "x").read()\n', "<t>", policy)
        self.assertNotIsInstance(fine, Rejected)


class TestRevealsInLoops(unittest.TestCase):
    def test_one_reveal_per_program_point(self) -> None:
        source = HEADER + (
            'BASE = pathlib.Path("data")\n'
            "for whatever in sys.argv[1:]:\n"
            "    assert pathlib.Path(whatever).resolve().is_relative_to(BASE)\n"
            "    certora.reveal_fact(whatever)\n"
            '    whatever = whatever + ".bak"\n'
            "    certora.reveal_fact(whatever)\n"
        )
        got = reveals(source)
        self.assertEqual(len(got), 2, got)
        self.assertEqual(got[0], "whatever: str at data/**")  # the header binds it afresh: the guard holds
        self.assertTrue(got[1].startswith("whatever: text"), got[1])


if __name__ == "__main__":
    unittest.main()
