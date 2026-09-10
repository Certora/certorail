"""``certora.reveal_fact(x)``: the analysis reports what it knows about a name at that point;
establishes nothing, kills nothing, refuses anything but a bare name."""
import pathlib
import tempfile
import unittest

from certorail import markers
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policy import Policy, constraint, hole, program, pure, validation
from certorail.walker import analyze

HEADER = "import pathlib\nimport sys\n"


def reveals(source: str, policy: Policy | None = None) -> list[str]:
    report = analyze(HEADER + source, "<t>", None if policy is None else policy.vocabulary())
    return [f"{r.name}: {r.fact}" for r in report.reveals]


class TestReveal(unittest.TestCase):
    def test_the_facts_the_walk_holds(self) -> None:
        got = reveals(
            'a = "src/main.py"\n'
            'p = pathlib.Path("src") / "x"\n'
            "u = sys.argv[1]\n"
            "n = 3\n"
            'q = "http://example.com/x"\n'
            "certora.reveal_fact(a)\n"
            "certora.reveal_fact(p)\n"
            "certora.reveal_fact(u)\n"
            "certora.reveal_fact(n)\n"
            "certora.reveal_fact(nothing)\n"
        )
        self.assertEqual(got[0], "a: text matching src/main.py")  # a str literal is text until a sink reads it as a path
        self.assertEqual(got[1], "p: path at src/x")
        self.assertEqual(got[2], "u: text")
        self.assertEqual(got[3], "n: a number")
        self.assertEqual(got[4], "nothing: nothing is known about it (not tracked at this point)")

    def test_atoms_and_handles_and_containers(self) -> None:
        policy = Policy.allow(
            programs=[program("ls", cwd=".", argv=["ls", hole("DIR")], holes={"DIR": constraint(any=True)}, source="listing")],
            validations=[validation("v", params=["x"], argv=["true"], establishes={"x": [pure("ok")]})],
        )
        got = reveals(
            'name = certora.check_single("v", sys.argv[1], cwd=pathlib.Path("."))\n'
            "certora.reveal_fact(name)\n"
            'out = certora.exec("ls", "x", cwd=pathlib.Path("."))\n'
            "certora.reveal_fact(out)\n"
            'items: list[str] = ["a", "b"]\n'
            "certora.reveal_fact(items)\n",
            policy,
        )
        self.assertEqual(got[0], "name: text (validated: ok)")
        self.assertTrue(got[1].startswith("out: a source handle yielding listing"), got[1])
        self.assertEqual(got[2], "items: a list")  # a plain list is a standard value, not a tracked container

    def test_the_probe_changes_nothing(self) -> None:
        # a fact survives the probe: check, reveal, then the gated exec is still accepted
        policy = Policy.allow(
            programs=[program("deploy", cwd=".", requires=["ready"])],
            validations=[validation("ready", argv=["true"], cwd=".", establishes={"cwd": ["ready"]}, writes=[])],
        )
        def program_text(probe: str) -> str:
            return HEADER + (
                "d = pathlib.Path('.')\n"
                'certora.check("ready", cwd=d)\n'
                + probe
                + 'certora.exec("deploy", cwd=d)\n'
            )

        control = host_check(program_text(""), "<t>", policy)
        if isinstance(control, Rejected):
            self.fail("control: " + "\n".join(control.describe("<t>")))
        outcome = host_check(program_text("certora.reveal_fact(d)\n"), "<t>", policy)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))
        assert isinstance(outcome, Accepted)
        lines = outcome.describe("<t>")
        self.assertTrue(lines[0].startswith("<t>:5:1: reveal: d: path at . (validated: ready)"), lines)

    def test_only_a_bare_name(self) -> None:
        for bad in ("certora.reveal_fact(a + b)", "certora.reveal_fact(x.y)", "certora.reveal_fact()", "certora.reveal_fact(a, b)", "certora.reveal_fact(x=a)"):
            with self.subTest(bad=bad):
                report = analyze(HEADER + "a = b = 'x'\n" + bad + "\n", "<t>")
                self.assertTrue(any("reveal_fact: exactly one bare name" in what for _, what in report.violations), report.violations)
                self.assertEqual(report.reveals, [])

    def test_a_rejection_shows_the_reveals_first(self) -> None:
        policy = Policy.allow(read=["src/**"])
        source = HEADER + 'p = pathlib.Path(sys.argv[1])\ncertora.reveal_fact(p)\nopen(p).read()\n'
        outcome = host_check(source, "<t>", policy)
        assert isinstance(outcome, Rejected)
        lines = outcome.describe("<t>")
        self.assertIn("reveal: p: path of unknown location", lines[0])
        self.assertTrue(any("denied" in line for line in lines[1:]))

    def test_the_runtime_marker_does_nothing(self) -> None:
        self.assertIsNone(markers.reveal_fact(object()))


if __name__ == "__main__":
    unittest.main()
