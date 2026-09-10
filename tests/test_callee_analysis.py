"""The callee analysis, phase one (EFFECTS.md): a call is the interpreter's own code -- no kill
-- when it is a roster builtin or module function under its argument condition, or a method on
an inert receiver with inert arguments; the walker tracks a coarse ``Std`` value for standard
values and a closedness bit on them and on handles. Anything that may run program code writes
everything and *opens* the standard values, so that a later call on an alias cannot be exempt."""
import unittest

from certorail.analysis import checks_of
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.ids import AtomId, ParamName, ValidationName
from certorail.policyfile import from_data
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
    "import re\n"
    "\n"
    "def helper():\n"
    "    return 1\n"
    "\n"
    "class Sink:\n"
    "    def write(self, s):\n"
    "        return None\n"
    "\n"
    "sink = Sink()\n"
    'repo = pathlib.Path("repos") / "x"\n'
    'h = certora.exec("git", "log", cwd=repo)\n'
    'certora.check("org-repo", cwd=repo)\n'
)
EXEC = 'certora.exec("git", "log", cwd=repo)\n'

LIVE = frozenset({"org-checkout"})
DEAD: frozenset[str] = frozenset()


def atoms_at_exec(between: str) -> frozenset[str]:
    report: Report = analyze(HEADER + between + EXEC, vocabulary=VOCAB)
    assert report.violations == [], report.violations
    execs = [s for s in report.sinks if isinstance(s, ExecSite)]
    return checks_of(execs[-1].cwd)


class TestInertCallsDoNotKill(unittest.TestCase):
    def test_methods_on_inert_receivers(self) -> None:
        for call in (
            '"".join(["a", "b"])\n',
            'names = ["b", "a"]\nsorted(names)\n"\\n".join(names)\n',
            'parts = "a b".split()\nparts[0].strip()\n',
            'str(repo).strip().split("/")\n',
            'd = json.loads("{}")\nd.get("k")\nlen(d)\n',
            'm = re.match("a", "a")\nm.group(0)\n',
            'k, v = ("a", 1)\nk.upper()\n',
            "n = 1\nn += 2\nprint(n)\n",
        ):
            with self.subTest(call=call):
                self.assertEqual(atoms_at_exec(call), LIVE)

    def test_roster_calls_over_inert_arguments(self) -> None:
        for call in (
            "sorted([3, 1])\n",
            'sorted(["b", "a"], key=len)\n',
            "xs = [1, 2]\nprint(*xs)\n",
            'opts = {"indent": 2}\njson.dumps({"a": 1}, **opts)\n',
            "certora.lines(h)\n",
        ):
            with self.subTest(call=call):
                self.assertEqual(atoms_at_exec(call), LIVE)

    def test_a_read_open_and_the_handle_it_binds(self) -> None:
        self.assertEqual(
            atoms_at_exec('with open(repo / "f") as f:\n    data = f.read()\n'), LIVE
        )

    def test_hash_and_identity_methods_take_anything(self) -> None:
        self.assertEqual(atoms_at_exec("xs = [1]\nxs.append(helper)\n"), LIVE)


class TestBindings(unittest.TestCase):
    def test_a_loop_variable_over_an_inert_iterable(self) -> None:
        # the boundary is a rehearsal of one iteration, not a state-free scan: the receiver is known
        for src in (
            'for w in "a b".split():\n    w.upper()\n',
            'for i, w in enumerate(["a"]):\n    w.strip()\n',
            'lines = ["a"]\nout = []\nfor line in lines:\n    out.append(line.strip())\n',
        ):
            with self.subTest(src=src):
                self.assertEqual(atoms_at_exec(src), LIVE)

    def test_a_comprehension_variable(self) -> None:
        self.assertEqual(atoms_at_exec('ws = [w.strip() for w in ["a"]]\n'), LIVE)
        self.assertEqual(atoms_at_exec('ws = {w: w.strip() for w in ["a"]}\n'), LIVE)


class TestProgramCodeKills(unittest.TestCase):
    def test_program_code_reached_through_an_argument(self) -> None:
        for call in (
            'sorted(["b"], key=lambda n: n)\n',
            '"".join(g for g in ["a"])\n',
            'list(g for g in ["a"])\n',
            '"{0}".format(sink)\n',
            "json.dumps(sink)\n",
            "helper()\n",
        ):
            with self.subTest(call=call):
                self.assertEqual(atoms_at_exec(call), DEAD)

    def test_a_file_write_still_kills(self) -> None:
        for call in (
            'with open(repo / "f", "w") as f:\n    pass\n',
            '(repo / "f").write_text("x")\n',
        ):
            with self.subTest(call=call):
                self.assertEqual(atoms_at_exec(call), DEAD)


class TestOpening(unittest.TestCase):
    """A non-inert value stored into a standard value opens the whole state: the receiver may
    alias anything, so no closed value is trusted afterwards until it is rebound."""

    def test_a_stored_program_object_opens_the_receiver(self) -> None:
        self.assertEqual(atoms_at_exec("xs = [1]\nxs.append(helper)\nsorted(xs)\n"), DEAD)

    def test_and_its_aliases(self) -> None:
        self.assertEqual(atoms_at_exec("a = [1]\nb = a\nb.append(helper)\nsorted(a)\n"), DEAD)

    def test_a_subscript_store(self) -> None:
        self.assertEqual(atoms_at_exec('d = {}\nd["k"] = helper\nsorted(d)\n'), DEAD)

    def test_an_attribute_store(self) -> None:
        self.assertEqual(atoms_at_exec('lines = "a b".split()\nsink.x = 1\n"".join(lines)\n'), DEAD)

    def test_rebinding_closes_again(self) -> None:
        self.assertEqual(
            atoms_at_exec("xs = [1]\nxs.append(helper)\nxs = [2]\nsorted(xs)\n"), LIVE
        )

    def test_a_loop_body_that_opens_is_taken_as_doing_anything(self) -> None:
        # one iteration: append (no kill, opens), pop (no kill); the next iteration may find an
        # opened value where this one found a closed one
        self.assertEqual(
            atoms_at_exec('lst = [1]\nfor w in ["a"]:\n    lst.append(helper)\n    lst.pop()\n'),
            DEAD,
        )
        self.assertEqual(atoms_at_exec('for w in ["a"]:\n    w.strip()\n    helper()\n'), DEAD)


POLICY = from_data({
    "policy-version": 1,
    "filesystem": {"read": ["repos/**"], "write": ["repos/**"], "list": ["repos/**"]},
    "regions": {"git.config": {"footprint": ".git/config"}},
    "atoms": {"org-checkout": {"reads": ["git.config"]}},
    "validation": [
        {"name": "org-repo", "argv": ["true"], "cwd": "repos/**", "effect-free": True,
         "establishes": {"cwd": ["org-checkout"]}},
    ],
    "program": [
        {"name": "git", "subcommand": "push", "cwd": "repos/**", "requires": ["org-checkout"]},
        {"name": "cargo", "subcommand": "build", "cwd": "repos/**"},
    ],
}, "<t>")


class TestSubprocessesDoNotOpen(unittest.TestCase):
    """A subprocess writes regions -- everything, for an undeclared rule -- but cannot touch a
    Python object: the standard values built before it stay closed, so the checking half after
    a build can still format what it gathered before."""

    def program(self, middle: str) -> str:
        return (
            "import pathlib\n"
            "def helper():\n    return 1\n"
            'repo = pathlib.Path("repos") / "x"\n'
            'lines = "a b".split()\n'
            + middle
            + 'certora.check("org-repo", cwd=repo)\n'
            'msg = "\\n".join(lines)\n'
            'certora.exec("git", "push", cwd=repo)\n'
        )

    def test_an_exec_leaves_the_values_closed(self) -> None:
        outcome = host_check(self.program('certora.exec("cargo", "build", cwd=repo)\n'), "<t>", POLICY)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))
        self.assertIsInstance(outcome, Accepted)

    def test_program_code_opens_them(self) -> None:
        outcome = host_check(self.program("helper()\n"), "<t>", POLICY)
        assert isinstance(outcome, Rejected), outcome
        self.assertIn("org-checkout", "\n".join(d.reason for d in outcome.denials))


if __name__ == "__main__":
    unittest.main()
