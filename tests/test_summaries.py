"""The callee analysis, phase two (EFFECTS.md, summaries.py): a call to a module-level function
applies that function's summary -- the kill its body applies, computed as a fixpoint over the
module with every parameter unknown -- and binds its result when that is a standard value.
Every other program call (a class instantiated, a lambda or a nested function held in a
variable, a parameter called) havocs; a read of a name some class defines as a property is an
unknown call."""
import unittest

from certorail.analysis import atoms_of
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

PRELUDE = (
    "import pathlib\n"
    'repo = pathlib.Path("repos") / "x"\n'
)
CHECK = 'certora.check("org-repo", cwd=repo)\n'
EXEC = 'certora.exec("git", "log", cwd=repo)\n'

LIVE = frozenset({"org-checkout"})
DEAD: frozenset[str] = frozenset()


def atoms_at_exec(definitions: str, between: str) -> frozenset[str]:
    """The atoms on the exec's cwd, with *definitions* above the check and *between* below it."""
    report: Report = analyze(PRELUDE + definitions + CHECK + between + EXEC, vocabulary=VOCAB)
    assert report.violations == [], report.violations
    execs = [s for s in report.sinks if isinstance(s, ExecSite)]
    return atoms_of(execs[-1].cwd)


class TestSummaries(unittest.TestCase):
    def test_an_inert_body_does_not_kill(self) -> None:
        for definitions, call in (
            ("def helper():\n    return 1\n", "helper()\n"),
            # a plain-typed parameter is a str (the runtime guard sees to it): inert receiver
            ("def fmt(x: str):\n    return x.strip().upper()\n", 'fmt(" a ")\n'),
            ("def build():\n    return [w.strip() for w in \"a b\".split()]\n", "build()\n"),
            # recursion converges from the bottom
            ("def count(n):\n    return 0 if n == 0 else 1 + count(n - 1)\n", "count(3)\n"),
            ("def ping():\n    return pong()\ndef pong():\n    return ping()\n", "ping()\n"),
            # a call of a function defined further down: the summaries precede the walk
            ("def first():\n    return later()\ndef later():\n    return 1\n", "first()\n"),
        ):
            with self.subTest(call=call):
                self.assertEqual(atoms_at_exec(definitions, call), LIVE)

    def test_an_effect_inside_kills_as_the_effect_does(self) -> None:
        self.assertEqual(
            atoms_at_exec('def log():\n    certora.exec("git", "log", cwd=repo)\n', "log()\n"), DEAD
        )
        # transitively
        self.assertEqual(
            atoms_at_exec(
                'def log():\n    certora.exec("git", "log", cwd=repo)\ndef outer():\n    log()\n',
                "outer()\n",
            ),
            DEAD,
        )

    def test_a_method_on_an_unknown_parameter_havocs(self) -> None:
        self.assertEqual(atoms_at_exec("def fmt(x):\n    return x.strip()\n", 'fmt("a")\n'), DEAD)

    def test_a_result_is_bound_when_standard(self) -> None:
        # the result is a closed list: sorting it is the interpreter's code
        self.assertEqual(
            atoms_at_exec("def make():\n    return [2, 1]\n", "xs = make()\nsorted(xs)\n"), LIVE
        )
        # a generator function's result is a program object: consuming it havocs
        self.assertEqual(
            atoms_at_exec("def gen():\n    yield 1\n", "g = gen()\nlist(g)\n"), DEAD
        )
        # falling off the end returns None; a str result is inert
        self.assertEqual(
            atoms_at_exec("def nothing():\n    pass\ndef text():\n    return 'a'\n",
                          "n = nothing()\nt = text()\nprint(n, t.upper())\n"),
            LIVE,
        )

    def test_consuming_a_generator_after_the_check_kills(self) -> None:
        # the body ran nothing at creation (above the check); it runs where it is consumed
        for definitions in (
            'g = (certora.exec("git", "log", cwd=repo) for _ in range(1))\n',
            'def gen():\n    certora.exec("git", "log", cwd=repo)\n    yield 1\ng = gen()\n',
        ):
            for between in (
                "list(g)\n", "for _ in g:\n    pass\n", "(a,) = g\n", "a, *rest = g\n", "print([x for x in g])\n",
                "print(*g)\n", "print(1 in g)\n", "take(*g)\n", "for _ in relay(g):\n    pass\n",
            ):
                with self.subTest(definitions=definitions, between=between):
                    helpers = "def take(*a):\n    return 1\ndef relay(it):\n    yield from it\n"
                    self.assertEqual(atoms_at_exec(helpers + definitions, between), DEAD)

    def test_iterating_a_parameter_of_unknown_type_is_an_unknown_call(self) -> None:
        # the parameter may be a generator, so the loop header may run program code; a typed
        # container parameter is inert, and iterating it is free
        self.assertEqual(atoms_at_exec("def show(lines):\n    for l in lines:\n        print(l)\n", 'show(["a"])\n'), DEAD)
        typed = (
            "import typing\n"
            "def show(lines: typing.Sequence[typing.Annotated[str, certora.no_slash]]):\n"
            "    for l in lines:\n        print(l)\n"
            'names: list[typing.Annotated[str, certora.no_slash]] = ["a"]\n'
        )
        self.assertEqual(atoms_at_exec(typed, "show(names)\n"), LIVE)

    def test_a_later_iteration_sees_what_an_earlier_one_killed(self) -> None:
        # the second exec runs after the first killed the check: a comprehension's element is
        # judged as every iteration's, as a loop body is
        for src in (
            'for _ in range(2):\n    certora.exec("git", "log", cwd=repo)\n',
            'print([certora.exec("git", "log", cwd=repo) for _ in range(2)])\n',
            'print(list(certora.exec("git", "log", cwd=repo) for _ in range(2)))\n',
        ):
            with self.subTest(src=src):
                report = analyze(PRELUDE + CHECK + src, vocabulary=VOCAB)
                self.assertEqual(report.violations, [])
                execs = [s for s in report.sinks if isinstance(s, ExecSite)]
                self.assertEqual(atoms_of(execs[-1].cwd), DEAD)

    def test_opening_inside_opens_the_caller(self) -> None:
        # the callee opens (an attribute store): the caller's standard values are opened, and a
        # later call over one of their elements is no longer exempt
        self.assertEqual(
            atoms_at_exec(
                "class Box:\n    pass\nbox = Box()\ndef mark():\n    box.x = 1\n",
                'xs = ["a"]\nmark()\n"".join(xs[0])\n',
            ),
            DEAD,
        )
        # but opening writes nothing: the check itself survives the call
        self.assertEqual(
            atoms_at_exec("class Box:\n    pass\nbox = Box()\ndef mark():\n    box.x = 1\n", "mark()\n"),
            LIVE,
        )


class TestHavoc(unittest.TestCase):
    def test_instantiation_and_variables_holding_callables(self) -> None:
        for definitions, call in (
            ("class Box:\n    pass\n", "Box()\n"),
            ("", "f = lambda: 1\nf()\n"),
            ("def outer():\n    def inner():\n        return 1\n    return inner()\n", "outer()\n"),
            ("def apply(fn):\n    return fn()\ndef helper():\n    return 1\n", "apply(helper)\n"),
        ):
            with self.subTest(call=call):
                self.assertEqual(atoms_at_exec(definitions, call), DEAD)

    def test_a_property_read_on_an_unknown_receiver(self) -> None:
        definitions = (
            "class C:\n"
            "    @property\n"
            "    def name(self):\n"
            "        return 1\n"
            "def read(o):\n"
            "    return o.name\n"
        )
        self.assertEqual(atoms_at_exec(definitions, "read(1)\n"), DEAD)
        # the same name on a receiver known to be inert is a data attribute of the interpreter's
        self.assertEqual(atoms_at_exec(definitions, "n = repo.name\n"), LIVE)


POLICY = from_data({
    "policy-version": 1,
    "filesystem": {"read": ["repos/**"], "write": ["repos/**"]},
    "regions": {
        "git.config": {"footprint": ".git/config"},
        "git.index": {"footprint": ".git/index"},
        "git.refs": {"footprint": ".git/refs"},
    },
    "atoms": {"org-checkout": {"reads": ["git.config"]}},
    "validation": [
        {"name": "org-repo", "argv": ["true"], "cwd": "repos/**", "writes": [],
         "establishes": {"cwd": ["org-checkout"]}},
    ],
    "program": [
        {"name": "git", "subcommand": "commit", "cwd": "repos/**", "network": False,
         "writes": ["git.refs", "git.index"]},
        {"name": "git", "subcommand": "push", "cwd": "repos/**", "requires": ["org-checkout"]},
    ],
}, "<t>")


class TestSummariesCarryWriteSets(unittest.TestCase):
    """A function's summary is the union of what its body writes, region by region: a helper
    that commits kills what a commit kills and no more."""

    def test_a_committing_helper_preserves_unrelated_atoms(self) -> None:
        source = (
            PRELUDE
            + 'def commit():\n    certora.exec("git", "commit", cwd=repo)\n'
            + CHECK
            + "commit()\n"
            + 'certora.exec("git", "push", cwd=repo)\n'
        )
        outcome = host_check(source, "<t>", POLICY)
        if isinstance(outcome, Rejected):
            self.fail("\n".join(outcome.describe("<t>")))
        self.assertIsInstance(outcome, Accepted)

    def test_inside_a_loop_too(self) -> None:
        source = (
            PRELUDE
            + 'def commit():\n    certora.exec("git", "commit", cwd=repo)\n'
            + CHECK
            + "for i in [1, 2]:\n    commit()\n"
            + 'certora.exec("git", "push", cwd=repo)\n'
        )
        self.assertIsInstance(host_check(source, "<t>", POLICY), Accepted)


if __name__ == "__main__":
    unittest.main()
