"""Code audited where it runs, not where it is written: a lambda body and the lazy part of a
generator expression see only what holds whenever they run (the module constants); ``finally``
also runs when the ``try`` body stops early; and a module constant is a name bound nowhere else
in the program."""
import unittest

from certorail import markers
from certorail.host import Accepted, Rejected
from certorail.host import check as host_check
from certorail.policy import Policy

HEADER = "import os\nimport sys\n"

DATA = Policy.allow(read=[markers.within("data")])


def outcome(body: str) -> Accepted | Rejected:
    return host_check(HEADER + body, "<t>", DATA)


class TestLambdas(unittest.TestCase):
    def test_a_name_rebound_before_the_call_is_unknown_in_the_body(self) -> None:
        got = outcome(
            'name = "notes.txt"\n'
            'def main() -> None:\n'
            '    name = "notes.txt"\n'
            '    reader = lambda: open(os.path.join("data", name)).read()\n'
            '    name = sys.argv[1]\n'
            '    print(reader())\n'
            'main()\n'
        )
        self.assertIsInstance(got, Rejected)

    def test_a_module_constant_holds_in_the_body(self) -> None:
        got = outcome(
            'NOTES = "data/notes.txt"\n'
            'reader = lambda: open(NOTES).read()\n'
            'print(reader())\n'
        )
        self.assertIsInstance(got, Accepted, got.describe("<t>") if isinstance(got, Rejected) else "")


class TestGeneratorExpressions(unittest.TestCase):
    def test_the_lazy_part_does_not_see_the_writing_state(self) -> None:
        got = outcome(
            'def main() -> None:\n'
            '    name = "notes.txt"\n'
            '    texts = (open(os.path.join("data", name)).read() for _ in range(1))\n'
            '    name = sys.argv[1]\n'
            '    print(list(texts))\n'
            'main()\n'
        )
        self.assertIsInstance(got, Rejected)

    def test_the_first_iterable_is_evaluated_where_written(self) -> None:
        got = outcome('texts = (open(p).read() for p in ["data/a.txt", "data/b.txt"])\nprint(list(texts))\n')
        self.assertIsInstance(got, Accepted, got.describe("<t>") if isinstance(got, Rejected) else "")


class TestFinally(unittest.TestCase):
    def test_finally_runs_when_a_guard_in_the_body_fails(self) -> None:
        got = outcome(
            'name = sys.argv[1]\n'
            'try:\n'
            '    assert "/" not in name\n'
            '    assert name != ".."\n'
            'finally:\n'
            '    print(open(os.path.join("data", name)).read())\n'
        )
        self.assertIsInstance(got, Rejected)

    def test_after_the_statement_the_body_completed(self) -> None:
        got = outcome(
            'name = sys.argv[1]\n'
            'try:\n'
            '    assert "/" not in name\n'
            '    assert name != ".."\n'
            'finally:\n'
            '    print("done")\n'
            'print(open(os.path.join("data", name)).read())\n'
        )
        self.assertIsInstance(got, Accepted, got.describe("<t>") if isinstance(got, Rejected) else "")


class TestComprehensions(unittest.TestCase):
    """A comprehension may run no iteration at all: what its filters and element establish
    holds inside it, never after it."""

    def test_a_filter_does_not_outlive_the_comprehension(self) -> None:
        for comp in (
            '[0 for _ in [] if "/" not in name and name != ".."]',
            '{0 for _ in sys.argv[2:] if "/" not in name and name != ".."}',
            '{0: 0 for _ in [] if "/" not in name and name != ".."}',
        ):
            with self.subTest(comp=comp):
                got = outcome(f'name = sys.argv[1]\nprint({comp})\nprint(open(os.path.join("data", name)).read())\n')
                assert isinstance(got, Rejected)
                self.assertTrue(got.denials, got.describe("<t>"))

    def test_inside_it_the_filter_holds(self) -> None:
        got = outcome(
            'print([open(os.path.join("data", n)).read() for n in sys.argv[1:] if "/" not in n and n != ".."])\n'
        )
        self.assertIsInstance(got, Accepted, got.describe("<t>") if isinstance(got, Rejected) else "")


class TestModuleConstants(unittest.TestCase):
    def test_a_match_capture_is_a_second_binding(self) -> None:
        got = outcome(
            'NOTES = "data/notes.txt"\n'
            'match sys.argv[1]:\n'
            '    case NOTES:\n'
            '        pass\n'
            'def show() -> None:\n'
            '    print(open(NOTES).read())\n'
            'show()\n'
        )
        self.assertIsInstance(got, Rejected)

    def test_a_binding_in_any_function_is_a_second_binding(self) -> None:
        got = outcome(
            'NOTES = "data/notes.txt"\n'
            'def outer() -> None:\n'
            '    NOTES = sys.argv[1]\n'
            '    def inner() -> None:\n'
            '        print(open(NOTES).read())\n'
            '    inner()\n'
            'outer()\n'
        )
        self.assertIsInstance(got, Rejected)

    def test_a_starred_parameter_is_a_second_binding(self) -> None:
        for params in ("*NOTES", "**NOTES", "*, NOTES", "NOTES, /"):
            with self.subTest(params=params):
                got = outcome(
                    'NOTES = "data/notes.txt"\n'
                    f'def unused({params}) -> None:\n'
                    '    pass\n'
                    'def show() -> None:\n'
                    '    print(open(NOTES).read())\n'
                    'show()\n'
                )
                assert isinstance(got, Rejected)
                self.assertEqual(got.violations, [])  # denied for the unknown path, not refused as a form
                self.assertTrue(got.denials)

    def test_a_type_parameter_is_a_second_binding(self) -> None:
        # inside show, NOTES is the type parameter, not the module's text
        for header in ("def show[NOTES]() -> None:", "def show[*NOTES]() -> None:", "def show[**NOTES]() -> None:"):
            with self.subTest(header=header):
                got = outcome(f'NOTES = "data/notes.txt"\n{header}\n    print(open(NOTES).read())\nshow()\n')
                assert isinstance(got, Rejected)
                self.assertEqual(got.violations, [])
                self.assertTrue(got.denials)

    def test_a_name_bound_once_is_a_constant(self) -> None:
        got = outcome('NOTES = "data/notes.txt"\ndef show() -> None:\n    print(open(NOTES).read())\nshow()\n')
        self.assertIsInstance(got, Accepted, got.describe("<t>") if isinstance(got, Rejected) else "")


if __name__ == "__main__":
    unittest.main()
