"""Builtin names are never rebound, by any binding form: the analysis reads ``tuple``, ``list``,
``sorted``, ``len`` and friends by their meaning (a roster read of a typed container is
``tuple(xs)``), so a program that gave one of those names another meaning could launder a
container through it. Class statements, imports and type parameters bind names too."""
import unittest

from certorail.walker import analyze

HEADER = "import typing\n"


def violations(body: str) -> list[str]:
    return [what for _, what in analyze(HEADER + body).violations]


class TestBuiltinsStayBound(unittest.TestCase):
    def test_assignment_forms(self) -> None:
        for body in (
            "tuple = 3\n",
            "def f(sorted):\n    return sorted\n",
            "for list in [[1]]:\n    pass\n",
            "def sorted(x):\n    return x\n",
        ):
            with self.subTest(body=body):
                self.assertIn("rebind builtin", violations(body))

    def test_a_class_statement(self) -> None:
        # the laundering shape: tuple(xs) is a blessed roster read, and this tuple keeps xs
        body = (
            "class tuple:\n"
            "    def __init__(self, xs):\n"
            "        self.xs = xs\n"
            "xs: list[typing.Annotated[str, certora.no_slash]] = []\n"
            "t = tuple(xs)\n"
        )
        self.assertIn("rebind builtin", violations(body))

    def test_an_import(self) -> None:
        self.assertIn("import shadows a builtin", violations("import len\n"))

    def test_type_parameters(self) -> None:
        self.assertIn("rebind builtin", violations("def f[tuple](x):\n    return x\n"))
        self.assertIn("rebind builtin", violations("class C[sorted]:\n    pass\n"))

    def test_a_class_may_still_be_defined_once(self) -> None:
        self.assertEqual(violations("class Point:\n    pass\n"), [])


if __name__ == "__main__":
    unittest.main()
