"""Ill-typed guards establish nothing. A string literal compared with a pathlib object is
nonsense the interpreter would raise on or decide vacuously -- ``".." in Path(x)`` is a
TypeError, ``Path(x) != ".."`` is always true -- and the recognizer must not turn it into a fact
the program never earned (found live: ``assert ".." not in pathlib.Path(name)`` established
no-parent-traversal on ``name``)."""
import ast
import unittest

from certorail.analysis import Located, PathFact, StrFact
from certorail.guards import apply, recognize
from certorail.ids import NO_PARENT_TRAVERSAL, NO_SLASH, NOT_ABSOLUTE, NOT_DOT_DOT
from certorail.locations import parse_location
from certorail.walker import analyze

HEADER = "import pathlib\nimport sys\n"


def refined(fact, cond: str, name: str = "x"):
    out = {name: fact}
    for g in recognize(ast.parse(cond, mode="eval").body, out):
        new = apply(out.get(g.subject), g.refinement)
        if new is not None:
            out[g.subject] = new
    return out.get(name)


def atoms_after(fact, cond: str, name: str = "x") -> frozenset:
    got = refined(fact, cond, name)
    return getattr(got, "atoms", frozenset())


class TestPathObjectsAgainstLiterals(unittest.TestCase):
    def test_the_sound_spellings_still_establish(self) -> None:
        text = StrFact()
        self.assertIn(NO_PARENT_TRAVERSAL, atoms_after(text, '".." not in x'))
        self.assertIn(NO_PARENT_TRAVERSAL, atoms_after(text, '".." not in x.split("/")'))
        self.assertIn(NO_PARENT_TRAVERSAL, atoms_after(text, '".." not in pathlib.Path(x).parts'))
        self.assertIn(NO_PARENT_TRAVERSAL, atoms_after(text, '".." not in str(x)'))
        self.assertIn(NO_SLASH, atoms_after(text, '"/" not in x'))
        self.assertIn(NOT_DOT_DOT, atoms_after(text, 'x not in (".", "..")'))
        self.assertIn(NOT_DOT_DOT, atoms_after(text, 'x != ".."'))
        self.assertIn(NOT_ABSOLUTE, atoms_after(text, 'x[0] != "/"'))

    def test_a_path_constructor_in_a_text_test_proves_nothing(self) -> None:
        text = StrFact()
        for cond in (
            '".." not in pathlib.Path(x)',           # TypeError: a Path is not iterable
            '".." not in pathlib.PurePath(x)',
            '"/" not in pathlib.Path(x)',
            'pathlib.Path(x) not in (".", "..")',    # vacuously true: a Path never equals a str
            'pathlib.Path(x) != ".."',
            '".." != pathlib.Path(x)',
            'pathlib.Path(x)[0] != "/"',              # TypeError: not subscriptable
            '".." not in pathlib.Path(x).resolve()',
            '".." not in (pathlib.Path("data") / x)',
            '".." not in pathlib.Path(x).parent',
        ):
            with self.subTest(cond=cond):
                self.assertEqual(atoms_after(text, cond), frozenset(), cond)

    def test_a_variable_the_state_knows_as_a_path_is_treated_the_same(self) -> None:
        for fact in (PathFact(), Located(parse_location("data/**"), "path")):
            with self.subTest(fact=type(fact).__name__):
                self.assertEqual(atoms_after(fact, '".." not in x'), frozenset())
                self.assertEqual(atoms_after(fact, 'x != ".."'), frozenset())
                self.assertEqual(atoms_after(fact, 'x not in (".", "..")'), frozenset())
        # its own component view still works (on a located value the containment already says it)
        self.assertIn(NO_PARENT_TRAVERSAL, atoms_after(PathFact(), '".." not in x.parts'))

    def test_methods_of_the_wrong_type_prove_nothing(self) -> None:
        text = StrFact()
        # str methods on a pathlib object: AttributeError
        self.assertEqual(atoms_after(text, 'pathlib.Path(x).startswith("data/")'), frozenset())
        self.assertEqual(atoms_after(text, 'not pathlib.Path(x).startswith("/")'), frozenset())
        self.assertEqual(atoms_after(text, 'pathlib.Path(x).isalnum()'), frozenset())
        # a pathlib method on text: AttributeError
        self.assertEqual(atoms_after(text, "not x.is_absolute()"), frozenset())
        # and the right ones still work
        self.assertIn(NOT_ABSOLUTE, atoms_after(text, 'not x.startswith("/")'))
        self.assertIn(NOT_ABSOLUTE, atoms_after(PathFact(), "not x.is_absolute()"))
        self.assertIn(NOT_ABSOLUTE, atoms_after(text, "not pathlib.Path(x).is_absolute()"))

    def test_the_program_that_found_it(self) -> None:
        source = HEADER + (
            "name = sys.argv[1]\n"
            'BASE = pathlib.Path("data")\n'
            'assert ".." not in pathlib.Path(name)\n'
            "certora.reveal_fact(name)\n"
            'assert name.startswith(str(BASE) + "/")\n'
            "certora.reveal_fact(name)\n"
        )
        report = analyze(source, "<t>")
        first, second = (r.fact for r in report.reveals)
        self.assertEqual(first, "text")  # nothing earned by the nonsense assert
        self.assertNotIn("data/**", second)  # so the prefix check stays conditional on ".." being excluded


if __name__ == "__main__":
    unittest.main()
