"""Document paths (``certorail.docpath``): built by attribute access mirroring the document,
printed the way the documentation spells them, and the same value pydantic's ``loc`` becomes."""
import copy
import pickle
import unittest

from certorail.docpath import DocPath, Indexed, Keyed, Path


class TestBuilding(unittest.TestCase):
    def test_the_grammar_one_level_deep(self) -> None:
        self.assertEqual(str(Path().program(0).holes["A"].location), "program[0].holes.A.location")
        self.assertEqual(str(Path().regions["git.config"].footprint), "regions.git.config.footprint")
        self.assertEqual(str(Path().apply(1).key("branch")), "apply[1].branch")
        self.assertEqual(str(Path().validation(2).argv(0)), "validation[2].argv[0]")
        self.assertEqual(str(Path().network(0).requires.at(1)), "network[0].requires[1]")
        self.assertEqual(str(Path().program(0).holes["F"].key("-k").requires["cwd"]), "program[0].holes.F.-k.requires.cwd")
        self.assertEqual(str(Path().program(3).effect_free), "program[3].effect-free")  # underscores are dashes
        self.assertEqual(str(Path()), "")
        self.assertFalse(Path())

    def test_sections_and_tables_are_their_own_kinds(self) -> None:
        self.assertIsInstance(Path().program, Indexed)
        self.assertIsInstance(Path().holes, Keyed)
        self.assertIsInstance(Path().cwd, Path)
        # what the type checker rejects statically is an AttributeError at runtime
        with self.assertRaises(AttributeError):
            Path().program.when  # pyright: ignore[reportAttributeAccessIssue]
        with self.assertRaises(TypeError):
            Path().holes(0)  # pyright: ignore[reportCallIssue]
        with self.assertRaises(AttributeError):
            Path().nonsense  # pyright: ignore[reportAttributeAccessIssue]

    def test_no_dunder_is_ever_a_segment(self) -> None:
        # copy and pickle probe __deepcopy__, __reduce_ex__ and friends through __getattr__
        p = Path().program(0).holes["A"]
        self.assertEqual(copy.deepcopy(p), p)
        self.assertEqual(pickle.loads(pickle.dumps(p)), p)
        self.assertEqual(hash(p), hash(Path().program(0).holes["A"]))

    def test_immutable(self) -> None:
        with self.assertRaises(AttributeError):
            Path().cwd._segments = ()  # pyright: ignore[reportAttributeAccessIssue]


class TestFromLoc(unittest.TestCase):
    def test_pydantics_machinery_is_dropped(self) -> None:
        loc = ("program", 0, "holes", "A", "hole:flags", "function-after[_location_text(), str]", "location", 1)
        self.assertEqual(str(DocPath.from_loc(loc)), "program[0].holes.A.location[1]")
        self.assertEqual(str(DocPath.from_loc(("regions", "r", "region:fs", "footprint", "list[str]"))), "regions.r.footprint")
        self.assertEqual(str(DocPath.from_loc(("atoms", "x", "[key]"))), "atoms.x")
        # the lifted fields are spelled inline in the document
        self.assertEqual(str(DocPath.from_loc(("program", 0, "holes", "A", "flags", "-q", "any"))), "program[0].holes.A.-q.any")
        self.assertEqual(str(DocPath.from_loc(("apply", 1, "bindings", "where"))), "apply[1].where")

    def test_parent_and_last(self) -> None:
        p = DocPath.from_loc(("program", 0, "colour"))
        self.assertEqual(p.last, "colour")
        self.assertEqual(str(p.parent), "program[0]")
        self.assertIsNone(Path().last)


if __name__ == "__main__":
    unittest.main()
