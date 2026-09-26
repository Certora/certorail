"""A match pattern reads its subject and binds names, with none of the nodes the lexical rules hang
off: a class pattern's keywords are attribute reads (``case object(__globals__=g)`` is ``g =
subject.__globals__``), a mapping pattern's keys are values, and a capture is a binding. Each is
held to the rule the attribute read, the value or the binding would be held to, wherever the
pattern sits."""
import unittest

from certorail.walker import analyze

HEADER = "import os\nimport dataclasses\n"


def violations(body: str) -> list[str]:
    return [what for _, what in analyze(HEADER + body).violations]


def matching(pattern: str) -> str:
    return f"def f(x):\n    match x:\n        case {pattern}:\n            return 1\n    return 0\n"


class TestPatternsReadTheSubject(unittest.TestCase):
    def test_a_keyword_is_an_attribute_read(self) -> None:
        for pattern, what in (
            ("object(__globals__=g)", "dunder attribute"),
            ("object(__init__=g)", "dunder attribute"),              # no exemption: nothing calls it here
            ("object(unlink=u)", "forbidden attribute unlink"),      # a banned method, taken whole
            ("object(write_text=w)", "write_text may only be called, not taken as a value"),
        ):
            with self.subTest(pattern=pattern):
                self.assertIn(what, violations(matching(pattern)))

    def test_wherever_the_class_pattern_sits(self) -> None:
        for pattern in (
            "[object(__globals__=g)]",
            "object(__globals__=g) as y",
            '{"k": object(__globals__=g)}',
            "1 | object(__code__=g)",
            "object(x=object(__globals__=g))",
        ):
            with self.subTest(pattern=pattern):
                self.assertIn("dunder attribute", violations(matching(pattern)))

    def test_a_mapping_key_is_a_value(self) -> None:
        self.assertIn("os.system is not an allowed member", violations(matching("{os.system: v}")))


class TestPatternsBindNames(unittest.TestCase):
    def test_no_dunder_is_bound(self) -> None:
        for pattern in ("object() as __builtins__", "[*__builtins__]", "{**__builtins__}"):
            with self.subTest(pattern=pattern):
                self.assertIn("bind dunder", violations(matching(pattern)))

    def test_nor_by_the_other_forms_that_bind_a_string_field(self) -> None:
        for body in (
            "try:\n    x = 1\nexcept ValueError as __builtins__:\n    x = 2\n",
            "class __builtins__:\n    pass\n",
            "def f[__builtins__](x):\n    return x\n",
        ):
            with self.subTest(body=body):
                self.assertIn("bind dunder", violations(body))

    def test_nor_a_builtin(self) -> None:
        self.assertIn("rebind builtin", violations(matching("object() as print")))


class TestOrdinaryPatterns(unittest.TestCase):
    def test_are_untouched(self) -> None:
        body = (
            "@dataclasses.dataclass\n"
            "class Point:\n"
            "    x: int\n"
            "    y: int\n"
            "def f(p: Point) -> int:\n"
            "    match p:\n"
            "        case Point(x=0, y=yy):\n"
            "            return yy\n"
            "        case {\"k\": v, **others}:\n"
            "            return 0\n"
            "        case [a, *rest]:\n"
            "            return 1\n"
            "        case str() as s:\n"
            "            return 2\n"
            "    return 3\n"
        )
        self.assertEqual(violations(body), [])


if __name__ == "__main__":
    unittest.main()
