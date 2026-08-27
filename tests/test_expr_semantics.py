"""Abstract expression semantics for ``certorail.analysis.interpret_expr``.

Every test parses a real Python expression, evaluates it against a mocked
abstract state (``name -> ValidationFact``), and checks the abstract value
that comes back. The suite is written against the *expected* semantics; it is
the specification the interpreter is filled in against.

Notation used in the helpers below:

* ``static("a", "b")``   -- a path known to be exactly ``a/b`` (relative to the root)
* ``splat("a")``         -- a path known to live somewhere at or below ``a/``
* ``path_of(loc)``       -- the path-typed fact carrying containment ``loc``
* ``validated(...)``     -- a string-typed fact carrying atoms and/or a pseudo-regex
"""
import ast
import unittest

from certorail.analysis import (
    ANY_STR,
    Alternation,
    AnyName,
    AtomicFact,
    Component,
    Concat,
    DirSplat,
    Exact,
    InvalidProgram,
    LocationFact,
    Matching,
    Named,
    OneOf,
    PathFact,
    PseudoRegex,
    RegexLit,
    StaticPath,
    StrFact,
    ValidationFact,
    interpret_expr,
)

type State = dict[str, ValidationFact]

ANY = AnyName()


def evaluate(src: str, st: State | None = None) -> ValidationFact | None:
    expr = ast.parse(src, mode="eval").body
    return interpret_expr(expr, st if st is not None else {})


def static(*parts: str | Component) -> StaticPath:
    return StaticPath(tuple(Named(p) if isinstance(p, str) else p for p in parts))


def splat(*prefix: str | Component, final: Component = ANY) -> DirSplat:
    return DirSplat(
        static_prefix=tuple(Named(p) if isinstance(p, str) else p for p in prefix),
        final_component=final,
    )


def path_of(loc: LocationFact) -> PathFact:
    return PathFact(containment=loc)


def validated(*atoms: AtomicFact, regex: PseudoRegex | None = None) -> StrFact:
    return StrFact(regex=ANY_STR if regex is None else regex, atoms=frozenset(atoms))


# A path known to be exactly ``base``.
BASE = path_of(static("base"))
# A path known to be somewhere at or below ``base/``.
UNDER_BASE = path_of(splat("base"))


class TestNames(unittest.TestCase):
    def test_bound_name_yields_its_fact(self) -> None:
        self.assertEqual(evaluate("p", {"p": BASE}), BASE)

    def test_unbound_name_is_unknown(self) -> None:
        self.assertIsNone(evaluate("q", {"p": BASE}))

    def test_empty_state_is_unknown(self) -> None:
        self.assertIsNone(evaluate("p"))


class TestPathFromLiteral(unittest.TestCase):
    def test_relative_literal_becomes_static_path(self) -> None:
        cases: list[tuple[str, StaticPath]] = [
            ('pathlib.Path("a")', static("a")),
            ('pathlib.Path("a/b")', static("a", "b")),
            ('pathlib.Path("a/b/c.txt")', static("a", "b", "c.txt")),
            # PurePath normalisation
            ('pathlib.Path("a//b")', static("a", "b")),
            ('pathlib.Path("./a")', static("a")),
            ('pathlib.Path("a/./b")', static("a", "b")),
            ('pathlib.Path("a/")', static("a")),
        ]
        for src, loc in cases:
            with self.subTest(src=src):
                self.assertEqual(evaluate(src), path_of(loc))

    def test_unsafe_or_empty_literal_is_unknown(self) -> None:
        cases = [
            'pathlib.Path("/etc/passwd")',
            'pathlib.Path("/")',
            'pathlib.Path("..")',
            'pathlib.Path("../a")',
            'pathlib.Path("a/../b")',
            'pathlib.Path("a/..")',
            'pathlib.Path("")',
            'pathlib.Path(".")',
        ]
        for src in cases:
            with self.subTest(src=src):
                self.assertIsNone(evaluate(src))


class TestPathFromName(unittest.TestCase):
    def test_static_containment_passes_through(self) -> None:
        self.assertEqual(evaluate("pathlib.Path(p)", {"p": BASE}), BASE)

    def test_splat_containment_passes_through(self) -> None:
        self.assertEqual(evaluate("pathlib.Path(d)", {"d": UNDER_BASE}), UNDER_BASE)

    def test_fact_without_containment_is_unknown(self) -> None:
        st: State = {"s": validated("no-slash", "no-parent-traversal")}
        self.assertIsNone(evaluate("pathlib.Path(s)", st))

    def test_unbound_name_is_unknown(self) -> None:
        self.assertIsNone(evaluate("pathlib.Path(q)", {"p": BASE}))


class TestPathFromMultipleArgs(unittest.TestCase):
    def test_literals_are_joined_in_order(self) -> None:
        cases: list[tuple[str, StaticPath]] = [
            ('pathlib.Path("a", "b")', static("a", "b")),
            ('pathlib.Path("a", "b", "c")', static("a", "b", "c")),
            ('pathlib.Path("a", "b/c")', static("a", "b", "c")),
            ('pathlib.Path("a/b", "c")', static("a", "b", "c")),
        ]
        for src, loc in cases:
            with self.subTest(src=src):
                self.assertEqual(evaluate(src), path_of(loc))

    def test_literal_then_static_fact(self) -> None:
        self.assertEqual(
            evaluate('pathlib.Path("a", p)', {"p": BASE}),
            path_of(static("a", "base")),
        )

    def test_literal_then_splat_fact(self) -> None:
        self.assertEqual(
            evaluate('pathlib.Path("a", d)', {"d": UNDER_BASE}),
            path_of(splat("a", "base")),
        )

    def test_static_fact_then_literal(self) -> None:
        self.assertEqual(
            evaluate('pathlib.Path(p, "x")', {"p": BASE}),
            path_of(static("base", "x")),
        )

    def test_splat_fact_then_literal_fixes_final_component(self) -> None:
        self.assertEqual(
            evaluate('pathlib.Path(d, "x/y")', {"d": UNDER_BASE}),
            path_of(splat("base", final=Named("y"))),
        )

    def test_two_static_facts(self) -> None:
        st: State = {"p": BASE, "q": path_of(static("x", "y"))}
        self.assertEqual(evaluate("pathlib.Path(p, q)", st), path_of(static("base", "x", "y")))

    def test_literal_then_single_component_string(self) -> None:
        st: State = {"s": validated("no-slash", "no-parent-traversal")}
        self.assertEqual(evaluate('pathlib.Path("a", s)', st), path_of(static("a", ANY)))

    def test_literal_then_relative_string_becomes_splat(self) -> None:
        st: State = {"s": validated("no-parent-traversal", "not-absolute")}
        self.assertEqual(evaluate('pathlib.Path("a", s)', st), path_of(splat("a")))

    def test_unsafe_trailing_argument_is_unknown(self) -> None:
        cases = [
            'pathlib.Path("a", "/abs")',
            'pathlib.Path("a", "..")',
            'pathlib.Path("a", "b/../c")',
            'pathlib.Path("a", "")',
        ]
        for src in cases:
            with self.subTest(src=src):
                self.assertIsNone(evaluate(src))

    def test_unbound_trailing_argument_is_unknown(self) -> None:
        self.assertIsNone(evaluate('pathlib.Path("a", q)', {"p": BASE}))

    def test_unvalidated_trailing_string_is_unknown(self) -> None:
        self.assertIsNone(evaluate('pathlib.Path("a", s)', {"s": validated()}))


class TestCallShapes(unittest.TestCase):
    def test_path_with_no_arguments_is_unknown(self) -> None:
        self.assertIsNone(evaluate("pathlib.Path()"))

    def test_bare_path_name_is_not_pathlib_path(self) -> None:
        # ``from pathlib import Path`` is rejected by the walker, so a bare
        # ``Path`` never refers to ``pathlib.Path``.
        self.assertIsNone(evaluate('Path("a")'))

    def test_other_attribute_call_is_unknown(self) -> None:
        self.assertIsNone(evaluate("os.fspath(p)", {"p": BASE}))

    def test_other_name_call_is_unknown(self) -> None:
        self.assertIsNone(evaluate("str(p)", {"p": BASE}))

    def test_super_method_call_is_unknown(self) -> None:
        self.assertIsNone(evaluate("super().resolve()", {"p": BASE}))

    def test_starred_first_argument_is_unknown(self) -> None:
        self.assertIsNone(evaluate("pathlib.Path(*parts)", {"p": BASE}))

    def test_starred_trailing_argument_is_unknown(self) -> None:
        self.assertIsNone(evaluate("pathlib.Path(p, *rest)", {"p": BASE}))

    def test_keyword_only_call_is_unknown(self) -> None:
        self.assertIsNone(evaluate('pathlib.Path(**kw)'))


class TestComputedCallees(unittest.TestCase):
    def test_lambda_callee_is_invalid(self) -> None:
        with self.assertRaises(InvalidProgram):
            evaluate("(lambda: 0)()")

    def test_call_of_call_is_invalid(self) -> None:
        with self.assertRaises(InvalidProgram):
            evaluate("f()()")

    def test_subscript_callee_is_invalid(self) -> None:
        with self.assertRaises(InvalidProgram):
            evaluate("fs[0]()")

    def test_method_on_call_result_is_invalid(self) -> None:
        with self.assertRaises(InvalidProgram):
            evaluate("f().g()")


class TestJoinWithLiteral(unittest.TestCase):
    def test_static_path_extends(self) -> None:
        cases: list[tuple[str, StaticPath]] = [
            ('p / "x"', static("base", "x")),
            ('p / "x/y"', static("base", "x", "y")),
            ('p / "x//y"', static("base", "x", "y")),
            ('p / "./x"', static("base", "x")),
            ('p / "x/./y"', static("base", "x", "y")),
            ('p / "x/"', static("base", "x")),
        ]
        for src, loc in cases:
            with self.subTest(src=src):
                self.assertEqual(evaluate(src, {"p": BASE}), path_of(loc))

    def test_static_path_rejects_unsafe_literal(self) -> None:
        cases = [
            'p / "/abs"',
            'p / ".."',
            'p / "../x"',
            'p / "x/../y"',
            'p / "x/.."',
            'p / ""',
            'p / "."',
        ]
        for src in cases:
            with self.subTest(src=src):
                self.assertIsNone(evaluate(src, {"p": BASE}))

    def test_splat_fixes_final_component(self) -> None:
        cases: list[tuple[str, DirSplat]] = [
            ('d / "x"', splat("base", final=Named("x"))),
            ('d / "x/y"', splat("base", final=Named("y"))),
        ]
        for src, loc in cases:
            with self.subTest(src=src):
                self.assertEqual(evaluate(src, {"d": UNDER_BASE}), path_of(loc))

    def test_splat_rejects_unsafe_literal(self) -> None:
        cases = ['d / "/abs"', 'd / ".."', 'd / "x/../y"', 'd / ""']
        for src in cases:
            with self.subTest(src=src):
                self.assertIsNone(evaluate(src, {"d": UNDER_BASE}))


class TestJoinWithPathFact(unittest.TestCase):
    def test_static_then_static_concatenates(self) -> None:
        st: State = {"p": BASE, "q": path_of(static("x", "y"))}
        self.assertEqual(evaluate("p / q", st), path_of(static("base", "x", "y")))

    def test_static_then_splat_extends_prefix(self) -> None:
        st: State = {"p": BASE, "q": path_of(splat("x", final=Matching(RegexLit(r"\w+"))))}
        self.assertEqual(
            evaluate("p / q", st),
            path_of(splat("base", "x", final=Matching(RegexLit(r"\w+")))),
        )

    def test_splat_then_static_keeps_prefix_takes_final(self) -> None:
        st: State = {"d": UNDER_BASE, "q": path_of(static("x", "y"))}
        self.assertEqual(evaluate("d / q", st), path_of(splat("base", final=Named("y"))))

    def test_splat_then_splat_keeps_prefix_takes_final(self) -> None:
        st: State = {"d": UNDER_BASE, "q": path_of(splat("x", final=Matching(RegexLit(r"\w+"))))}
        self.assertEqual(evaluate("d / q", st), path_of(splat("base", final=Matching(RegexLit(r"\w+")))))


class TestJoinWithValidatedString(unittest.TestCase):
    """The right operand is a string-typed fact carrying atoms, no containment."""

    def test_single_component_extends_with_wildcard(self) -> None:
        st: State = {"p": BASE, "s": validated("no-slash", "no-parent-traversal")}
        self.assertEqual(evaluate("p / s", st), path_of(static("base", ANY)))

    def test_single_component_carries_its_regex(self) -> None:
        r = RegexLit(r"\w+\.txt")
        st: State = {"p": BASE, "s": validated("no-slash", "no-parent-traversal", regex=r)}
        self.assertEqual(evaluate("p / s", st), path_of(static("base", Matching(r))))

    def test_relative_multi_component_becomes_splat(self) -> None:
        st: State = {"p": BASE, "s": validated("no-parent-traversal", "not-absolute")}
        self.assertEqual(evaluate("p / s", st), path_of(splat("base")))

    def test_relative_multi_component_ignores_regex(self) -> None:
        r = RegexLit(r"[a-z/]+")
        st: State = {"p": BASE, "s": validated("no-parent-traversal", "not-absolute", regex=r)}
        self.assertEqual(evaluate("p / s", st), path_of(splat("base")))

    def test_all_atoms_prefers_single_component(self) -> None:
        st: State = {
            "p": BASE,
            "s": validated("no-slash", "no-parent-traversal", "not-absolute"),
        }
        self.assertEqual(evaluate("p / s", st), path_of(static("base", ANY)))

    def test_insufficient_atoms_is_unknown(self) -> None:
        cases: list[tuple[AtomicFact, ...]] = [
            (),
            ("no-slash",),
            ("not-absolute",),
            ("no-parent-traversal",),
            ("no-slash", "not-absolute"),
        ]
        for atoms in cases:
            with self.subTest(atoms=atoms):
                st: State = {"p": BASE, "s": validated(*atoms)}
                self.assertIsNone(evaluate("p / s", st))

    def test_opaque_regex_alone_proves_nothing(self) -> None:
        st: State = {"p": BASE, "s": validated(regex=RegexLit(r"\w+"))}
        self.assertIsNone(evaluate("p / s", st))

    def test_splat_base_single_component_replaces_final(self) -> None:
        r = RegexLit(r"\w+")
        st: State = {"d": UNDER_BASE, "s": validated("no-slash", "no-parent-traversal", regex=r)}
        self.assertEqual(evaluate("d / s", st), path_of(splat("base", final=Matching(r))))

    def test_splat_base_relative_multi_component_stays_splat(self) -> None:
        st: State = {"d": UNDER_BASE, "s": validated("no-parent-traversal", "not-absolute")}
        self.assertEqual(evaluate("d / s", st), path_of(splat("base")))


class TestJoinWithRegexDerivedAtoms(unittest.TestCase):
    """Atoms not stated explicitly are derived from the shape of the pseudo-regex."""

    def test_exact_filename_extends(self) -> None:
        st: State = {"p": BASE, "s": validated(regex=Exact("foo.txt"))}
        self.assertEqual(evaluate("p / s", st), path_of(static("base", "foo.txt")))

    def test_exact_unsafe_is_unknown(self) -> None:
        for exact in ("..", "../x", "/etc"):
            with self.subTest(exact=exact):
                st: State = {"p": BASE, "s": validated(regex=Exact(exact))}
                self.assertIsNone(evaluate("p / s", st))

    def test_exact_empty_joins_to_the_path_itself(self) -> None:
        # "" has no slash and is not "..", so it is relative with no parent traversal; it is not a
        # component, but the join is p itself, which the at-or-below reading of the splat covers
        st: State = {"p": BASE, "s": validated(regex=Exact(""))}
        self.assertEqual(evaluate("p / s", st), path_of(splat("base")))

    def test_alternation_of_safe_exacts_extends(self) -> None:
        alt = Alternation([Exact("a.txt"), Exact("b.txt")])
        st: State = {"p": BASE, "s": validated(regex=alt)}
        self.assertEqual(
            evaluate("p / s", st), path_of(static("base", OneOf(frozenset({"a.txt", "b.txt"}))))
        )

    def test_alternation_with_unsafe_branch_is_unknown(self) -> None:
        alt = Alternation([Exact("a.txt"), Exact("../b.txt")])
        st: State = {"p": BASE, "s": validated(regex=alt)}
        self.assertIsNone(evaluate("p / s", st))

    def test_alternation_with_opaque_branch_needs_atoms(self) -> None:
        alt = Alternation([Exact("a.txt"), RegexLit(r"\w+")])
        self.assertIsNone(evaluate("p / s", {"p": BASE, "s": validated(regex=alt)}))
        st: State = {"p": BASE, "s": validated("no-slash", "no-parent-traversal", regex=alt)}
        self.assertEqual(evaluate("p / s", st), path_of(static("base", Matching(alt))))

    def test_concat_needs_atoms(self) -> None:
        cat = Concat([Exact("report-"), RegexLit(r"\d+")])
        self.assertIsNone(evaluate("p / s", {"p": BASE, "s": validated(regex=cat)}))
        st: State = {"p": BASE, "s": validated("no-slash", "no-parent-traversal", regex=cat)}
        self.assertEqual(evaluate("p / s", st), path_of(static("base", Matching(cat))))

    def test_concat_with_no_parent_only_becomes_splat_when_head_is_relative(self) -> None:
        # not-absolute is derived from the first piece of the concatenation
        cat = Concat([Exact("report-"), RegexLit(r".+")])
        st: State = {"p": BASE, "s": validated("no-parent-traversal", regex=cat)}
        self.assertEqual(evaluate("p / s", st), path_of(splat("base")))

    def test_concat_with_opaque_head_is_unknown(self) -> None:
        cat = Concat([RegexLit(r".+"), Exact(".txt")])
        st: State = {"p": BASE, "s": validated("no-parent-traversal", regex=cat)}
        self.assertIsNone(evaluate("p / s", st))


class TestJoinOperandRestrictions(unittest.TestCase):
    def test_literal_left_operand_is_unknown(self) -> None:
        self.assertIsNone(evaluate('"a" / p', {"p": BASE}))

    def test_unbound_left_operand_is_unknown(self) -> None:
        self.assertIsNone(evaluate('q / "x"', {"p": BASE}))

    def test_unbound_right_operand_is_unknown(self) -> None:
        self.assertIsNone(evaluate("p / q", {"p": BASE}))

    def test_string_typed_left_operand_is_unknown(self) -> None:
        s = StrFact(containment=static("base"))
        self.assertIsNone(evaluate('s / "x"', {"s": s}))

    def test_path_without_containment_is_unknown(self) -> None:
        self.assertIsNone(evaluate('p / "x"', {"p": PathFact()}))

    def test_other_binary_operators_do_not_join(self) -> None:
        for src in ('p + "x"', 'p // "x"', 'p % "x"'):
            with self.subTest(src=src):
                self.assertIsNone(evaluate(src, {"p": BASE}))


class TestCompoundExpressions(unittest.TestCase):
    """Sub-expressions are interpreted recursively."""

    def test_chained_join(self) -> None:
        self.assertEqual(evaluate('p / "a" / "b"', {"p": BASE}), path_of(static("base", "a", "b")))

    def test_parenthesised_chained_join(self) -> None:
        self.assertEqual(evaluate('(p / "a") / "b"', {"p": BASE}), path_of(static("base", "a", "b")))

    def test_join_onto_constructor(self) -> None:
        self.assertEqual(evaluate('pathlib.Path("a") / "b"'), path_of(static("a", "b")))

    def test_join_constructor_onto_fact(self) -> None:
        self.assertEqual(evaluate('pathlib.Path("a") / p', {"p": BASE}), path_of(static("a", "base")))

    def test_join_fact_onto_constructor(self) -> None:
        self.assertEqual(evaluate('p / pathlib.Path("x")', {"p": BASE}), path_of(static("base", "x")))

    def test_constructor_of_join(self) -> None:
        self.assertEqual(evaluate('pathlib.Path(p / "x")', {"p": BASE}), path_of(static("base", "x")))

    def test_constructor_of_constructor(self) -> None:
        self.assertEqual(evaluate('pathlib.Path("a", pathlib.Path("b"))'), path_of(static("a", "b")))

    def test_chained_join_onto_splat(self) -> None:
        self.assertEqual(
            evaluate('d / "a" / "b"', {"d": UNDER_BASE}),
            path_of(splat("base", final=Named("b"))),
        )

    def test_unsafe_component_anywhere_in_chain_is_unknown(self) -> None:
        for src in ('p / ".." / "b"', 'p / "a" / "/b"', 'pathlib.Path("..") / "b"'):
            with self.subTest(src=src):
                self.assertIsNone(evaluate(src, {"p": BASE}))


class TestUnsupportedForms(unittest.TestCase):
    def test_non_path_expressions_are_unknown(self) -> None:
        cases = [
            "3",
            "None",
            "p[0]",
            '(p, "x")',
            '[p, "x"]',
            '{"k": p}',
            "p == q",
        ]
        st: State = {"p": BASE, "q": BASE}
        for src in cases:
            with self.subTest(src=src):
                self.assertIsNone(evaluate(src, st))


if __name__ == "__main__":
    unittest.main()
