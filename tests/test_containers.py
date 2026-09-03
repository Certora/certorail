"""Typed containers (CONTAINERS.md): opt-in list/set tracking, the roster, escapes with
provenance, invariance at call sites, Sequence borrows, and move-out returns."""
import unittest

from certorail.walker import analyze

HEADER = "import typing\n"

# P is strictly stronger than Q: mutual entailment fails one way, so invariance can be probed
P = "typing.Annotated[str, certora.no_slash, certora.no_parent_traversal]"
Q = "typing.Annotated[str, certora.no_slash]"

DECL = f'xs: list[{P}] = ["a", "b"]\n'
USE = (
    f"def use(v: {P}) -> None:\n"
    "    pass\n"
)


def violations(source: str) -> list[str]:
    return [what for _, what in analyze(HEADER + source).violations]


class TestConstruction(unittest.TestCase):
    def test_a_conforming_display_constructs(self) -> None:
        self.assertEqual(violations(DECL), [])

    def test_a_bad_element_is_a_violation(self) -> None:
        got = violations(f'xs: list[{P}] = ["a", "b/c"]\n')
        self.assertTrue(any("element 2 does not establish" in v for v in got))

    def test_empty_constructors(self) -> None:
        self.assertEqual(violations(f"xs: list[{P}] = list()\nss: set[{Q}] = set()\n"), [])

    def test_the_copy_constructor_is_the_blessed_alias(self) -> None:
        # P implies Q: copying down is fine; copying back up is not
        self.assertEqual(violations(DECL + f"ys: list[{Q}] = list(xs)\n"), [])
        got = violations(f'ys: list[{Q}] = ["a"]\nzs: list[{P}] = list(ys)\n')
        self.assertTrue(any("copied elements do not establish" in v for v in got))

    def test_plain_aliasing_is_not_a_constructor(self) -> None:
        got = violations(DECL + f"ws: list[{P}] = xs\n")
        self.assertTrue(any("not a recognized list constructor" in v for v in got))

    def test_sequence_cannot_be_constructed(self) -> None:
        got = violations(f'zs: typing.Sequence[{P}] = ["a"]\n')
        self.assertTrue(any("borrowed view" in v for v in got))


class TestRoster(unittest.TestCase):
    def test_a_good_write_keeps_the_container(self) -> None:
        self.assertEqual(violations(USE + DECL + 'xs.append("c")\nuse(xs[0])\n'), [])

    def test_a_bad_write_is_a_violation(self) -> None:
        got = violations(DECL + 'xs.append("c/d")\n')
        self.assertTrue(any("appended element does not establish" in v for v in got))
        got = violations(DECL + 'xs[0] = "z/x"\n')
        self.assertTrue(any("assigned element does not establish" in v for v in got))

    def test_extend_and_augmented_assign(self) -> None:
        self.assertEqual(violations(DECL + 'xs += ["ok"]\n'), [])
        got = violations(DECL + 'xs.extend(["c", "d/e"])\n')
        self.assertTrue(any("extended elements do not establish" in v for v in got))

    def test_the_kinds_carry_their_own_methods(self) -> None:
        got = violations(f'ss: set[{Q}] = set()\nss.append("a")\n')
        self.assertTrue(any("has no append()" in v for v in got))
        self.assertEqual(violations(f'ss: set[{Q}] = set()\nss.add("a")\n'), [])

    def test_reads_yield_the_element_fact(self) -> None:
        self.assertEqual(violations(USE + DECL + "use(xs[0])\n"), [])
        self.assertEqual(violations(USE + DECL + "for v in xs:\n    use(v)\n"), [])


class TestEscape(unittest.TestCase):
    """Every off-roster use is a violation: a typed container is an opt-in promise, and this
    is code written de novo to be analyzable -- there is no 'oh well, lost precision'."""

    def test_aliasing_is_an_escape_violation(self) -> None:
        got = violations(DECL + "ys = xs\n")
        self.assertTrue(any("escapes" in v for v in got))

    def test_passing_to_an_unvouched_call_is_an_escape_violation(self) -> None:
        got = violations(DECL + "print(xs)\n")
        self.assertTrue(any("escapes" in v for v in got))

    def test_a_parameter_escape_is_an_error_too(self) -> None:
        got = violations(
            f"def leak(zs: list[{P}]) -> None:\n"
            "    print(zs)\n"
        )
        self.assertTrue(any("escapes" in v for v in got))

    def test_a_loop_boundary_escape_is_caught(self) -> None:
        got = violations(
            f"def leaky(zs: list[{P}]) -> None:\n"
            "    for i in [1]:\n"
            "        print(zs)\n"
        )
        self.assertTrue(any("escapes" in v for v in got))


class TestStoreShapes(unittest.TestCase):
    """Only the direct, single-target element store is the blessed shape: every other store
    spelling escapes the container rather than writing it unobligated."""

    def test_a_tuple_target_store_is_an_escape_violation(self) -> None:
        # (xs[0], z) = ("/", ...) must never be a silently unobligated write
        got = violations(DECL + '(xs[0], z) = ("/", "lmao")\n')
        self.assertTrue(any("escapes" in v for v in got))

    def test_an_augmented_subscript_store_is_an_escape_violation(self) -> None:
        got = violations(DECL + 'xs[0] += "/"\n')
        self.assertTrue(any("escapes" in v for v in got))

    def test_a_for_target_store_is_an_escape_violation(self) -> None:
        got = violations(DECL + 'for xs[0] in ["a"]:\n    pass\n')
        self.assertTrue(any("escapes" in v for v in got))

    def test_the_direct_store_still_works(self) -> None:
        self.assertEqual(violations(DECL + 'xs[0] = "ok"\n'), [])


class TestCalls(unittest.TestCase):
    MUT = (
        f"def mut(zs: list[{Q}]) -> None:\n"
        '    zs.append("ok")\n'
    )
    RO = (
        f"def ro(zs: typing.Sequence[{Q}]) -> None:\n"
        "    print(len(zs))\n"
    )

    def test_list_parameters_are_invariant(self) -> None:
        got = violations(self.MUT + DECL + "mut(xs)\n")
        self.assertTrue(any("invariance" in v for v in got))

    def test_sequence_parameters_are_covariant_borrows(self) -> None:
        # P implies Q, and the caller keeps its fact across the borrow: the element read
        # after the call still discharges a P rely
        self.assertEqual(
            violations(self.RO + USE + DECL + "ro(xs)\n" + "use(xs[0])\n"), []
        )

    def test_sequence_parameters_are_read_only(self) -> None:
        got = violations(
            f"def bad(zs: typing.Sequence[{Q}]) -> None:\n"
            '    zs.append("ok")\n'
        )
        self.assertTrue(any("read-only" in v for v in got))


class TestReturns(unittest.TestCase):
    MAKE = (
        f"def make() -> list[{P}]:\n"
        f"    out: list[{P}] = []\n"
        '    out.append("a")\n'
        "    return out\n"
    )

    def test_a_local_moves_out_against_its_guarantee(self) -> None:
        self.assertEqual(violations(self.MAKE), [])

    def test_the_caller_receives_the_move(self) -> None:
        self.assertEqual(
            violations(self.MAKE + USE + "ws = make()\n" + "use(ws[0])\n"), []
        )

    def test_returning_a_parameter_is_an_error(self) -> None:
        got = violations(
            f"def ret(zs: list[{P}]) -> list[{P}]:\n"
            "    return zs\n"
        )
        self.assertTrue(any("may not be returned" in v for v in got))

    def test_a_move_needs_its_guarantee(self) -> None:
        got = violations(
            f"def weak() -> list[{P}]:\n"
            f"    out: list[{Q}] = []\n"
            "    return out\n"
        )
        self.assertTrue(any("container guarantee" in v for v in got))


if __name__ == "__main__":
    unittest.main()
