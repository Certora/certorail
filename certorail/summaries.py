"""Function summaries: the second half of the callee analysis (EFFECTS.md).

A call the enforcement cannot place may run *program* code. For a call to a module-level
function by name -- the one shape of program call the subset makes resolvable: such a name is
bound exactly once and may not be rebound (``safepy``) -- the walker computes a
:class:`Summary`: what one call does to the state (a :class:`Kill`) and what it returns, as a
fixpoint over the module for recursion. Every other program call -- a class instantiated, a
method on an instance, a lambda or a nested function held in a variable, a parameter called --
havocs the world: it writes everything and opens everything. Classes are deliberately not
modelled; the precision a receiver analysis would buy is not worth its machinery.

Also here, read off the module once: the names defined as ``@property`` anywhere. A read of an
attribute by such a name on a receiver the analysis does not know to be inert may run a
getter, so it is an unknown call.
"""
import ast
from collections.abc import Iterable
from dataclasses import dataclass

from certorail.analysis import Std
from certorail.enforcement import NO_KILL, OPAQUE, Kill

# ---------------------------------------------------------------------------
# the lattice
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Never:
    """The result of a function no call has been seen to return from -- the bottom of the
    result lattice, from which the fixpoint iteration starts."""


NEVER = Never()

# what a call returns, as far as the callee analysis cares: a standard value (its kind and
# closedness), or -- None, the top -- possibly a program object: a function, a generator, an
# instance
type Result = Std | Never | None


def join_result(a: Result, b: Result) -> Result:
    if isinstance(a, Never):
        return b
    if isinstance(b, Never):
        return a
    if a is None or b is None:
        return None
    return Std(a.kind if a.kind == b.kind else None, a.closed and b.closed)


@dataclass(frozen=True)
class Summary:
    """What one call of a function does: the kill it applies to the caller's state -- the
    regions it may write, whether it opens -- and what it returns. Computed with every
    parameter unknown, so it holds for any argument."""

    kill: Kill
    result: Result

    def __or__(self, other: "Summary") -> "Summary":
        return Summary(self.kill | other.kill, join_result(self.result, other.result))


BOTTOM = Summary(NO_KILL, NEVER)
# a call nothing is known about: program code may run and hand back anything
HAVOC = Summary(OPAQUE, None)


# ---------------------------------------------------------------------------
# what is summarized
# ---------------------------------------------------------------------------


def is_generator(node: ast.FunctionDef) -> bool:
    """Does the body yield? Then a call creates a generator and runs nothing; the body runs when
    the generator is consumed (EFFECTS.md: creation applies the body's kill eagerly, and the
    result is not inert)."""
    pending: list[ast.AST] = list(node.body)
    while pending:
        n = pending.pop()
        match n:
            case ast.Yield() | ast.YieldFrom():
                return True
            case ast.FunctionDef() | ast.Lambda() | ast.ClassDef():
                continue  # a nested scope's yields are its own
            case _:
                pending.extend(ast.iter_child_nodes(n))
    return False


def module_functions(module: ast.Module) -> dict[str, ast.FunctionDef]:
    """The module-level defs by name: the callees a bare name resolves to."""
    return {s.name: s for s in module.body if isinstance(s, ast.FunctionDef)}


def property_names(module: ast.Module) -> frozenset[str]:
    """Every name defined with ``@property`` anywhere in the module."""
    return frozenset(
        n.name
        for n in ast.walk(module)
        if isinstance(n, ast.FunctionDef)
        and any(isinstance(d, ast.Name) and d.id == "property" for d in n.decorator_list)
    )


def join_all(summaries: Iterable[Summary]) -> Summary:
    total = BOTTOM
    for s in summaries:
        total = total | s
    return total
