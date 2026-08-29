"""Source rewriting for execution.

Applied to a program *after* it has passed the analysis and the policy, and before it runs: every
module-level function with a contract gets ``@certora.checked`` prepended, the runtime guard for
the plain-type half of its annotations (see ``markers.checked``). The markers need no runtime
counterpart -- relies are discharged at call sites and guarantees at returns, statically.

The result is unparsed back to source, so what runs is exactly what was analysed, plus the
decorators.
"""
import ast
from collections.abc import Iterable

from .markers import NAMESPACE


def rewrite(tree: ast.Module, contracted: Iterable[str]) -> str:
    """The program's source as it will run: contracted functions checked."""
    names = frozenset(contracted)
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name in names:
            checked = ast.Attribute(
                value=ast.Name(id=NAMESPACE, ctx=ast.Load()), attr="checked", ctx=ast.Load()
            )
            # first in the list = outermost: the check wraps whatever other decorators produce
            stmt.decorator_list.insert(0, ast.copy_location(checked, stmt))
    return ast.unparse(ast.fix_missing_locations(tree))
