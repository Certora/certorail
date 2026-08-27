"""A small term language over the expression shapes the analysis has opinions about.

Python's ``match`` cannot compute anything inside a pattern: a class pattern only tests
``isinstance`` and reads attributes the subject already has, so every "is this callee
``os.path.isabs``" ends up in a guard, and the same guard is repeated at every use. :func:`lower`
does that computation once, turning an ``ast.expr`` into a :data:`Term` whose structure *is* the
thing the recognizers care about, so they can be written as plain patterns::

    match lower(cond):
        case Compare(Const("/") | Dotted(("os", "sep")), ast.NotIn, x): ...
        case Call(("re", "fullmatch"), (Const(str() as r), x), ()): ...
        case Method(Method(p, "resolve", (), ()), "is_relative_to", (base,), ()): ...

The lowering is total and never raises: anything without a shape of interest becomes
:class:`Opaque`. Every term keeps its source ``node`` for diagnostics and for handing back to
``interpret_expr``; ``node`` is excluded from equality, so two terms are equal iff they are the
same expression up to source position.

Dotted names are ambiguous in Python syntax -- ``p.resolve()`` and ``os.path.isabs(x)`` are the
same shape -- so the lowering is parameterised by the names that denote *modules*: an attribute
chain rooted at one of them becomes :class:`Dotted`/:class:`Call` with a static path, any other
becomes :class:`Attr`/:class:`Method` on a term.
"""
import ast
from dataclasses import dataclass, field
from types import EllipsisType

from .analysis import resolve_callee
from .markers import NAMESPACE

# Names whose dotted attributes the analysis interprets. The walker can pass its actual imports
# instead; the default is the vocabulary the recognizers know about.
KNOWN_MODULES: frozenset[str] = frozenset({"os", "pathlib", "re", "sys", "typing", NAMESPACE})


@dataclass(frozen=True)
class _Node:
    # kw_only keeps it out of __match_args__ and out of the positional constructor
    node: ast.expr = field(compare=False, repr=False, kw_only=True)

    # -- small readers, available on every Term -------------------------------

    def as_str(self) -> str | None:
        match self:
            case Const(str() as s):
                return s
            case _:
                return None

    def as_int(self) -> int | None:
        match self:
            case Const(int() as n) if not isinstance(n, bool):
                return n
            case _:
                return None

    def str_items(self) -> list[str] | None:
        """The strings of a display of string literals (``("a", "b")``, ``{"a": 1}``'s keys)."""
        match self:
            case Items(items):
                out: list[str] = []
                for item in items:
                    s = item.as_str()
                    if s is None:
                        return None
                    out.append(s)
                return out
            case _:
                return None


@dataclass(frozen=True)
class Var(_Node):
    """A bare name."""
    name: str


@dataclass(frozen=True)
class Const(_Node):
    """A literal: ``"..."``, ``0``, ``-1``, ``None``, ``...``, ``b"..."``."""
    value: str | bytes | bool | int | float | complex | EllipsisType | None


@dataclass(frozen=True)
class Dotted(_Node):
    """A module-rooted attribute chain used as a value: ``os.sep``, ``pathlib.Path``."""
    path: tuple[str, ...]


@dataclass(frozen=True)
class Attr(_Node):
    """An attribute of a non-module term: ``p.parts``, ``pathlib.PurePath(x).name``."""
    recv: "Term"
    name: str


@dataclass(frozen=True)
class Call(_Node):
    """A call of a builtin or module-rooted name: ``str(p)``, ``os.path.isabs(x)``."""
    callee: tuple[str, ...]
    args: tuple["Term", ...]
    kwargs: tuple[tuple[str, "Term"], ...]


@dataclass(frozen=True)
class Method(_Node):
    """A call of an attribute of a non-module term: ``x.startswith(...)``, ``p.resolve()``."""
    recv: "Term"
    name: str
    args: tuple["Term", ...]
    kwargs: tuple[tuple[str, "Term"], ...]


@dataclass(frozen=True)
class Compare(_Node):
    """A single comparison; chained comparisons stay Opaque."""
    left: "Term"
    op: type[ast.cmpop]
    right: "Term"


@dataclass(frozen=True)
class Not(_Node):
    inner: "Term"


@dataclass(frozen=True)
class Bool(_Node):
    op: type[ast.boolop]
    parts: tuple["Term", ...]


@dataclass(frozen=True)
class BinOp(_Node):
    left: "Term"
    op: type[ast.operator]
    right: "Term"


@dataclass(frozen=True)
class Items(_Node):
    """The elements of a tuple/list/set display, or the keys of a dict display."""
    items: tuple["Term", ...]


@dataclass(frozen=True)
class Subscript(_Node):
    value: "Term"
    index: "Term"


@dataclass(frozen=True)
class Slice(_Node):
    lower: "Term | None"
    upper: "Term | None"
    step: "Term | None"


@dataclass(frozen=True)
class Opaque(_Node):
    """An expression with no shape of interest."""


type Term = (
    Var | Const | Dotted | Attr | Call | Method | Compare | Not | Bool | BinOp | Items | Subscript
    | Slice | Opaque
)


def dotted_path(e: ast.expr, modules: frozenset[str]) -> tuple[str, ...] | None:
    """``m.a.b`` rooted at a module name -> ``("m", "a", "b")``; anything else -> None."""
    if not isinstance(e, ast.Attribute):
        return None
    access = resolve_callee(e)
    if access is None or not access.is_var_base or access.base_name not in modules:
        return None
    return (access.base_name, *access.field_names)


def lower(e: ast.expr, modules: frozenset[str] = KNOWN_MODULES) -> Term:
    """Lower an expression into a Term. Total: unknown shapes become Opaque."""

    def rec(x: ast.expr) -> Term:
        return lower(x, modules)

    match e:
        case ast.Name(id=name):
            return Var(name, node=e)
        case ast.Constant(value=v):
            return Const(v, node=e)
        case ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=int() as v)) if (
            not isinstance(v, bool)
        ):
            return Const(-v, node=e)
        case ast.UnaryOp(op=ast.Not(), operand=inner):
            return Not(rec(inner), node=e)
        case ast.BoolOp(op=op, values=values):
            return Bool(type(op), tuple(rec(v) for v in values), node=e)
        case ast.Compare(left=left, ops=[op], comparators=[right]):
            return Compare(rec(left), type(op), rec(right), node=e)
        case ast.BinOp(left=left, op=op, right=right):
            return BinOp(rec(left), type(op), rec(right), node=e)
        case ast.Attribute(value=value, attr=attr):
            path = dotted_path(e, modules)
            if path is not None:
                return Dotted(path, node=e)
            return Attr(rec(value), attr, node=e)
        case ast.Call(func=func, args=args, keywords=keywords):
            if any(isinstance(a, ast.Starred) for a in args) or any(k.arg is None for k in keywords):
                return Opaque(node=e)  # splats defeat static binding
            largs = tuple(rec(a) for a in args)
            lkwargs = tuple((k.arg, rec(k.value)) for k in keywords if k.arg is not None)
            match func:
                case ast.Name(id=name):
                    return Call((name,), largs, lkwargs, node=e)
                case ast.Attribute(value=recv, attr=name):
                    path = dotted_path(func, modules)
                    if path is not None:
                        return Call(path, largs, lkwargs, node=e)
                    return Method(rec(recv), name, largs, lkwargs, node=e)
                case _:
                    return Opaque(node=e)  # computed callee
        case ast.Tuple(elts=elts) | ast.List(elts=elts) | ast.Set(elts=elts):
            if any(isinstance(x, ast.Starred) for x in elts):
                return Opaque(node=e)
            return Items(tuple(rec(x) for x in elts), node=e)
        case ast.Dict(keys=keys):
            if any(k is None for k in keys):
                return Opaque(node=e)  # a ** splat: unknown keys
            return Items(tuple(rec(k) for k in keys if k is not None), node=e)
        case ast.Subscript(value=value, slice=index):
            return Subscript(rec(value), rec(index), node=e)
        case ast.Slice(lower=lo, upper=up, step=st):
            return Slice(
                None if lo is None else rec(lo),
                None if up is None else rec(up),
                None if st is None else rec(st),
                node=e,
            )
        case _:
            return Opaque(node=e)
