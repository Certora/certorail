import ast
from contextlib import contextmanager
import inspect
from typing import Any, cast, Callable, Literal, Sequence
from dataclasses import dataclass, is_dataclass
from .dangerous import DANGEROUS_MEMBERS, FORBIDDEN_ATTRIBUTES, FORBIDDEN_MODULES

sensitive_builtins = (
    "getattr",
    "setattr",
    "delattr",
    "vars",
    "locals",
    "globals",
    "compile",
    "eval",
    "exec",
    "open",
    "breakpoint"
)

validator_funcs = frozenset([
    "certora_within",
    "certora_matches"
])

def is_dunder(x: str) -> bool:
    return x.startswith("__") and x.endswith("__")

@dataclass
class RegexMatch:
    regex: str

@dataclass
class PathConfinement:
    confined_path: str

type ValidationRule = PathConfinement | RegexMatch

@dataclass
class ValidatedUsage:
    ident: str
    validation_rule: ValidationRule

@dataclass
class OpenCall:
    where: ast.AST
    mode: str
    target: str | list[ValidationRule]

type AuditEvents = OpenCall

@dataclass
class Validated:
    ident: str
    validations: list[ValidationRule]

def is_call_to(
    i: ast.AST
) -> str | None:
    if not isinstance(i, ast.Call):
        return None
    if not isinstance(i.func, ast.Name):
        return None
    return i.func.id

class InvalidConstantForm(Exception):
    ...

def cast_as_const_or_default[T](
    t: type[T],
    elem: Any
) -> T:
    if not isinstance(elem, ast.expr) and not isinstance(elem, t):
        raise InvalidConstantForm(f"Unexpected type: {type(elem)}")
    return as_const_or_default(t, elem)

def as_const_or_default[T](
    t: type[T],
    elem: T | ast.expr
) -> T:
    if isinstance(elem, t):
        return elem
    if not isinstance(elem, ast.Constant):
        raise InvalidConstantForm(f"Not a constnat expr: {type(elem).__name__}")
    if not isinstance(elem.value, t):
        raise InvalidConstantForm(f"Invalid constant type, expected: {t}, got {type(elem.value)}")
    return elem.value

def as_const[T](t: type[T], elem: ast.expr) -> T:
    if not isinstance(elem, ast.Constant):
        raise InvalidConstantForm(f"Expression is not a constant, got: {type(elem)}")
    if not isinstance(elem.value, t):
        raise InvalidConstantForm(f"Constant value is not a {t}, got {type(elem.value)}")
    return elem.value

@dataclass(frozen=True)
class OptionMonad[T]:
    s: T | None

    def map[S](self, m: Callable[[T], S]) -> "OptionMonad[S]":
        if self.s is None:
            return OptionMonad(None)
        d = m(self.s)
        if d is None:
            raise ValueError("You maybe don't know how monads work")
        return OptionMonad(d)

    def bind[S](self, m: "Callable[[T], S | None | OptionMonad[S]]") -> "OptionMonad[S]":
        if self.s is None:
            return OptionMonad(None)
        res =  m(self.s)
        if isinstance(res, OptionMonad):
            return res
        return OptionMonad(res)

    def downcast[X](self, t: type[X]) -> "OptionMonad[X]":
        if self.s is None or not isinstance(self.s, t):
            return OptionMonad(None)
        return OptionMonad(self.s)

    @classmethod
    def lift[R](cls, s: R | None) -> "OptionMonad[R]":
        return OptionMonad(s)

    def unwrap(self) -> T | None:
        return self.s

    def unwrap_or(self, default: T) -> T:
        if self.s is None:
            return default
        return self.s

@dataclass
class CertoraMatch:
    target: ast.expr
    matches: ast.expr


@dataclass
class PyOpenCall:
    file: ast.expr
    mode: ast.expr | str = "r"
    encoding: ast.expr | None = None
    errors : ast.expr | None = None
    newline: ast.expr | None = None
    closefd: ast.expr | bool = True
    opener: ast.expr | None = None

def bind_call_args[T](call: ast.Call, spec: type[T]) -> T | None:
    """Match the arguments of *call* against the dataclass type *spec*.
 
    On success returns ``spec(...)`` built from the call's argument
    expressions. Returns None when the call can't be statically bound:
 
      - *args / **kwargs splats anywhere in the call
      - too many positional arguments
      - unknown or duplicate keyword arguments
      - a required (no-default) field isn't supplied
      - a kw_only field passed positionally
      - an argument supplied both positionally and by keyword
 
    Only *binding* failures become None. The instance is constructed after
    binding succeeds, so exceptions from your own __post_init__ (a natural
    place for validation) propagate instead of masquerading as parse
    failures.
    """
    if not (isinstance(spec, type) and is_dataclass(spec)):
        raise TypeError(f"spec must be a dataclass type, got {spec!r}")
 
    # Splats defeat static binding.
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    kwargs: dict[str, ast.expr] = {}
    for kw in call.keywords:
        if kw.arg is None:  # a **splat
            return None
        if kw.arg in kwargs:  # impossible in parsed source; hand-built ASTs only
            return None
        kwargs[kw.arg] = kw.value
 
    # The dataclass's generated __init__ is the signature; bind against it.
    try:
        bound = inspect.signature(spec).bind(*call.args, **kwargs)
    except TypeError:  # any way the binding can fail at runtime
        return None
    return spec(*bound.args, **bound.kwargs)


def unfold_attr(e: ast.Attribute) -> tuple[ast.Name | Literal["super"], Sequence[tuple[str, ast.Attribute]]] | ast.AST:
    attr_path : list[tuple[str, ast.Attribute]] = []
    it = e
    while True:
        if isinstance(it, ast.Attribute):
            attr_path.append((it.attr, it))
            it = e.value
        elif isinstance(it, ast.Name):
            return (it, list(reversed(attr_path)))
        elif isinstance(it, ast.Call) and len(it.args) == 0 and len(it.keywords) == 0 and \
            isinstance(it.func, ast.Name) and it.func.id == "super":
            return ("super", list(reversed(attr_path)))
        else:
            return it

def is_prefix[T](s: Sequence[T], r: Sequence[T]) -> bool:
    if len(s) > len(r):
        return False
    for i in range(0, len(s)):
        if s[i] != r[i]:
            return False
    return True

class ValidationAnalysis(ast.NodeVisitor):
    def __init__(self):
        self.violations : list[tuple[ast.AST, str]] = []
        self.validation_stack : list[Validated] = []

        self.report : list[AuditEvents] = []

    def _get_validations(self, s: str) -> list[ValidationRule] | None:
        return next((i.validations for i in self.validation_stack if i.ident == s), None)

    def _violation(self, n: ast.AST, what: str):
        self.violations.append((n, what))

    def visit_Call(self, node: ast.Call):
        if not isinstance(node.func, ast.Name) and not isinstance(node.func, ast.Attribute):
            self._violation(node.func, "computed callee")
        call_name = is_call_to(node)
        if call_name == "open":
            call_match = bind_call_args(node, PyOpenCall)
            if call_match is None:
                self._violation(node, "Illegal open call shape")
                self.generic_visit(node)
                return
            try:
                mode = as_const_or_default(str, call_match.mode)
            except InvalidConstantForm:
                self._violation(node, "mode type")
                self.generic_visit(node)
                return
            
            file_arg = call_match.file
            if not isinstance(file_arg, ast.Name) and not (isinstance(file_arg, ast.Constant) and isinstance(file_arg.value, str)):
                self._violation(file_arg, f"not a recognizable open type {type(file_arg)}")
                return
            if isinstance(file_arg, ast.Name):
                self.report.append(OpenCall(
                    node, mode=mode, target=self._get_validations(file_arg.id) or []
                ))
            else:
                assert isinstance(file_arg, ast.Constant) and isinstance(file_arg.value, str)
                self.report.append(OpenCall(
                    node, mode=mode, target=file_arg.value
                ))
            return
        return self.generic_visit(node)

    def to_call(self, n: ast.AST) -> ast.Call:
        return cast(ast.Call, n)

    def _bind_target(self, it: ast.withitem) -> str | None:
        if it.optional_vars is None:
            return None
        if not isinstance(it.optional_vars, ast.Name):
            return None
        if self._get_validations(it.optional_vars.id) is not None:
            self._violation(it.optional_vars, "Overwriting bound validation")
        return it.optional_vars.id

    def visit_With(self, node: ast.With) -> Any:
        old = self.validation_stack.copy()
        try:
            for i in node.items:
                named_function = is_call_to(i.context_expr)
                if named_function is None:
                    self.generic_visit(i)
                    continue
                try:
                    match named_function:
                        case "certora_matches" | "certora_within":
                            args = bind_call_args(self.to_call(i.context_expr), CertoraMatch)
                            if args is None:
                                self._violation(i.context_expr, "Illegal certora match call")
                                continue
                            self.visit(args.target)
                            carried_validations = (
                                OptionMonad.lift(args.target)
                                .downcast(ast.Name)
                                .bind(lambda nm: self._get_validations(nm.id))
                                .unwrap_or([])
                            )
                            matches = as_const(str, args.matches)
                            if (tgt := self._bind_target(i)) is None:
                                self._violation(i.context_expr, "Illegal binding for certora guard")
                                continue
                            validation = RegexMatch(matches) if named_function == "certora_matches" else PathConfinement(matches)
                            self.validation_stack.append(Validated(tgt, carried_validations + [validation]))
                        case _:
                            self.generic_visit(i)
                except InvalidConstantForm:
                    self._violation(i, "Illegal certora guard binding")
            for s in node.body:
                self.visit(s)
        finally:
            self.validation_stack = old

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        attr = unfold_attr(node)
        if isinstance(attr, ast.AST):
            self._violation(attr, "invalid attr format")
            return
        (base, fields) = attr
        dunder_attr = next(
            (node for (fld, node) in fields if is_dunder(fld) and fld != "__init__"), None
        )
        if dunder_attr is not None:
            self._violation(dunder_attr, "dunder attribute")
            return
        if base != "super":
            path = [base.id]
            for (fld, _) in fields[:-1]:
                path.append(fld)
            pref = tuple(path)
            last = fields[-1][0]
            if fields[-1][0] in DANGEROUS_MEMBERS.get(pref, {}):
                self._violation(node, "access to forbidden attr")
                return
            dangerous_prefix = pref + (last,)
            for k in DANGEROUS_MEMBERS.keys():
                if is_prefix(dangerous_prefix, k):
                    self._violation(node, "dangerous module escape")
            self._name_visit(base)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if is_dunder(node.name) and node.name != "__init__":
            self.violations.append((node, "define dunder"))
        if node.name in validator_funcs:
            self._violation(node, "validation alias")
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._violation(node, "async def")

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        self.violations.append((node, "import from"))
        return self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> Any:
        for a in node.names:
            if a.asname is not None:
                self.violations.append((a, "as-alias"))
            if a.name in FORBIDDEN_MODULES:
                self._violation(node, "forbidden module import")
        return self.generic_visit(node)

    def _name_visit(self, node: ast.Name):
        if isinstance(node.ctx, ast.Load):
            if node.id in sensitive_builtins:
                self.violations.append(
                    (node, "built in escape")
                )

        if is_dunder(node.id):
            self._violation(node, "read dunder")

        if isinstance(node.ctx, ast.Store) and self._get_validations(node.id) is not None:
            self._violation(node, "write to validated id")

    def visit_Name(self, node: ast.Name) -> Any:
        self._name_visit(node)
        
        for k in DANGEROUS_MEMBERS.keys():
            if is_prefix((node.id,), k):
                self._violation(node, "module escape")

        return self.generic_visit(node)
