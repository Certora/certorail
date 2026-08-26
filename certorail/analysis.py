import ast
from contextlib import contextmanager
import inspect
import pathlib
import stat
from turtle import isvisible
from types import UnionType
from typing import Any, cast, Callable, Literal, Sequence, final, override, reveal_type
from dataclasses import dataclass, is_dataclass
from typing_extensions import TypeForm
from .dangerous import DANGEROUS_MEMBERS, FORBIDDEN_MODULES
from .typed_ast_tsp import typed_ast

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

type ContainerSort = Literal["set", "list", "dict_key", "dict_val", "tuple"]

@dataclass
class ContainerOf:
    of: "ValidationRule"
    sort: ContainerSort


type ValidationRule = PathConfinement | RegexMatch | ContainerOf

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


@dataclass
class NameAccess:
    _wrappedBase: ast.Name | Literal["super"]
    fields: Sequence[tuple[str, ast.Attribute]]

    @property
    def base_var(self) -> str:
        assert isinstance(self._wrappedBase, ast.Name)
        return self._wrappedBase.id

    @property
    def is_var_base(self) -> bool:
        return isinstance(self._wrappedBase, ast.Name)

    @property
    def field_names(self) -> tuple[str, ...]:
        return tuple(fld for (fld, _) in self.fields)

    def matches(self, *names: str) -> bool:
        return len(names) > 0 and self.is_var_base and self.base_var == names[0] and tuple(names[1:]) == self.field_names

def unfold_attr(e: ast.Attribute) -> NameAccess | ast.AST:
    attr_path : list[tuple[str, ast.Attribute]] = []
    it = e
    while True:
        if isinstance(it, ast.Attribute):
            attr_path.append((it.attr, it))
            it = it.value
        elif isinstance(it, ast.Name):
            return NameAccess(it, list(reversed(attr_path)))
        elif isinstance(it, ast.Call) and len(it.args) == 0 and len(it.keywords) == 0 and \
            isinstance(it.func, ast.Name) and it.func.id == "super":
            return NameAccess("super", list(reversed(attr_path)))
        else:
            return it

def is_call_to(
    i: ast.AST
) -> str | None:
    if not isinstance(i, ast.Call):
        return None
    if not isinstance(i.func, ast.Name):
        return None
    return i.func.id

def resolve_callee(
    i: ast.AST
) -> NameAccess | None:
    if isinstance(i, ast.Name):
        return NameAccess(i, ())
    elif isinstance(i, ast.Attribute):
        r = unfold_attr(i)
        return r if isinstance(r, NameAccess) else None
    else:
        return None
    

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

def as_const_or_null[T](t: type[T], elem: ast.expr) -> T | None:
    if not isinstance(elem, ast.Constant):
        return None
    if not isinstance(elem.value, t):
        return None
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

def is_prefix[T](s: Sequence[T], r: Sequence[T]) -> bool:
    if len(s) > len(r):
        return False
    for i in range(0, len(s)):
        if s[i] != r[i]:
            return False
    return True

@dataclass(frozen=True)
class RegexLit:
    reg: str

@dataclass(frozen=True)
class Exact:
    exact_str: str

@dataclass(frozen=True)
class Concat:
    seq: list["PseudoRegex"]

@dataclass(frozen=True)
class Alternation:
    any_of: list["PseudoRegex"]

type PseudoRegex = Alternation | Concat | RegexLit | Exact

@dataclass(frozen=True)
class StaticPath:
    path_components: tuple[PseudoRegex, ...]

    @property
    def final_component(self) -> PseudoRegex:
        return self.path_components[-1]

    def merge_other(self, other: "LocationFact") -> "LocationFact":
        if isinstance(other, StaticPath):
            return StaticPath(self.path_components + other.path_components)
        else:
            return DirSplat(self.path_components + other.static_prefix, other.final_component)

    def extend_static(self, other: tuple[str, ...]) -> "StaticPath":
        return StaticPath(self.path_components + tuple(Exact(i) for i in other))

    def extend_single(self, other: PseudoRegex) -> "StaticPath":
        return StaticPath(self.path_components + (other,))

    def to_splat(self, final_component: PseudoRegex) -> "DirSplat":
        return DirSplat(self.path_components, final_component)

@dataclass(frozen=True)
class DirSplat:
    static_prefix: tuple[PseudoRegex, ...]
    final_component: PseudoRegex

    def merge_other(self, other: "LocationFact") -> "DirSplat":
        return DirSplat(static_prefix=self.static_prefix, final_component=other.final_component)

    def extend_static(self, ext: tuple[str, ...]) -> "DirSplat":
        return DirSplat(
            static_prefix=self.static_prefix,
            final_component=Exact(ext[-1])
        )

    def extend_single(self, other: PseudoRegex) -> "DirSplat":
        return DirSplat(
            self.static_prefix,
            other
        )

    def to_splat(self, final_component: PseudoRegex) -> "DirSplat":
        return DirSplat(self.static_prefix, final_component)


type LocationFact = StaticPath | DirSplat

type AtomicFact = Literal["no-slash", "no-parent-traversal", "not-absolute"]

def _explicit_check_no_parent(regex: PseudoRegex) -> bool:
    match regex:
        case Alternation():
            return all(_explicit_check_no_parent(p) for p in regex.any_of)
        case Exact():
            return _safe_path_extension(regex.exact_str) is not None
        case RegexLit():
            return False
        case Concat():
            return False

def _explicit_check_no_slash(regex: PseudoRegex) -> bool:
    match regex:
        case Alternation():
            return all(_explicit_check_no_slash(p) for p in regex.any_of)
        case Exact():
            return "/" not in regex.exact_str
        case RegexLit():
            return False
        case Concat():
            return all(_explicit_check_no_slash(p) for p in regex.seq)

def _explicit_check_not_absolute(regex: PseudoRegex):
    match regex:
        case Alternation():
            return all(_explicit_check_not_absolute(p) for p in regex.any_of)
        case Exact():
            return not regex.exact_str.startswith("/")
        case RegexLit():
            return False
        case Concat():
            return _explicit_check_not_absolute(regex.seq[0])

def _explicit_check(other: AtomicFact, regex: PseudoRegex) -> bool:
    match other:
        case "no-parent-traversal":
            return _explicit_check_no_parent(regex)
        case "no-slash":
            return _explicit_check_no_slash(regex)
        case "not-absolute":
            return _explicit_check_not_absolute(regex)

@dataclass(frozen=True)
class ValidationFact:
    regex: PseudoRegex | None
    containment: LocationFact | None
    atoms: frozenset[AtomicFact]

    def __contains__(self, other: AtomicFact):
        return other in self.atoms or (
            self.regex is not None and _explicit_check(other, self.regex)
        )
        

    type_info: Literal["str", "path"]


class InvalidProgram(Exception):
    def __init__(self, node: ast.AST, msg: str):
        super().__init__(msg)
        self.node = node

def reroot(
    s: StaticPath,
    new_root: StaticPath
):
    return StaticPath(
        s.path_components + new_root.path_components
    )

def _safe_path_extension(s: str) -> tuple[str, ...] | None:
    as_path = pathlib.PurePath(s)
    if as_path.is_absolute():
        return None
    if any(p == ".." for p in as_path.parts):
        return None
    last = as_path.name
    if last:
        return as_path.parts
    else:
        return None


def combine_containment(
    cont: LocationFact,
    child: str | ValidationFact | None
):
    if child is None:
        return None
    
    if isinstance(child, str):
        as_path = _safe_path_extension(child)
        if as_path is None:
            return None
        return cont.extend_static(as_path)

    elif child.containment is not None:
        return cont.merge_other(child.containment)
    elif "no-parent-traversal" in child and "no-slash" in child:
        return cont.extend_single(other=child.regex or RegexLit(".*"))
    elif "no-parent-traversal" in child and "not-absolute" in child:
        return cont.to_splat(RegexLit(".*"))
    else:
        return None

class OperandInterpreter():
    def __init__(self, st: dict[str, ValidationFact]):
        self.st = st

    def interp[R](
        self,
        e: ast.expr,
        on_str: Callable[[OptionMonad[str]], OptionMonad[R]],
        on_fact: Callable[[OptionMonad[ValidationFact]], OptionMonad[R]],
        on_expr: Callable[[OptionMonad[ast.expr]], OptionMonad[R]] | None = None
    ) -> R | None:
        if (as_str := as_const_or_null(str, e)):
            return on_str(OptionMonad(as_str)).unwrap()
        if not isinstance(e, ast.Name):
            if on_expr is None:
                return None
            return on_expr(OptionMonad(e)).unwrap()
        res = self.st.get(e.id)
        if res is None:
            return None
        return on_fact(OptionMonad(res)).unwrap()

    def interp_bind[R](
        self,
        e: ast.expr,
        on_str: Callable[[OptionMonad[str]], OptionMonad[R]],
        on_fact: Callable[[OptionMonad[ValidationFact]], OptionMonad[R]],
        on_expr : Callable[[OptionMonad[ast.expr]], OptionMonad[R]] | None = None
    ) -> OptionMonad[R]:
        return OptionMonad.lift(self.interp(e, on_str, on_fact, on_expr))


class ExprInterpreter:
    def __init__(self, st: dict[str, ValidationFact]):
        self.st = st

def type_cast[T](t: TypeForm[T]) -> Callable[[T], T]:
    return lambda x: x

def take_if[T](pred: Callable[[T], bool]) -> Callable[[T], T | None]:
    def to_ret(it: T) -> T | None:
        if not pred(it):
            return None
        else:
            return it
    return to_ret

class _default:
    @classmethod
    def BindNone[T, R](cls) -> Callable[[OptionMonad[T]], OptionMonad[R]]:
        return lambda _ign: OptionMonad.lift(None)

    @classmethod
    def Cast[R](cls, ty: TypeForm[R]) -> Callable[[OptionMonad[R]], OptionMonad[R]]:
        return lambda x: x.bind(type_cast(ty))

@dataclass(frozen=True, eq=False)
class CurriedMonad[M, R]:
    staged: Callable[[OptionMonad[M]], OptionMonad[R]]

    def bind_curried[S](self, c: Callable[[R], OptionMonad[S] | S | None]) -> "CurriedMonad[M, S]":
        return CurriedMonad(lambda to_exec: self.staged(to_exec).bind(c))

    def __call__(self, arg: OptionMonad[M]) -> OptionMonad[R]:
        return self.staged(arg)

def interpret_expr(e: ast.expr, st: dict[str, ValidationFact]) -> ValidationFact | None:
    interp = OperandInterpreter(st)
    if isinstance(e, ast.Name):
        return st.get(e.id, None)

    wrapper : CurriedMonad[ast.expr, ValidationFact] = CurriedMonad(lambda exp_m: exp_m.bind(lambda exp: interpret_expr(exp, st)))

    if isinstance(e, ast.Call):
        node = e
        call = resolve_callee(node.func)
        if call is None:
            raise InvalidProgram(node.func, "invalid call")
        if call.matches("pathlib", "Path") and len(e.args) > 0:
            accum = interp.interp(e.args[0],
                on_fact=(lambda f: f.bind(lambda proj: proj.containment)),
                on_str=lambda nm: (
                    nm.bind(_safe_path_extension).map(lambda feats: tuple(Exact(i) for i in feats)).map(StaticPath)
                ),
                on_expr=wrapper.bind_curried(lambda fact: fact.containment)
            )
            if accum is None:
                return None
            for i in e.args[:1]:
                d = interp.interp(
                    i,
                    on_str=lambda id: id.map(type_cast(str | ValidationFact)),
                    on_fact=lambda id: id.map(type_cast(str | ValidationFact)),
                    on_expr=wrapper.bind_curried(type_cast(str | ValidationFact))
                )
                if d is None:
                    return None
                accum = combine_containment(accum, d)
                if accum is None:
                    return None
            return ValidationFact(
                regex=None,
                containment=accum,
                atoms=frozenset(),
                type_info="path"
            )
    elif isinstance(e, ast.BinOp) and isinstance(e.op, ast.Div):
        return interp.interp_bind(
            e.left,
            on_str=_default.BindNone(),
            on_fact=lambda nm: nm,
            on_expr=wrapper
        ).bind(take_if(
            lambda d: d.type_info == "path" and d.containment is not None
        )).bind(lambda fact: \
            combine_containment(
                cast(LocationFact, fact.containment),
                interp.interp(
                    e.right,
                    on_str=lambda nm: nm.map(type_cast(str | ValidationFact)),
                    on_fact=lambda nm: nm.map(type_cast(str | ValidationFact)),
                    on_expr=wrapper.bind_curried(type_cast(str | ValidationFact))
                )
            )
        ).map(lambda fact: \
            ValidationFact(
                None, fact, frozenset(), "path"
            )
        ).unwrap()
        
class ValidationWalker(ast.NodeVisitor):
    def __init__(self):
        self.state : dict[str, ValidationFact] = {}

    def visit_Await(self, node: ast.Await) -> Any:
        raise InvalidProgram(node, "async")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        raise InvalidProgram(node, "async")

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        raise InvalidProgram(node, "async")

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        raise InvalidProgram(node, "async")

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        raise InvalidProgram(node, "walrus")

    def visit_Nonlocal(self, node: ast.Nonlocal) -> Any:
        raise InvalidProgram(node, "nonlocal")

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        return super().visit_AnnAssign(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        
        return super().visit_Assign(node)

    def visit_Call(self, node: ast.Call) -> Any:
        call = resolve_callee(node.func)
        if call is None:
            raise InvalidProgram(node.func, "invalid call")
        return super().visit_Call(node)

    def visit_Assert(self, node: ast.Assert) -> Any:
        return super().visit_Assert(node)

    @contextmanager
    def state_snapshot(self):
        saved = self.state.copy()
        try:
            yield
        finally:
            self.state = saved

    def _parse_args(self, node: ast.FunctionDef) -> dict[str, ValidationFact]:
        ...

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        with self.state_snapshot():
            self.state = self._parse_args(node)
            for s in node.body:
                self.generic_visit(s)

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
