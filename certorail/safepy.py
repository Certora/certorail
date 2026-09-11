import ast
from collections.abc import Iterable, Sequence
from enum import StrEnum
from opcode import hasconst
from typing import Any, cast

import builtins

from certorail.terms import lower, Var, Dotted

from .annotations import Contract, InvalidAnnotation, parse_annotation, parse_function
from .analysis import (
    Container,
    InvalidProgram,
    NameAccess,
    is_dunder,
    is_prefix,
    sensitive_builtins,
    unfold_attr,
    validator_funcs,
)
from .dangerous import (
    ALLOWED_BASES,
    ALLOWED_DECORATORS,
    ALLOWED_MEMBERS,
    CLASS_FACTORIES,
    DANGEROUS_MEMBERS,
    FORBIDDEN_ATTRIBUTES,
    NAMESPACE,
    FORBIDDEN_CLASS_KEYWORDS,
    FORBIDDEN_MODULES,
    PATH_SINK_METHODS,
    PERMITTED_SUBMODULES,
    TYPE_CALL_MAX_ARGS,
)


def _forbidden_module(dotted: str) -> bool:
    """``import os.path`` binds ``os``: a module is forbidden if any prefix of its name is.
    A carved-out submodule (``urllib.parse``) is importable by its exact name only."""
    if dotted in PERMITTED_SUBMODULES:
        return False
    parts = dotted.split(".")
    return any(".".join(parts[:i]) in FORBIDDEN_MODULES for i in range(1, len(parts) + 1))


def _disallowed_member(path: tuple[str, ...]) -> tuple[str, ...] | None:
    """Under an allowlisted module, the first ``m.a`` along *path* whose ``a`` is not listed."""
    for i in range(1, len(path)):
        allowed = ALLOWED_MEMBERS.get(path[:i])
        if allowed is not None and path[i] not in allowed:
            return path[: i + 1]
    return None

class _LexicalAnalysis(ast.NodeVisitor):
    def __init__(self):
        self.violations : list[tuple[ast.AST, str]] = []

    def _violation(self, n: ast.AST, what: str):
        self.violations.append((n, what))

    def report_violations(self) -> bool:
        for (where, what) in self.violations:
            # assert hasattr(where, "lineno")
            line_no = getattr(where, "lineno", None)
            print(f"Found illegal code @ line {line_no} -> {what}")
        return bool(self.violations)
            
class AttributeContext(StrEnum):
    load = "LOAD"    # taken as a value
    store = "STORE"  # assigned to
    apply = "APPLY"  # used without being taken as a value: called, subscripted, decorating
    type = "TYPE"    # a type position: an annotation, an except clause, isinstance' second argument, a class base

class ImportAnalysis(_LexicalAnalysis):
    def __init__(self):
        super().__init__()
        self._imports : set[tuple[str, ...]] = set()

    @property
    def import_roots(self) -> frozenset[str]:
        return frozenset(nm[0] for nm in self._imports)

    @property
    def imports(self) -> frozenset[tuple[str, ...]]:
        """The dotted module paths the program imports (``import os.path`` -> ``("os", "path")``)."""
        return frozenset(self._imports)

    def visit_Import(self, node: ast.Import) -> Any:
        for a in node.names:
            if a.asname is not None:
                self.violations.append((a, "as-alias"))
            # a private module is its public twin with the guards off: `_io` is `io`, `_thread`
            # is `threading`. Ban any dotted component that starts with "_" wholesale rather than
            # chase each `_name` into DANGEROUS_MEMBERS.
            if any(part.startswith("_") for part in a.name.split(".")):
                self._violation(node, "private (underscore-prefixed) module import")
            elif _forbidden_module(a.name):
                self._violation(node, "forbidden module import")
            elif a.name.split(".")[0] in dir(builtins):
                # ``import tuple`` would bind a builtin's name to a module: the analysis reads
                # builtin names by their meaning, so nothing may rebind one
                self._violation(node, "import shadows a builtin")
            self._imports.add(tuple(a.name.split(".")))
        return self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        self._violation(node, "import from")
        return self.generic_visit(node)

class ClassAnalysis(_LexicalAnalysis):
    def __init__(self):
        super().__init__()
        self._known_classes = set({})

    @property
    def known_classes(self) -> frozenset[str]:
        return frozenset(self._known_classes)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        if node.name in self._known_classes:
            self._violation(node, "class name redef")
        self._known_classes.add(node.name)
        return self.generic_visit(node)

class FunctionAnalysis(_LexicalAnalysis):
    """Module-level functions and their contracts.

    A bare-name callee resolves to exactly one module-level definition, which is what lets the
    walker discharge relies at call sites; so function names are defined once, and marker contracts
    (anything beyond a plain type) are allowed on module-level functions only -- anywhere else they
    would be assumed by the body and discharged by nobody.
    """

    def __init__(self):
        super().__init__()
        self._contracts: dict[str, tuple[ast.FunctionDef, Contract]] = {}
        self._nesting = 0

    @property
    def contracts(self) -> dict[str, tuple[ast.FunctionDef, Contract]]:
        """The module-level functions by name, with their contracts. Like class names, these names
        may not be rebound; those with a rely may only be called directly (see ValidationAnalysis)."""
        return dict(self._contracts)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        try:
            contract: Contract | None = parse_function(node)
        except InvalidAnnotation as e:
            self._violation(e.node, str(e))
            contract = None
        if self._nesting == 0:
            if node.name in self._contracts:
                self._violation(node, f"function {node.name} is defined more than once; its contract is ambiguous")
            elif contract is not None:
                self._contracts[node.name] = (node, contract)
        elif contract is not None and contract.has_markers:
            self._violation(node, "marker contracts on nested functions and methods are not checked; move the function to module level")
        self._nesting += 1
        try:
            self.generic_visit(node)
        finally:
            self._nesting -= 1

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self._nesting += 1
        try:
            self.generic_visit(node)
        finally:
            self._nesting -= 1

class InheritanceAnalysis(_LexicalAnalysis):
    def __init__(self, *, known_classes: frozenset[str], module_roots: frozenset[str]):
        super().__init__()
        self.known_classes = known_classes
        self.module_roots = module_roots

    def visit_ClassDef(self, node: ast.ClassDef):
        # static inheritance: every base is a *name* (a class this program defines, or one of
        # ALLOWED_BASES), so no subclass of a sensitive class and no computed base can exist
        for b in node.bases:
            match lower(b, self.module_roots):
                case Var(name=nm) if nm in self.known_classes or (nm,) in ALLOWED_BASES:
                    pass
                case Var(name=nm):
                    self._violation(b, f"base {nm} is not an allowed class")
                case Dotted(path=path) if path in ALLOWED_BASES:
                    pass
                case Dotted(path=path):
                    self._violation(b, f"base {'.'.join(path)} is not an allowed class")
                case _:
                    self._violation(b, "computed class base")
        # class X(metaclass=M): class creation handed to M, a class factory in disguise; a
        # ``**kwargs`` splat could smuggle the same keyword
        for kw in node.keywords:
            if kw.arg is None or kw.arg in FORBIDDEN_CLASS_KEYWORDS:
                self._violation(kw, f"class keyword {kw.arg or '**'} is forbidden")
        self.generic_visit(node)

class ContainerClosureAnalysis(_LexicalAnalysis):
    """A tracked container may not be closed over (CONTAINERS.md): a ``def`` or ``lambda`` that
    names a typed container declared in an enclosing scope -- without binding that name itself
    -- is a violation, whatever it does with it. The walker analyses a body from its parameters
    and the module constants; a container reached through a closure would be an untracked name
    there, and a write to it would break the invariant every other use relies on. Pass it as a
    parameter instead: the contract carries the obligation.

    Purely syntactic. A scope is the module, a function, a lambda or a class body; a
    comprehension is transparent (the walker walks it inline) except that its targets shadow.
    A name bound in a scope -- a parameter, an assignment, a def -- is that scope's own, so
    ``xs = []`` inside the body makes ``xs`` local as Python does."""

    def visit_Module(self, node: ast.Module) -> Any:
        self._scope(node.body, bound=set(), closable=frozenset())

    def _scope(self, body: Sequence[ast.stmt], *, bound: set[str], closable: frozenset[str]) -> None:
        """Walk one scope's statements. *closable* is every container an enclosing scope
        declared; those the scope binds itself are its own. Its own container declarations
        join *closable* for the scopes nested in it."""
        bound |= _scope_binds(body)
        visible = closable - bound
        declared = frozenset(self._declared_containers(body))
        self._walk(body, visible, visible | declared)

    def _walk(self, nodes: Iterable[ast.AST], visible: frozenset[str], inner: frozenset[str]) -> None:
        """*visible*: names that, read here, close over a container. *inner*: what a scope
        nested here may close over."""
        stack: list[ast.AST] = list(nodes)
        while stack:
            n = stack.pop()
            match n:
                case ast.Name(id=name) if name in visible:
                    self._violation(
                        n,
                        f"{name!r} is a typed container of an enclosing scope: a container may not "
                        "be closed over; pass it as a parameter",
                    )
                case ast.FunctionDef() | ast.AsyncFunctionDef():
                    # decorators, defaults and annotations are evaluated here; the body is a scope
                    stack.extend(n.decorator_list)
                    stack.extend(d for d in (*n.args.defaults, *n.args.kw_defaults) if d is not None)
                    stack.extend(a.annotation for a in _parameters(n.args) if a.annotation is not None)
                    if n.returns is not None:
                        stack.append(n.returns)
                    self._scope(n.body, bound={a.arg for a in _parameters(n.args)}, closable=inner)
                case ast.Lambda():
                    stack.extend(d for d in (*n.args.defaults, *n.args.kw_defaults) if d is not None)
                    params = {a.arg for a in _parameters(n.args)}
                    self._walk([n.body], inner - params, inner - params)
                case ast.ClassDef():
                    # a class body is a scope of its own whose names methods cannot close over,
                    # so its declarations are not offered to them either
                    stack.extend(n.decorator_list)
                    stack.extend(n.bases)
                    stack.extend(k.value for k in n.keywords)
                    self._walk(n.body, inner - _scope_binds(n.body), inner)
                case ast.ListComp(generators=gens) | ast.SetComp(generators=gens) | ast.GeneratorExp(generators=gens) | ast.DictComp(generators=gens):
                    targets = {t.id for g in gens for t in ast.walk(g.target) if isinstance(t, ast.Name)}
                    self._walk(ast.iter_child_nodes(n), visible - targets, inner - targets)
                case _:
                    stack.extend(ast.iter_child_nodes(n))

    @staticmethod
    def _declared_containers(body: Iterable[ast.stmt]) -> list[str]:
        """The typed containers a scope declares: ``x: list[Annotated[...]] = ...`` at any depth
        of its own statements (not inside nested scopes)."""
        out: list[str] = []
        stack: list[ast.AST] = list(body)
        while stack:
            n = stack.pop()
            match n:
                case ast.FunctionDef() | ast.AsyncFunctionDef() | ast.Lambda() | ast.ClassDef():
                    continue
                case ast.AnnAssign(target=ast.Name(id=name), annotation=annotation):
                    try:
                        if isinstance(parse_annotation(annotation), Container):
                            out.append(name)
                    except InvalidProgram:
                        pass  # FunctionAnalysis' report
                case _:
                    pass
            stack.extend(ast.iter_child_nodes(n))
        return out


def _parameters(args: ast.arguments) -> list[ast.arg]:
    params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    for extra in (args.vararg, args.kwarg):
        if extra is not None:
            params.append(extra)
    return params


def _scope_binds(body: Iterable[ast.stmt]) -> set[str]:
    """Every name a scope binds in its own statements: assignments, defs and classes by name,
    loop and ``with`` targets, except-clause names, imports. Not descending into nested scopes;
    comprehension targets are the comprehension's own."""
    out: set[str] = set()
    stack: list[ast.AST] = list(body)
    while stack:
        n = stack.pop()
        match n:
            case ast.FunctionDef(name=name) | ast.AsyncFunctionDef(name=name) | ast.ClassDef(name=name):
                out.add(name)
                continue
            case ast.Lambda() | ast.ListComp() | ast.SetComp() | ast.DictComp() | ast.GeneratorExp():
                continue
            case ast.Name(id=name, ctx=ast.Store() | ast.Del()):
                out.add(name)
            case ast.ExceptHandler(name=str() as name):
                out.add(name)
            case ast.Import(names=aliases) | ast.ImportFrom(names=aliases):
                out.update((a.asname or a.name).split(".")[0] for a in aliases)
            case _:
                pass
        stack.extend(ast.iter_child_nodes(n))
    return out


class ValidationAnalysis(_LexicalAnalysis):
    def __init__(
        self,
        *,
        module_roots: frozenset[str],
        known_classes: frozenset[str],
        contracts: dict[str, tuple[ast.FunctionDef, Contract]],
    ):
        super().__init__()
        self._module_roots = module_roots
        self._known_classes = known_classes
        self._known_functions = {name: node for name, (node, _) in contracts.items()}
        # a rely is discharged by the walker at direct call sites and nowhere else, so the name of a
        # function that has one may not travel (``sorted(xs, key=f)``, ``g = f``, ``@f``): like a
        # module symbol, it is fully applied or not mentioned
        self._contracted = frozenset(name for name, (_, c) in contracts.items() if c.has_rely_markers)

    def exp_to_access(self, node: ast.expr) -> NameAccess | ast.AST:
        if isinstance(node, ast.Name):
            return NameAccess(node, ())
        elif isinstance(node, ast.Attribute):
            return unfold_attr(node)
        else:
            return node

    def visit_it(self, thing):
        if isinstance(thing, ast.AST):
            self.visit(thing)
        elif isinstance(thing, list):
            for it in thing:
                if isinstance(it, ast.AST):
                    self.visit(it)

    def visit_Call(self, node: ast.Call):
        callee = self.exp_to_access(node.func)
        self._visit_ap(callee, node, context=AttributeContext.apply)
        if not isinstance(callee, ast.AST) and callee.is_var_base:
            # classes may only come from `class` statements: no factories, no 3-argument type()
            if callee.full_path in CLASS_FACTORIES:
                self._violation(node, f"{'.'.join(callee.full_path)} creates a class at runtime")
            if callee.full_path == ("type",) and (
                len(node.args) > TYPE_CALL_MAX_ARGS or node.keywords
            ):
                self._violation(node, "type(name, bases, namespace) creates a class at runtime")
        if not isinstance(callee, ast.AST):
            if callee.is_var_base and callee.full_path == ("isinstance",) and len(node.args) == 2:
                self.generic_visit(node.args[0])
                if isinstance(as_read := self.exp_to_access(node.args[1]), NameAccess):
                    self._visit_ap(as_read, node.args[1], context=AttributeContext.type)
                    return
    
        for i in node._fields:
            if i == "func":
                continue
            self.visit_it(getattr(node, i))

    def to_call(self, n: ast.AST) -> ast.Call:
        return cast(ast.Call, n)

    def visit_Subscript(self, node: ast.Subscript) -> Any:
        self.visit(node.slice)
        nm = self.exp_to_access(node.value)
        if not isinstance(nm, ast.AST):
            self._visit_ap(nm, node.value, context=AttributeContext.apply)
        else:
            self.visit(node.value)

    def _visit_ap(
            self,
            attr: NameAccess | ast.AST,
            node: ast.AST, *, context: AttributeContext):
        if isinstance(attr, ast.AST):
            # ``f()()``, ``fs[0]()``: a callee with no name is refused structurally -- the rules
            # hang off names. (``f().g()`` is a computed *receiver*, handled below.)
            self._violation(attr, "computed callee")
            return
        if (base := attr.computed_base) is not None:
            # ``x().foo`` is ``y = x(); y.foo``: the receiver is an ordinary expression, checked as
            # such, about which nothing is known. Writing through it is another matter: that is how
            # ``type(p).read_text = f`` would patch a class.
            if context == AttributeContext.store:
                self._violation(node, "attribute store on a computed receiver")
                return
            self.visit(base)
        is_import_path = attr.is_var_base and attr.base_name in self._module_roots

        # `open` reached through a module is banned wholesale -- io.open, codecs.open, os.open,
        # tokenize.open, dbm.open, webbrowser.open, and pathlib.Path.open (the *unbound* form, which
        # the walker's `<path>.open()` audit never sees) are all file/fd/URL openers that sidestep
        # the audited builtin. Too many entry points to chase one by one. The two legitimate opens
        # are untouched: the bare builtin `open(...)` (a Name, never a dotted path) and
        # `<path>.open()` on a pathlib value (its base is a variable, not a module).
        if is_import_path and "open" in attr.field_names:
            self._violation(node, "open through a module is forbidden; use the builtin open() or a pathlib path's .open()")
            return

        if is_import_path and context == "LOAD":
            self._violation(node, "import name escape")
        elif is_import_path and context == "STORE":
            self._violation(node, "import name write")
        fields = attr.fields
        dunder_attr = next(
            (node for (fld, node) in fields if is_dunder(fld) and fld != "__init__"), None
        )
        if dunder_attr is not None:
            self._violation(dunder_attr, "dunder attribute")
            return
        # receiver-independent bans: frame/code internals, link creation, archive extraction, ...
        # -- except the direct members of the ``certora`` namespace, whose names are the host's
        # own API (``certora.extract`` is the JSON extractor, not TarFile.extract): the namespace
        # is unrebindable, so nothing else can hide behind that receiver
        own_api = attr.is_var_base and attr.base_name == NAMESPACE and len(fields) == 1
        forbidden_attr = next((n for (fld, n) in fields if fld in FORBIDDEN_ATTRIBUTES), None)
        if forbidden_attr is not None and not own_api:
            self._violation(forbidden_attr, f"forbidden attribute {forbidden_attr.attr}")
            return
        # sink methods get the module-symbol treatment: fully applied or not at all, so that
        # ``f = p.read_text; f()`` cannot launder the read past the walker's audit
        if fields and fields[-1][0] in PATH_SINK_METHODS and context != AttributeContext.apply:
            self._violation(fields[-1][1], f"{fields[-1][0]} may only be called, not taken as a value")
            return
        if attr.is_var_base and (denied := _disallowed_member(attr.full_path)) is not None:
            self._violation(node, f"{'.'.join(denied)} is not an allowed member")
            return
        if attr.is_var_base:
            if len(attr.field_names) > 0:
                pref = tuple(attr.full_path[:-1])    
                last = attr.field_names[-1]
                if last in DANGEROUS_MEMBERS.get(pref, {}):
                    self._violation(node, "access to forbidden attr")
                    return
            self._name_visit(attr.base_var, context if len(attr.field_names) == 0 else AttributeContext.load)

    def _visit_binding(self, nm: str, ctxt: ast.AST):
        if nm in self._module_roots:
            self._violation(ctxt, "rebind import name")
        # the definition itself is the one permitted binding of a class name (a second
        # definition is ClassAnalysis' report)
        if nm in self._known_classes and not (isinstance(ctxt, ast.ClassDef) and ctxt.name == nm):
            self._violation(ctxt, "rebind class name")
        # the definition itself is the one permitted binding of a module-level function's name
        if nm in self._known_functions and self._known_functions[nm] is not ctxt:
            self._violation(ctxt, "rebind function name")
        if nm in dir(builtins):
            self._violation(ctxt, "rebind builtin")

    def visit_Attribute(self, node: ast.Attribute) -> Any:
        attr = unfold_attr(node)
        
        self._visit_ap(attr, node, context=AttributeContext.store if isinstance(node.ctx, ast.Store) else AttributeContext.load)

    # -- type-test and application positions -------------------------------------------------
    #
    # An imported class or module may be *named* here without escaping: ``except json.JSONDecodeError``,
    # ``p: pathlib.Path``, ``-> typing.Annotated[pathlib.Path, certora.within("data")]``,
    # ``@dataclasses.dataclass``. Everything else about the access (dunders, dangerous members)
    # still applies. ``ClassDef.bases`` is one too: which bases are *permitted* is
    # InheritanceAnalysis' job (ALLOWED_BASES), not the escape rule's.

    def _visit_mention(self, e: ast.expr, context: AttributeContext) -> None:
        match e:
            case ast.Name() | ast.Attribute():
                self._visit_ap(self.exp_to_access(e), e, context=context)
            case ast.Tuple(elts=elts):  # except (A, B): ; Annotated[T, marker, ...] ; tuple[T, ...]
                for el in elts:
                    self._visit_mention(el, context)
            case ast.Subscript(value=value, slice=index):  # typing.Annotated[...], list[T], dict[K, V]
                self._visit_mention(value, context)
                self._visit_mention(index, context)
            case ast.BinOp(left=left, op=ast.BitOr(), right=right):  # T | None
                self._visit_mention(left, context)
                self._visit_mention(right, context)
            case ast.Constant():
                pass  # string annotations, Ellipsis, None
            case _:
                self.visit(e)  # marker calls, decorator factories, ...: the ordinary rules

    def _visit_decorators(self, decorators: list[ast.expr]) -> None:
        # A decorator is an application without a Call node (``@p.unlink`` would delete the file
        # with nothing audited), and a work script has no business defining its own: only
        # ALLOWED_DECORATORS, bare (``@staticmethod``) or applied (``@dataclasses.dataclass(frozen=True)``).
        # The arguments of an applied one are ordinary expressions.
        for d in decorators:
            target = d.func if isinstance(d, ast.Call) else d
            match lower(target, self._module_roots):
                case Var(name=nm) if (nm,) in ALLOWED_DECORATORS:
                    pass
                case Dotted(path=path) if path in ALLOWED_DECORATORS:
                    pass
                case _:
                    self._violation(d, "only the allowed decorators may be used")
                    continue
            if isinstance(d, ast.Call):
                for a in d.args:
                    self.visit(a)
                for kw in d.keywords:
                    self.visit(kw.value)

    def visit_arguments(self, node: ast.arguments) -> Any:
        params = [*node.posonlyargs, *node.args, *node.kwonlyargs]
        if node.vararg is not None:
            params.append(node.vararg)
        if node.kwarg is not None:
            params.append(node.kwarg)
        for a in params:
            if a.annotation is not None:
                self._visit_mention(a.annotation, AttributeContext.type)
            self._visit_binding(a.arg, a)
        for d in [*node.defaults, *node.kw_defaults]:
            if d is not None:
                self.visit(d)  # defaults are ordinary values

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if is_dunder(node.name) and node.name != "__init__":
            self.violations.append((node, "define dunder"))
        if node.name in validator_funcs:
            self._violation(node, "validation alias")
        self._visit_decorators(node.decorator_list)
        for tp in node.type_params:
            self.visit(tp)
        self._visit_binding(node.name, node)
        self.visit(node.args)
        if node.returns is not None:
            self._visit_mention(node.returns, AttributeContext.type)
        for s in node.body:
            self.visit(s)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self._visit_decorators(node.decorator_list)
        for b in node.bases:
            self._visit_mention(b, AttributeContext.type)  # allowed or not is InheritanceAnalysis' call
        for kw in node.keywords:
            self.visit(kw.value)
        for tp in node.type_params:
            self.visit(tp)
        # a class statement binds its name like a def does: ``class tuple:`` with an __init__
        # that keeps its argument would launder a typed container through a roster read
        self._visit_binding(node.name, node)
        for s in node.body:
            self.visit(s)

    # PEP 695 type parameters bind names in an annotation scope the body can see; a TypeVar is
    # not callable, but a bound builtin name is a bound builtin name
    def visit_TypeVar(self, node: ast.TypeVar) -> Any:
        self._visit_binding(node.name, node)
        return self.generic_visit(node)

    def visit_ParamSpec(self, node: ast.ParamSpec) -> Any:
        self._visit_binding(node.name, node)
        return self.generic_visit(node)

    def visit_TypeVarTuple(self, node: ast.TypeVarTuple) -> Any:
        self._visit_binding(node.name, node)
        return self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> Any:
        if node.name is not None:
            self._visit_binding(node.name, node)

    def visit_MatchStar(self, node: ast.MatchStar) -> Any:
        if node.name is not None:
            self._visit_binding(node.name, node)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> Any:
        if node.rest is not None:
            self._visit_binding(node.rest, node)
    
    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        self._visit_mention(node.annotation, AttributeContext.type)
        self.visit(node.target)
        if node.value is not None:
            self.visit(node.value)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> Any:
        if node.type is not None:
            self._visit_mention(node.type, AttributeContext.type)
        if node.name is not None:
            self._visit_binding(node.name, node)  # ``except E as name`` binds name
        for s in node.body:
            self.visit(s)

    def visit_name_str(self, name_str: str, node: ast.AST, visit_context: AttributeContext):
        # `open` may be applied (it is a sink the walker audits); the other sensitive builtins may
        # not appear at all
        if name_str in sensitive_builtins and not (
            name_str == "open" and visit_context == AttributeContext.apply
        ):
            self.violations.append(
                (node, "built in escape")
            )
        # (a STORE is already reported as a rebinding)
        if name_str in self._contracted and visit_context not in (AttributeContext.apply, AttributeContext.store):
            self._violation(
                node, f"{name_str} has a marker contract: it may only be called directly, not passed or stored"
            )

        if is_dunder(name_str):
            self._violation(node, "read dunder")

        if visit_context == "STORE":
            self._visit_binding(name_str, node)

    def _name_visit(self, node: ast.Name, visit_context: AttributeContext):
        return self.visit_name_str(node.id, node, visit_context)

    def ast_ctxt_to_attr_context(self, c: ast.expr_context):
        if isinstance(c, ast.Store):
            return AttributeContext.store
        else:
            return AttributeContext.load

    def visit_Name(self, node: ast.Name) -> Any:
        self._name_visit(node, self.ast_ctxt_to_attr_context(node.ctx))
        return self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> Any:
        self._violation(node, "async")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._violation(node, "async")

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self._violation(node, "async")

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self._violation(node, "async")

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self._violation(node, "walrus")

    def visit_Nonlocal(self, node: ast.Nonlocal) -> Any:
        self._violation(node, "nonlocal")

    def visit_Global(self, node: ast.Global) -> Any:
        # the last direct way a function could rebind a module-level name: without it, an
        # assignment inside a function is local. Banning it (with module-level names assigned
        # once) makes module constants provably immutable, so the analysis may read them.
        self._violation(node, "global")
