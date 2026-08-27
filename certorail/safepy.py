import ast
from contextlib import contextmanager
from typing import Any, cast

from .analysis import (
    AuditEvents,
    CertoraMatch,
    InvalidConstantForm,
    InvalidProgram,
    OpenCall,
    OptionMonad,
    PathConfinement,
    PyOpenCall,
    RegexMatch,
    Validated,
    ValidationFact,
    ValidationRule,
    as_const,
    as_const_or_default,
    bind_call_args,
    is_call_to,
    is_dunder,
    is_prefix,
    resolve_callee,
    sensitive_builtins,
    unfold_attr,
    validator_funcs,
)
from .dangerous import DANGEROUS_MEMBERS, FORBIDDEN_MODULES

class _LexicalAnalysis(ast.NodeVisitor):
    def __init__(self):
        self.violations : list[tuple[ast.AST, str]] = []

    def _violation(self, n: ast.AST, what: str):
        self.violations.append((n, what))

    

class _ImportAnalysis(_LexicalAnalysis):
    def __init__(self):
        super().__init__()
        self._imports : set[tuple[str, ...]] = set()
    
    def visit_Import(self, node: ast.Import) -> Any:
        for a in node.names:
            if a.asname is not None:
                self.violations.append((a, "as-alias"))
            if a.name in FORBIDDEN_MODULES:
                self._violation(node, "forbidden module import")
            self._imports.add(tuple(a.name.split(".")))
        return self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        self._violation(node, "import from")
        return self.generic_visit(node)


class ValidationAnalysis(ast.NodeVisitor):
    def __init__(self, known_imports: frozenset[tuple[str, ...]]):
        self._known_imports = known_imports
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
        fields = attr.fields
        dunder_attr = next(
            (node for (fld, node) in fields if is_dunder(fld) and fld != "__init__"), None
        )
        if dunder_attr is not None:
            self._violation(dunder_attr, "dunder attribute")
            return
        if attr.is_var_base:
            path = [attr.base_name]
            for (fld, _) in fields[:-1]:
                path.append(fld)
            pref = tuple(path)
            last = attr.field_names[-1]
            if last in DANGEROUS_MEMBERS.get(pref, {}):
                self._violation(node, "access to forbidden attr")
                return
            dangerous_prefix = pref + (last,)
            for k in DANGEROUS_MEMBERS.keys():
                if is_prefix(dangerous_prefix, k):
                    self._violation(node, "dangerous module escape")
            self._name_visit(attr.base_var)

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
