"""The TOML/JSON policy format: the object model of ``policy.py`` as reviewable data.

    policy-version = 1

    [filesystem]
    read  = ["**"]
    write = ["repos/**"]
    list  = ["repos/**"]

    [atoms]
    org-checkout = {}                          # environmental, opaque
    not-force    = { pure = true }             # pure, established by a checker
    no-flag      = { matches = '[^-].*' }      # defined: the regex is its meaning (pure)

    [[validation]]
    name        = "not-force-check"
    params      = ["value"]
    argv        = ["test", "${value}", "!=", "--force"]
    cwd         = "**"
    effect-free = true
    establishes = { value = ["not-force"] }

    [[program]]
    name           = "git"
    subcommand     = "push origin"
    cwd            = "repos/**"
    requires       = ["org-checkout"]
    argument-atoms = ["not-force"]

Locations are the compact spelling the reports use (``pretty_location``): components separated
by "/", each a literal name, ``*`` (any one name), ``{a,b}`` (one of), or ``<regex>`` (a
fullmatch, spelled raw -- the one place this syntax and the reports diverge); a trailing ``**``
means "at or below", optionally followed by one leaf component (``repos/**/<\\w+\\.tar>``);
``.`` is the root. Argv pieces are literals, except a whole-token ``${param}``, which
substitutes the named parameter. Atoms are declared once, centrally: purity and any text meaning
live in ``[atoms]``, and ``establishes``/``requires``/``argument-atoms`` refer to them by name.

The schema is strict and fails closed: unknown keys, undeclared atoms, malformed locations and
mistyped values are all errors, and all of them are reported, not just the first. One default
deliberately diverges from the Python API: ``unknown-arguments`` is *false* here -- the reviewed
artifact opts into looseness explicitly.
"""
import json
import pathlib
import re
import tomllib
from typing import Any, cast

from . import markers
from .analysis import (
    ANY_NAME,
    Component,
    DirSplat,
    LocationFact,
    Matching,
    Named,
    OneOf,
    RegexLit,
    StaticPath,
    is_safe_name,
)
from .policy import AtomDef, Param, Policy, Validation, atom, program, pure, validation


class PolicyFileError(Exception):
    """The policy document does not conform; every problem found, one per line."""


# ---------------------------------------------------------------------------
# the location micro-syntax
# ---------------------------------------------------------------------------


def _split_components(text: str) -> list[str]:
    """Split on "/", except inside a ``<...>`` component, whose regex may contain "/": the
    component runs to the ">" that precedes a "/" or the end of the string."""
    out: list[str] = []
    start = 0
    in_regex = False
    for i, c in enumerate(text):
        if in_regex:
            if c == ">" and (i + 1 == len(text) or text[i + 1] == "/"):
                in_regex = False
        elif c == "<" and i == start:
            in_regex = True
        elif c == "/":
            out.append(text[start:i])
            start = i + 1
    out.append(text[start:])
    return out


def _parse_component(piece: str) -> Component:
    if piece == "*":
        return ANY_NAME
    if piece.startswith("<"):
        if not piece.endswith(">") or len(piece) < 3:
            raise ValueError(f"malformed regex component {piece!r}")
        regex = piece[1:-1]
        try:
            re.compile(regex)
        except re.error as e:
            raise ValueError(f"bad regex in {piece!r}: {e}")
        return Matching(RegexLit(regex))
    if piece.startswith("{"):
        if not piece.endswith("}") or len(piece) < 3:
            raise ValueError(f"malformed choice component {piece!r}")
        names = [n.strip() for n in piece[1:-1].split(",")]
        if not names or not all(is_safe_name(n) for n in names):
            raise ValueError(f"choice components must be plain names: {piece!r}")
        return OneOf(frozenset(names))
    if not is_safe_name(piece):
        raise ValueError(f"not a path component: {piece!r}")
    return Named(piece)


def parse_location(text: str) -> LocationFact:
    """The location a compact spelling names; raises ``ValueError`` for a malformed one."""
    if text in (".", ""):
        return StaticPath(())
    pieces = _split_components(text)
    if "" in pieces:
        raise ValueError(f"empty path component in {text!r}")
    splat_at = [i for i, p in enumerate(pieces) if p == "**"]
    if not splat_at:
        return StaticPath(tuple(_parse_component(p) for p in pieces))
    if len(splat_at) > 1 or splat_at[0] < len(pieces) - 2:
        raise ValueError(
            f"'**' may appear once, as the last component or followed by one leaf: {text!r}"
        )
    at = splat_at[0]
    prefix = tuple(_parse_component(p) for p in pieces[:at])
    leaf = ANY_NAME if at == len(pieces) - 1 else _parse_component(pieces[at + 1])
    return DirSplat(prefix, leaf)


_PARAM_REF = re.compile(r"\$\{(\w+)\}")


def _parse_argv_piece(piece: str) -> str | Param:
    m = _PARAM_REF.fullmatch(piece)
    if m is not None:
        return Param(m.group(1))
    if "${" in piece:
        raise ValueError(f"parameter references must be whole arguments: {piece!r}")
    return piece


# ---------------------------------------------------------------------------
# the strict schema
# ---------------------------------------------------------------------------


class _Loader:
    """Reads the parsed document, collecting every problem instead of stopping at the first."""

    def __init__(self, where: str):
        self.where = where
        self.errors: list[str] = []

    def error(self, path: str, what: str) -> None:
        self.errors.append(f"{self.where}: {path}: {what}")

    def table(self, path: str, value: Any, known: frozenset[str]) -> dict[str, Any]:
        if not isinstance(value, dict):
            self.error(path, "expected a table")
            return {}
        for key in sorted(value.keys() - known):
            self.error(path, f"unknown key {key!r}")
        return value

    def field[T](self, path: str, table: dict[str, Any], key: str, t: type[T]) -> T | None:
        value = table.get(key)
        if value is None:
            return None
        if isinstance(value, bool) and t is not bool or not isinstance(value, t):
            self.error(f"{path}.{key}", f"expected {t.__name__}")
            return None
        to_ret = value
        assert isinstance(to_ret, t)
        return cast(T, value)

    def required_str(self, path: str, table: dict[str, Any], key: str) -> str | None:
        if key not in table:
            self.error(path, f"{key} is required")
            return None
        return self.field(path, table, key, str)

    def str_list(self, path: str, table: dict[str, Any], key: str) -> list[str]:
        value = table.get(key)
        if value is None:
            return []
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            self.error(f"{path}.{key}", "expected a list of strings")
            return []
        return value

    def location(self, path: str, table: dict[str, Any], key: str) -> LocationFact | None:
        text = self.required_str(path, table, key)
        if text is None:
            return None
        try:
            return parse_location(text)
        except ValueError as e:
            self.error(f"{path}.{key}", str(e))
            return None

    def locations(self, path: str, table: dict[str, Any], key: str) -> list[LocationFact]:
        out: list[LocationFact] = []
        for i, text in enumerate(self.str_list(path, table, key)):
            try:
                out.append(parse_location(text))
            except ValueError as e:
                self.error(f"{path}.{key}[{i}]", str(e))
        return out

    def atom_names(
        self, path: str, table: dict[str, Any], key: str, declared: frozenset[str]
    ) -> list[str]:
        names = self.str_list(path, table, key)
        for n in names:
            if n not in declared:
                self.error(f"{path}.{key}", f"atom {n!r} is not declared in [atoms]")
        return names

    def entries(self, key: str, data: dict[str, Any]) -> list[Any]:
        value = data.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            self.error(key, "expected an array of tables")
            return []
        return value


_TOP_KEYS = frozenset({"policy-version", "filesystem", "atoms", "validation", "program"})
_ATOM_KEYS = frozenset({"pure", "matches"})
_VALIDATION_KEYS = frozenset({"name", "params", "argv", "cwd", "establishes", "effect-free"})
_PROGRAM_KEYS = frozenset(
    {"name", "subcommand", "cwd", "requires", "argument-atoms", "unknown-arguments", "argument-locations"}
)


def from_data(data: object, where: str = "<policy>") -> Policy:
    """The Policy a parsed document (TOML or JSON, as a dict) declares; raises
    ``PolicyFileError`` with every problem found. This is also the entry point for
    machine-synthesized policies, which need never touch a file."""
    loader = _Loader(where)
    top = loader.table("policy", data, _TOP_KEYS)

    if "policy-version" not in top:
        loader.error("policy", "policy-version = 1 is required")
    else:
        version = loader.field("policy", top, "policy-version", int)
        if version is not None and version != 1:
            loader.error("policy", f"unsupported policy-version {version}")

    fs = loader.table("filesystem", top.get("filesystem", {}), frozenset({"read", "write", "list"}))
    read = loader.locations("filesystem", fs, "read")
    write = loader.locations("filesystem", fs, "write")
    listing = loader.locations("filesystem", fs, "list")

    # atoms first: everything else refers to them by name. The [atoms] table has open keys (the
    # names themselves), so it skips the strict-key check its sub-tables get.
    atom_defs: list[AtomDef] = []
    pure_names: set[str] = set()
    declared: set[str] = set()
    atoms_table = top.get("atoms", {})
    if not isinstance(atoms_table, dict):
        loader.error("atoms", "expected a table")
        atoms_table = {}
    for name, spec_data in atoms_table.items():
        path = f"atoms.{name}"
        spec = loader.table(path, spec_data, _ATOM_KEYS)
        declared.add(name)
        meaning = loader.field(path, spec, "matches", str)
        pure_flag = loader.field(path, spec, "pure", bool)
        if meaning is not None:
            if pure_flag is False:
                loader.error(path, "a defined atom is pure by construction")
            try:
                re.compile(meaning)
            except re.error as e:
                loader.error(f"{path}.matches", f"bad regex: {e}")
                continue
            atom_defs.append(atom(name, markers.matches(meaning)))
            pure_names.add(name)
        elif pure_flag:
            pure_names.add(name)
    declared_f = frozenset(declared)

    validations: list[Validation] = []
    for i, entry in enumerate(loader.entries("validation", top)):
        path = f"validation[{i}]"
        t = loader.table(path, entry, _VALIDATION_KEYS)
        name = loader.required_str(path, t, "name")
        params = loader.str_list(path, t, "params")
        if "argv" not in t:
            loader.error(path, "argv is required")
        argv: list[str | Param] = []
        for piece in loader.str_list(path, t, "argv"):
            try:
                argv.append(_parse_argv_piece(piece))
            except ValueError as e:
                loader.error(f"{path}.argv", str(e))
        cwd = loader.location(path, t, "cwd")
        effect_free = loader.field(path, t, "effect-free", bool) or False
        est_table = loader.table(
            f"{path}.establishes", t.get("establishes", {}), frozenset(params) | {"cwd"}
        )
        establishes = {
            key: [pure(a) if a in pure_names else a for a in loader.atom_names(f"{path}.establishes", est_table, key, declared_f)]
            for key in est_table.keys() & (frozenset(params) | {"cwd"})
        }
        if name is None or cwd is None or not argv:
            continue
        try:
            validations.append(
                validation(
                    name, argv=argv, cwd=cwd, params=params,
                    establishes=establishes, effect_free=effect_free,
                )
            )
        except ValueError as e:
            loader.error(path, str(e))

    programs = []
    for i, entry in enumerate(loader.entries("program", top)):
        path = f"program[{i}]"
        t = loader.table(path, entry, _PROGRAM_KEYS)
        name = loader.required_str(path, t, "name")
        cwd = loader.location(path, t, "cwd")
        if name is None or cwd is None:
            continue
        try:
            programs.append(
                program(
                    name,
                    cwd=cwd,
                    subcommand=loader.field(path, t, "subcommand", str) or (),
                    unknown_arguments=loader.field(path, t, "unknown-arguments", bool) or False,
                    argument_locations=loader.locations(path, t, "argument-locations"),
                    requires=loader.atom_names(path, t, "requires", declared_f),
                    argument_atoms=loader.atom_names(path, t, "argument-atoms", declared_f),
                )
            )
        except ValueError as e:
            loader.error(path, str(e))

    if loader.errors:
        raise PolicyFileError("\n".join(loader.errors))
    try:
        return Policy.allow(
            read=read, write=write, listing=listing,
            programs=programs, validations=validations, atoms=atom_defs,
        )
    except ValueError as e:
        raise PolicyFileError(f"{where}: {e}")


def load_policy_file(path: pathlib.Path) -> Policy:
    """Load a ``.toml`` or ``.json`` policy document."""
    text = path.read_text(encoding="utf-8")
    match path.suffix:
        case ".toml":
            try:
                data: object = tomllib.loads(text)
            except tomllib.TOMLDecodeError as e:
                raise PolicyFileError(f"{path}: {e}")
        case ".json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError as e:
                raise PolicyFileError(f"{path}: {e}")
        case _:
            raise PolicyFileError(f"{path}: expected a .toml or .json policy document")
    return from_data(data, str(path))
