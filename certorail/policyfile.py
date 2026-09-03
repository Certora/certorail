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

    [[network]]
    host    = "api.github.com"
    methods = ["GET"]

Locations are the compact spelling the reports use (``pretty_location``): components separated
by "/", each a literal name, ``*`` (any one name), ``{a,b}`` (one of), or ``<regex>`` (a
fullmatch, spelled raw -- the one place this syntax and the reports diverge); a trailing ``**``
means "at or below", optionally followed by one leaf component (``repos/**/<\\w+\\.tar>``);
``.`` is the root. A leading ``/`` anchors the location at the *filesystem* root instead of the
sandbox root (``/srv/checkouts/**``); the two anchors never relate, so an absolute allowance
says nothing about sandbox-relative paths and vice versa. Argv pieces are literals, except a
whole-token ``${param}``, which substitutes the named parameter. Atoms are declared once, centrally: purity and any text meaning
live in ``[atoms]``, and ``establishes``/``requires``/``argument-atoms`` refer to them by name.
A validation's ``cwd`` is optional: omitted, the check does not care where it runs --
``certora.check`` may then be called without ``cwd=`` -- and it may not establish atoms on cwd.
``[[network]]`` rules govern the program's own requests (``certora.network``), enforced
statically at every call site and again by the broker at runtime, on every redirect hop:
``schemes`` defaults to https only, an empty ``ports`` means the scheme's default port, an
empty ``methods`` any method. A rule's ``requires`` names atoms the URL value must carry at
the call site -- established by a live ``certora.check``, or discharged from an exactly-known
URL's text. Each entry is an atom name, or ``{ atom = "...", on-redirect = "..." }`` choosing
what a redirect hop -- a URL the analysis never saw -- owes the atom: ``recheck`` (the broker
re-establishes it from the hop URL's text; textual atoms only), ``stop`` (the rule refuses to
authorize hops), or ``waive`` (the atom speaks about the original request only). A bare name
defaults to recheck when the atom is textual, stop otherwise. Network rules say nothing about
exec'd programs, whose network access is folded into their ``[[program]]`` grant.

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
from .policy import (
    AtomDef,
    NetworkRule,
    Param,
    Policy,
    RequiredAtom,
    Validation,
    atom,
    network,
    program,
    pure,
    validation,
)


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
    """The location a compact spelling names; raises ``ValueError`` for a malformed one. A
    leading "/" anchors the location at the filesystem root instead of the sandbox root."""
    if text in (".", ""):
        return StaticPath(())
    absolute = text.startswith("/")
    if absolute:
        text = text[1:]
        if not text:
            return StaticPath((), absolute=True)  # "/": the filesystem root itself
    pieces = _split_components(text)
    if "" in pieces:
        raise ValueError(f"empty path component in {text!r}")
    splat_at = [i for i, p in enumerate(pieces) if p == "**"]
    if not splat_at:
        return StaticPath(tuple(_parse_component(p) for p in pieces), absolute)
    if len(splat_at) > 1 or splat_at[0] < len(pieces) - 2:
        raise ValueError(
            f"'**' may appear once, as the last component or followed by one leaf: {text!r}"
        )
    at = splat_at[0]
    prefix = tuple(_parse_component(p) for p in pieces[:at])
    leaf = ANY_NAME if at == len(pieces) - 1 else _parse_component(pieces[at + 1])
    return DirSplat(prefix, leaf, absolute)


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

    def int_list(self, path: str, table: dict[str, Any], key: str) -> list[int]:
        value = table.get(key)
        if value is None:
            return []
        if not isinstance(value, list) or any(
            isinstance(v, bool) or not isinstance(v, int) for v in value
        ):
            self.error(f"{path}.{key}", "expected a list of integers")
            return []
        return value

    def number(self, path: str, table: dict[str, Any], key: str) -> float | None:
        value = table.get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            self.error(f"{path}.{key}", "expected a number")
            return None
        return float(value)

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

    def required_atoms(
        self, path: str, table: dict[str, Any], key: str, declared: frozenset[str]
    ) -> list[str | RequiredAtom]:
        """A network rule's ``requires``: each entry an atom name (redirect treatment decided
        by the atom's textuality), or ``{ atom = "...", on-redirect = "..." }``."""
        value = table.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            self.error(f"{path}.{key}", "expected a list")
            return []
        out: list[str | RequiredAtom] = []
        for j, entry in enumerate(value):
            where = f"{path}.{key}[{j}]"
            mode = None
            if isinstance(entry, str):
                name = entry
            elif isinstance(entry, dict):
                sub = self.table(where, entry, frozenset({"atom", "on-redirect"}))
                name = self.required_str(where, sub, "atom")
                mode = self.field(where, sub, "on-redirect", str)
                if mode is not None and mode not in ("recheck", "stop", "waive"):
                    self.error(f"{where}.on-redirect", "expected recheck, stop or waive")
                    mode = None
                if name is None:
                    continue
            else:
                self.error(
                    where, 'expected an atom name or { atom = "...", on-redirect = "..." }'
                )
                continue
            if name not in declared:
                self.error(where, f"atom {name!r} is not declared in [atoms]")
            out.append(name if mode is None else RequiredAtom(name, mode))
        return out

    def entries(self, key: str, data: dict[str, Any]) -> list[Any]:
        value = data.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            self.error(key, "expected an array of tables")
            return []
        return value


_TOP_KEYS = frozenset(
    {"policy-version", "root", "filesystem", "atoms", "validation", "program", "network"}
)
_ATOM_KEYS = frozenset({"pure", "matches"})
_VALIDATION_KEYS = frozenset({"name", "params", "argv", "cwd", "establishes", "effect-free"})
_NETWORK_KEYS = frozenset({
    "host", "schemes", "ports", "methods", "allow-nonpublic", "requires",
    "read-timeout", "total-timeout", "max-response-bytes",
})
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

    # the self-identification for ambiently-discovered policies (policydir): which sandbox
    # root this document governs. Optional here; the ambient lookup requires and matches it.
    root_id = loader.field("policy", top, "root", str)
    if root_id is not None and not root_id.startswith("/"):
        loader.error("policy.root", "expected an absolute path")

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
        # cwd is optional: omitted, the check does not care where it runs, and certora.check
        # may be called without cwd=
        cwd_given = "cwd" in t
        cwd = loader.location(path, t, "cwd") if cwd_given else None
        effect_free = loader.field(path, t, "effect-free", bool) or False
        est_table = loader.table(
            f"{path}.establishes", t.get("establishes", {}), frozenset(params) | {"cwd"}
        )
        establishes = {
            key: [pure(a) if a in pure_names else a for a in loader.atom_names(f"{path}.establishes", est_table, key, declared_f)]
            for key in est_table.keys() & (frozenset(params) | {"cwd"})
        }
        if name is None or (cwd_given and cwd is None) or not argv:
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

    net_rules: list[NetworkRule] = []
    for i, entry in enumerate(loader.entries("network", top)):
        path = f"network[{i}]"
        t = loader.table(path, entry, _NETWORK_KEYS)
        host = loader.required_str(path, t, "host")
        if host is None:
            continue
        try:
            net_rules.append(
                network(
                    host,
                    schemes=loader.str_list(path, t, "schemes") or ("https",),
                    ports=loader.int_list(path, t, "ports"),
                    methods=loader.str_list(path, t, "methods"),
                    allow_nonpublic=loader.field(path, t, "allow-nonpublic", bool) or False,
                    requires=loader.required_atoms(path, t, "requires", declared_f),
                    read_timeout=loader.number(path, t, "read-timeout"),
                    total_timeout=loader.number(path, t, "total-timeout"),
                    max_response_bytes=loader.field(path, t, "max-response-bytes", int),
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
            network=net_rules,
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
