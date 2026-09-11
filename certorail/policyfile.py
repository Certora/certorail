"""The TOML/JSON policy format: the object model of ``policy.py`` as reviewable data.

    policy-version = 1

    [filesystem]
    read  = ["**"]
    write = ["repos/**"]
    list  = ["repos/**"]

    [regions]
    git.config = { footprint = ".git/config", about = "remotes and everything else git reads from config" }
    git.remote = { network = true, about = "the remote repository" }

    [atoms]
    org-checkout = { reads = ["git.config"] }  # environmental: dies when git.config is written
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
    name         = "git"
    argv         = ["git", "push", "origin", "${BRANCH}"]
    cwd          = "repos/**"
    requires     = ["org-checkout"]
    holes.BRANCH = { atoms = ["not-force"] }
    writes       = ["git.remote"]

    [[network]]
    host    = "api.github.com"
    methods = ["GET"]

Locations are the compact spelling the reports use (``pretty_location``): components separated
by "/", each a literal name, ``*`` (any one name), ``{a,b}`` (one of), or ``<regex>`` (a
fullmatch, spelled raw -- the one place this syntax and the reports diverge); a trailing ``**``
means "at or below", optionally followed by one leaf component (``repos/**/<\\w+\\.tar>``);
``.`` is the root. A leading ``/`` anchors the location at the *filesystem* root instead of the
sandbox root (``/srv/checkouts/**``); the two anchors never relate, so an absolute allowance
says nothing about sandbox-relative paths and vice versa. A rule's or a validation's ``cwd`` is
a location *slot*: one spelling, or a list of them meaning any-of. Argv pieces are literals,
except a whole-token ``${param}``, which substitutes the named parameter, and
``${checkers}/<name>`` heading ``argv[0]``, which names the executable ``<name>`` in the config
directory's ``checkers/`` (resolved at load; it must exist). Atoms are declared once, centrally:
purity and any text meaning live in ``[atoms]``, and ``establishes``/``requires``/a hole's
``atoms`` refer to them by name. One atom is built in and may not be declared: ``not-option``,
the value does not begin with ``-``; a checker may list it in ``establishes``.
A ``[[program]]`` rule is either its words alone (``name`` plus ``subcommand``: exactly those,
no arguments) or a template (``argv`` with ``${HOLE}`` pieces and a ``holes`` table saying what
each hole is); there is no third form that takes arguments it does not describe. A flags hole
may carry ``any = true``, the open vocabulary, for a tool trusted with its own options.
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
``[regions]`` (EFFECTS.md) names the state checks depend on and commands change, each with one
medium: a ``footprint`` -- locations relative to the cwd of the check whose atom depends on it,
or absolute, each meaning that path and everything below -- or ``network = true``. A rule or a
validation may claim the media it reaches (``network = false``, ``write = false``;
``effect-free = true`` is neither) and what it ``writes`` within them, region names or a medium
name for the whole medium; an environmental atom may say what it ``reads``. Undeclared means
everything, so a policy that says nothing keeps the crude kill. A rule with an open flag
vocabulary or an ``any`` hole the tool could read as an option cannot say what it writes.

The schema is strict and fails closed: unknown keys, undeclared atoms, malformed locations and
mistyped values are all errors, and all of them are reported, not just the first. This is the
only policy language; the constructors in ``policy`` are the object model it builds.
"""
import hashlib
import json
import os
import pathlib
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from . import markers
from .effects import Medium, as_medium
from .templates import NOT_OPTION
from .ids import AtomId, FlagName, FlagsetId, HoleName, ParamName, RegionId
from .locations import parse_location
from .policydir import config_dir
from .analysis import (
    ANY_NAME,
    Component,
    DirSplat,
    Exact,
    LocationFact,
    Matching,
    Named,
    OneOf,
    RegexLit,
    StaticPath,
    alternation,
    is_safe_name,
)
from .policy import (
    AtomDef,
    NetworkRule,
    Param,
    Policy,
    Program,
    Region,
    RequiredAtom,
    Source,
    Validation,
    atom,
    network,
    program,
    pure,
    region,
    validation,
)
from .templates import Constraint, Each, Flags, Flagset, Hole, HoleRef, Piece, Token


class PolicyFileError(Exception):
    """The policy document does not conform; every problem found, one per line."""


# the location micro-syntax lives in ``locspec`` (the grammar, stdlib-only, shared with the
# runtime's ``certora.pathmatch``) and ``locations`` (the conversion to LocationFact, shared with
# the analysis' pathmatch guard); ``parse_location`` is re-exported here for its callers
__all__ = ["PolicyFileError", "from_data", "load_policy_file", "parse_location", "rulesets_dir"]


_PARAM_REF = re.compile(r"\$\{(\w+)\}")
_CHECKERS_VAR = "${checkers}"


def _resolve_checker(loader: "_Loader", where: str, piece: str, index: int) -> str | None:
    """``${checkers}/<name>`` at the head of ``argv[0]``: the executable ``<name>`` in the
    config directory's ``checkers/`` -- the one audited place for a policy's checkers, spelled
    without anyone's home directory so validations travel between users. Resolved at load, and
    the file must exist and be executable, so a policy naming a missing checker fails here
    rather than at every check. Anywhere else, or bare, ``${checkers}`` is an error."""
    prefix = _CHECKERS_VAR + "/"
    if index != 0 or not piece.startswith(prefix) or len(piece) == len(prefix):
        loader.error(where, f"{_CHECKERS_VAR} may only head argv[0], as {_CHECKERS_VAR}/<name>")
        return None
    rel = pathlib.PurePosixPath(piece[len(prefix):])
    if rel.is_absolute() or ".." in rel.parts:
        loader.error(where, f"the checker name must be a relative path without '..': {piece!r}")
        return None
    checkers = config_dir() / "checkers"
    resolved = checkers / rel
    if not (resolved.is_file() and os.access(resolved, os.X_OK)):
        loader.error(where, f"checker {rel} is not installed (executable) in {checkers}")
        return None
    return str(resolved)


def _parse_argv_piece(piece: str) -> str | Param:
    m = _PARAM_REF.fullmatch(piece)
    if m is not None:
        return Param(ParamName(m.group(1)))
    if "${" in piece:
        raise ValueError(f"parameter references must be whole arguments: {piece!r}")
    return piece


# ---------------------------------------------------------------------------
# the strict schema
# ---------------------------------------------------------------------------


class _Loader:
    """Reads the parsed document, collecting every problem instead of stopping at the first."""

    def __init__(self, where: str, errors: list[str] | None = None):
        self.where = where
        # shared across the documents of one composition (the root and its applied rulesets),
        # so every problem in every file is reported at once
        self.errors: list[str] = [] if errors is None else errors

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

    def location_slot(
        self, path: str, table: dict[str, Any], key: str
    ) -> tuple[LocationFact, ...] | None:
        """A required location *slot* (a rule's or a validation's ``cwd``): one spelling or a
        non-empty list of them, meaning any-of. None when absent or malformed (reported)."""
        value = table.get(key)
        if value is None:
            self.error(path, f"{key} is required")
            return None
        texts = value if isinstance(value, list) else [value]
        if not texts or not all(isinstance(v, str) for v in texts):
            self.error(f"{path}.{key}", "expected a location or a non-empty list of locations")
            return None
        out: list[LocationFact] = []
        for i, text in enumerate(texts):
            try:
                out.append(parse_location(text))
            except ValueError as e:
                where = f"{path}.{key}[{i}]" if isinstance(value, list) else f"{path}.{key}"
                self.error(where, str(e))
        return tuple(out) if len(out) == len(texts) else None

    def locations(self, path: str, table: dict[str, Any], key: str) -> list[LocationFact]:
        out: list[LocationFact] = []
        for i, text in enumerate(self.str_list(path, table, key)):
            try:
                out.append(parse_location(text))
            except ValueError as e:
                self.error(f"{path}.{key}[{i}]", str(e))
        return out

    def atom_names(
        self, path: str, table: dict[str, Any], key: str, declared: frozenset[AtomId]
    ) -> list[AtomId]:
        names = self.str_list(path, table, key)
        for n in names:
            if n not in declared and n != NOT_OPTION:
                self.error(f"{path}.{key}", f"atom {n!r} is not declared in [atoms]")
        return [AtomId(n) for n in names]

    def required_atoms(
        self, path: str, table: dict[str, Any], key: str, declared: frozenset[AtomId]
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
            if name not in declared and name != NOT_OPTION:
                self.error(where, f"atom {name!r} is not declared in [atoms]")
            out.append(name if mode is None else RequiredAtom(AtomId(name), mode))
        return out

    def region_names(
        self, path: str, table: dict[str, Any], key: str, regions: Mapping[RegionId, Medium]
    ) -> list[str] | None:
        """A list of regions under *key* (``writes``, ``reads``): declared region names, or a
        medium name (``fs``, ``network``) for the whole medium. None when absent -- undeclared --
        or malformed (reported); an empty list is a declaration of nothing."""
        if key not in table:
            return None
        names = self.str_list(path, table, key)
        ok = isinstance(table.get(key), list)
        for n in names:
            if RegionId(n) not in regions and as_medium(n) is None:
                self.error(f"{path}.{key}", f"region {n!r} is not declared in [regions]")
                ok = False
        return names if ok else None

    def entries(self, key: str, data: dict[str, Any]) -> list[Any]:
        value = data.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            self.error(key, "expected an array of tables")
            return []
        return value


_TOP_KEYS = frozenset({
    "policy-version", "root", "filesystem", "regions", "atoms", "flagset", "validation",
    "program", "network", "apply", "source",
})
# a ruleset (TEMPLATES.md): exec-side vocabulary only -- no filesystem grants, no network, no root
_RULESET_TOP_KEYS = frozenset({
    "ruleset-version", "params", "regions", "atoms", "flagset", "validation", "program", "apply",
    "source",
})
# a region (EFFECTS.md): one medium -- a footprint (fs) or network = true
_REGION_KEYS = frozenset({"footprint", "network", "about"})
# the media a grant claims to reach, and what it writes within them
_MEDIA_KEYS = frozenset({"network", "write", "writes"})
_SOURCE_KEYS = frozenset({"name", "location"})
_PARAM_KINDS = ("directory", "atom")
# where a ruleset's parameters may be substituted: location slots (a directory parameter heads
# the spelling) and atom lists (an atom parameter is the whole entry)
_LOCATION_KEYS = frozenset({"cwd", "location"})
_ATOM_LIST_KEYS = frozenset({"requires", "atoms"})
_HEAD_PARAM = re.compile(r"\$\{(\w+)\}(?:/(.+))?")
_WHOLE_PARAM = re.compile(r"\$\{(\w+)\}")
# stock, config-free, non-spawning predicates a ruleset's validation may run besides
# ${checkers}/<name>: the whole executable surface a shared file can reach
RULESET_STOCK_CHECKERS: frozenset[str] = frozenset({"test"})
_ATOM_KEYS = frozenset({"pure", "matches", "reads"})
_VALIDATION_KEYS = (
    frozenset({"name", "params", "argv", "cwd", "establishes", "effect-free"}) | _MEDIA_KEYS
)
_NETWORK_KEYS = frozenset({
    "host", "schemes", "ports", "methods", "allow-nonpublic", "requires",
    "read-timeout", "total-timeout", "max-response-bytes", "source", "path", "writes",
})
# the flat rule's argument keys of old: an argument is now a hole of a template, which knows
# which position it fills. Named here so the error says where the spelling went
_RETIRED_PROGRAM_KEYS = frozenset({"argument-atoms", "unknown-arguments", "argument-locations"})
_PROGRAM_KEYS = (
    frozenset({"name", "cwd", "requires", "argv", "holes", "source", "effect-free", "subcommand"})
    | _MEDIA_KEYS
)
# a constraint table: a token hole, an each hole's elements, a valued flag (TEMPLATES.md)
_CONSTRAINT_KEYS = frozenset({"location", "matches", "one-of", "atoms", "literal", "any"})
_HOLE_KEYS = _CONSTRAINT_KEYS | {"kind", "min", "flagset", "bare"}
_HOLE_KINDS = ("token", "each", "flags")
_FLAGSET_KEYS = frozenset({"name", "bare", "any"})
_HOLE_REF = re.compile(r"\$\{(\w+)(\.\.\.)?\}")


# ---------------------------------------------------------------------------
# command templates (TEMPLATES.md)
# ---------------------------------------------------------------------------


def _open_table(loader: _Loader, path: str, value: Any, known: frozenset[str]) -> dict[str, Any] | None:
    """A table whose keys are *known* or flag names (``-``-prefixed): hole tables and flagsets."""
    if not isinstance(value, dict):
        loader.error(path, "expected a table")
        return None
    ok = True
    for key in sorted(value.keys() - known):
        if not key.startswith("-"):
            loader.error(path, f"unknown key {key!r}")
            ok = False
    return value if ok else None


def _location_list(
    loader: _Loader, path: str, table: dict[str, Any], key: str
) -> tuple[LocationFact, ...] | None:
    """An optional location slot under *key* (a constraint's ``location``, a network rule's
    ``path``): one spelling or a list (any-of); empty when absent, None when malformed."""
    value = table.get(key)
    if value is None:
        return ()
    texts = value if isinstance(value, list) else [value]
    if not texts or not all(isinstance(v, str) for v in texts):
        loader.error(f"{path}.{key}", "expected a location or a non-empty list of locations")
        return None
    out: list[LocationFact] = []
    for i, text in enumerate(texts):
        try:
            out.append(parse_location(text))
        except ValueError as e:
            loader.error(f"{path}.{key}[{i}]", str(e))
    return tuple(out) if len(out) == len(texts) else None


def _constraint(
    loader: _Loader, path: str, table: dict[str, Any], declared: frozenset[AtomId]
) -> Constraint | None:
    locations = _location_list(loader, path, table, "location")
    matches = loader.field(path, table, "matches", str)
    one_of = loader.str_list(path, table, "one-of")
    atoms = loader.atom_names(path, table, "atoms", declared)
    literal = loader.field(path, table, "literal", bool) or False
    anything = loader.field(path, table, "any", bool) or False
    if locations is None:
        return None
    regex = None
    if matches is not None:
        try:
            re.compile(matches)
        except re.error as e:
            loader.error(f"{path}.matches", f"bad regex: {e}")
            return None
        regex = RegexLit(matches)
    if one_of:
        if regex is not None:
            loader.error(path, "matches and one-of exclude each other")
            return None
        regex = alternation(*(Exact(n) for n in one_of))
    try:
        return Constraint(locations, regex, frozenset(atoms), literal, anything)
    except ValueError as e:
        loader.error(path, str(e))
        return None


def _flag_vocabulary(
    loader: _Loader,
    path: str,
    table: dict[str, Any],
    declared: frozenset[AtomId],
    reserved: frozenset[str],
) -> Flagset | None:
    """``bare`` plus every ``-``-keyed valued flag, or ``any = true`` alone -- the open
    vocabulary; *reserved* are the table's own keys."""
    if loader.field(path, table, "any", bool):
        listed = sorted(k for k in table if k == "bare" or k.startswith("-"))
        if listed:
            loader.error(path, f"an open flag vocabulary (any = true) lists no flags: {', '.join(listed)}")
            return None
        return Flagset(any=True)
    bare = loader.str_list(path, table, "bare")
    valued: dict[FlagName, Constraint] = {}
    ok = True
    for key, spec in table.items():
        if key in reserved:
            continue
        where = f"{path}.{key}"
        if not isinstance(spec, dict):
            loader.error(where, "expected a constraint table")
            ok = False
            continue
        if not spec:
            loader.error(where, "an empty table is not a bare flag: list bare flags under `bare`")
            ok = False
            continue
        for k in sorted(spec.keys() - _CONSTRAINT_KEYS):
            loader.error(where, f"unknown key {k!r}")
            ok = False
        c = _constraint(loader, where, spec, declared)
        if c is None:
            ok = False
        else:
            valued[FlagName(key)] = c
    if not ok:
        return None
    try:
        return Flagset(frozenset(FlagName(b) for b in bare), valued)
    except ValueError as e:
        loader.error(path, str(e))
        return None


def _hole(
    loader: _Loader,
    path: str,
    table: dict[str, Any],
    flagsets: Mapping[FlagsetId, Flagset],
    declared: frozenset[AtomId],
) -> Hole | None:
    kind = loader.field(path, table, "kind", str) or "token"
    if kind not in _HOLE_KINDS:
        loader.error(f"{path}.kind", f"expected one of {', '.join(_HOLE_KINDS)}")
        return None
    # `any` is a vocabulary only on a flags hole (the open vocabulary); on a token or each hole
    # it is the constraint
    inline = "bare" in table or (kind == "flags" and "any" in table) or any(k.startswith("-") for k in table)
    if kind == "flags":
        ref = loader.field(path, table, "flagset", str)
        for k in sorted(((_CONSTRAINT_KEYS - {"any"}) | {"min"}) & table.keys()):
            loader.error(path, f"a flags hole carries a vocabulary, not {k!r}")
            return None
        if ref is not None and inline:
            loader.error(path, "flagset and an inline vocabulary exclude each other")
            return None
        if ref is not None:
            fs = flagsets.get(FlagsetId(ref))
            if fs is None:
                loader.error(f"{path}.flagset", f"flagset {ref!r} is not declared")
                return None
            return Flags(fs)
        if not inline:
            loader.error(path, "a flags hole needs a flagset or an inline vocabulary")
            return None
        fs = _flag_vocabulary(loader, path, table, declared, _HOLE_KEYS)
        return None if fs is None else Flags(fs)
    if inline or "flagset" in table:
        loader.error(path, f"a {kind} hole carries a constraint, not a flag vocabulary")
        return None
    c = _constraint(loader, path, table, declared)
    if c is None:
        return None
    if kind == "token":
        if "min" in table:
            loader.error(path, "min applies to each holes only")
            return None
        return Token(c)
    minimum = loader.field(path, table, "min", int)
    return Each(c, 0 if minimum is None else minimum)


def _source_atom(
    loader: _Loader,
    path: str,
    table: dict[str, Any],
    key: str,
    declared: frozenset[AtomId],
    pure_names: frozenset[AtomId],
) -> AtomId | None:
    """A source atom (PROVENANCE.md) named under *key*: declared, and *pure*."""
    name = loader.field(path, table, key, str)
    if name is None:
        return None
    if name not in declared:
        loader.error(f"{path}.{key}", f"atom {name!r} is not declared in [atoms]")
        return None
    if name not in pure_names:
        loader.error(f"{path}.{key}", f"a source atom is pure: declare {name!r} with pure = true")
        return None
    return AtomId(name)


def _sources(
    loader: _Loader, top: dict[str, Any], declared: frozenset[AtomId], pure_names: frozenset[AtomId]
) -> list[Source]:
    """``[[source]]``: read locations whose contents yield an atom."""
    out: list[Source] = []
    for i, entry in enumerate(loader.entries("source", top)):
        path = f"source[{i}]"
        t = loader.table(path, entry, _SOURCE_KEYS)
        if "name" not in t:
            loader.error(path, "name is required")
            continue
        name = _source_atom(loader, path, t, "name", declared, pure_names)
        locations = loader.location_slot(path, t, "location")
        if name is None or locations is None:
            continue
        out.append(Source(name, locations))
    return out


def _pieces(loader: _Loader, path: str, words: list[str]) -> tuple[Piece, ...] | None:
    out: list[Piece] = []
    ok = True
    for i, word in enumerate(words):
        m = _HOLE_REF.fullmatch(word)
        if m is not None:
            out.append(HoleRef(HoleName(m.group(1)), m.group(2) is not None))
        elif "${" in word:
            loader.error(f"{path}.argv[{i}]", f"hole references are whole words: {word!r}")
            ok = False
        else:
            out.append(word)
    return tuple(out) if ok else None


# ---------------------------------------------------------------------------
# rulesets and [[apply]] (TEMPLATES.md)
# ---------------------------------------------------------------------------


def rulesets_dir() -> pathlib.Path:
    return config_dir() / "rulesets"


@dataclass
class _Document:
    """One document of a composition: the root policy, or one instantiated ruleset."""

    top: dict[str, Any]
    label: str            # how messages name it: "unix.toml (where=repos, /srv/data)"
    origin: str | None    # provenance on the rules it contributes; None for the root
    restricted: bool      # a ruleset: restricted validation argv


def _ruleset_params(loader: _Loader, top: dict[str, Any]) -> dict[str, str]:
    """``[params]``: name -> kind."""
    table = top.get("params", {})
    if not isinstance(table, dict):
        loader.error("params", "expected a table")
        return {}
    out: dict[str, str] = {}
    for name, spec in table.items():
        path = f"params.{name}"
        s = loader.table(path, spec, frozenset({"kind"}))
        kind = loader.field(path, s, "kind", str)
        if kind is None or kind not in _PARAM_KINDS:
            loader.error(path, f"kind must be one of {', '.join(_PARAM_KINDS)}")
            continue
        out[name] = kind
    return out


def _bindings(
    loader: _Loader, path: str, table: dict[str, Any], params: Mapping[str, str]
) -> dict[str, Any] | None:
    """The ``[[apply]]`` entry's bindings, checked against the ruleset's parameters: a directory
    parameter takes one directory or a non-empty list of them (a StaticPath: no splat, no regex);
    an atom parameter takes one atom name."""
    out: dict[str, Any] = {}
    ok = True
    for name, kind in params.items():
        if name not in table:
            loader.error(path, f"parameter {name!r} is not bound")
            ok = False
            continue
        value = table[name]
        if kind == "directory":
            texts = value if isinstance(value, list) else [value]
            if not texts or not all(isinstance(t, str) for t in texts):
                loader.error(f"{path}.{name}", "expected a directory or a non-empty list of them")
                ok = False
                continue
            for text in texts:
                try:
                    loc = parse_location(text)
                except ValueError as e:
                    loader.error(f"{path}.{name}", str(e))
                    ok = False
                    continue
                if not isinstance(loc, StaticPath):
                    loader.error(f"{path}.{name}", f"{text!r} is not a directory (no '**' or regex components)")
                    ok = False
            out[name] = list(texts)
        else:
            if not isinstance(value, str):
                loader.error(f"{path}.{name}", "expected an atom name")
                ok = False
                continue
            out[name] = value
    for key in sorted(table.keys() - params.keys() - {"ruleset"}):
        loader.error(path, f"{key!r} is not a parameter of the ruleset")
        ok = False
    return out if ok else None


def _join_dir(base: str, rest: str | None) -> str:
    if rest is None:
        return base
    if base in (".", ""):
        return rest
    return base.rstrip("/") + "/" + rest if base.rstrip("/") else "/" + rest


def _instantiate(
    loader: _Loader, top: dict[str, Any], params: Mapping[str, str], bindings: Mapping[str, Any]
) -> dict[str, Any]:
    """Substitute the parameters into a ruleset's rules. A directory parameter heads a location
    spelling and maps over its bound directories (``${where}/**`` with two directories is two
    locations: any-of); an atom parameter is a whole entry of an atom list. Everything else the
    parser will see is checked to contain no stray reference and no absolute location."""

    def locations(value: Any, where: str) -> Any:
        texts = value if isinstance(value, list) else [value]
        if not all(isinstance(t, str) for t in texts):
            return value  # the parser reports the type
        out: list[str] = []
        for text in texts:
            if text.startswith("/"):
                loader.error(where, f"a ruleset names no absolute locations: {text!r}")
            m = _HEAD_PARAM.fullmatch(text)
            if m is None:
                if "${" in text:
                    loader.error(where, f"a parameter may only head a location: {text!r}")
                out.append(text)
                continue
            name, rest = m.group(1), m.group(2)
            if params.get(name) != "directory":
                loader.error(where, f"{name!r} is not a directory parameter")
                out.append(text)
                continue
            out.extend(_join_dir(base, rest) for base in bindings[name])
        if isinstance(value, list) or len(out) != 1:
            return out
        return out[0]

    def atoms(value: Any, where: str) -> Any:
        texts = value if isinstance(value, list) else [value]
        if not all(isinstance(t, str) for t in texts):
            return value
        out: list[str] = []
        for text in texts:
            m = _WHOLE_PARAM.fullmatch(text)
            if m is None:
                if "${" in text:
                    loader.error(where, f"a parameter is a whole atom entry: {text!r}")
                out.append(text)
                continue
            name = m.group(1)
            if params.get(name) != "atom":
                loader.error(where, f"{name!r} is not an atom parameter")
                out.append(text)
                continue
            out.append(str(bindings[name]))
        return out if isinstance(value, list) else out[0]

    def walk(node: Any, key: str, where: str) -> Any:
        if key in _LOCATION_KEYS:
            return locations(node, where)
        if key in _ATOM_LIST_KEYS:
            return atoms(node, where)
        if key == "establishes" and isinstance(node, dict):
            return {k: atoms(v, f"{where}.{k}") for k, v in node.items()}
        if isinstance(node, dict):
            return {k: walk(v, k, f"{where}.{k}") for k, v in node.items()}
        if isinstance(node, list) and all(isinstance(x, dict) for x in node):
            return [walk(x, key, f"{where}[{i}]") for i, x in enumerate(node)]
        return node

    def apply_entry(entry: Any, where: str) -> Any:
        """A nested ``[[apply]]``: its bindings may pass this ruleset's parameters down whole
        (``where = "${where}"``), a directory parameter as its list of directories."""
        if not isinstance(entry, dict):
            return entry
        out: dict[str, Any] = {}
        for k, v in entry.items():
            texts = v if isinstance(v, list) else [v]
            if k == "ruleset" or not all(isinstance(t, str) for t in texts):
                out[k] = v
                continue
            new: list[str] = []
            for text in texts:
                m = _WHOLE_PARAM.fullmatch(text)
                if m is None:
                    if "${" in text:
                        loader.error(f"{where}.{k}", f"a parameter is passed down whole: {text!r}")
                    new.append(text)
                    continue
                name = m.group(1)
                if name not in params:
                    loader.error(f"{where}.{k}", f"{name!r} is not a parameter of this ruleset")
                    new.append(text)
                    continue
                bound = bindings[name]
                new.extend(bound if isinstance(bound, list) else [bound])
            out[k] = new if (isinstance(v, list) or len(new) != 1) else new[0]
        return out

    result = dict(top)
    for section in ("program", "validation", "flagset", "source"):
        if section in top:
            result[section] = walk(top[section], section, section)
    applies = top.get("apply")
    if isinstance(applies, list):
        result["apply"] = [apply_entry(e, f"apply[{i}]") for i, e in enumerate(applies)]
    return result


def _apply_all(
    loader: _Loader,
    top: dict[str, Any],
    chain: tuple[str, ...],
    seen: dict[tuple[str, str], tuple[str, str]],
    out: list[_Document],
) -> None:
    """Resolve the ``[[apply]]`` entries of *top* -- a root or a ruleset -- depth-first into
    *out*. An application is identified by (realpath, hash, bindings): reached twice with the
    same bindings (a composition diamond) it is one document; with different bindings it is an
    error -- lift it to the root with the union. A ruleset is applied at most once."""
    for i, entry in enumerate(loader.entries("apply", top)):
        path = f"apply[{i}]"
        if not isinstance(entry, dict):
            loader.error(path, "expected a table")
            continue
        name = loader.required_str(path, entry, "ruleset")
        if name is None:
            continue
        if "/" in name or name in (".", "..") or not name.endswith(".toml"):
            loader.error(f"{path}.ruleset", f"expected the name of a .toml file in {rulesets_dir()}")
            continue
        file = rulesets_dir() / name
        try:
            text = file.read_text(encoding="utf-8")
            real = str(file.resolve())
        except OSError as e:
            loader.error(f"{path}.ruleset", f"cannot read ruleset {name}: {e}")
            continue
        if real in chain:
            loader.error(f"{path}.ruleset", f"ruleset {name} applies itself (via {' -> '.join(chain)})")
            continue
        try:
            data: object = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            loader.error(f"{path}.ruleset", f"{name}: {e}")
            continue
        sub = _Loader(name, loader.errors)
        rtop = sub.table("ruleset", data, _RULESET_TOP_KEYS)
        if "ruleset-version" not in rtop:
            sub.error("ruleset", "ruleset-version = 1 is required")
        elif sub.field("ruleset", rtop, "ruleset-version", int) not in (None, 1):
            sub.error("ruleset", "unsupported ruleset-version")
        params = _ruleset_params(sub, rtop)
        bindings = _bindings(loader, path, entry, params)
        if bindings is None:
            continue
        canonical = json.dumps(bindings, sort_keys=True)
        route = f"{loader.where} {path}"
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        key = (real, digest)
        if key in seen:
            previous, previous_route = seen[key]
            if previous != canonical:
                loader.error(
                    path,
                    f"ruleset {name} is applied with different bindings here and at "
                    f"{previous_route}; apply it once, at the root, with the union",
                )
            continue  # the same application again: one document
        seen[key] = (canonical, route)
        shown = ", ".join(
            f"{k}={','.join(v) if isinstance(v, list) else v}" for k, v in sorted(bindings.items())
        )
        label = f"{name} ({shown})" if shown else name
        instantiated = _instantiate(sub, rtop, params, bindings)
        out.append(_Document(instantiated, label, label, True))
        _apply_all(_Loader(label, loader.errors), instantiated, (*chain, real), seen, out)


# ---------------------------------------------------------------------------
# the per-document parsers
# ---------------------------------------------------------------------------


def _declare_regions(
    loader: _Loader, documents: Sequence[_Document]
) -> tuple[list[Region], dict[RegionId, Medium]]:
    """``[regions]`` across the composition (EFFECTS.md): the state vocabulary. Two files
    declaring the same name mean the same region -- the vocabulary is the shared thing -- so
    identical declarations merge and differing ones are an error. A footprint is relative (to
    the cwd of the check whose atom depends on the region) or absolute; a ruleset's footprints
    are relative only, like its other locations."""
    out: dict[RegionId, Region] = {}
    declared_by: dict[RegionId, str] = {}
    for doc in documents:
        dl = _Loader(doc.label, loader.errors)
        table = doc.top.get("regions", {})
        if not isinstance(table, dict):
            dl.error("regions", "expected a table")
            continue
        for name, spec_data in table.items():
            path = f"regions.{name}"
            spec = dl.table(path, spec_data, _REGION_KEYS)
            is_network = dl.field(path, spec, "network", bool) or False
            about = dl.field(path, spec, "about", str) or ""
            footprint = _location_list(dl, path, spec, "footprint") if "footprint" in spec else None
            if "footprint" in spec and not footprint:
                continue  # malformed or empty: reported by _location_list
            if doc.restricted and footprint and any(loc.absolute for loc in footprint):
                dl.error(f"{path}.footprint", "a ruleset names no absolute locations")
                continue
            try:
                r = region(name, footprint=footprint, network=is_network, about=about)
            except ValueError as e:
                dl.error(path, str(e))
                continue
            previous = out.get(r.name)
            if previous is None:
                out[r.name] = r
                declared_by[r.name] = doc.label
            elif (previous.medium, previous.footprint) != (r.medium, r.footprint):
                dl.error(
                    path,
                    f"region {name!r} is declared differently by {declared_by[r.name]}; one name, one region",
                )
    return list(out.values()), {r.name: r.medium for r in out.values()}


def _declare_atoms(
    loader: _Loader, documents: Sequence[_Document], regions: Mapping[RegionId, Medium]
) -> tuple[list[AtomDef], frozenset[AtomId], frozenset[AtomId], dict[str, list[str]]]:
    """``[atoms]`` across the composition: defined atoms, pure names, all declared names, and
    what each environmental atom depends on (``reads``, by atom name, as spelled). A name is
    declared once, whatever file declares it; two files declaring the same name is an error even
    when the definitions agree (namespace by convention: ``unix.no-arg``)."""
    atom_defs: list[AtomDef] = []
    pure_names: set[AtomId] = set()
    declared_by: dict[AtomId, str] = {}
    reads_map: dict[str, list[str]] = {}
    for doc in documents:
        dl = _Loader(doc.label, loader.errors)
        atoms_table = doc.top.get("atoms", {})
        if not isinstance(atoms_table, dict):
            dl.error("atoms", "expected a table")
            continue
        for name, spec_data in atoms_table.items():
            path = f"atoms.{name}"
            aid = AtomId(name)
            if aid == NOT_OPTION:
                dl.error(path, f"atom {name!r} is built in (the value does not begin with '-') and cannot be declared")
                continue
            if aid in declared_by:
                dl.error(path, f"atom {name!r} is also declared by {declared_by[aid]}; atom names are unique")
                continue
            declared_by[aid] = doc.label
            spec = dl.table(path, spec_data, _ATOM_KEYS)
            meaning = dl.field(path, spec, "matches", str)
            pure_flag = dl.field(path, spec, "pure", bool)
            depends = dl.region_names(path, spec, "reads", regions)
            if meaning is not None:
                if pure_flag is False:
                    dl.error(path, "a defined atom is pure by construction")
                try:
                    re.compile(meaning)
                except re.error as e:
                    dl.error(f"{path}.matches", f"bad regex: {e}")
                    continue
                atom_defs.append(atom(name, markers.matches(meaning)))
                pure_names.add(aid)
            elif pure_flag:
                pure_names.add(aid)
            if "reads" in spec:
                if aid in pure_names:
                    dl.error(f"{path}.reads", "a pure atom depends on no state; reads applies to environmental atoms")
                elif depends is not None and not depends:
                    dl.error(f"{path}.reads", "an atom that depends on nothing is pure; say pure = true")
                elif depends is not None:
                    reads_map[name] = depends
    return atom_defs, frozenset(pure_names), frozenset(declared_by), reads_map


def _media_keys(
    loader: _Loader, path: str, t: dict[str, Any], regions: Mapping[RegionId, Medium]
) -> tuple[bool, bool | None, bool | None, list[str] | None]:
    """A grant's ``effect-free``, ``network``, ``write`` and ``writes`` (EFFECTS.md)."""
    return (
        loader.field(path, t, "effect-free", bool) or False,
        loader.field(path, t, "network", bool),
        loader.field(path, t, "write", bool),
        loader.region_names(path, t, "writes", regions),
    )


def _flagsets(
    loader: _Loader, top: dict[str, Any], declared: frozenset[AtomId]
) -> dict[FlagsetId, Flagset]:
    """``[[flagset]]``: private to the document that declares them."""
    flagsets: dict[FlagsetId, Flagset] = {}
    for i, entry in enumerate(loader.entries("flagset", top)):
        path = f"flagset[{i}]"
        t = _open_table(loader, path, entry, _FLAGSET_KEYS)
        if t is None:
            continue
        fname = loader.required_str(path, t, "name")
        fs = _flag_vocabulary(loader, path, t, declared, _FLAGSET_KEYS)
        if fname is None or fs is None:
            continue
        fid = FlagsetId(fname)
        if fid in flagsets:
            loader.error(path, f"flagset {fname!r} is declared twice")
            continue
        flagsets[fid] = fs
    return flagsets


def _validations(
    loader: _Loader,
    top: dict[str, Any],
    declared: frozenset[AtomId],
    pure_names: frozenset[AtomId],
    restricted: bool,
    regions: Mapping[RegionId, Medium],
) -> list[Validation]:
    validations: list[Validation] = []
    for i, entry in enumerate(loader.entries("validation", top)):
        path = f"validation[{i}]"
        t = loader.table(path, entry, _VALIDATION_KEYS)
        name = loader.required_str(path, t, "name")
        params = loader.str_list(path, t, "params")
        if "argv" not in t:
            loader.error(path, "argv is required")
        raw_argv = loader.str_list(path, t, "argv")
        if restricted and raw_argv and not (
            raw_argv[0].startswith(_CHECKERS_VAR + "/") or raw_argv[0] in RULESET_STOCK_CHECKERS
        ):
            loader.error(
                f"{path}.argv[0]",
                f"a ruleset's validation runs {_CHECKERS_VAR}/<name> or one of "
                f"{', '.join(sorted(RULESET_STOCK_CHECKERS))}, not {raw_argv[0]!r}",
            )
        argv: list[str | Param] = []
        for j, piece in enumerate(raw_argv):
            if _CHECKERS_VAR in piece:
                resolved = _resolve_checker(loader, f"{path}.argv[{j}]", piece, j)
                if resolved is not None:
                    argv.append(resolved)
                continue
            try:
                argv.append(_parse_argv_piece(piece))
            except ValueError as e:
                loader.error(f"{path}.argv", str(e))
        # cwd is optional: omitted, the check does not care where it runs, and certora.check
        # may be called without cwd=
        cwd_given = "cwd" in t
        cwd = loader.location_slot(path, t, "cwd") if cwd_given else None
        effect_free, net_flag, write_flag, writes = _media_keys(loader, path, t, regions)
        est_table = loader.table(
            f"{path}.establishes", t.get("establishes", {}), frozenset(params) | {"cwd"}
        )
        establishes = {
            key: [
                pure(a) if a in pure_names else a
                for a in loader.atom_names(f"{path}.establishes", est_table, key, declared)
            ]
            for key in est_table.keys() & (frozenset(params) | {"cwd"})
        }
        if name is None or (cwd_given and cwd is None) or not argv or len(argv) != len(raw_argv):
            continue
        try:
            validations.append(
                validation(
                    name, argv=argv, cwd=cwd, params=params,
                    establishes=establishes, effect_free=effect_free,
                    network=net_flag, write=write_flag, writes=writes,
                )
            )
        except ValueError as e:
            loader.error(path, str(e))
    return validations


def _programs(
    loader: _Loader,
    top: dict[str, Any],
    declared: frozenset[AtomId],
    pure_names: frozenset[AtomId],
    flagsets: Mapping[FlagsetId, Flagset],
    origin: str | None,
    regions: Mapping[RegionId, Medium],
) -> list[Program]:
    programs: list[Program] = []
    for i, entry in enumerate(loader.entries("program", top)):
        path = f"program[{i}]"
        if isinstance(entry, dict):
            for k in sorted(_RETIRED_PROGRAM_KEYS & entry.keys()):
                loader.error(
                    path,
                    f"{k!r} is no longer a rule key: a rule is its words alone, or a template "
                    "(argv + holes) whose holes say what each argument is (a location, a regex, "
                    "atoms, or any = true)",
                )
            entry = {k: v for k, v in entry.items() if k not in _RETIRED_PROGRAM_KEYS}
        t = loader.table(path, entry, _PROGRAM_KEYS)
        name = loader.required_str(path, t, "name")
        cwd = loader.location_slot(path, t, "cwd")
        yields = _source_atom(loader, path, t, "source", declared, pure_names)
        effect_free, net_flag, write_flag, writes = _media_keys(loader, path, t, regions)
        if "argv" in t:
            # a templated form (TEMPLATES.md): the shape is argv + holes; its leading words are
            # the argv's literal head, so a subcommand has no place on it
            legacy = "subcommand" in t
            if legacy:
                loader.error(path, "a templated rule carries no subcommand; its leading words are the argv's literal head")
            pieces = _pieces(loader, path, loader.str_list(path, t, "argv"))
            holes_table = t.get("holes", {})
            if not isinstance(holes_table, dict):
                loader.error(f"{path}.holes", "expected a table of holes")
                holes_table = {}
            holes: dict[str, Hole] = {}
            ok = pieces is not None and not legacy
            for hname, spec in holes_table.items():
                hpath = f"{path}.holes.{hname}"
                sub = _open_table(loader, hpath, spec, _HOLE_KEYS)
                if sub is None:
                    ok = False
                    continue
                h = _hole(loader, hpath, sub, flagsets, declared)
                if h is None:
                    ok = False
                else:
                    holes[hname] = h
            if not ok or name is None or cwd is None or pieces is None:
                continue
            try:
                programs.append(
                    program(
                        name,
                        cwd=cwd,
                        requires=loader.atom_names(path, t, "requires", declared),
                        argv=pieces,
                        holes=holes,
                        origin=origin,
                        source=yields,
                        effect_free=effect_free,
                        network=net_flag,
                        write=write_flag,
                        writes=writes,
                    )
                )
            except ValueError as e:
                loader.error(path, str(e))
            continue
        if "holes" in t:
            loader.error(path, "holes need an argv template")
            continue
        if name is None or cwd is None:
            continue
        try:
            programs.append(
                program(
                    name,
                    cwd=cwd,
                    subcommand=loader.field(path, t, "subcommand", str) or (),
                    requires=loader.atom_names(path, t, "requires", declared),
                    origin=origin,
                    source=yields,
                    effect_free=effect_free,
                    network=net_flag,
                    write=write_flag,
                    writes=writes,
                )
            )
        except ValueError as e:
            loader.error(path, str(e))
    return programs


def from_data(data: object, where: str = "<policy>") -> Policy:
    """The Policy a parsed document (TOML or JSON, as a dict) declares, with every ruleset it
    applies; raises ``PolicyFileError`` with every problem found in every file. This is also the
    entry point for machine-synthesized policies, which need never touch a file."""
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

    # pass 1: the composition -- the root and every ruleset it applies, instantiated
    documents = [_Document(top, where, None, False)]
    _apply_all(loader, top, (), {}, documents)
    # pass 2: regions, then atoms, across the composition, so any document may reference any
    # other's
    region_list, regions = _declare_regions(loader, documents)
    atom_defs, pure_names, declared, reads_map = _declare_atoms(loader, documents, regions)
    # pass 3: each document's vocabulary; flagsets stay private to their document
    validations: list[Validation] = []
    programs: list[Program] = []
    sources: list[Source] = []
    for doc in documents:
        dl = loader if doc.origin is None else _Loader(doc.label, loader.errors)
        flagsets = _flagsets(dl, doc.top, declared)
        validations += _validations(dl, doc.top, declared, pure_names, doc.restricted, regions)
        programs += _programs(dl, doc.top, declared, pure_names, flagsets, doc.origin, regions)
        sources += _sources(dl, doc.top, declared, pure_names)

    net_rules: list[NetworkRule] = []
    for i, entry in enumerate(loader.entries("network", top)):
        path = f"network[{i}]"
        t = loader.table(path, entry, _NETWORK_KEYS)
        host = loader.required_str(path, t, "host")
        paths = _location_list(loader, path, t, "path")
        if host is None or paths is None:
            continue
        try:
            net_rules.append(
                network(
                    host,
                    path=paths,
                    schemes=loader.str_list(path, t, "schemes") or ("https",),
                    ports=loader.int_list(path, t, "ports"),
                    methods=loader.str_list(path, t, "methods"),
                    allow_nonpublic=loader.field(path, t, "allow-nonpublic", bool) or False,
                    requires=loader.required_atoms(path, t, "requires", declared),
                    read_timeout=loader.number(path, t, "read-timeout"),
                    total_timeout=loader.number(path, t, "total-timeout"),
                    max_response_bytes=loader.field(path, t, "max-response-bytes", int),
                    source=_source_atom(loader, path, t, "source", declared, pure_names),
                    writes=loader.region_names(path, t, "writes", regions),
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
            network=net_rules, sources=sources, regions=region_list, reads=reads_map,
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
