"""The policy loader: from a TOML/JSON document to a ``Policy``.

The format itself -- which sections exist, which keys each table takes, the local invariants --
is ``schema``, a pydantic schema that decides the *shape* of a document and stops there.
Everything that needs to look at more than one table -- or outside the document -- is here, as
a short sequence of passes over typed values, each doing one thing:

1. **Composition** (``_compose``): the root and every ruleset it ``[[apply]]``-es, depth-first.
   A ruleset is parsed, its parameters bound from the application, ``when`` resolved, the
   parameters substituted (``_Instantiator``), and the result read like any other document. An
   application is identified by (file, hash, bindings): reached twice identically it is one
   document, differently an error.
2. **Declarations** (``_declare``): regions merge across documents (one name, one region);
   atoms are declared once across the composition and given their kind -- a ``SourceId`` where
   some rule yields the name, a ``CheckId`` otherwise -- beside the built-ins nothing declares.
3. **Rules** (``_rules``): each document's flagsets (private to it), validations (a ruleset's
   restricted to ``${checkers}/<name>`` and the stock predicates), programs and sources, each
   name resolved through the declaration table, each checker resolved against the config
   directory, each built with the ``policy`` constructors.
4. ``Policy.allow`` does the cross-rule checks it always did.

Errors are collected, not raised: every problem in every document, each as ``<document>:
<path>: <what>``, and no ``Policy`` is built if there is one. Substitution happens on typed
values -- a location spelling, an atom list, a hole -- never on raw tables, so a parser never
meets ``${…}`` it did not expect.
"""
import hashlib
import json
import os
import pathlib
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, overload

from . import markers
from .analysis import Exact, RegexLit, StaticPath, alternation
from .docpath import DocPath, Keyed, Path
from .ids import BUILTIN_ATOMS, Atom, CheckId, FlagName, FlagsetId, HoleName, ParamName, SourceId
from .locations import parse_location
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
    source,
    validation,
)
from .policydir import config_dir
from .schema import (
    ApplyDecl,
    AtomDecl,
    ConstraintFields,
    EachHole,
    FlagEntry,
    FlagsetDecl,
    FlagsetRef,
    FlagsHole,
    FlagVocabulary,
    FootprintRegion,
    HoleSpec,
    NetworkRegion,
    ParamKind,
    PolicyDoc,
    ProgramDecl,
    RulesetDoc,
    SchemaError,
    SourceDecl,
    TokenHole,
    ValidationDecl,
    hole_reference,
    parse_hole,
    parse_policy,
    parse_ruleset,
    reference,
)
from .templates import Constraint, Demands, Each, Flags, Flagset, Hole, HoleRef, Piece, Token

# the location micro-syntax lives in ``locspec`` and ``locations``; ``parse_location`` is
# re-exported here for its callers
__all__ = ["PolicyFileError", "from_data", "load_policy_file", "parse_location", "rulesets_dir"]


class PolicyFileError(Exception):
    """The policy document does not conform; every problem found, one per line."""


# stock, config-free, non-spawning predicates a ruleset's validation may run besides
# ${checkers}/<name>: the whole executable surface a shared file can reach
RULESET_STOCK_CHECKERS: frozenset[str] = frozenset({"test"})
_CHECKERS = "${checkers}"
_CWD = "cwd"


def rulesets_dir() -> pathlib.Path:
    return config_dir() / "rulesets"

# ---------------------------------------------------------------------------
# errors: collected, located
# ---------------------------------------------------------------------------


class _Errors:
    """Every problem of a composition, in order found. One list shared by every pass."""

    def __init__(self) -> None:
        self.lines: list[str] = []

    def add(self, where: str, path: DocPath, what: str) -> None:
        self.lines.append(f"{where}: {path}: {what}" if path else f"{where}: {what}")

    def schema(self, e: SchemaError) -> None:
        self.lines.extend(f"{e.where}: {p}" for p in e.problems)

    def raise_if_any(self) -> None:
        if self.lines:
            raise PolicyFileError("\n".join(self.lines))


# ---------------------------------------------------------------------------
# 1. composition: rulesets, bindings, when, substitution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Dirs:
    """A directory parameter's binding: one or more plain directories (any-of)."""

    paths: tuple[str, ...]


@dataclass(frozen=True)
class Atoms:
    """An atom-list parameter's binding: names spliced where the list stands; may be empty."""

    names: tuple[str, ...]


@dataclass(frozen=True)
class Toggle:
    """A bool parameter's binding; unbound is ``False``."""

    value: bool


@dataclass(frozen=True)
class Shape:
    """A constraint parameter's binding: the token hole its table spells, checked where the
    root wrote it."""

    hole: TokenHole


type Bound = Dirs | Atoms | Toggle | Shape


def _bind(
    apply: ApplyDecl, ruleset: RulesetDoc, where: str, path: Path, errors: _Errors
) -> dict[str, Bound] | None:
    """The application's bindings, typed by the parameter kinds the ruleset declares. A
    parameter left unbound is absent (a bool is ``Toggle(False)``); whether that is an error
    depends on whether anything surviving ``when`` still references it."""
    out: dict[str, Bound] = {}
    ok = True
    for name, raw in apply.bindings.items():
        decl = ruleset.params.get(name)
        at = path.key(name)  # a binding is a key of the [[apply]] table itself
        if decl is None:
            errors.add(where, path, f"{name!r} is not a parameter of the ruleset")
            ok = False
            continue
        match decl.kind, raw:
            case "directory", str() | list() if all(isinstance(t, str) for t in ([raw] if isinstance(raw, str) else raw)):
                texts: list[str] = [raw] if isinstance(raw, str) else list(raw)
                if not texts:
                    errors.add(where, at, "expected a directory or a non-empty list of them")
                    ok = False
                    continue
                for text in texts:
                    try:
                        loc = parse_location(text)
                    except ValueError as e:
                        errors.add(where, at, str(e))
                        ok = False
                        continue
                    if not isinstance(loc, StaticPath):
                        errors.add(where, at, f"{text!r} is not a directory (no '**' or regex components)")
                        ok = False
                out[name] = Dirs(tuple(texts))
            case "atom", str() | list() if all(isinstance(t, str) for t in ([raw] if isinstance(raw, str) else raw)):
                out[name] = Atoms((raw,) if isinstance(raw, str) else tuple(raw))
            case "bool", bool():
                out[name] = Toggle(raw)
            case "constraint", dict():
                try:
                    out[name] = Shape(parse_hole(raw, where))
                except SchemaError as e:
                    for problem in e.problems:
                        errors.add(where, at, problem)
                    ok = False
            case kind, _:
                expected = {
                    "directory": "a directory or a non-empty list of them",
                    "atom": "an atom name or a list of them",
                    "bool": "true or false",
                    "constraint": "a constraint table ({ atoms = [...] }, { any = true }, ...)",
                }[kind]
                errors.add(where, at, f"expected {expected}")
                ok = False
    for name, decl in ruleset.params.items():
        if decl.kind == "bool" and name not in out:
            out[name] = Toggle(False)  # canonical: an application with an unbound bool is the false one
    return out if ok else None


def _show(b: Bound) -> str:
    match b:
        case Dirs(paths=ps) | Atoms(names=ps):
            return ",".join(ps) if ps else "[]"
        case Toggle(value=v):
            return "true" if v else "false"
        case Shape(hole=h):
            return json.dumps(_table_of(h), sort_keys=True, separators=(",", ":"))


def _table_of(hole: TokenHole) -> dict[str, Any]:
    """The constraint table as the root spelled it, for labels and for passing down."""
    return hole.model_dump(by_alias=True, exclude_defaults=True, exclude={"kind"})


def _canonical(bindings: Mapping[str, Bound]) -> str:
    return json.dumps({k: _show(v) for k, v in sorted(bindings.items())})


class _Instantiator:
    """Substitutes one ruleset's parameters into its typed tables. Every method takes a typed
    value and returns one of the same type with references resolved; a reference to an unbound
    or wrong-kind parameter is reported at *path* and the value is returned as it was (the load
    fails anyway). ``when`` is resolved first, so a parameter referenced only from dropped
    pieces needs no binding. With no parameters (the root document) only literal ``when``s are
    admissible."""

    def __init__(self, ruleset: RulesetDoc | None, bindings: Mapping[str, Bound], where: str, errors: _Errors) -> None:
        self.params = {} if ruleset is None else ruleset.params
        self.restricted = ruleset is not None
        self.bindings = bindings
        self.where = where
        self.errors = errors

    # -- references --------------------------------------------------------------------------

    @overload
    def _bound(self, name: str, kind: Literal["directory"], path: DocPath) -> Dirs | None: ...
    @overload
    def _bound(self, name: str, kind: Literal["atom"], path: DocPath) -> Atoms | None: ...
    @overload
    def _bound(self, name: str, kind: Literal["bool"], path: DocPath) -> Toggle | None: ...
    @overload
    def _bound(self, name: str, kind: Literal["constraint"], path: DocPath) -> Shape | None: ...

    def _bound(self, name: str, kind: ParamKind, path: DocPath) -> Bound | None:
        """The binding of *name*, which must be a *kind* parameter; None (reported) otherwise.
        The kind fixes the binding's type: ``_bind`` built the table that way."""
        decl = self.params.get(name)
        if decl is None:
            self.errors.add(self.where, path, f"{name!r} is not a parameter of this ruleset")
            return None
        if decl.kind != kind:
            self.errors.add(self.where, path, f"{name!r} is not a {kind} parameter")
            return None
        b = self.bindings.get(name)
        if b is None:
            self.errors.add(self.where, path, f"parameter {name!r} is not bound")
        return b

    def when(self, value: bool | str | None, path: Path) -> bool:
        """Is the piece enabled? Absent: yes."""
        if value is None or isinstance(value, bool):
            return value is not False
        name = reference(value)
        assert name is not None  # the schema admitted only a reference
        b = self._bound(name, "bool", path.when)
        return b is not None and b.value

    def locations(self, slot: list[str], path: DocPath) -> list[str]:
        """A location slot: a directory parameter at the head maps over its directories. A
        ruleset spells no absolute location of its own; those enter through the root's bindings."""
        out: list[str] = []
        for text in slot:
            ref, rest = _split_head(text)
            if ref is None:
                if self.restricted and text.startswith("/"):
                    self.errors.add(self.where, path, f"a ruleset names no absolute locations: {text!r}")
                out.append(text)
                continue
            b = self._bound(ref, "directory", path)
            if b is None:
                out.append(text)
            else:
                out.extend(_join_dir(base, rest) for base in b.paths)
        return out

    def atoms(self, names: Sequence[str], path: DocPath) -> list[str]:
        """An atom list: an atom parameter is spliced where it stands."""
        out: list[str] = []
        for text in names:
            name = reference(text)
            if name is None:
                out.append(text)
                continue
            b = self._bound(name, "atom", path)
            out.extend([text] if b is None else b.names)
        return out

    # -- tables ------------------------------------------------------------------------------

    def constraint[C: ConstraintFields](self, c: C, path: Path) -> C:
        update: dict[str, Any] = {}
        if c.location is not None:
            update["location"] = self.locations(c.location, path.location)
        if c.atoms is not None:
            update["atoms"] = self.atoms(c.atoms, path.atoms)
        return c.model_copy(update=update) if update else c

    def demands(self, d: Mapping[str, list[str]], path: Keyed) -> dict[str, list[str]]:
        return {k: self.atoms(v, path[k]) for k, v in d.items()}

    def entry(self, e: FlagEntry, path: Path) -> FlagEntry:
        """A surviving flag entry: its constraint and demands substituted, its ``when`` --
        already decided by the caller -- cleared, so the instantiated document carries no
        reference that is not resolved."""
        e = self.constraint(e, path)
        update: dict[str, Any] = {"when": None}
        if e.requires is not None:
            update["requires"] = self.demands(e.requires, path.requires)
        return e.model_copy(update=update)

    def vocabulary[V: FlagVocabulary](self, v: V, path: Path) -> V:
        # a flag entry is a key of the vocabulary's own table in the document ("-k" = {...})
        flags = {
            name: self.entry(e, path.key(name))
            for name, e in v.flags.items()
            if self.when(e.when, path.key(name))
        }
        return v.model_copy(update={"flags": flags})

    def hole(self, spec: HoleSpec, path: Path) -> HoleSpec:
        """A hole with its parameters substituted; a hole that *is* a constraint parameter
        becomes the token hole the root bound."""
        match spec:
            case str():
                name = reference(spec)
                assert name is not None  # the schema admitted only a reference
                b = self._bound(name, "constraint", path)
                return spec if b is None else b.hole
            case TokenHole() | EachHole():
                return self.constraint(spec, path)
            case FlagsHole():
                return self.vocabulary(spec, path)
            case FlagsetRef():
                return spec

    def program(self, p: ProgramDecl, path: Path) -> ProgramDecl:
        update: dict[str, Any] = {"when": None, "cwd": self.locations(p.cwd, path.cwd)}
        if p.holes is not None:
            update["holes"] = {h: self.hole(spec, path.holes[h]) for h, spec in p.holes.items()}
        if isinstance(p.requires, dict):
            update["requires"] = self.demands(p.requires, path.requires)
        elif p.requires is not None:
            update["requires"] = self.atoms(p.requires, path.requires)
        return p.model_copy(update=update)

    def validation(self, v: ValidationDecl, path: Path) -> ValidationDecl:
        update: dict[str, Any] = {
            "establishes": {k: self.atoms(a, path.establishes[k]) for k, a in v.establishes.items()}
        }
        if v.cwd is not None:
            update["cwd"] = self.locations(v.cwd, path.cwd)
        return v.model_copy(update=update)

    def flagset(self, f: FlagsetDecl, path: Path) -> FlagsetDecl:
        return self.vocabulary(f, path)

    def source(self, s: SourceDecl, path: Path) -> SourceDecl:
        return s.model_copy(update={"location": self.locations(s.location, path.location)})

    def apply(self, a: ApplyDecl, path: Path) -> ApplyDecl:
        """A nested application: bindings may pass this ruleset's parameters down whole; an
        unbound one is left unbound below, for the applied ruleset to judge."""
        bindings: dict[str, Any] = {}
        for k, v in a.bindings.items():
            name = reference(v) if isinstance(v, str) else None
            if name is None:
                if isinstance(v, str) and "${" in v:
                    self.errors.add(self.where, path.key(k), f"a parameter is passed down whole: {v!r}")
                bindings[k] = v
                continue
            if name not in self.params:
                self.errors.add(self.where, path.key(k), f"{name!r} is not a parameter of this ruleset")
                bindings[k] = v
                continue
            b = self.bindings.get(name)
            match b:
                case None:
                    continue
                case Dirs(paths=ps) | Atoms(names=ps):
                    bindings[k] = list(ps)
                case Toggle(value=t):
                    bindings[k] = t
                case Shape(hole=h):
                    bindings[k] = _table_of(h)
        return a.model_copy(update={"bindings": bindings, "when": None})

    def document[D: PolicyDoc | RulesetDoc](self, doc: D) -> D:
        """The whole document with ``when`` resolved and parameters substituted."""
        root = Path()
        programs = [
            self.program(p, root.program(i)) for i, p in enumerate(doc.program) if self.when(p.when, root.program(i))
        ]
        applies = [
            self.apply(a, root.apply(i)) for i, a in enumerate(doc.apply) if self.when(a.when, root.apply(i))
        ]
        return doc.model_copy(update={
            "program": programs,
            "apply": applies,
            "flagset": [self.flagset(f, root.flagset(i)) for i, f in enumerate(doc.flagset)],
            "validation": [self.validation(v, root.validation(i)) for i, v in enumerate(doc.validation)],
            "source": [self.source(s, root.source(i)) for i, s in enumerate(doc.source)],
        })


def _split_head(text: str) -> tuple[str | None, str | None]:
    """``${where}/rest`` -> (``where``, ``rest``); ``${where}`` -> (``where``, None); a spelling
    with no parameter head -> (None, None). The schema admitted nothing else."""
    if not text.startswith("${"):
        return None, None
    end = text.index("}")
    return text[2:end], text[end + 2 :] if len(text) > end + 1 else None


def _join_dir(base: str, rest: str | None) -> str:
    if rest is None:
        return base
    if base in (".", ""):
        return rest
    return base.rstrip("/") + "/" + rest if base.rstrip("/") else "/" + rest


@dataclass(frozen=True)
class _Document:
    """One document of a composition: the root policy, or one instantiated ruleset."""

    body: PolicyDoc | RulesetDoc
    label: str            # how messages name it: "unix.toml (where=repos,/srv/data)"
    origin: str | None    # provenance on the rules it contributes; None for the root

    @property
    def restricted(self) -> bool:
        return isinstance(self.body, RulesetDoc)


def _compose(root: PolicyDoc, where: str, errors: _Errors) -> list[_Document]:
    """The root (its literal ``when``s resolved) and every ruleset it applies, instantiated."""
    top = _Instantiator(None, {}, where, errors).document(root)
    out = [_Document(top, where, None)]
    _apply_all(top, where, (), {}, out, errors)
    return out


def _apply_all(
    doc: PolicyDoc | RulesetDoc,
    where: str,
    chain: tuple[str, ...],
    seen: dict[tuple[str, str], tuple[str, str]],
    out: list[_Document],
    errors: _Errors,
) -> None:
    for i, entry in enumerate(doc.apply):
        path = Path().apply(i)
        file = rulesets_dir() / entry.ruleset
        try:
            text = file.read_text(encoding="utf-8")
            real = str(file.resolve())
        except OSError as e:
            errors.add(where, path.ruleset, f"cannot read ruleset {entry.ruleset}: {e}")
            continue
        if real in chain:
            errors.add(where, path.ruleset, f"ruleset {entry.ruleset} applies itself (via {' -> '.join(chain)})")
            continue
        try:
            ruleset = parse_ruleset(tomllib.loads(text), entry.ruleset)
        except tomllib.TOMLDecodeError as e:
            errors.add(where, path.ruleset, f"{entry.ruleset}: {e}")
            continue
        except SchemaError as e:
            errors.schema(e)
            continue
        bindings = _bind(entry, ruleset, where, path, errors)
        if bindings is None:
            continue
        canonical = _canonical(bindings)
        key = (real, hashlib.sha256(text.encode("utf-8")).hexdigest())
        if key in seen:
            previous, previous_route = seen[key]
            if previous != canonical:
                errors.add(
                    where, path,
                    f"ruleset {entry.ruleset} is applied with different bindings here and at "
                    f"{previous_route}; apply it once, at the root, with the union",
                )
            continue  # the same application again: one document
        seen[key] = (canonical, f"{where} {path}")
        shown = ", ".join(f"{k}={_show(v)}" for k, v in sorted(bindings.items()))
        label = f"{entry.ruleset} ({shown})" if shown else entry.ruleset
        instantiated = _Instantiator(ruleset, bindings, label, errors).document(ruleset)
        out.append(_Document(instantiated, label, label))
        _apply_all(instantiated, label, (*chain, real), seen, out, errors)


# ---------------------------------------------------------------------------
# 2. declarations: regions and atoms across the composition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Declared:
    """The composition's vocabulary of names."""

    regions: tuple[Region, ...]
    atoms: Mapping[str, Atom]        # every nameable atom by spelling: built-ins, and each declared name as its kind
    defined: tuple[AtomDef, ...]
    pure: frozenset[str]
    reads: Mapping[str, list[str]]   # environmental atom -> the regions it reads, as spelled

    def atom(self, name: str, where: str, path: DocPath, errors: _Errors) -> Atom | None:
        a = self.atoms.get(name)
        if a is None:
            errors.add(where, path, f"atom {name!r} is not declared in [atoms]")
        return a

    def atom_list(self, names: Sequence[str], where: str, path: DocPath, errors: _Errors) -> list[Atom]:
        out = [self.atom(n, where, path, errors) for n in names]
        return [a for a in out if a is not None]

    def source_atom(self, name: str | None, where: str, path: DocPath, errors: _Errors) -> SourceId | None:
        """The source atom a rule's ``source`` (or a ``[[source]]``'s ``name``) names: declared,
        a source by the composition's own rules, and pure."""
        if name is None:
            return None
        a = self.atom(name, where, path, errors)
        if a is None:
            return None
        if not isinstance(a, SourceId):
            errors.add(where, path, f"a source atom is a declared atom, not the built-in {name!r}")
            return None
        if name not in self.pure:
            errors.add(where, path, f"a source atom is pure: declare {name!r} with pure = true")
            return None
        return a


def _source_names(documents: Sequence[_Document]) -> frozenset[str]:
    """Every atom name some rule yields as a source: what makes a declared name a source."""
    names: set[str] = set()
    for d in documents:
        names.update(p.source for p in d.body.program if p.source is not None)
        names.update(s.name for s in d.body.source)
        if isinstance(d.body, PolicyDoc):
            names.update(r.source for r in d.body.network if r.source is not None)
    return frozenset(names)


def _declare(documents: Sequence[_Document], errors: _Errors) -> _Declared:
    regions: dict[str, Region] = {}
    declared_by: dict[str, str] = {}
    for d in documents:
        for name, spec in d.body.regions.items():
            path = Path().regions[name]
            match spec:
                case FootprintRegion(footprint=slot, about=about):
                    if d.restricted and any(s.startswith("/") for s in slot):
                        errors.add(d.label, path.footprint, "a ruleset names no absolute locations")
                        continue
                    r = region(name, footprint=[parse_location(s) for s in slot], about=about)
                case NetworkRegion(about=about):
                    r = region(name, network=True, about=about)
            previous = regions.get(name)
            if previous is None:
                regions[name] = r
                declared_by[name] = d.label
            elif (previous.medium, previous.footprint) != (r.medium, r.footprint):
                errors.add(d.label, path, f"region {name!r} is declared differently by {declared_by[name]}; one name, one region")
    sources = _source_names(documents)
    atoms: dict[str, Atom] = dict(BUILTIN_ATOMS)
    pure_names: set[str] = set(BUILTIN_ATOMS)
    defined: list[AtomDef] = []
    reads: dict[str, list[str]] = {}
    atom_by: dict[str, str] = {}
    for d in documents:
        for name, spec in d.body.atoms.items():
            path = Path().atoms[name]
            if name in atom_by:
                errors.add(d.label, path, f"atom {name!r} is also declared by {atom_by[name]}; atom names are unique")
                continue
            atom_by[name] = d.label
            atoms[name] = SourceId(name) if name in sources else CheckId(name)
            if spec.matches is not None:
                defined.append(atom(name, markers.matches(spec.matches)))
                pure_names.add(name)
            elif spec.pure:
                pure_names.add(name)
            if spec.reads is not None:
                # whether each name is a declared region (or a medium word) is Policy.allow's
                # check, as for every `writes`: one rule, one place
                reads[name] = list(spec.reads)
    return _Declared(tuple(regions.values()), atoms, tuple(defined), frozenset(pure_names), reads)


# ---------------------------------------------------------------------------
# 3. rules: each document's vocabulary, built with the policy constructors
# ---------------------------------------------------------------------------


def _resolve_checker(piece: str, where: str, path: DocPath, errors: _Errors) -> str | None:
    """``${checkers}/<name>``: the executable in the config directory's ``checkers/``, which
    must exist and be executable, so a policy naming a missing checker fails here."""
    prefix = _CHECKERS + "/"
    if not piece.startswith(prefix) or len(piece) == len(prefix):
        errors.add(where, path, f"{_CHECKERS} may only head argv[0], as {_CHECKERS}/<name>")
        return None
    rel = pathlib.PurePosixPath(piece[len(prefix):])
    if rel.is_absolute() or ".." in rel.parts:
        errors.add(where, path, f"the checker name must be a relative path without '..': {piece!r}")
        return None
    checkers = config_dir() / "checkers"
    resolved = checkers / rel
    if not (resolved.is_file() and os.access(resolved, os.X_OK)):
        errors.add(where, path, f"checker {rel} is not installed (executable) in {checkers}")
        return None
    return str(resolved)


def _slot(slot: list[str]) -> list[Any]:
    return [parse_location(s) for s in slot]


class _Rules:
    """One document's rules, resolved against the composition's declarations."""

    def __init__(self, doc: _Document, declared: _Declared, errors: _Errors) -> None:
        self.doc = doc
        self.where = doc.label
        self.declared = declared
        self.errors = errors
        self.flagsets: dict[FlagsetId, Flagset] = {}

    def atoms(self, names: Sequence[str] | None, path: DocPath) -> list[Atom]:
        return [] if names is None else self.declared.atom_list(names, self.where, path, self.errors)

    def constraint(self, c: ConstraintFields, path: Path) -> Constraint | None:
        regex = None
        if c.matches is not None:
            regex = RegexLit(c.matches)
        elif c.one_of is not None:
            regex = alternation(*(Exact(n) for n in c.one_of))
        try:
            return Constraint(
                tuple(_slot(c.location)) if c.location is not None else (),
                regex,
                frozenset(self.atoms(c.atoms, path.atoms)),
                c.literal,
                c.any,
            )
        except ValueError as e:
            self.errors.add(self.where, path, str(e))
            return None

    def demands(self, d: Mapping[str, list[str]], path: Keyed) -> Demands:
        out: dict[str, frozenset[Atom]] = {}
        for target, names in d.items():
            atoms = self.atoms(names, path[target])
            if atoms:  # an empty list -- a ruleset's []-bound gate -- demands nothing
                out[target] = frozenset(atoms)
        return out

    def vocabulary(self, v: FlagVocabulary, path: Path, holes: Sequence[str] = ()) -> Flagset | None:
        if v.any:
            return Flagset(any=True)
        bare = set(v.bare or ())
        valued: dict[FlagName, Constraint] = {}
        requires: dict[FlagName, Demands] = {}
        ok = True
        for name, e in v.flags.items():
            at = path.key(name)  # "-k" = {...}: a key of the vocabulary's own table
            if e.requires is not None:
                requires[FlagName(name)] = self.demands(e.requires, at.requires)
            if e.value is False:
                bare.add(name)
                continue
            c = self.constraint(e, at)
            if c is None:
                ok = False
            else:
                valued[FlagName(name)] = c
        if not ok:
            return None
        try:
            return Flagset(
                frozenset(FlagName(b) for b in bare), valued, requires=requires,
                holes=frozenset(HoleName(h) for h in holes),
            )
        except ValueError as e:
            self.errors.add(self.where, path, str(e))
            return None

    def declare_flagsets(self) -> None:
        for i, f in enumerate(self.doc.body.flagset):
            fs = self.vocabulary(f, Path().flagset(i), f.holes or ())
            if fs is not None:
                self.flagsets[FlagsetId(f.name)] = fs

    def hole(self, spec: HoleSpec, path: Path) -> Hole | None:
        match spec:
            case str():
                self.errors.add(self.where, path, 'a hole is a table; a constraint parameter ("${name}") is substituted only inside a ruleset')
                return None
            case FlagsetRef(flagset=ref):
                fs = self.flagsets.get(FlagsetId(ref))
                if fs is None:
                    self.errors.add(self.where, path.key("flagset"), f"flagset {ref!r} is not declared")
                    return None
                return Flags(fs)
            case FlagsHole():
                fs = self.vocabulary(spec, path)
                return None if fs is None else Flags(fs)
            case EachHole(min=minimum):
                c = self.constraint(spec, path)
                return None if c is None else Each(c, minimum)
            case TokenHole():
                c = self.constraint(spec, path)
                return None if c is None else Token(c)

    def source_atom(self, name: str | None, path: DocPath) -> SourceId | None:
        return self.declared.source_atom(name, self.where, path, self.errors)

    def validations(self) -> list[Validation]:
        out: list[Validation] = []
        for i, v in enumerate(self.doc.body.validation):
            path = Path().validation(i)
            if self.doc.restricted and not (v.argv[0].startswith(_CHECKERS + "/") or v.argv[0] in RULESET_STOCK_CHECKERS):
                self.errors.add(
                    self.where, path.argv(0),
                    f"a ruleset's validation runs {_CHECKERS}/<name> or one of "
                    f"{', '.join(sorted(RULESET_STOCK_CHECKERS))}, not {v.argv[0]!r}",
                )
            argv: list[str | Param] = []
            for j, piece in enumerate(v.argv):
                if piece.startswith(_CHECKERS):
                    resolved = _resolve_checker(piece, self.where, path.argv(j), self.errors)
                    if resolved is not None:
                        argv.append(resolved)
                    continue
                # here ${p} names one of the validation's own params (the schema checked the
                # spelling; `validation()` checks the name is declared)
                name = reference(piece)
                argv.append(piece if name is None else Param(ParamName(name)))
            establishes = {
                key: [pure(a) if a in self.declared.pure else a for a in self.atoms(names, path.establishes[key])]
                for key, names in v.establishes.items()
            }
            if len(argv) != len(v.argv):
                continue
            try:
                out.append(validation(
                    v.name, argv=argv, cwd=None if v.cwd is None else _slot(v.cwd), params=v.params,
                    establishes=establishes, effect_free=v.effect_free, network=v.network, write=v.write,
                    writes=v.writes,
                ))
            except ValueError as e:
                self.errors.add(self.where, path, str(e))
        return out

    def programs(self) -> list[Program]:
        out: list[Program] = []
        for i, p in enumerate(self.doc.body.program):
            path = Path().program(i)
            yields = self.source_atom(p.source, path.key("source"))
            if isinstance(p.requires, dict):
                requires: list[Atom] | Demands = self.demands(p.requires, path.requires)
            else:
                requires = self.atoms(p.requires, path.requires)
            pieces: list[Piece] | None = None
            holes: dict[str, Hole] = {}
            if p.argv is not None:
                pieces = [_piece(w) for w in p.argv]
                ok = True
                for hname, spec in (p.holes or {}).items():
                    h = self.hole(spec, path.holes[hname])
                    if h is None:
                        ok = False
                    else:
                        holes[hname] = h
                if not ok:
                    continue
            try:
                out.append(program(
                    p.name, cwd=_slot(p.cwd), subcommand=p.subcommand or (), requires=requires,
                    argv=pieces, holes=holes if pieces is not None else None, origin=self.doc.origin,
                    source=yields, effect_free=p.effect_free, network=p.network, write=p.write, writes=p.writes,
                ))
            except ValueError as e:
                self.errors.add(self.where, path, str(e))
        return out

    def sources(self) -> list[Source]:
        out: list[Source] = []
        for i, s in enumerate(self.doc.body.source):
            name = self.source_atom(s.name, Path().source(i).name)
            if name is not None:
                out.append(source(name, _slot(s.location)))
        return out


def _piece(word: str) -> Piece:
    ref = hole_reference(word)
    return word if ref is None else HoleRef(HoleName(ref[0]), ref[1])


def _network(root: PolicyDoc, where: str, declared: _Declared, errors: _Errors) -> list[NetworkRule]:
    out: list[NetworkRule] = []
    for i, r in enumerate(root.network):
        path = Path().network(i)
        requires: list[str | RequiredAtom] = []
        for j, entry in enumerate(r.requires or ()):
            name, mode = (entry, None) if isinstance(entry, str) else (entry.atom, entry.on_redirect)
            a = declared.atom(name, where, path.requires.at(j), errors)
            if a is not None:
                requires.append(RequiredAtom(a, mode))
        try:
            out.append(network(
                r.host, path=_slot(r.path) if r.path is not None else (), schemes=r.schemes or ("https",),
                ports=r.ports or (), methods=r.methods or (), allow_nonpublic=r.allow_nonpublic,
                requires=requires, read_timeout=r.read_timeout, total_timeout=r.total_timeout,
                max_response_bytes=r.max_response_bytes,
                source=declared.source_atom(r.source, where, path.key("source"), errors),
                writes=r.writes,
            ))
        except ValueError as e:
            errors.add(where, path, str(e))
    return out


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------


def from_data(data: object, where: str = "<policy>") -> Policy:
    """The Policy a parsed document (TOML or JSON, as a dict) declares, with every ruleset it
    applies; raises ``PolicyFileError`` with every problem found in every file."""
    errors = _Errors()
    try:
        root = parse_policy(data, where)
    except SchemaError as e:
        errors.schema(e)
        errors.raise_if_any()
        raise AssertionError("unreachable")
    documents = _compose(root, where, errors)
    declared = _declare(documents, errors)
    validations: list[Validation] = []
    programs: list[Program] = []
    sources: list[Source] = []
    for d in documents:
        rules = _Rules(d, declared, errors)
        rules.declare_flagsets()
        validations += rules.validations()
        programs += rules.programs()
        sources += rules.sources()
    top = documents[0].body
    assert isinstance(top, PolicyDoc)
    net_rules = _network(top, where, declared, errors)
    errors.raise_if_any()
    try:
        return Policy.allow(
            read=_slot(top.filesystem.read) if top.filesystem.read else [],
            write=_slot(top.filesystem.write) if top.filesystem.write else [],
            listing=_slot(top.filesystem.list_) if top.filesystem.list_ else [],
            programs=programs, validations=validations, atoms=declared.defined,
            network=net_rules, sources=sources, regions=declared.regions, reads=declared.reads,
        )
    except ValueError as e:
        raise PolicyFileError(f"{where}: {e}") from None


def load_policy_file(path: pathlib.Path) -> Policy:
    """Load a ``.toml`` or ``.json`` policy document."""
    text = path.read_text(encoding="utf-8")
    match path.suffix:
        case ".toml":
            try:
                data: object = tomllib.loads(text)
            except tomllib.TOMLDecodeError as e:
                raise PolicyFileError(f"{path}: {e}") from None
        case ".json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError as e:
                raise PolicyFileError(f"{path}: {e}") from None
        case _:
            raise PolicyFileError(f"{path}: expected a .toml or .json policy file")
    return from_data(data, str(path))
