"""The security policy, evaluated against the analysis' findings.

The analysis turns a program into a list of *sites*: filesystem operations with the location of
the path they touch and what they do to it (read / write / list), and ``certora.exec`` calls with
their program, cwd and arguments. A policy says which of those are permitted. It is written in the
same vocabulary as the annotations -- ``markers.within("repos")``, ``markers.exactly("data/x")``
-- and evaluated with the same ordering the rely check uses (``location_le``), so "the policy
permits reads within ``data``" and "this function relies on a path within ``data``" mean the same
thing::

    POLICY = Policy.allow(
        read=[markers.within("data"), markers.within("repos")],
        write=[markers.within("repos")],
        listing=[markers.within("repos")],
        programs=[
            program("git", cwd=markers.within("repos"), requires=["org-checkout"]),
            program("gh", cwd=".", unknown_arguments=True),
        ],
        validations=[
            validation(
                "org-repo",
                argv=("check-org", "certora", "--", param("url")),
                cwd=markers.within("repos"),
                params=("url",),
                establishes={"url": [pure("good-url")], "cwd": ["org-checkout"]},
            ),
        ],
    )

A ``validation()`` declares a runtime predicate the program may invoke as
``certora.check("org-repo", url=u, cwd=repo)``: the evaluator argv (literals plus the check's
named parameters), where it may run, and which atoms its success establishes on which argument.
An atom wrapped in ``pure()`` is a property of the value's text alone -- no effect can invalidate
it -- while a bare atom is about the environment and dies at any potentially-effectful call;
``effect_free=True`` declares the evaluator itself mutates nothing, so its run kills no atoms
(without it, two checkers cannot stack environment atoms on one value). Both are trusted
assertions, like everything in this file. ``program(..., requires=[...])`` consumes atoms: the
exec's cwd must carry them, live, at the site.

Evaluation presupposes ``Report.ok``: every site already has a proven location. The policy
decides whether that location is one the host permits.
"""
import pathlib
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from . import markers
from .analysis import (
    ANY_NAME,
    Component,
    DirSplat,
    Exact,
    Located,
    LocationFact,
    Matching,
    Named,
    OneOf,
    PseudoRegex,
    RegexLit,
    StaticPath,
    _safe_path_extension,
    alternation,
    checks_of,
    concat,
    is_prefix,
    is_safe_name,
    known_text,
    location_le,
    pretty_location,
    saturate,
    ValidationFact
)
from .walker import CheckSignature, CheckSite, ExecSite, Report, SinkSite, Site, Vocabulary

# ---------------------------------------------------------------------------
# the marker vocabulary -> the location domain (the runtime-object twin of annotations.py)
# ---------------------------------------------------------------------------

type Where = markers.Within | markers.Exactly | str | LocationFact


def _regex_of(fragment: markers.Fragment) -> PseudoRegex:
    match fragment:
        case str():
            return Exact(fragment)
        case markers.Matches(regex=r):
            return RegexLit(r)
        case markers.OneOf(names=names):
            return alternation(*(Exact(n) for n in names))
        case markers.Seq(pieces=pieces):
            return concat(*(_regex_of(p) for p in pieces))


def _components_of(fragment: markers.Fragment) -> tuple[Component, ...]:
    """A fragment in component position: a literal may name several components, a marker one."""
    match fragment:
        case str():
            parts = _safe_path_extension(fragment)
            if parts is None:
                raise ValueError(f"path fragment {fragment!r} must be relative, non-empty and free of '..'")
            return tuple(Named(p) for p in parts)
        case markers.OneOf(names=names):
            if not all(is_safe_name(n) for n in names):
                raise ValueError(f"one_of{tuple(names)} in a path must name single components")
            return (OneOf(frozenset(names)),)
        case _:
            return (Matching(_regex_of(fragment)),)


def location_of(where: Where) -> LocationFact:
    """``within(...)``/``exactly(...)``/a literal path as a location; ``"."`` is the root. A
    LocationFact passes through: the data-policy loader (``policyfile``) hands those in."""
    match where:
        case StaticPath() | DirSplat():
            return where
        case str():
            if where in (".", ""):
                return StaticPath(())
            return StaticPath(_components_of(where))
        case markers.Exactly(components=components):
            if not components:
                raise ValueError("exactly() needs at least one component")
            return StaticPath(tuple(c for f in components for c in _components_of(f)))
        case markers.Within(prefix=prefix, leaf=leaf):
            prefix_components: tuple[Component, ...] = (
                () if prefix in (".", "") else _components_of(prefix)
            )
            if leaf is None:
                return DirSplat(prefix_components, ANY_NAME)
            leaf_components = _components_of(leaf)
            if len(leaf_components) != 1:
                raise ValueError("within(leaf=...) must be a single component")
            return DirSplat(prefix_components, leaf_components[0])


def _locations(wheres: Iterable[Where]) -> tuple[LocationFact, ...]:
    return tuple(location_of(w) for w in wheres)


# ---------------------------------------------------------------------------
# validations: policy-declared runtime predicates (certora.check)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Param:
    """A reference, inside an ``argv`` template, to one of the check's declared parameters."""

    name: str


def param(name: str) -> Param:
    return Param(name)


@dataclass(frozen=True)
class Pure:
    """An atom that is a property of the value's text alone: no effect can invalidate it, so it
    survives every call and dies only with the value. A bare-string atom is environmental."""

    name: str


def pure(name: str) -> Pure:
    return Pure(name)


CWD = "cwd"  # the establishes-key for the check's cwd argument


@dataclass(frozen=True)
class AtomDef:
    """A *defined* atom: its meaning is a text property (a marker Fragment), so the checker
    establishes it directly on any value whose text it knows -- a literal ``"master"`` satisfies
    ``atom("not-force", markers.matches(r"[^-].*"))`` with no runtime check -- and it is pure by
    construction. An undefined (opaque) atom is only ever established by an evaluator."""

    name: str
    regex: PseudoRegex


def atom(name: str, meaning: markers.Fragment) -> AtomDef:
    if not name:
        raise ValueError("atom: the name must be non-empty")
    return AtomDef(name, _regex_of(meaning))


@dataclass(frozen=True)
class Validation:
    """One ``validation()`` declaration: the evaluator, where it may run, and what its success
    establishes. The name, parameters, establishes-map, purity and effect-freedom are also the
    analysis-side vocabulary (``Policy.vocabulary``); the argv template is the runtime's business
    (``markers.check``)."""

    name: str
    params: tuple[str, ...]
    argv: tuple[str | Param, ...]
    cwd: LocationFact
    establishes: dict[str, frozenset[str]]  # param name or CWD -> atoms
    pure_atoms: frozenset[str] = frozenset()  # the established atoms wrapped in pure()
    effect_free: bool = False  # the evaluator mutates nothing: its run kills no atoms


def validation(
    name: str,
    *,
    argv: Iterable[str | Param],
    cwd: Where,
    params: Iterable[str] = (),
    establishes: Mapping[str, Iterable[str | Pure]],
    effect_free: bool = False,
) -> Validation:
    params_t = tuple(params)
    if len(set(params_t)) != len(params_t) or CWD in params_t:
        raise ValueError(f"validation {name!r}: parameters must be unique and may not be named {CWD!r}")
    argv_t = tuple(argv)
    if not argv_t or not isinstance(argv_t[0], str):
        raise ValueError(f"validation {name!r}: argv must start with a literal program name")
    for piece in argv_t:
        if isinstance(piece, Param) and piece.name not in params_t:
            raise ValueError(f"validation {name!r}: argv references undeclared parameter {piece.name!r}")
    est: dict[str, frozenset[str]] = {}
    pure_set: set[str] = set()
    env_set: set[str] = set()
    for key, atoms in establishes.items():
        if key != CWD and key not in params_t:
            raise ValueError(f"validation {name!r}: establishes references undeclared parameter {key!r}")
        names: set[str] = set()
        for a in atoms:
            match a:
                case Pure(name=atom) if atom:
                    pure_set.add(atom)
                case str() as atom if atom:
                    env_set.add(atom)
                case _:
                    raise ValueError(f"validation {name!r}: atoms must be non-empty strings or pure(...)")
            names.add(atom)
        if not names:
            raise ValueError(f"validation {name!r}: establishes entries need at least one atom")
        est[key] = frozenset(names)
    if pure_set & env_set:
        raise ValueError(
            f"validation {name!r}: atoms declared both pure and environmental: {sorted(pure_set & env_set)}"
        )
    return Validation(name, params_t, argv_t, location_of(cwd), est, frozenset(pure_set), effect_free)


# ---------------------------------------------------------------------------
# the policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Program:
    """A permitted ``certora.exec`` program."""

    name: str
    cwd: LocationFact
    # may the arguments include values the analysis cannot vouch for (URLs, JSON fields)?
    # Vouched-for means exactly-known text or a proven path; a computed str is unknown even
    # when it is tracked as a fact
    unknown_arguments: bool = True
    # located arguments must lie within one of these; empty means anywhere proven
    argument_locations: tuple[LocationFact, ...] = ()
    # validation atoms the cwd must carry, live, at the exec (established by certora.check)
    requires: frozenset[str] = frozenset()
    # the leading literal arguments this rule governs ("push origin"). Once any rule for a
    # program names a subcommand, that program fails closed: an exec matching no declared
    # subcommand -- unlisted, or computed -- is denied. Prefix-freedom (checked in allow())
    # makes the applicable rule unique.
    subcommand: tuple[str, ...] = ()
    # atoms every argument after the subcommand must satisfy: by a live check, or -- for a
    # defined atom -- by its known text (saturate)
    argument_atoms: frozenset[str] = frozenset()


def program(
    name: str,
    *,
    cwd: Where,
    subcommand: str | Iterable[str] = (),
    unknown_arguments: bool = True,
    argument_locations: Iterable[Where] = (),
    requires: Iterable[str] = (),
    argument_atoms: Iterable[str] = (),
) -> Program:
    words = tuple(subcommand.split()) if isinstance(subcommand, str) else tuple(subcommand)
    if not all(isinstance(w, str) and w for w in words):
        raise ValueError(f"program {name!r}: subcommand words must be non-empty strings")
    return Program(
        name,
        location_of(cwd),
        unknown_arguments,
        _locations(argument_locations),
        frozenset(requires),
        words,
        frozenset(argument_atoms),
    )


def _prefix_matches(prefix: tuple[str, ...], arguments: tuple) -> bool:
    if len(arguments) < len(prefix):
        return False
    return all(known_text(arguments[i]) == word for i, word in enumerate(prefix))


# ---------------------------------------------------------------------------
# literal checkers: running an evaluator on statically-known text at check time
# ---------------------------------------------------------------------------


def _literal_slot(v: Validation, atom_name: str) -> str | None:
    """The single input slot through which *v* can establish *atom_name* on a literal, if it is a
    literal checker at all: effect-free (safe to run at check time), the atom pure (the result
    stays valid), and exactly one input -- one declared parameter, or none plus cwd -- so the
    binding of the literal is unambiguous."""
    if not v.effect_free or atom_name not in v.pure_atoms:
        return None
    if not v.params and atom_name in v.establishes.get(CWD, frozenset()):
        return CWD
    if len(v.params) == 1 and atom_name in v.establishes.get(v.params[0], frozenset()):
        return v.params[0]
    return None


def _run_literal_checker(v: Validation, slot: str, text: str, root: pathlib.Path) -> bool:
    """One evaluator run with *text* bound to *slot*: argv substitution for a parameter slot,
    ``cwd=root/text`` for the cwd slot (a pure text predicate should not care where it runs, so a
    parameter-slot checker runs at the root)."""
    argv = [piece if isinstance(piece, str) else text for piece in v.argv]
    cwd = root / text if slot == CWD else root
    if not cwd.is_dir():
        return False
    try:
        result = subprocess.run(argv, cwd=cwd, shell=False, capture_output=True, check=False)
    except OSError:
        return False
    return result.returncode == 0


@dataclass(frozen=True)
class Denial:
    site: Site
    reason: str


@dataclass(frozen=True)
class Policy:
    read: tuple[LocationFact, ...] = ()
    write: tuple[LocationFact, ...] = ()
    listing: tuple[LocationFact, ...] = ()
    programs: tuple[Program, ...] = ()
    validations: tuple[Validation, ...] = ()
    atoms: tuple[AtomDef, ...] = ()

    @classmethod
    def allow(
        cls,
        *,
        read: Iterable[Where] = (),
        write: Iterable[Where] = (),
        listing: Iterable[Where] = (),
        programs: Iterable[Program] = (),
        validations: Iterable[Validation] = (),
        atoms: Iterable[AtomDef] = (),
    ) -> "Policy":
        vals = tuple(validations)
        names = [v.name for v in vals]
        if len(set(names)) != len(names):
            raise ValueError("validation names must be unique")
        atoms_t = tuple(atoms)
        defined_names = frozenset(a.name for a in atoms_t)
        if len(defined_names) != len(atoms_t):
            raise ValueError("defined atom names must be unique")
        progs = tuple(programs)
        by_name: dict[str, list[Program]] = {}
        for p in progs:
            by_name.setdefault(p.name, []).append(p)
        for pname, rs in by_name.items():
            subbed = [r for r in rs if r.subcommand]
            if subbed and len(subbed) != len(rs):
                raise ValueError(f"program {pname!r}: subcommand rules cannot mix with a bare rule")
            for i, a in enumerate(subbed):
                for b in subbed[i + 1 :]:
                    if is_prefix(a.subcommand, b.subcommand) or is_prefix(b.subcommand, a.subcommand):
                        raise ValueError(
                            f"program {pname!r}: subcommands {' '.join(a.subcommand)!r} and "
                            f"{' '.join(b.subcommand)!r} overlap; the applicable rule must be unique"
                        )
        # an atom means one thing: pure in one declaration and environmental in another is a bug.
        # A defined atom is pure by construction, however it is established.
        pure_names = {a for v in vals for a in v.pure_atoms} | defined_names
        conflicted = {
            a
            for v in vals
            for established in v.establishes.values()
            for a in established
            if a not in defined_names and (a in pure_names) != (a in v.pure_atoms)
        }
        if conflicted:
            raise ValueError(f"atoms declared both pure and environmental: {sorted(conflicted)}")
        return cls(_locations(read), _locations(write), _locations(listing), progs, vals, atoms_t)

    def vocabulary(self) -> Vocabulary:
        """The analysis-side half of the validations and defined atoms, for ``analyze``."""
        return Vocabulary(
            signatures={
                v.name: CheckSignature(v.name, v.params, dict(v.establishes), v.effect_free)
                for v in self.validations
            },
            pure_atoms=frozenset(a for v in self.validations for a in v.pure_atoms)
            | frozenset(a.name for a in self.atoms),
            defined={a.name: a.regex for a in self.atoms},
        )

    @property
    def _defined(self) -> dict[str, PseudoRegex]:
        return {a.name: a.regex for a in self.atoms}

    def discharger(self, root: pathlib.Path | str) -> Callable[[str, str], bool]:
        """A runner for literal checkers: ``discharge(atom, text)`` is True when some effect-free
        validation establishing the pure *atom* through a single slot accepts the exact *text*,
        run right now under *root*. Cached per (atom, text); handed to ``evaluate`` and to
        ``analyze`` so constants need neither a ``certora.check`` nor a regex definition."""
        rootpath = pathlib.Path(root)
        cache: dict[tuple[str, str], bool] = {}

        def discharge(atom_name: str, text: str) -> bool:
            key = (atom_name, text)
            if key not in cache:
                cache[key] = any(
                    _run_literal_checker(v, slot, text, rootpath)
                    for v in self.validations
                    if (slot := _literal_slot(v, atom_name)) is not None
                )
            return cache[key]

        return discharge

    def evaluate(
        self, report: Report, discharge: Callable[[str, str], bool] | None = None
    ) -> list[Denial]:
        return [d for site in report.sinks for d in self._evaluate(site, discharge)]

    def _evaluate(
        self, site: Site, discharge: Callable[[str, str], bool] | None = None
    ) -> list[Denial]:
        match site:
            case SinkSite(kind=kind, fact=Located(location=loc)):
                permitted = {"read": self.read, "write": self.write, "list": self.listing}[kind]
                if any(location_le(loc, allowed) for allowed in permitted):
                    return []
                return [Denial(site, f"{kind} of {pretty_location(loc)} is not permitted")]
            case SinkSite():
                return [Denial(site, "the location of the path is not proven")]
            case ExecSite(program=name, cwd=cwd, arguments=arguments):
                rules = [p for p in self.programs if p.name == name]
                if not rules:
                    return [Denial(site, f"program {name!r} is not permitted")]
                if not isinstance(cwd, Located):
                    return [Denial(site, "the cwd is not proven")]
                if any(r.subcommand for r in rules):
                    # subcommands fail closed: at most one rule matches (prefix-freedom); an
                    # unlisted or computed subcommand matches nothing and is denied
                    rule = next((r for r in rules if _prefix_matches(r.subcommand, arguments)), None)
                    if rule is None:
                        return [
                            Denial(
                                site,
                                f"arguments match no declared subcommand of {name!r} "
                                "(subcommands fail closed)",
                            )
                        ]
                    reason = self._exec_mismatch(
                        rule, cwd, arguments[len(rule.subcommand):], discharge
                    )
                    return [] if reason is None else [Denial(site, reason)]
                reasons: list[str] = []
                for rule in rules:
                    reason = self._exec_mismatch(rule, cwd, arguments, discharge)
                    if reason is None:
                        return []
                    reasons.append(reason)
                return [Denial(site, "; ".join(reasons))]
            case CheckSite(name=name, cwd=cwd):
                declared = next((v for v in self.validations if v.name == name), None)
                if declared is None:
                    return [Denial(site, f"validation {name!r} is not declared by the policy")]
                if not isinstance(cwd, Located):
                    return [Denial(site, "the cwd is not proven")]
                if not location_le(cwd.location, declared.cwd):
                    return [
                        Denial(
                            site,
                            f"check {name!r} may not run at {pretty_location(cwd.location)} "
                            f"(permitted: {pretty_location(declared.cwd)})",
                        )
                    ]
                return []

    def _missing_atoms(
        self,
        value: str | ValidationFact | None,
        required: frozenset[str],
        discharge: Callable[[str, str], bool] | None,
    ) -> frozenset[str]:
        """The required atoms *value* does not carry, after saturation (regex-defined atoms on
        known text) and after running literal checkers on exactly-known text."""
        if not required:
            return required
        sat = saturate(value, self._defined)
        have = frozenset() if sat is None or isinstance(sat, str) else sat.checks
        missing = required - have
        if missing and discharge is not None and (text := known_text(value)) is not None:
            missing = frozenset(a for a in missing if not discharge(a, text))
        return missing

    def _exec_mismatch(
        self,
        rule: Program,
        cwd: Located,
        arguments: tuple,
        discharge: Callable[[str, str], bool] | None = None,
    ) -> str | None:
        """*arguments* excludes the matched subcommand words, if the rule has any."""
        if not location_le(cwd.location, rule.cwd):
            return f"cwd {pretty_location(cwd.location)} is not within {pretty_location(rule.cwd)}"
        missing = self._missing_atoms(cwd, rule.requires, discharge)
        if missing:
            return f"cwd is not validated by: {', '.join(sorted(missing))}"
        if not rule.unknown_arguments:
            for i, a in enumerate(arguments):
                # vouched-for means exactly-known text or a proven path: a computed str
                # (f-string, .strip()) is a StrFact, not None, but is still unknown
                if known_text(a) is None and not isinstance(a, Located):
                    return (
                        f"argument {i + len(rule.subcommand) + 1} is of unknown provenance "
                        "(neither statically known text nor a proven path)"
                    )
        if rule.argument_locations:
            for a in arguments:
                if isinstance(a, Located) and not any(
                    location_le(a.location, allowed) for allowed in rule.argument_locations
                ):
                    return f"argument at {pretty_location(a.location)} is outside the permitted locations"
        if rule.argument_atoms:
            for i, a in enumerate(arguments):
                missing = self._missing_atoms(a, rule.argument_atoms, discharge)
                if missing:
                    return (
                        f"argument {i + len(rule.subcommand) + 1} is not validated by: "
                        f"{', '.join(sorted(missing))}"
                    )
        return None


# ---------------------------------------------------------------------------
# the default policy: what ``certorail program.py`` applies when no policy file is given
# ---------------------------------------------------------------------------

# Everything the analysis proves to lie within the root, plus the two programs the reference
# example shells out to, run anywhere within the root. Tight enough that any escape from the root
# is a denial, loose enough that a well-formed script needs no policy file.
DEFAULT_POLICY = Policy.allow(
    read=[markers.within(".")],
    write=[markers.within(".")],
    listing=[markers.within(".")],
    programs=[],
)
