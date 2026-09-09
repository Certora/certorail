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
from os import PathLike
import pathlib
import subprocess
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal, cast

from . import markers
from .analysis import (
    ANY_NAME,
    Alternation,
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
    _literal_location,
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
    url_of,
    ValidationFact
)
from .templates import (
    BindError,
    Constraint,
    Each,
    Flags,
    Flagset,
    Hole,
    HoleRef,
    Many,
    Piece,
    Template,
    Token,
    Value,
    bind,
    hole_failures,
    instantiate,
    matches_leading,
)
from .walker import (
    CheckSignature,
    CheckSite,
    ExecSite,
    NetworkSite,
    Report,
    SinkSite,
    Site,
    Vocabulary,
)

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


def _absolute_prefix(s: str) -> StaticPath:
    """A leading-"/" literal as an absolute location."""
    loc = _literal_location(s)
    if loc is None:
        raise ValueError(f"absolute path {s!r} must be free of '..'")
    return loc


def location_of(where: Where) -> LocationFact:
    """``within(...)``/``exactly(...)``/a literal path as a location; ``"."`` is the root, and a
    leading "/" anchors the location at the filesystem root instead (the two anchors never
    relate -- see ``location_le``). A LocationFact passes through: the data-policy loader
    (``policyfile``) hands those in."""
    match where:
        case StaticPath() | DirSplat():
            return where
        case str():
            if where in (".", ""):
                return StaticPath(())
            if where.startswith("/"):
                return _absolute_prefix(where)
            return StaticPath(_components_of(where))
        case markers.Exactly(components=components):
            if not components:
                raise ValueError("exactly() needs at least one component")
            return StaticPath(tuple(c for f in components for c in _components_of(f)))
        case markers.Within(prefix=prefix, leaf=leaf):
            absolute = False
            if prefix in (".", ""):
                prefix_components: tuple[Component, ...] = ()
            elif isinstance(prefix, str) and prefix.startswith("/"):
                base = _absolute_prefix(prefix)
                prefix_components, absolute = base.path_components, True
            else:
                prefix_components = _components_of(prefix)
            if leaf is None:
                return DirSplat(prefix_components, ANY_NAME, absolute)
            leaf_components = _components_of(leaf)
            if len(leaf_components) != 1:
                raise ValueError("within(leaf=...) must be a single component")
            return DirSplat(prefix_components, leaf_components[0], absolute)


def _locations(wheres: Iterable[Where]) -> tuple[LocationFact, ...]:
    return tuple(location_of(w) for w in wheres)


def _one_or_many(where: Where | Iterable[Where]) -> tuple[LocationFact, ...]:
    """A location *slot* (``Program.cwd``, ``Validation.cwd``): one spelling, or several meaning
    any-of -- the same reading filesystem grants and ``argument_locations`` have always had."""
    if isinstance(where, (str, markers.Within, markers.Exactly, StaticPath, DirSplat)):
        return (location_of(where),)
    out = tuple(location_of(w) for w in where)
    if not out:
        raise ValueError("a location slot needs at least one location")
    return out


def pretty_locations(locations: Iterable[LocationFact]) -> str:
    names = [pretty_location(loc) for loc in locations]
    return names[0] if len(names) == 1 else "one of " + ", ".join(names)


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
    # where the check may run: any of these. None: the check does not care where it runs --
    # callers may omit cwd=, and no location is required or proven. Such a check cannot
    # establish atoms on cwd.
    cwd: tuple[LocationFact, ...] | None
    establishes: dict[str, frozenset[str]]  # param name or CWD -> atoms
    pure_atoms: frozenset[str] = frozenset()  # the established atoms wrapped in pure()
    effect_free: bool = False  # the evaluator mutates nothing: its run kills no atoms


def validation(
    name: str,
    *,
    argv: Iterable[str | Param],
    cwd: Where | Iterable[Where] | None = None,
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
    if cwd is None and CWD in est:
        raise ValueError(
            f"validation {name!r}: a check that does not care about its cwd cannot establish "
            "atoms on cwd"
        )
    return Validation(
        name, params_t, argv_t, None if cwd is None else _one_or_many(cwd), est,
        frozenset(pure_set), effect_free,
    )


# ---------------------------------------------------------------------------
# the policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Program:
    """A permitted ``certora.exec`` program."""

    name: str
    cwd: tuple[LocationFact, ...]  # the exec's cwd must lie within one of these
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
    # the command-line shape (TEMPLATES.md). None for the flat rule above, which is the template
    # [name, *subcommand, ${REST...}] in disguise: a trailing each hole taking any statically
    # known text (or anything, with unknown_arguments)
    template: Template | None = None
    # provenance for reports: the ruleset (and bindings) this rule came from, None for a rule
    # the root policy wrote itself
    origin: str | None = None

    @property
    def leading_words(self) -> tuple[str, ...]:
        """What selects this rule: the program and the literal words that follow it. A
        program's rules are prefix-free in these, so an exec selects exactly one."""
        if self.template is not None:
            return self.template.leading_words
        return (self.name, *self.subcommand)


def program(
    name: str,
    *,
    cwd: Where | Iterable[Where],
    subcommand: str | Iterable[str] = (),
    unknown_arguments: bool = True,
    argument_locations: Iterable[Where] = (),
    requires: Iterable[str] = (),
    argument_atoms: Iterable[str] = (),
    argv: Iterable[Piece] | None = None,
    holes: Mapping[str, Hole] | None = None,
    origin: str | None = None,
) -> Program:
    words = tuple(subcommand.split()) if isinstance(subcommand, str) else tuple(subcommand)
    if not all(isinstance(w, str) and w for w in words):
        raise ValueError(f"program {name!r}: subcommand words must be non-empty strings")
    template = None
    if argv is not None or holes is not None:
        if argv is None or holes is None:
            raise ValueError(f"program {name!r}: argv and holes go together")
        if words or not unknown_arguments or tuple(argument_locations) or tuple(argument_atoms):
            raise ValueError(
                f"program {name!r}: a templated rule carries no subcommand or argument keys; "
                "constrain the holes instead"
            )
        template = Template(tuple(argv), dict(holes))
        if template.program != name:
            raise ValueError(f"program {name!r}: its template begins with {template.program!r}")
    return Program(
        name,
        _one_or_many(cwd),
        unknown_arguments,
        _locations(argument_locations),
        frozenset(requires),
        words,
        frozenset(argument_atoms),
        template,
        origin,
    )


def hole(name: str) -> HoleRef:
    """``${name}``: one token."""
    return HoleRef(name)


def splice(name: str) -> HoleRef:
    """``${name...}``: a splice of zero or more tokens."""
    return HoleRef(name, variadic=True)


def constraint(
    *,
    location: Where | Iterable[Where] = (),
    matches: str | None = None,
    one_of: Iterable[str] = (),
    atoms: Iterable[str] = (),
    literal: bool = False,
    any: bool = False,
) -> Constraint:
    """A hole's rely, in the marker vocabulary (see ``templates.Constraint`` for the rules)."""
    regex: PseudoRegex | None = None
    if matches is not None:
        regex = RegexLit(matches)
    names = tuple(one_of)
    if names:
        if regex is not None:
            raise ValueError("matches and one_of exclude each other")
        regex = alternation(*(Exact(n) for n in names))
    return Constraint(
        _one_or_many(location) if location else (), regex, frozenset(atoms), literal, any
    )


def flagset(bare: Iterable[str] = (), valued: Mapping[str, Constraint] | None = None) -> Flagset:
    return Flagset(frozenset(bare), dict(valued or {}))


@dataclass(frozen=True)
class RequiredAtom:
    """One atom a network rule requires of the URL value, with its treatment at a redirect --
    a URL the static analysis never saw:

    - ``"recheck"``: re-established from the hop URL's text (a defined atom's regex, or a
      literal checker); only textually-establishable atoms qualify.
    - ``"stop"``: the atom cannot vouch for an unseen URL, so the rule refuses to authorize
      redirect hops (another rule without it may still cover the hop).
    - ``"waive"``: the atom speaks about the original request only (say, "no auth-key
      parameter"); hops do not re-demand it, so a pre-signed redirect target with a
      colliding parameter name is not tanked.
    - ``None``: decide at ``Policy.allow`` -- recheck when the atom is textual, stop
      otherwise.

    Whatever the mode, the static check demands the atom on the original URL at every
    ``certora.network`` site."""

    name: str
    on_redirect: Literal["recheck", "stop", "waive"] | None = None


def waived(atom_name: str) -> RequiredAtom:
    """The atom applies to the original request only; redirects do not re-demand it."""
    return RequiredAtom(atom_name, "waive")


def rechecked(atom_name: str) -> RequiredAtom:
    """The atom is re-established from every hop URL's text; ``Policy.allow`` rejects this
    for atoms that are not textually establishable."""
    return RequiredAtom(atom_name, "recheck")


def no_redirect(atom_name: str) -> RequiredAtom:
    """The atom refuses redirects outright, even when it could be re-checked textually."""
    return RequiredAtom(atom_name, "stop")


@dataclass(frozen=True)
class NetworkRule:
    """A permitted ``certora.network`` destination, enforced by the broker (``broker.py``) on
    every request and on every redirect hop. Deny by default: a URL matching no rule is
    refused. The exec'd-program analog is coarse by design (a ``program()`` grant folds in
    whatever network that program needs); these rules govern only the confined program's own
    requests, which all pass through the broker."""

    # exact name, or "*.suffix" (matches subdomains, not the suffix itself)
    host: str
    schemes: frozenset[str] = frozenset({"https"})
    # empty means the scheme's default port only
    ports: frozenset[int] = frozenset()
    # empty means any method; name methods to tighten ("GET": reads only)
    methods: frozenset[str] = frozenset()
    # permit destinations that are (or resolve to) loopback/private/link-local addresses
    allow_nonpublic: bool = False
    # atoms the URL value must carry at the call site -- by a live certora.check, or (for an
    # exactly-known URL) discharged from its text -- each with its redirect treatment; see
    # RequiredAtom. The static check always demands all of them on the original URL.
    requires: frozenset[RequiredAtom] = frozenset()
    # per-destination overrides of the broker's global caps (None: the broker default), so one
    # slow API can get a long leash without loosening the rest of the allowlist
    read_timeout: float | None = None
    total_timeout: float | None = None
    max_response_bytes: int | None = None


def network(
    host: str,
    *,
    schemes: Iterable[str] = ("https",),
    ports: Iterable[int] = (),
    methods: Iterable[str] = (),
    allow_nonpublic: bool = False,
    requires: Iterable[str | RequiredAtom] = (),
    read_timeout: float | None = None,
    total_timeout: float | None = None,
    max_response_bytes: int | None = None,
) -> NetworkRule:
    normalized = host.lower().rstrip(".")
    if not normalized:
        raise ValueError("network rule needs a host")
    schemes_f = frozenset(s.lower() for s in schemes)
    if not schemes_f or not schemes_f <= {"http", "https"}:
        raise ValueError(f"network rule {host!r}: schemes must be among http, https")
    return NetworkRule(
        normalized,
        schemes_f,
        frozenset(int(p) for p in ports),
        frozenset(m.upper() for m in methods),
        allow_nonpublic,
        frozenset(r if isinstance(r, RequiredAtom) else RequiredAtom(r) for r in requires),
        None if read_timeout is None else float(read_timeout),
        None if total_timeout is None else float(total_timeout),
        None if max_response_bytes is None else int(max_response_bytes),
    )


def _host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]              # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def matches_endpoint(rule: NetworkRule, scheme: str, host: str, port: int, method: str) -> bool:
    """Does *rule* permit *method* against ``scheme://host:port``? The one definition of the
    rule semantics: the broker asks it per redirect hop at runtime, ``Policy.evaluate`` per
    statically-proven endpoint."""
    if not _host_matches(rule.host, host):
        return False
    if scheme not in rule.schemes:
        return False
    if rule.ports:
        if port not in rule.ports:
            return False
    elif port != default_port(scheme):
        return False
    if rule.methods and method not in rule.methods:
        return False
    return True


def _netloc_endpoints(netloc: PseudoRegex) -> list[tuple[str, int | None]] | None:
    """The (host, explicit-port) pairs an exactly-known netloc denotes: an Exact, or an
    alternation of Exacts. None otherwise -- a netloc only partially known cannot be held
    against the allowlist."""
    match netloc:
        case Exact(exact_str=s):
            texts = [s]
        case Alternation(any_of=branches) if all(isinstance(b, Exact) for b in branches):
            texts = [b.exact_str for b in branches if isinstance(b, Exact)]
        case _:
            return None
    out: list[tuple[str, int | None]] = []
    for text in texts:
        try:
            # urlsplit does the netloc surgery: lowercases, strips userinfo and brackets
            parts = urllib.parse.urlsplit(f"//{text}")
            host, port = parts.hostname, parts.port
        except ValueError:
            return None
        if host is None:
            return None
        out.append((host.rstrip("."), port))
    return out


def _select(rules: Sequence[Program], arguments: Sequence[Value]) -> Program | None:
    """The rule whose leading words (after the program) begin *arguments*: unique, by the
    prefix-freedom ``Policy.allow`` enforces; None when no form matches (fail closed)."""
    return next((r for r in rules if matches_leading(r.leading_words[1:], arguments)), None)


@dataclass(frozen=True)
class Refusal:
    """Why the broker will not spawn this exec."""

    reason: str


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
    network: tuple[NetworkRule, ...] = ()

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
        network: Iterable[NetworkRule] = (),
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
            # one shape per prefix: a program's rules are prefix-free in their leading words (a
            # bare rule is the empty prefix), so an exec selects exactly one rule and an
            # unlisted form fails closed
            for i, a in enumerate(rs):
                for b in rs[i + 1 :]:
                    if is_prefix(a.leading_words, b.leading_words) or is_prefix(
                        b.leading_words, a.leading_words
                    ):
                        raise ValueError(
                            f"program {pname!r}: forms {' '.join(a.leading_words)!r} and "
                            f"{' '.join(b.leading_words)!r} overlap; the applicable rule must be unique"
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
        # resolve each network requirement's redirect treatment: a textually-establishable
        # atom (defined, or with a literal checker: an effect-free single-input validation)
        # defaults to being re-checked by the broker on every hop; anything else defaults to
        # refusing hops. Only an *explicit* recheck of a non-textual atom is an error.
        recheckable = defined_names | {
            a
            for v in vals
            for established in v.establishes.values()
            for a in established
            if _literal_slot(v, a) is not None
        }
        net_rules = []
        for r in network:
            resolved = set()
            for ra in r.requires:
                if ra.on_redirect is None:
                    resolved.add(
                        replace(ra, on_redirect="recheck" if ra.name in recheckable else "stop")
                    )
                elif ra.on_redirect == "recheck" and ra.name not in recheckable:
                    raise ValueError(
                        f"network rule {r.host!r}: atom {ra.name!r} is declared "
                        "recheck-on-redirect but cannot be re-checked from the URL text alone "
                        "(it is neither a defined atom nor established by an effect-free "
                        "single-parameter validation)"
                    )
                else:
                    resolved.add(ra)
            net_rules.append(replace(r, requires=frozenset(resolved)))
        return cls(
            _locations(read), _locations(write), _locations(listing), progs, vals, atoms_t,
            tuple(net_rules),
        )

    def vocabulary(self) -> Vocabulary:
        """The analysis-side half of the validations and defined atoms, for ``analyze``."""
        return Vocabulary(
            signatures={
                v.name: CheckSignature(
                    v.name, v.params, dict(v.establishes), v.effect_free,
                    needs_cwd=v.cwd is not None,
                )
                for v in self.validations
            },
            pure_atoms=frozenset(a for v in self.validations for a in v.pure_atoms)
            | frozenset(a.name for a in self.atoms),
            defined={a.name: a.regex for a in self.atoms},
        )

    @property
    def _defined(self) -> dict[str, PseudoRegex]:
        return {a.name: a.regex for a in self.atoms}

    def exec_command(
        self,
        program_name: str,
        arguments: Sequence[str],
        keywords: Mapping[str, str | Sequence[str]],
        cwd: str,
        discharge: Callable[[str, str], bool] | None = None,
    ) -> list[str] | Refusal:
        """The broker's re-check of one concrete exec, and the argv to spawn for it.

        Necessarily incomplete against the full rules -- runtime strings carry no provenance,
        so environmental atoms and the flat rule's ``unknown_arguments``/``argument_*`` are the
        static analysis' alone. What IS decidable on concrete values is decided: the program is
        permitted, its leading words select a declared form (fail closed), the cwd lies within
        the rule's locations, and for a templated form the same ``bind`` and hole checks the
        analysis ran -- flag vocabulary and arity, regexes, lexical locations, the leading-dash
        guard, textual atoms -- run again on the strings. The template, not the program,
        then composes the argv."""
        rules = [p for p in self.programs if p.name == program_name]
        if not rules:
            return Refusal(f"program {program_name!r} is not permitted")
        cwd_loc = _literal_location(cwd)
        if cwd_loc is None:
            return Refusal(f"cwd {cwd!r} has no safe location")
        rule = _select(rules, arguments)
        if rule is None:
            return Refusal(
                f"arguments match no declared subcommand of {program_name!r} (subcommands fail closed)"
            )
        if not any(location_le(cwd_loc, allowed) for allowed in rule.cwd):
            return Refusal(f"cwd {cwd!r} is not within {pretty_locations(rule.cwd)}")
        if rule.template is None:
            if keywords:
                return Refusal(f"the rule for {program_name!r} takes no keyword arguments")
            return [program_name, *arguments]
        bound = bind(
            rule.template,
            list(arguments),
            {k: v if isinstance(v, str) else Many(tuple(v)) for k, v in keywords.items()},
        )
        if isinstance(bound, BindError):
            return Refusal("; ".join(bound.reasons))
        # only textual atoms can be re-established from a string; the environmental ones were
        # the static check's to demand
        textual = self.vocabulary().pure_atoms
        failures = hole_failures(
            bound, lambda value, atoms: self._missing_atoms(value, atoms & textual, discharge)
        )
        if failures:
            return Refusal("; ".join(failures))
        return instantiate(bound)

    def exec_refusal(self, program_name: str, arguments: Sequence[str], cwd: str) -> str | None:
        """``exec_command`` for the flat form: the refusal's reason, or None when permitted."""
        outcome = self.exec_command(program_name, arguments, {}, cwd)
        return outcome.reason if isinstance(outcome, Refusal) else None

    def discharger(self, root: PathLike[str] | str) -> Callable[[str, str], bool]:
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
            case ExecSite(program=name, cwd=cwd, arguments=arguments, keywords=keywords):
                rules = [p for p in self.programs if p.name == name]
                if not rules:
                    return [Denial(site, f"program {name!r} is not permitted")]
                if not isinstance(cwd, Located):
                    return [Denial(site, "the cwd is not proven")]
                # forms fail closed: the leading words select exactly one rule
                # (prefix-freedom); an unlisted or computed form matches nothing
                rule = _select(rules, arguments)
                if rule is None:
                    return [
                        Denial(
                            site,
                            f"arguments match no declared subcommand of {name!r} "
                            "(subcommands fail closed)",
                        )
                    ]
                if rule.template is None:
                    if keywords:
                        return [Denial(site, f"the rule for {name!r} takes no keyword arguments")]
                    reason = self._exec_mismatch(
                        rule, cwd, arguments[len(rule.leading_words) - 1:], discharge
                    )
                else:
                    reason = self._template_mismatch(
                        rule, rule.template, cwd, arguments, keywords, discharge
                    )
                if reason is None:
                    return []
                # provenance: which ruleset's rule spoke
                if rule.origin is not None:
                    reason = f"{rule.origin}: {reason}"
                return [Denial(site, reason)]
            case NetworkSite(method=method, url=url):
                lifted = url_of(url)
                if lifted is None or lifted.scheme is None or lifted.netloc is None:
                    return [
                        Denial(
                            site,
                            "the URL is not proven: its scheme and netloc must be known "
                            "(a literal URL, or urllib.parse.urlsplit guards)",
                        )
                    ]
                endpoints = _netloc_endpoints(lifted.netloc)
                if endpoints is None:
                    return [Denial(site, "the URL's netloc is not a known, finite set of hosts")]
                for host, port in endpoints:
                    resolved = port if port is not None else default_port(lifted.scheme)
                    candidates = [
                        rule
                        for rule in self.network
                        if matches_endpoint(rule, lifted.scheme, host, resolved, method)
                    ]
                    if not candidates:
                        return [
                            Denial(
                                site,
                                f"{method} {lifted.scheme}://{host}:{resolved} matches no "
                                "network rule",
                            )
                        ]
                    # whatever their redirect treatment, every required atom is demanded of
                    # the original URL here
                    missing = min(
                        (
                            self._missing_atoms(
                                url, frozenset(ra.name for ra in rule.requires), discharge
                            )
                            for rule in candidates
                        ),
                        key=len,
                    )
                    if missing:
                        return [
                            Denial(
                                site,
                                f"the URL is not validated by: {', '.join(sorted(missing))}",
                            )
                        ]
                return []
            case CheckSite(name=name, cwd=cwd):
                declared = next((v for v in self.validations if v.name == name), None)
                if declared is None:
                    return [Denial(site, f"validation {name!r} is not declared by the policy")]
                if declared.cwd is None:
                    return []  # the check declared no interest in where it runs
                if not isinstance(cwd, Located):
                    return [Denial(site, "the cwd is not proven")]
                if not any(location_le(cwd.location, allowed) for allowed in declared.cwd):
                    return [
                        Denial(
                            site,
                            f"check {name!r} may not run at {pretty_location(cwd.location)} "
                            f"(permitted: {pretty_locations(declared.cwd)})",
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

    def _cwd_mismatch(
        self, rule: Program, cwd: Located, discharge: Callable[[str, str], bool] | None
    ) -> str | None:
        if not any(location_le(cwd.location, allowed) for allowed in rule.cwd):
            return f"cwd {pretty_location(cwd.location)} is not within {pretty_locations(rule.cwd)}"
        missing = self._missing_atoms(cwd, rule.requires, discharge)
        if missing:
            return f"cwd is not validated by: {', '.join(sorted(missing))}"
        return None

    def _template_mismatch(
        self,
        rule: Program,
        template: Template,
        cwd: Located,
        arguments: Sequence[Value],
        keywords: Mapping[str, object],
        discharge: Callable[[str, str], bool] | None,
    ) -> str | None:
        """The templated form: bind the call like a signature, then every hole is a rely."""
        reason = self._cwd_mismatch(rule, cwd, discharge)
        if reason is not None:
            return reason
        bound = bind(template, arguments, cast(Mapping[str, Any], keywords))
        if isinstance(bound, BindError):
            return "; ".join(bound.reasons)
        failures = hole_failures(
            bound, lambda value, atoms: self._missing_atoms(value, atoms, discharge)
        )
        return "; ".join(failures) if failures else None

    def _exec_mismatch(
        self,
        rule: Program,
        cwd: Located,
        arguments: tuple,
        discharge: Callable[[str, str], bool] | None = None,
    ) -> str | None:
        """The flat form. *arguments* excludes the matched subcommand words, if any."""
        reason = self._cwd_mismatch(rule, cwd, discharge)
        if reason is not None:
            return reason
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
