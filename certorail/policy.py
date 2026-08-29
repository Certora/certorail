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
            program("git", cwd=markers.within("repos")),
            program("gh", cwd=".", unknown_arguments=True),
        ],
    )

Evaluation presupposes ``Report.ok``: every site already has a proven location. The policy
decides whether that location is one the host permits.
"""
from collections.abc import Iterable
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
    concat,
    is_safe_name,
    location_le,
    pretty_location,
)
from .walker import ExecSite, Report, SinkSite, Site

# ---------------------------------------------------------------------------
# the marker vocabulary -> the location domain (the runtime-object twin of annotations.py)
# ---------------------------------------------------------------------------

type Where = markers.Within | markers.Exactly | str


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
    """``within(...)``/``exactly(...)``/a literal path as a location; ``"."`` is the root."""
    match where:
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
# the policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Program:
    """A permitted ``certora.exec`` program."""

    name: str
    cwd: LocationFact
    # may the arguments include values the analysis knows nothing about (URLs, JSON fields)?
    unknown_arguments: bool = True
    # located arguments must lie within one of these; empty means anywhere proven
    argument_locations: tuple[LocationFact, ...] = ()


def program(
    name: str,
    *,
    cwd: Where,
    unknown_arguments: bool = True,
    argument_locations: Iterable[Where] = (),
) -> Program:
    return Program(name, location_of(cwd), unknown_arguments, _locations(argument_locations))


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

    @classmethod
    def allow(
        cls,
        *,
        read: Iterable[Where] = (),
        write: Iterable[Where] = (),
        listing: Iterable[Where] = (),
        programs: Iterable[Program] = (),
    ) -> "Policy":
        return cls(_locations(read), _locations(write), _locations(listing), tuple(programs))

    def evaluate(self, report: Report) -> list[Denial]:
        return [d for site in report.sinks for d in self._evaluate(site)]

    def _evaluate(self, site: Site) -> list[Denial]:
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
                reasons: list[str] = []
                for rule in rules:
                    reason = self._exec_mismatch(rule, cwd.location, arguments)
                    if reason is None:
                        return []
                    reasons.append(reason)
                return [Denial(site, "; ".join(reasons))]

    @staticmethod
    def _exec_mismatch(rule: Program, cwd: LocationFact, arguments: tuple) -> str | None:
        if not location_le(cwd, rule.cwd):
            return f"cwd {pretty_location(cwd)} is not within {pretty_location(rule.cwd)}"
        if not rule.unknown_arguments and any(a is None for a in arguments):
            return "arguments of unknown provenance are not permitted"
        if rule.argument_locations:
            for a in arguments:
                if isinstance(a, Located) and not any(
                    location_le(a.location, allowed) for allowed in rule.argument_locations
                ):
                    return f"argument at {pretty_location(a.location)} is outside the permitted locations"
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
