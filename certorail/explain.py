"""``certorail explain``: why a program was rejected, and what would have to change.

    certorail explain program.py [--root DIR] [--policy P] [--json]
    certorail explain -c SOURCE  [same options]

The same pipeline ``--check`` runs (``host.check``: the subset rules, then the dataflow, then the
policy), reported instead of summarised. For every violation and every denial: the site with its
source line, the operation, the reason -- which subset rule fired, which location is unproven,
which policy rule refused, which atom obligation is undischarged -- and two remedies, one written
in the policy's own vocabulary and one in the program's.

What it does not do, by construction:

- It never runs the program. ``run`` is not imported here, there is no argument passthrough and
  no ``--no-jail``.
- It never relaxes a check to have more to say: the verdict and the exit status are the ones
  ``--check`` gives.
- It reports policy content only where a site in the program asked for it -- the allowances for a
  kind the program attempted, the rules for a program it named. It never enumerates the policy,
  so it cannot become a way to read an ambient policy the program's author was not handed.

One thing it does share with ``--check``: given ``--root``, the policy's own literal checkers may
run (``Policy.discharger``), because running one on known text is how a pure atom is discharged.
Those are the host's trusted programs, not the confined one.

The explanation goes to stdout in both verdicts -- unlike ``main``, which puts a rejection on
stderr -- because here it is the requested product and a tool downstream consumes it. Only
notices and errors stay on stderr; the verdict rides on the exit status.
"""
import argparse
import json
import pathlib
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from .analysis import (
    ANY_NAME,
    AnyName,
    Component,
    DirSplat,
    LocationFact,
    Located,
    Matching,
    Named,
    OneOf,
    PseudoRegex,
    RegexLit,
    StaticPath,
    location_le,
    pretty_location,
    pretty_regex,
)
from .host import (
    Accepted,
    PolicySource,
    add_common_arguments,
    check,
    load_policy_described,
    read_source,
)
from .policy import (
    ArgumentMissingAtoms,
    ArgumentOutside,
    Cause,
    CheckCwdOutside,
    CwdMissingAtoms,
    CwdOutside,
    CWD,
    EndpointUnmatched,
    ExecDenied,
    ExecDetail,
    NetlocNotFinite,
    NetworkRule,
    NoSubcommand,
    NotPermitted,
    Policy,
    Program,
    UndeclaredValidation,
    UnknownProgram,
    Unproven,
    UnvouchedArgument,
    UrlMissingAtoms,
    Validation,
    _host_matches,
    default_port,
)
from .policyfile import parse_location
from .analysis import known_text
from .walker import CheckSite, ExecSite, NetworkSite, Site, SinkSite, describe_sink

# ---------------------------------------------------------------------------
# the explanation, as data
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Span:
    """Where a finding is, and the line of source that is there."""

    file: str
    line: int | None
    column: int | None  # 1-based, the way ``walker.where`` numbers it
    end_line: int | None
    end_column: int | None
    source: str | None  # from the source that was analysed, never re-read from disk


@dataclass(frozen=True)
class Edit:
    """A policy change, as a schema path plus the text to put there.

    Not a line number: ``tomllib`` reports no positions, so a document line is not obtainable and
    is not promised."""

    path: str  # "filesystem.read", "program[0].cwd", "network", "validation"
    add: str  # the value, or the TOML fragment
    widens: bool = False  # the edit permits more than this one site needs


@dataclass(frozen=True)
class Remedy:
    channel: Literal["policy", "program"]
    text: str
    edit: Edit | None = None


@dataclass(frozen=True)
class Finding:
    kind: Literal["violation", "denial"]
    span: Span
    operation: str | None  # read|write|list|exec|check|network; None for a violation
    what: str  # the site's what, or the pass name for a violation
    detail: str  # describe_sink(site), or "" for a violation
    reason: str
    cause: Cause | None
    remedies: tuple[Remedy, ...]


@dataclass(frozen=True)
class SiteLine:
    """One entry of the site inventory: what the program touches, and how it fared.

    ``confined`` is the analysis' verdict -- the location was proven -- and ``denied`` the
    policy's. A site can be confined and still denied: proving where a path points says nothing
    about whether the host permits it."""

    span: Span
    operation: str
    what: str
    confined: bool
    denied: bool
    detail: str


@dataclass(frozen=True)
class Explanation:
    filename: str
    root: str | None
    policy: PolicySource
    accepted: bool
    findings: tuple[Finding, ...]
    sites: tuple[SiteLine, ...]
    # the pass that rejected the program, when a subset rule did. The policy is not evaluated at
    # all in that case, so a reader must not read the absence of denials as the policy's blessing.
    phase: str | None = None


# ---------------------------------------------------------------------------
# spelling a location the way a policy document spells it
# ---------------------------------------------------------------------------


def _component_spelling(c: Component) -> str | None:
    match c:
        case Named(name=n):
            return n
        case AnyName():
            return "*"
        case OneOf(names=ns):
            return "{" + ",".join(sorted(ns)) + "}"
        case Matching(regex=RegexLit(reg=r)):
            return f"<{r}>"
        case _:
            # a Matching whose regex was built rather than written (an f-string's shape, a
            # translated glob) has no document spelling at all
            return None


def _assemble(components: Sequence[str], tail: str | None, absolute: bool) -> str:
    parts = [*components, *([] if tail is None else [tail])]
    if not parts:
        return "/" if absolute else "."
    return ("/" if absolute else "") + "/".join(parts)


def policy_spelling(loc: LocationFact) -> str | None:
    """*loc* as ``policyfile.parse_location`` would read it back, or None when that grammar
    cannot write it.

    Not ``pretty_location``: a ``Matching`` component is ``<raw regex>`` in a document and
    ``</raw regex/>`` in a report, and a regex that was built rather than written has no spelling.
    The result is checked by parsing it again, so a spelling that would not round-trip -- a regex
    containing a delimiter the splitter reads -- comes back as None rather than as a suggestion
    that does not mean what it says."""
    match loc:
        case StaticPath(path_components=cs, absolute=ab):
            spelled = [_component_spelling(c) for c in cs]
            tail = None
        case DirSplat(static_prefix=ps, final_component=leaf, absolute=ab):
            spelled = [_component_spelling(c) for c in ps]
            if leaf == ANY_NAME:
                tail = "**"
            else:
                leaf_spelling = _component_spelling(leaf)
                if leaf_spelling is None:
                    return None
                tail = f"**/{leaf_spelling}"
    if any(c is None for c in spelled):
        return None
    candidate = _assemble([c for c in spelled if c is not None], tail, ab)
    try:
        return candidate if parse_location(candidate) == loc else None
    except ValueError:
        return None


def enclosing_spelling(loc: LocationFact) -> str:
    """A spellable allowance that covers *loc*: its components up to the first one the document
    grammar cannot write, then ``**``.

    Always defined, and always at least as wide as *loc* -- which is why a remedy built on it is
    marked ``widens``."""
    components = loc.path_components if isinstance(loc, StaticPath) else loc.static_prefix
    prefix: list[str] = []
    for c in components:
        spelled = _component_spelling(c)
        if spelled is None:
            break
        prefix.append(spelled)
    candidate = _assemble(prefix, "**", loc.absolute)
    try:
        if location_le(loc, parse_location(candidate)):
            return candidate
    except ValueError:
        pass
    return "/**" if loc.absolute else "**"


def _location_value(loc: LocationFact) -> tuple[str, bool]:
    """The value a policy edit should carry for *loc*, and whether it widens beyond it."""
    exact = policy_spelling(loc)
    return (exact, False) if exact is not None else (enclosing_spelling(loc), True)


# ---------------------------------------------------------------------------
# reading the policy for one site
# ---------------------------------------------------------------------------


def operation_of(site: Site) -> str:
    match site:
        case SinkSite(kind=kind):
            return kind
        case ExecSite():
            return "exec"
        case CheckSite():
            return "check"
        case NetworkSite():
            return "network"


def establishers(policy: Policy, atom_name: str) -> tuple[tuple[Validation, str], ...]:
    """Every declared validation that establishes *atom_name*, with the slot it establishes it on
    (a parameter name, or ``cwd``)."""
    return tuple(
        (v, slot)
        for v in policy.validations
        for slot, atoms in sorted(v.establishes.items())
        if atom_name in atoms
    )


def defined_regex(policy: Policy, atom_name: str) -> PseudoRegex | None:
    """The regex that *is* a defined atom's meaning; None for an opaque one."""
    return next((a.regex for a in policy.atoms if a.name == atom_name), None)


def _atom_program_remedy(policy: Policy, atom_name: str, slot: str) -> str:
    """How the program itself could carry *atom_name* on *slot* (prose names the slot; the
    snippet uses ``value``, so it is pastable)."""
    regex = defined_regex(policy, atom_name)
    if regex is not None:
        raw = regex.reg if isinstance(regex, RegexLit) else None
        pattern = f'r"{raw}"' if raw is not None else f"r\"{pretty_regex(regex)}\""
        return (
            f"{slot}: {atom_name} is defined as the text property {pretty_regex(regex)}, so text "
            "the analysis already knows carries it, and a computed value carries it after "
            f"assert re.fullmatch({pattern}, value) -- that exact regex text, not an "
            "equivalent one"
        )
    found = establishers(policy, atom_name)
    if not found:
        return (
            f"{slot}: no declared validation establishes {atom_name}, so no guard in the program "
            "can carry it; the policy must declare one"
        )
    calls = []
    for validation, established_on in found:
        if established_on == CWD:
            calls.append(f'certora.check("{validation.name}", cwd=<the directory>)')
        elif len(validation.params) == 1:
            calls.append(
                f'value = certora.check_single("{validation.name}", value)'
                " -- the atoms ride the returned value"
            )
        else:
            calls.append(
                f'certora.check("{validation.name}", {established_on}=value, cwd=...)'
            )
    return (
        f"{slot}: call the validation that establishes {atom_name}, immediately before the "
        "site -- " + "; ".join(calls)
        + " -- since an environmental atom dies at every potentially-effectful call in between"
    )


def _program_block(name: str, cwd_value: str, subcommand: str | None = None) -> str:
    lines = ["[[program]]", f'name       = "{name}"']
    if subcommand is not None:
        lines.append(f'subcommand = "{subcommand}"')
    lines.append(f'cwd        = "{cwd_value}"')
    return "\n".join(lines) + "\n"


def _named(items: Sequence[str], nothing: str) -> str:
    return ", ".join(items) if items else nothing


# ---------------------------------------------------------------------------
# the remedies
# ---------------------------------------------------------------------------

_FILESYSTEM_KEY = {"read": "read", "write": "write", "list": "list"}

_SUBSET_POINTER = "see examples/SUBSET_PROMPT.md for the forms the analysis reads"


def _exec_detail_remedies(
    policy: Policy,
    program_name: str,
    index: int,
    rule: Program,
    detail: ExecDetail,
) -> tuple[Remedy, ...]:
    match detail:
        case CwdOutside(location=loc):
            value, widens = _location_value(loc)
            return (
                Remedy(
                    "policy",
                    f'widen program[{index}].cwd to cover "{value}", or add a second [[program]] '
                    f"rule for {program_name!r} with that cwd",
                    Edit(f"program[{index}].cwd", value, widens),
                ),
                Remedy(
                    "program",
                    f"run the exec from a directory within {pretty_location(rule.cwd)}",
                ),
            )
        case CwdMissingAtoms(missing=missing):
            names = ", ".join(sorted(missing))
            return (
                Remedy(
                    "policy",
                    f"drop the obligation deliberately: remove {names} from "
                    f"program[{index}].requires",
                    Edit(f"program[{index}].requires", f"remove {names}", widens=True),
                ),
                Remedy(
                    "program",
                    "; ".join(
                        _atom_program_remedy(policy, a, "the cwd") for a in sorted(missing)
                    ),
                ),
            )
        case UnvouchedArgument(argument=n):
            return (
                Remedy(
                    "policy",
                    "in a TOML policy unknown-arguments defaults to false; setting it true "
                    "admits arguments of unknown provenance",
                    Edit(f"program[{index}].unknown-arguments", "true", widens=True),
                ),
                Remedy(
                    "program",
                    f"pass argument {n} as a literal, or as a value the analysis located; an "
                    "f-string, a .strip() result and a checked-but-computed string are all "
                    f"unvouched for ({_SUBSET_POINTER})",
                ),
            )
        case ArgumentOutside(argument=n, location=loc):
            value, widens = _location_value(loc)
            permitted = ", ".join(pretty_location(a) for a in rule.argument_locations)
            return (
                Remedy(
                    "policy",
                    f'add "{value}" to program[{index}].argument-locations '
                    f"(currently: {permitted})",
                    Edit(f"program[{index}].argument-locations", value, widens),
                ),
                Remedy("program", f"pass argument {n} as a path within {permitted}"),
            )
        case ArgumentMissingAtoms(argument=n, missing=missing):
            names = ", ".join(sorted(missing))
            return (
                Remedy(
                    "policy",
                    f"drop the obligation deliberately: remove {names} from "
                    f"program[{index}].argument-atoms",
                    Edit(f"program[{index}].argument-atoms", f"remove {names}", widens=True),
                ),
                Remedy(
                    "program",
                    "; ".join(
                        _atom_program_remedy(policy, a, f"argument {n}") for a in sorted(missing)
                    ),
                ),
            )


def _network_near_misses(
    policy: Policy, method: str, scheme: str, host: str, port: int
) -> tuple[Remedy, ...]:
    """For every rule that already names this host, the clauses of ``matches_endpoint`` it failed:
    a rule one field away is a likelier intent than a whole new rule."""
    out: list[Remedy] = []
    for i, rule in enumerate(policy.network):
        if not _host_matches(rule.host, host):
            continue
        failed = []
        if scheme not in rule.schemes:
            failed.append(f"schemes {sorted(rule.schemes)} does not admit {scheme}")
        if rule.ports:
            if port not in rule.ports:
                failed.append(f"ports {sorted(rule.ports)} does not admit {port}")
        elif port != default_port(scheme):
            failed.append(
                f"ports is empty, which means the scheme's default port ({default_port(scheme)}) "
                f"only, not {port}"
            )
        if rule.methods and method not in rule.methods:
            failed.append(f"methods {sorted(rule.methods)} does not admit {method}")
        if failed:
            out.append(
                Remedy(
                    "policy",
                    f"network[{i}] already names host {rule.host!r} but " + "; ".join(failed),
                    Edit(f"network[{i}]", "; ".join(failed), widens=True),
                )
            )
    return tuple(out)


def _unproven_remedies(subject: Literal["path", "cwd", "url"]) -> tuple[Remedy, ...]:
    """A value the analysis could not pin down. The policy channel is empty in every case, and
    saying so is the point: a policy grants locations and endpoints, and nothing here is one."""
    match subject:
        case "path":
            return (
                Remedy(
                    "policy",
                    "none -- a policy grants locations, and this one is not known; no allowance "
                    "can cover a path the analysis cannot place",
                ),
                Remedy(
                    "program",
                    "prove the location: build the path from literals under the root, guard the "
                    'untrusted component (assert "/" not in c and c not in (".", ".."), or a '
                    "re.fullmatch), or pass it through a function whose annotation guarantees it "
                    f"({_SUBSET_POINTER})",
                ),
            )
        case "cwd":
            return (
                Remedy("policy", "none -- an unproven cwd is not something a policy can grant"),
                Remedy(
                    "program",
                    'pass cwd= a path the analysis can place: pathlib.Path("<dir>") / "<name>" '
                    f"built from literals or from guarded components ({_SUBSET_POINTER})",
                ),
            )
        case "url":
            return (
                Remedy(
                    "policy",
                    "none -- network rules match a scheme, host and port, and none of them is "
                    "known here",
                ),
                Remedy(
                    "program",
                    "use a literal URL, or guard it: assert "
                    'urllib.parse.urlsplit(u).scheme == "https" and '
                    'urllib.parse.urlsplit(u).netloc == "<host>"',
                ),
            )


def remedies_for(policy: Policy, site: Site, cause: Cause) -> tuple[Remedy, ...]:
    """The smallest policy change that would permit *site*, and where the program could instead
    prove the fact itself. Both channels are always present, policy first.

    Every policy edit here is one of four shapes the language actually has: adding an entry to a
    list, replacing one location, removing a ``requires`` entry, or setting ``unknown-arguments``.
    Where no policy edit exists -- an unproven value, a subset rule -- the policy remedy says so
    rather than inventing a key."""
    match cause:
        case NotPermitted(kind=kind, location=loc):
            value, widens = _location_value(loc)
            key = _FILESYSTEM_KEY[kind]
            current = [pretty_location(a) for a in {"read": policy.read, "write": policy.write, "list": policy.listing}[kind]]
            widening = " -- this covers more than the site needs" if widens else ""
            return (
                Remedy(
                    "policy",
                    f'add "{value}" to [filesystem] {key}{widening} '
                    f"(currently: {_named(current, 'nothing is permitted')})",
                    Edit(f"filesystem.{key}", value, widens),
                ),
                Remedy(
                    "program",
                    f"move the {kind} under one of the permitted locations, or build the path "
                    f"from those components ({_named(current, 'there are none')})",
                ),
            )
        case Unproven(subject=subject):
            return _unproven_remedies(subject)
        case NetlocNotFinite():
            return (
                Remedy(
                    "policy",
                    "none -- a rule names hosts, so a netloc that is not a finite set of them "
                    "cannot be held against one",
                ),
                Remedy(
                    "program",
                    'constrain the netloc to a finite set: == "<host>", or in ("a", "b")',
                ),
            )
        case UnknownProgram(program=name):
            cwd = site.cwd if isinstance(site, ExecSite) else None
            value = _location_value(cwd.location)[0] if isinstance(cwd, Located) else "."
            granted = sorted({p.name for p in policy.programs})
            return (
                Remedy(
                    "policy",
                    f"no [[program]] rule names {name!r} (the policy names: "
                    f"{_named(granted, 'no programs at all')}); add one",
                    Edit("program", _program_block(name, value)),
                ),
                Remedy(
                    "program",
                    "no change to the program can grant a program the policy does not name",
                ),
            )
        case NoSubcommand(program=name):
            declared = [
                " ".join(p.subcommand) for p in policy.programs if p.name == name and p.subcommand
            ]
            words = []
            if isinstance(site, ExecSite):
                for a in site.arguments:
                    text = known_text(a)
                    if text is None:
                        break
                    words.append(text)
            cwd = site.cwd if isinstance(site, ExecSite) else None
            value = _location_value(cwd.location)[0] if isinstance(cwd, Located) else "."
            return (
                Remedy(
                    "policy",
                    f"the declared subcommands of {name!r} are: {_named(declared, 'none')}; "
                    "add a rule for this one",
                    Edit(
                        "program",
                        _program_block(name, value, " ".join(words[:2]) if words else ""),
                    ),
                ),
                Remedy(
                    "program",
                    "spell the subcommand out as literal strings; a computed subcommand matches "
                    "no rule, and a program with any subcommand rule fails closed",
                ),
            )
        case ExecDenied(program=name, mismatches=mismatches):
            out: list[Remedy] = []
            for mismatch in mismatches:
                out.extend(
                    _exec_detail_remedies(
                        policy, name, mismatch.rule_index, mismatch.rule, mismatch.detail
                    )
                )
            return tuple(out)
        case EndpointUnmatched(method=method, scheme=scheme, host=host, port=port):
            lines = ["[[network]]", f'host    = "{host}"']
            if scheme != "https":
                lines.append(f'schemes = ["{scheme}"]')
            if port != default_port(scheme):
                lines.append(f"ports   = [{port}]")
            return (
                Remedy(
                    "policy",
                    f"no [[network]] rule admits {method} {scheme}://{host}:{port}; add one",
                    Edit("network", "\n".join(lines) + "\n"),
                ),
                *_network_near_misses(policy, method, scheme, host, port),
                Remedy("program", "direct the request at an endpoint some rule already permits"),
            )
        case UrlMissingAtoms(candidates=candidates):
            index, _rule, missing = min(candidates, key=lambda c: len(c[2]))
            names = ", ".join(sorted(missing))
            return (
                Remedy(
                    "policy",
                    f"drop the obligation deliberately: remove {names} from "
                    f"network[{index}].requires",
                    Edit(f"network[{index}].requires", f"remove {names}", widens=True),
                ),
                Remedy(
                    "program",
                    "; ".join(
                        _atom_program_remedy(policy, a, "the URL") for a in sorted(missing)
                    ),
                ),
            )
        case UndeclaredValidation(name=name):
            declared = [v.name for v in policy.validations]
            return (
                Remedy(
                    "policy",
                    f"the policy declares: {_named(declared, 'no validations')}; declare this one",
                    Edit(
                        "validation",
                        f'[[validation]]\nname = "{name}"\nargv = ["<checker>"]\n',
                    ),
                ),
                Remedy("program", "call a validation the policy declares"),
            )
        case CheckCwdOutside(name=name, location=loc, permitted=permitted):
            index = next(
                (i for i, v in enumerate(policy.validations) if v.name == name), 0
            )
            value, widens = _location_value(loc)
            return (
                Remedy(
                    "policy",
                    f'widen validation[{index}].cwd to cover "{value}"',
                    Edit(f"validation[{index}].cwd", value, widens),
                ),
                Remedy(
                    "program",
                    f"run the check from a directory within {pretty_location(permitted)}",
                ),
            )


def violation_remedies(phase: str | None) -> tuple[Remedy, ...]:
    where = f"in the {phase} pass" if phase else "by the analysis"
    return (
        Remedy(
            "policy",
            "none -- the subset the analysis accepts is not configurable; no policy grants this",
        ),
        Remedy(
            "program",
            f"a rule of the Python subset, checked {where} before any policy is consulted; "
            f"rewrite to satisfy it ({_SUBSET_POINTER})",
        ),
    )


# ---------------------------------------------------------------------------
# building the explanation
# ---------------------------------------------------------------------------


def _span(filename: str, lines: list[str], node: object) -> Span:
    line = getattr(node, "lineno", None)
    column = getattr(node, "col_offset", None)
    end_line = getattr(node, "end_lineno", None)
    end_column = getattr(node, "end_col_offset", None)
    text = lines[line - 1].rstrip() if line is not None and 0 < line <= len(lines) else None
    return Span(
        filename,
        line,
        None if column is None else column + 1,
        end_line,
        None if end_column is None else end_column + 1,
        text,
    )


def explain(
    source: str,
    filename: str,
    policy: Policy,
    root: pathlib.Path | None = None,
    policy_source: PolicySource = PolicySource("default"),
) -> Explanation:
    """Analyse and evaluate, then report. Raises ``SyntaxError``, exactly as ``check`` does."""
    outcome = check(source, filename, policy, root)
    lines = source.splitlines()
    denied_sites = (
        [] if isinstance(outcome, Accepted) else [id(d.site) for d in outcome.denials]
    )
    sites = tuple(
        SiteLine(
            _span(filename, lines, s.node),
            operation_of(s),
            s.what,
            s.confined,
            id(s) in denied_sites,
            describe_sink(s),
        )
        for s in outcome.report.sinks
    )
    root_text = None if root is None else str(root)
    if isinstance(outcome, Accepted):
        return Explanation(
            filename=filename,
            root=root_text,
            policy=policy_source,
            accepted=True,
            findings=(),
            sites=sites,
            phase=outcome.report.phase,
        )

    findings = [
        Finding(
            "violation",
            _span(filename, lines, node),
            None,
            outcome.report.phase or "analysis",
            "",
            what,
            None,
            violation_remedies(outcome.report.phase),
        )
        for node, what in outcome.violations
    ]
    findings += [
        Finding(
            "denial",
            _span(filename, lines, d.site.node),
            operation_of(d.site),
            d.site.what,
            describe_sink(d.site),
            d.reason,
            d.cause,
            () if d.cause is None else remedies_for(policy, d.site, d.cause),
        )
        for d in outcome.denials
    ]
    return Explanation(
        filename=filename,
        root=root_text,
        policy=policy_source,
        accepted=False,
        findings=tuple(findings),
        sites=sites,
        phase=outcome.report.phase,
    )


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _where(span: Span) -> str:
    if span.line is None:
        return span.file
    return f"{span.file}:{span.line}" + ("" if span.column is None else f":{span.column}")


def _describe_policy(source: PolicySource) -> str:
    match source.kind:
        case "default":
            return "the built-in default policy"
        case "explicit":
            return str(source.path)
        case "ambient":
            return f"{source.path} (ambient, governing {source.governs})"


def render(explanation: Explanation) -> str:
    out: list[str] = []
    count = len(explanation.findings)
    if explanation.accepted:
        out.append(f"{explanation.filename}: accepted")
    else:
        problems = "1 problem" if count == 1 else f"{count} problems"
        out.append(f"{explanation.filename}: rejected -- {problems}")
    out.append(f"policy: {_describe_policy(explanation.policy)}")
    out.append(f"root:   {explanation.root or 'not given'}")
    if any(f.kind == "violation" for f in explanation.findings):
        out.append(
            "note:   the policy was not evaluated -- the program must satisfy the subset first"
        )
    out.append("")

    for n, finding in enumerate(explanation.findings, start=1):
        label = "violation" if finding.kind == "violation" else "denied"
        out.append(f"{n}. {_where(finding.span)}  {label}  {finding.what}  {finding.reason}")
        if finding.span.source:
            out.append(f"     {finding.span.source.strip()}")
        if finding.detail:
            out.append(f"   what:     {finding.operation}, {finding.detail}")
        for channel in ("policy", "program"):
            texts = [r for r in finding.remedies if r.channel == channel]
            if not texts:
                continue
            for remedy in texts:
                out.append(f"   {channel + ':':9} {remedy.text}")
                edit = remedy.edit
                if edit is not None and "\n" in edit.add.rstrip("\n"):
                    for edit_line in edit.add.rstrip("\n").splitlines():
                        out.append(f"               {edit_line}")
        out.append("")

    out.append(f"sites ({len(explanation.sites)}):")
    for site in explanation.sites:
        status = "DENIED" if site.denied else ("ok" if site.confined else "UNCONFINED")
        out.append(f"   {_where(site.span)}  {site.what}  {status}  {site.detail}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# the JSON document
# ---------------------------------------------------------------------------


def _location_json(loc: LocationFact) -> dict:
    return {"pretty": pretty_location(loc), "policy": policy_spelling(loc)}


def _rule_json(rule: NetworkRule) -> dict:
    return {
        "host": rule.host,
        "schemes": sorted(rule.schemes),
        "ports": sorted(rule.ports),
        "methods": sorted(rule.methods),
    }


def _cause_json(cause: Cause) -> dict:
    match cause:
        case NotPermitted(kind=kind, location=loc):
            return {"kind": "not-permitted-location", "access": kind, "location": _location_json(loc)}
        case Unproven(subject=subject):
            return {"kind": "unproven", "subject": subject}
        case NetlocNotFinite():
            return {"kind": "netloc-not-finite"}
        case UnknownProgram(program=name):
            return {"kind": "unknown-program", "program": name}
        case NoSubcommand(program=name):
            return {"kind": "no-subcommand", "program": name}
        case ExecDenied(program=name, mismatches=mismatches):
            return {
                "kind": "exec-denied",
                "program": name,
                "mismatches": [
                    {
                        "rule_index": m.rule_index,
                        "rule": {
                            "name": m.rule.name,
                            "cwd": _location_json(m.rule.cwd),
                            "subcommand": list(m.rule.subcommand),
                        },
                        "detail": _detail_json(m.detail),
                    }
                    for m in mismatches
                ],
            }
        case EndpointUnmatched(method=method, scheme=scheme, host=host, port=port):
            return {
                "kind": "endpoint-unmatched",
                "method": method,
                "scheme": scheme,
                "host": host,
                "port": port,
            }
        case UrlMissingAtoms(method=method, scheme=scheme, host=host, port=port, candidates=cs):
            return {
                "kind": "url-missing-atoms",
                "method": method,
                "scheme": scheme,
                "host": host,
                "port": port,
                "candidates": [
                    {"rule_index": i, "rule": _rule_json(rule), "missing": sorted(missing)}
                    for i, rule, missing in cs
                ],
            }
        case UndeclaredValidation(name=name):
            return {"kind": "undeclared-validation", "name": name}
        case CheckCwdOutside(name=name, location=loc, permitted=permitted):
            return {
                "kind": "check-cwd-outside",
                "name": name,
                "location": _location_json(loc),
                "permitted": _location_json(permitted),
            }


def _detail_json(detail: ExecDetail) -> dict:
    match detail:
        case CwdOutside(location=loc):
            return {"kind": "cwd-outside", "location": _location_json(loc)}
        case CwdMissingAtoms(missing=missing):
            return {"kind": "cwd-missing-atoms", "missing": sorted(missing)}
        case UnvouchedArgument(argument=n):
            return {"kind": "unvouched-argument", "argument": n}
        case ArgumentOutside(argument=n, location=loc):
            return {"kind": "argument-outside", "argument": n, "location": _location_json(loc)}
        case ArgumentMissingAtoms(argument=n, missing=missing):
            return {
                "kind": "argument-missing-atoms",
                "argument": n,
                "missing": sorted(missing),
            }


def _span_json(span: Span) -> dict:
    return {
        "file": span.file,
        "line": span.line,
        "column": span.column,  # 1-based
        "end_line": span.end_line,
        "end_column": span.end_column,
        "source": span.source,
    }


def _remedy_json(remedy: Remedy) -> dict:
    return {
        "channel": remedy.channel,
        "text": remedy.text,
        "edit": None
        if remedy.edit is None
        else {"path": remedy.edit.path, "add": remedy.edit.add, "widens": remedy.edit.widens},
    }


def to_json(explanation: Explanation) -> dict:
    """The same content, machine-readably. Built key by key rather than with ``asdict``, so no AST
    node and no frozenset can leak into the document."""
    return {
        "certorail": 1,
        "file": explanation.filename,
        "root": explanation.root,
        "policy": {
            "kind": explanation.policy.kind,
            "path": None if explanation.policy.path is None else str(explanation.policy.path),
            "governs": None
            if explanation.policy.governs is None
            else str(explanation.policy.governs),
        },
        "accepted": explanation.accepted,
        "phase": explanation.phase,
        "findings": [
            {
                "kind": f.kind,
                "where": _span_json(f.span),
                "operation": f.operation,
                "what": f.what,
                "detail": f.detail,
                "reason": f.reason,
                "cause": None if f.cause is None else _cause_json(f.cause),
                "remedies": [_remedy_json(r) for r in f.remedies],
            }
            for f in explanation.findings
        ],
        "sites": [
            {
                "where": _span_json(s.span),
                "operation": s.operation,
                "what": s.what,
                "confined": s.confined,
                "denied": s.denied,
                "detail": s.detail,
            }
            for s in explanation.sites
        ],
    }


# ---------------------------------------------------------------------------
# the CLI
# ---------------------------------------------------------------------------


def explain_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="certorail explain",
        description="Explain why a program is rejected, and what would have to change. "
        "Does not run it.",
    )
    add_common_arguments(parser)
    parser.add_argument("--json", action="store_true", help="one JSON document on stdout")
    ns = parser.parse_args(argv)

    source, filename = read_source(ns, parser)
    root = ns.root.resolve()
    policy, described = load_policy_described(ns.policy, root)
    try:
        result = explain(source, filename, policy, root, described)
    except SyntaxError as e:
        print(f"{filename}:{e.lineno}: syntax error: {e.msg}", file=sys.stderr)
        return 2
    print(json.dumps(to_json(result), indent=2) if ns.json else render(result))
    return 0 if result.accepted else 1
