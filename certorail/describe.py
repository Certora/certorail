"""``certorail --describe``: the policy as the agent needs it.

The TOML is the policy's *implementation* -- reviewer comments, checker paths, redirect modes,
defaults left implicit, ``[[apply]]`` lines that expand to forty templates. The agent writing
confined programs needs its *interface*: exactly the set of operations ``Policy.evaluate`` will
accept, in the vocabulary the program has to use (template signatures, hole names, validation
names and parameters, atom regexes), with every default spelled out. This renders that from the
loaded ``Policy``, so what the agent reads is what will be enforced. A Claude Code
``SessionStart`` hook running ``certorail --describe`` puts it into the agent's context.

Values the program supplies are written in one compact notation, explained in the program-author
guide (``SUBSET_PROMPT.md``, which the session hook injects ahead of this text): ``</re/>`` text
matching a regex, ``<(a|b)>`` one of, ``<path within L, M>`` a proven path, ``<literal>``,
``<any>``, ``<... validated X>``. So a flag reads ``-atime </[+-]?\\d+/>``.
"""
from collections.abc import Iterable

from .analysis import pretty_location, pretty_regex
from .effects import EVERYTHING, Effects
from .ids import BUILTIN_ATOMS, NOT_OPTION, Atom, FlagName, SourceId
from .policy import NetworkRule, Policy, Program, Validation, literal_slot, pretty_locations
from .templates import CWD, Constraint, Each, Flags, Flagset, HoleRef, Template, Token

def constraint_phrase(c: Constraint, sources: frozenset[SourceId]) -> str:
    if c.any:
        return "<any>"
    parts: list[str] = []
    if c.locations:
        parts.append("path within " + ", ".join(pretty_location(loc) for loc in c.locations))
    if c.regex is not None:
        parts.append(pretty_regex(c.regex))
    if c.literal:
        parts.append("literal")
    validated = sorted(a for a in c.atoms if a not in sources)
    provenance = sorted(a for a in c.atoms if a in sources)
    if validated:
        parts.append("validated " + ", ".join(validated))
    if provenance:
        parts.append("from " + ", ".join(provenance))
    return "<" + " ".join(parts) + ">"


def flag_demands(fs: Flagset, flag: FlagName) -> str:
    """What a flag demands while present, as a suffix; empty when nothing."""
    demands = fs.requires.get(flag)
    if not demands:
        return ""
    parts = [
        f"{'the cwd' if target == CWD else target} validated by {', '.join(sorted(atoms))}"
        for target, atoms in sorted(demands.items())
    ]
    return " (requires " + "; ".join(parts) + ")"


def flagset_lines(fs: Flagset, sources: frozenset[SourceId]) -> list[str]:
    if fs.any:
        return ["any flag, any value: the tool is trusted with its own options"]
    out: list[str] = []
    plain = sorted(f for f in fs.bare if f not in fs.requires)
    if plain:
        out.append("bare: " + " ".join(plain))
    for name in sorted(f for f in fs.bare if f in fs.requires):
        out.append(f"{name}{flag_demands(fs, name)}")
    for name, c in fs.valued.items():  # declaration order: the author's grouping
        out.append(f"{name} {constraint_phrase(c, sources)}{flag_demands(fs, name)}")
    if fs.expand_single_flags:
        out.append("bundled short flags accepted: -lr is -l -r (bare single-letter flags only)")
    return out


def signature(t: Template) -> str:
    words: list[str] = []
    for p in t.pieces:
        if isinstance(p, str):
            words.append(p)
        else:
            words.append(p.name + ("..." if p.variadic else ""))
    return " ".join(words)


# -- effects (EFFECTS.md) -------------------------------------------------------------------


def writes_phrase(e: Effects) -> str:
    """A write set as a phrase: the regions, and a whole medium as "anything ..."."""
    if e.empty:
        return "none"
    parts : list[str] = sorted(e.regions)
    if "fs" in e.media:
        parts.append("anything on the filesystem")
    if "network" in e.media:
        parts.append("anything remote")
    return "writes " + ", ".join(parts)


def depends_phrase(e: Effects) -> str:
    if e == EVERYTHING:
        return "everything"
    parts : list[str] = sorted(e.regions)
    if "fs" in e.media:
        parts.append("any filesystem state")
    if "network" in e.media:
        parts.append("any remote state")
    return ", ".join(parts)


def effects_line(policy: Policy, rule: Program | Validation) -> str:
    """What a grant does to the state atoms depend on, with the media it forgoes."""
    if rule.effect_free:
        return "effects: none (effect-free: kills no facts)"
    notes = []
    if not rule.network:
        notes.append("no network")
    if not rule.write_fs:
        notes.append("no filesystem writes")
    text = f"effects: {writes_phrase(policy.write_set(rule))}"
    return text + (f" ({'; '.join(notes)})" if notes else "")


def jail_line(rule: Program | Validation) -> str | None:
    """The grant's jail (childjail), when it restricts anything: what the OS denies the child.
    The media are enforced this way; ``writes`` stays the rule's claim."""
    j = rule.jail
    if not j.restricts:
        return None
    parts: list[str] = []
    if not j.network:
        parts.append("no network")
    if not j.write_fs:
        parts.append("no filesystem writes (a private TMPDIR only)")
    if not j.spawn:
        parts.append("no subprocesses")
    if j.confined:
        parts.append("sees only what the policy grants (the filesystem section as mounts)")
        extras = [f"{pretty_location(loc)} (read)" for loc in rule.mount_read]
        extras += [f"{pretty_location(loc)} (write)" for loc in rule.mount_write]
        if extras:
            parts.append("also sees: " + ", ".join(extras))
    if j.env is not None:
        if j.env.empty:
            parts.append("environment: empty")
        else:
            passed = ", ".join(j.env.passed) if j.env.passed else "nothing passed through"
            sets = "".join(f"; sets {k}={v}" for k, v in j.env.sets)
            parts.append(f"environment: {passed}{sets}")
    return "jailed (enforced by the OS): " + "; ".join(parts)


def dies_on(policy: Policy, atom_name: Atom) -> str:
    """Every declared operation whose write set meets the atom's read set, computed."""
    hits: list[str] = []
    for p in policy.programs:
        if policy.kills(p, atom_name):
            hits.append(" ".join(p.leading_words))
    for r in policy.network:
        if policy.kills(r, atom_name):
            methods = "/".join(sorted(r.methods)) if r.methods else "any method"
            hits.append(f"{methods} {r.host}")
    for v in policy.validations:
        if policy.kills(v, atom_name):
            hits.append(f"check {v.name}")
    state = policy.read_set(atom_name)
    if "fs" in state.media or any(r.medium == "fs" and r.name in state.regions for r in policy.regions):
        hits.append("any file write")
    return "; ".join(hits) if hits else "nothing this policy permits"


def _regions(policy: Policy) -> list[str]:
    out: list[str] = []
    for r in policy.regions:
        if r.medium == "network":
            where = "remote"
        else:
            where = "on disk at " + ", ".join(pretty_location(loc) for loc in r.footprint)
        out.append(f"- {r.name} ({where})" + (f": {r.about}" if r.about else ""))
    return out


# -- the sections -------------------------------------------------------------------------


def _program(p: Program, policy: Policy) -> list[str]:
    out: list[str] = []
    origin = f"    [from {p.origin}]" if p.origin else ""
    t = p.template
    if t is None:
        out.append("- " + " ".join(p.leading_words) + origin)
        out.append(f"    cwd within {pretty_locations(p.cwd)}")
        if p.requires:
            out.append(f"    cwd validated by {', '.join(sorted(p.requires))} (check right before)")
        if p.source:
            out.append(f"    yields {p.source}: extract values from the result with certora.extract / extract_all / lines")
        out.append(f"    {effects_line(policy, p)}")
        if (jailed := jail_line(p)) is not None:
            out.append(f"    {jailed}")
        out.append("    exactly these words: no further arguments")
        return out
    out.append("- " + signature(t) + origin)
    out.append(f"    cwd within {pretty_locations(p.cwd)}")
    if p.requires:
        out.append(f"    cwd validated by {', '.join(sorted(p.requires))} (check right before)")
    if p.source:
        out.append(f"    yields {p.source}: extract values from the result with certora.extract / extract_all / lines")
    out.append(f"    {effects_line(policy, p)}")
    if (jailed := jail_line(p)) is not None:
        out.append(f"    {jailed}")
    keyword_only = t.keyword_only
    if keyword_only:
        out.append(f"    bind by keyword: {', '.join(keyword_only)}")
    refs = [piece for piece in t.pieces if isinstance(piece, HoleRef)]
    for i, ref in enumerate(refs):
        if ref.variadic and ref is not t.pieces[-1] and t.terminable(ref.name) and ref.name not in keyword_only:
            nxt = refs[i + 1].name if i + 1 < len(refs) else "the end"
            out.append(
                f"    {ref.name}... ends at the first positional that is not a flag; {nxt} begins there "
                "(a value that could be either is rejected: bind by keyword)"
            )
    interior = [piece for piece in t.pieces[len(t.leading_words):] if isinstance(piece, str)]
    if interior:
        out.append(f"    inserted by the host, do not spell: {' '.join(interior)}")
    sources = policy.source_atoms
    for name, hole in t.holes.items():
        match hole:
            case Token(constraint=c):
                out.append(f"    {name}: {constraint_phrase(c, sources)}")
            case Each(constraint=c, min=minimum):
                need = f", at least {minimum}" if minimum else ""
                out.append(f"    {name}...: each {constraint_phrase(c, sources)}{need}")
            case Flags(flagset=fs):
                out.append(f"    {name}...: a list of flags --")
                out.extend(f"        {line}" for line in flagset_lines(fs, sources))
    return out


def _validation(v: Validation, policy: Policy, defined: frozenset[Atom]) -> list[str]:
    params = ", ".join(f"{p}=<str>" for p in v.params)
    cwd = "" if v.cwd is None else f"cwd=<path within {', '.join(pretty_location(l) for l in v.cwd)}>"
    call = ", ".join(x for x in (f'"{v.name}"', params, cwd) if x)
    out = [f"- certora.check({call})"]
    for key, atoms in v.establishes.items():
        kinds = ", ".join(
            f"{a} ({'built in' if a in BUILTIN_ATOMS else 'defined' if a in defined else 'pure' if a in v.pure_atoms else 'environmental'})"
            for a in sorted(atoms)
        )
        out.append(f"    establishes on {key}: {kinds}")
    out.append(f"    {effects_line(policy, v)}")
    if (jailed := jail_line(v)) is not None:
        out.append(f"    {jailed}")
    if len(v.params) == 1:
        out.append(f'    also as an expression: certora.check_single("{v.name}", value)')
    on_literals = sorted(a for atoms in v.establishes.values() for a in atoms if literal_slot(v, a) is not None)
    if on_literals:
        out.append(
            f"    on a literal: no check needed -- a literal (or a value whose text is exactly known) "
            f"where {', '.join(on_literals)} is required is checked at analysis time and carries it"
        )
    return out


BUILTIN_MEANING = {
    "no-slash": "the text has no '/': a single path component",
    "no-parent-traversal": "the text has no '..' component",
    "not-absolute": "the text does not begin with '/'",
    "not-dot-dot": "the text is not '..'",
    "not-option": "the text does not begin with '-', so no tool reads it as an option. Every hole not preceded by a spelled '--' requires it",
}


def _atoms(policy: Policy) -> list[str]:
    defined = {a.name: a.regex for a in policy.atoms}
    pure: set[Atom] = set()
    environmental: set[Atom] = set()
    for v in policy.validations:
        for atoms in v.establishes.values():
            for a in atoms:
                if a in defined or a in BUILTIN_ATOMS:
                    continue
                (pure if a in v.pure_atoms else environmental).add(a)
    out: list[str] = []
    for name in sorted(defined):
        out.append(f"- {name}: <{pretty_regex(defined[name])}> -- a literal has it; so does a variable after "
                   "assert re.fullmatch with that exact regex")
    for name in sorted(pure):
        literal = any(literal_slot(v, name) is not None for v in policy.validations)
        out.append(
            f"- {name}: a property of the value's text, established by a check; survives calls"
            + ("; a literal carries it without a check (checked at analysis time)" if literal else "")
        )
    out.append(
        "- built in (every policy; a literal or a guard such as assert not s.startswith('-') "
        "establishes them, and a check may vouch for one): "
        + "; ".join(f"{name}: {BUILTIN_MEANING[name]}" for name in BUILTIN_ATOMS)
    )
    for name in sorted(environmental):
        state = policy.read_set(name)
        if state == EVERYTHING:
            out.append(
                f"- {name}: a property of the environment, established by a check; dies at any "
                "effectful call, so check immediately before the use"
            )
        else:
            out.append(
                f"- {name}: a property of the environment, established by a check; depends on "
                f"{depends_phrase(state)}; dies on: {dies_on(policy, name)}"
            )
    for name in sorted(policy.source_atoms):
        out.append(
            f"- {name}: provenance -- a value extracted, unmodified, from the source that yields "
            "it (certora.extract / extract_all / lines / field, or `for line in f`); any string "
            "operation drops it; no literal has it"
        )
    return out


def _sources(policy: Policy) -> list[str]:
    return [
        f"- reading under {pretty_locations(s.locations)} (read_text, open, f.read, for line in f) yields {s.name}"
        for s in policy.sources
    ]


def _network(r: NetworkRule, policy: Policy) -> str:
    methods = ", ".join(sorted(r.methods)) if r.methods else "any method"
    schemes = "/".join(sorted(r.schemes))
    ports = (":" + ",".join(str(p) for p in sorted(r.ports))) if r.ports else ""
    line = f"- {methods} {schemes}://{r.host}{ports}"
    if r.paths:
        line += f"; path within {pretty_locations(r.paths)}"
    if r.requires:
        line += "; the URL must be validated by " + ", ".join(sorted(ra.name for ra in r.requires))
    if r.source:
        line += f"; yields {r.source}"
    ws = policy.write_set(r)
    if not ws.empty:
        line += f"; {writes_phrase(ws)}"
    return line


def _section(title: str, lines: Iterable[str]) -> list[str]:
    body = list(lines)
    return [f"## {title}", *(body or ["- none"]), ""]


def describe(policy: Policy, origin: str, governs: str | None = None) -> str:
    """The policy's interface, as text for the program author."""
    head = [
        "# certorail: what a confined program may do here",
        f"Policy: {origin}"
        + (
            f" -- governs {governs} and every directory below it that has no policy of its own"
            if governs
            else ""
        ),
        "Programs are analysed before they run; every operation not listed here is denied. "
        "Locations are relative to the sandbox root (the working directory) unless they begin "
        "with '/'. Check without running: certorail-run --check -c SOURCE",
        *(
            [f"Rulesets composed into this policy: {', '.join(policy.applied)}"
             + (" (base.toml is the config directory's base ruleset; base = false opts out)" if "base.toml" in policy.applied else "")]
            if policy.applied else []
        ),
        "",
    ]
    fs = [
        f"- {kind}: " + (", ".join(pretty_location(loc) for loc in locs) if locs else "nothing")
        for kind, locs in (("read", policy.read), ("write", policy.write), ("list", policy.listing))
    ]
    if policy.no_write:
        fs.append(
            "- protected (no write may touch these, whatever write grants; a written path must "
            "provably lie outside them): " + ", ".join(pretty_location(loc) for loc in policy.no_write)
        )
    defined = frozenset(a.name for a in policy.atoms)
    programs = [line for p in policy.programs for line in _program(p, policy)]
    if policy.default_allow:
        listed = sorted({p.name for p in policy.programs})
        programs.append(
            "- DEFAULT-ALLOW: any program not named above"
            + (f" (and not denied: {', '.join(sorted(policy.denied - set(listed)))})" if policy.denied - set(listed) else "")
            + " runs with any arguments and your authority: unjailed, its effects unknown (every environmental "
            "fact dies at it). Only the leading program name decides; a program named above keeps exactly "
            "its listed shapes"
        )
    validations = [line for v in policy.validations for line in _validation(v, policy, defined)]
    return "\n".join(
        head
        + _section("Filesystem", fs)
        + _section("Programs: certora.exec(<words>, <holes>, cwd=<proven path>)", programs)
        + _section("Validations", validations)
        + (
            _section("Regions: the state checks depend on and commands change", _regions(policy))
            if policy.regions
            else []
        )
        + _section("Atoms", _atoms(policy))
        + _section("Network: certora.network.<method>(url)", (_network(r, policy) for r in policy.network))
        + (_section("Sources: file reads that yield provenance", _sources(policy)) if policy.sources else [])
    ).rstrip() + "\n"
