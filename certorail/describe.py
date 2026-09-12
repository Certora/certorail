"""``certorail --describe``: the policy as the agent needs it.

The TOML is the policy's *implementation* -- reviewer comments, checker paths, redirect modes,
defaults left implicit, ``[[apply]]`` lines that expand to forty templates. The agent writing
confined programs needs its *interface*: exactly the set of operations ``Policy.evaluate`` will
accept, in the vocabulary the program has to use (template signatures, hole names, validation
names and parameters, atom regexes), with every default spelled out. This renders that from the
loaded ``Policy``, so what the agent reads is what will be enforced. A Claude Code
``SessionStart`` hook running ``certorail --describe`` puts it into the agent's context.

Values the program supplies are written in one compact notation, explained once in the header:
``</re/>`` text matching a regex, ``<(a|b)>`` one of, ``<path within L, M>`` a proven path,
``<literal>``, ``<any>``, ``<... validated X>``. So a flag reads ``-atime </[+-]?\\d+/>``.
"""
from collections.abc import Iterable

from .analysis import pretty_location, pretty_regex
from .effects import EVERYTHING, Effects
from .ids import BUILTIN_ATOMS, NOT_OPTION, Atom, FlagName, SourceId
from .policy import NetworkRule, Policy, Program, Validation, pretty_locations
from .templates import CWD, Constraint, Each, Flags, Flagset, Template, Token

NOTATION = (
    "Notation: <...> marks a value the program supplies. </re/> text known to match the regex "
    "(a literal, or a variable guarded by re.fullmatch with that regex); <(a|b)> one of; "
    "<path within L, M> a proven path within one of the locations; <literal> text the program "
    "itself names (a literal or a constant), never a value read from a file, argv or an API; "
    "<any> anything, unknown values included; <... validated X> also carries the atom X (a "
    "check, a guard, or a built-in property of the text); <... from S> came, unmodified, from "
    "the source S. Claims combine: </dev-\\w+/ literal> is a named database of that shape. NAME... "
    "takes a list. A flags list is flag names in order, each valued flag followed by its value; "
    "only the flags listed exist. Locations are spelled repos/** (at or below), repos/*/x (one "
    "arbitrary component), <re> (a component matching re), {a,b} (one of), a leading / for the "
    "filesystem root; a program proves a dynamic path is at a location with "
    'assert certora.pathmatch(p, "<that spelling>") -- for a URL, on urllib.parse.urlsplit(u).path.'
)


def _constraint(c: Constraint, sources: frozenset[SourceId]) -> str:
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


def _demands(fs: Flagset, flag: FlagName) -> str:
    """What a flag demands while present, as a suffix; empty when nothing."""
    demands = fs.requires.get(flag)
    if not demands:
        return ""
    parts = [
        f"{'the cwd' if target == CWD else target} validated by {', '.join(sorted(atoms))}"
        for target, atoms in sorted(demands.items())
    ]
    return " (requires " + "; ".join(parts) + ")"


def _flagset(fs: Flagset, sources: frozenset[SourceId]) -> list[str]:
    if fs.any:
        return ["any flag, any value: the tool is trusted with its own options"]
    out: list[str] = []
    plain = sorted(f for f in fs.bare if f not in fs.requires)
    if plain:
        out.append("bare: " + " ".join(plain))
    for name in sorted(f for f in fs.bare if f in fs.requires):
        out.append(f"{name}{_demands(fs, name)}")
    for name, c in fs.valued.items():  # declaration order: the author's grouping
        out.append(f"{name} {_constraint(c, sources)}{_demands(fs, name)}")
    return out


def _signature(t: Template) -> str:
    words: list[str] = []
    for p in t.pieces:
        if isinstance(p, str):
            words.append(p)
        else:
            words.append(p.name + ("..." if p.variadic else ""))
    return " ".join(words)


# -- effects (EFFECTS.md) -------------------------------------------------------------------


def _writes(e: Effects) -> str:
    """A write set as a phrase: the regions, and a whole medium as "anything ..."."""
    if e.empty:
        return "none"
    parts : list[str] = sorted(e.regions)
    if "fs" in e.media:
        parts.append("anything on the filesystem")
    if "network" in e.media:
        parts.append("anything remote")
    return "writes " + ", ".join(parts)


def _depends(e: Effects) -> str:
    if e == EVERYTHING:
        return "everything"
    parts : list[str] = sorted(e.regions)
    if "fs" in e.media:
        parts.append("any filesystem state")
    if "network" in e.media:
        parts.append("any remote state")
    return ", ".join(parts)


def _effects_line(policy: Policy, rule: Program | Validation) -> str:
    """What a grant does to the state atoms depend on, with the media it forgoes."""
    if rule.effect_free:
        return "effects: none (effect-free: kills no facts)"
    notes = []
    if not rule.network:
        notes.append("no network")
    if not rule.write:
        notes.append("no filesystem writes")
    text = f"effects: {_writes(policy.write_set(rule))}"
    return text + (f" ({'; '.join(notes)})" if notes else "")


def _dies_on(policy: Policy, atom_name: Atom) -> str:
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
    if "fs" in state.media:
        hits.append("any file write")
    else:
        under = [
            pretty_location(loc)
            for r in policy.regions
            if r.medium == "fs" and r.name in state.regions
            for loc in r.footprint
        ]
        if under:
            hits.append(f"file writes under {', '.join(under)} (below the check's cwd)")
    return "; ".join(hits) if hits else "nothing this policy permits"


def _regions(policy: Policy) -> list[str]:
    out: list[str] = []
    for r in policy.regions:
        if r.medium == "network":
            where = "remote"
        else:
            where = (
                "on disk at " + ", ".join(pretty_location(loc) for loc in r.footprint)
                + " below the check's cwd, and everything under it"
            )
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
        out.append(f"    {_effects_line(policy, p)}")
        out.append("    exactly these words: no further arguments")
        return out
    out.append("- " + _signature(t) + origin)
    out.append(f"    cwd within {pretty_locations(p.cwd)}")
    if p.requires:
        out.append(f"    cwd validated by {', '.join(sorted(p.requires))} (check right before)")
    if p.source:
        out.append(f"    yields {p.source}: extract values from the result with certora.extract / extract_all / lines")
    out.append(f"    {_effects_line(policy, p)}")
    keyword_only = t.keyword_only
    if keyword_only:
        out.append(f"    bind by keyword: {', '.join(keyword_only)}")
    interior = [piece for piece in t.pieces[len(t.leading_words):] if isinstance(piece, str)]
    if interior:
        out.append(f"    inserted by the host, do not spell: {' '.join(interior)}")
    sources = policy.source_atoms
    for name, hole in t.holes.items():
        match hole:
            case Token(constraint=c):
                out.append(f"    {name}: {_constraint(c, sources)}")
            case Each(constraint=c, min=minimum):
                need = f", at least {minimum}" if minimum else ""
                out.append(f"    {name}...: each {_constraint(c, sources)}{need}")
            case Flags(flagset=fs):
                out.append(f"    {name}...: a list of flags --")
                out.extend(f"        {line}" for line in _flagset(fs, sources))
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
    out.append(f"    {_effects_line(policy, v)}")
    if len(v.params) == 1:
        out.append(f'    also as an expression: certora.check_single("{v.name}", value)')
    return out


_BUILTIN_MEANING = {
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
        out.append(f"- {name}: a property of the value's text, established by a check; survives calls")
    out.append(
        "- built in (every policy; a literal or a guard such as assert not s.startswith('-') "
        "establishes them, and a check may vouch for one): "
        + "; ".join(f"{name}: {_BUILTIN_MEANING[name]}" for name in BUILTIN_ATOMS)
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
                f"{_depends(state)}; dies on: {_dies_on(policy, name)}"
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
        line += f"; {_writes(ws)}"
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
        "with '/'. Check without running: certorail -c SOURCE --check",
        NOTATION,
        "",
    ]
    fs = [
        f"- {kind}: " + (", ".join(pretty_location(loc) for loc in locs) if locs else "nothing")
        for kind, locs in (("read", policy.read), ("write", policy.write), ("list", policy.listing))
    ]
    defined = frozenset(a.name for a in policy.atoms)
    programs = [line for p in policy.programs for line in _program(p, policy)]
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
