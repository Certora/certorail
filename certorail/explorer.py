"""``certorail-explore``: the loaded policy as an interactive tree.

``--describe`` (``describe.py``) renders the policy's interface as text for the *program
author*. This renders the same loaded ``Policy`` for the *human auditor*: the grants in a tree
on the left, and whatever the cursor lands on -- a rule, one hole of its template, a flag
vocabulary, an atom, a region -- expanded on the right with its constraints and its
cross-references (which checks establish an atom, which rules consume it, what kills it).
What the explorer shows is what ``Policy.evaluate`` enforces; nothing here grants, loads or
interprets on its own.

A tree node's payload is a closure that builds its detail card, so the tree carries no
stringly identifiers and selection needs no dispatch.
"""
import argparse
import pathlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from functools import partial
from typing import Literal

from rich.console import Group, RenderableType
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Footer, Header, Static, Tree

from .analysis import pretty_location, pretty_regex
from .describe import (
    BUILTIN_MEANING,
    constraint_phrase,
    depends_phrase,
    dies_on,
    effects_line,
    flagset_lines,
    writes_phrase,
)
from .effects import EVERYTHING
from .host import load_policy, policy_origin
from .ids import BUILTIN_ATOMS, Atom, HoleName
from .policy import (
    NetworkRule,
    Param,
    Policy,
    Program,
    Region,
    Source,
    Validation,
    pretty_locations,
)
from .templates import CWD, Constraint, Each, Flags, Hole, Template, Token

# a node's payload: how to render its detail card
type Card = Callable[[], RenderableType]
type AtomKind = Literal["defined", "pure", "environmental", "source", "built-in"]

# styles, in one place
LIT = "bold"                 # literal command words
INS = "bold dim"             # host-inserted interior literals ("--")
HOLE = "bold cyan"           # a hole token in a signature
HOLE_HERE = "bold black on cyan"  # the hole the cursor is on
LOC = "green"                # locations
RX = "yellow"                # regexes
ATOM = "magenta"             # atom names
DIM = "dim"
HEAD = "bold underline"

_BUILTIN_BY_ATOM: dict[str, str] = {str(v): BUILTIN_MEANING[k] for k, v in BUILTIN_ATOMS.items()}


def _line(*parts: str | tuple[str, str]) -> Text:
    out = Text()
    for p in parts:
        if isinstance(p, str):
            out.append(p)
        else:
            out.append(p[0], style=p[1])
    return out


# ---------------------------------------------------------------------------
# the atom cross-reference index
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AtomInfo:
    atom: Atom
    kind: AtomKind
    regex_text: str | None = None
    established_by: tuple[str, ...] = ()
    consumed_by: tuple[str, ...] = ()
    yielded_by: tuple[str, ...] = ()


@dataclass
class _IndexBuilder:
    atoms: dict[str, Atom] = field(default_factory=dict)
    established: dict[str, list[str]] = field(default_factory=dict)
    consumed: dict[str, list[str]] = field(default_factory=dict)
    yielded: dict[str, list[str]] = field(default_factory=dict)

    def see(self, a: Atom) -> str:
        name = str(a)
        self.atoms.setdefault(name, a)
        return name

    def establish(self, a: Atom, by: str) -> None:
        self.established.setdefault(self.see(a), []).append(by)

    def consume(self, a: Atom, by: str) -> None:
        self.consumed.setdefault(self.see(a), []).append(by)

    def yield_(self, a: Atom, by: str) -> None:
        self.yielded.setdefault(self.see(a), []).append(by)


def atom_index(policy: Policy) -> dict[str, AtomInfo]:
    """Every atom the policy mentions: its kind, and who establishes / consumes / yields it."""
    b = _IndexBuilder()
    defined: dict[str, str] = {}
    for decl in policy.atoms:
        defined[b.see(decl.name)] = pretty_regex(decl.regex)
    source = {b.see(a) for a in policy.source_atoms}
    builtin = {b.see(a) for a in BUILTIN_ATOMS.values()}
    pure: set[str] = set()
    environmental: set[str] = set()
    for v in policy.validations:
        for slot, atoms in v.establishes.items():
            where = "the cwd" if slot == CWD else f"param {slot}"
            for a in atoms:
                name = b.see(a)
                b.establish(a, f'certora.check("{v.name}") on {where}')
                if name not in defined and name not in builtin:
                    (pure if a in v.pure_atoms else environmental).add(name)
    for p in policy.programs:
        words = " ".join(p.leading_words)
        for a in p.requires:
            b.consume(a, f"the cwd of {words}")
        if p.source is not None:
            b.yield_(p.source, words)
        t = p.template
        if t is None:
            continue
        for hname, hole in t.holes.items():
            match hole:
                case Token(constraint=c) | Each(constraint=c):
                    for a in c.atoms:
                        b.consume(a, f"{words} -- hole {hname}")
                case Flags(flagset=fs):
                    for flag, c in fs.valued.items():
                        for a in c.atoms:
                            b.consume(a, f"{words} -- the value of {flag}")
                    for flag, demands in fs.requires.items():
                        for target, atoms in demands.items():
                            of = "the cwd" if target == CWD else f"hole {target}"
                            for a in atoms:
                                b.consume(a, f"{words} -- {of}, while {flag} is present")
    for r in policy.network:
        for ra in r.requires:
            b.consume(ra.name, f"the URL of {r.host}")
        if r.source is not None:
            b.yield_(r.source, r.host)
    for s in policy.sources:
        b.yield_(s.name, f"reads under {pretty_locations(s.locations)}")
    out: dict[str, AtomInfo] = {}
    for name in sorted(b.atoms):
        kind: AtomKind = (
            "defined" if name in defined
            else "built-in" if name in builtin
            else "source" if name in source
            else "pure" if name in pure
            else "environmental"
        )
        out[name] = AtomInfo(
            b.atoms[name], kind, defined.get(name),
            tuple(b.established.get(name, ())),
            tuple(b.consumed.get(name, ())),
            tuple(b.yielded.get(name, ())),
        )
    return out


# ---------------------------------------------------------------------------
# detail cards
# ---------------------------------------------------------------------------


def signature_text(p: Program, selected: str | None = None) -> Text:
    """The rule's shape, holes styled; *selected* is highlighted."""
    t = p.template
    out = Text()
    if t is None:
        out.append(" ".join(p.leading_words), style=LIT)
        return out
    lead = len(t.leading_words)
    for i, piece in enumerate(t.pieces):
        if i:
            out.append(" ")
        if isinstance(piece, str):
            out.append(piece, style=LIT if i < lead else INS)
        else:
            label = piece.name + ("..." if piece.variadic else "")
            out.append(label, style=HOLE_HERE if piece.name == selected else HOLE)
    return out


def _atom_lines(
    atoms: frozenset[Atom], ix: dict[str, AtomInfo], policy: Policy, indent: str
) -> list[Text]:
    out: list[Text] = []
    for name in sorted(str(a) for a in atoms):
        info = ix.get(name)
        if info is None:
            out.append(_line(indent, "validated ", (name, ATOM)))
            continue
        out.append(_line(indent, "validated ", (name, ATOM), (f"  ({info.kind})", DIM)))
        more = indent + "    "
        if info.kind == "defined" and info.regex_text is not None:
            out.append(_line(more, ("defined as ", DIM), (info.regex_text, RX),
                             ("; a literal has it, and so does a variable after assert re.fullmatch with that regex", DIM)))
        elif info.kind == "built-in":
            out.append(_line(more, (_BUILTIN_BY_ATOM.get(name, ""), DIM)))
        elif info.kind == "source":
            out.append(_line(more, ("provenance: only a value extracted, unmodified, from its source satisfies it", DIM)))
        elif info.kind == "environmental":
            out.append(_line(more, ("dies on: ", DIM), (dies_on(policy, info.atom), DIM)))
    return out


def constraint_block(
    c: Constraint, ix: dict[str, AtomInfo], policy: Policy, indent: str = "  "
) -> list[Text]:
    """One constraint, one claim per line, each explained."""
    if c.any:
        return [_line(indent, ("anything", "bold"),
                      (" -- this position is data for the tool; nothing is checked", DIM))]
    out: list[Text] = []
    if c.locations:
        out.append(_line(indent, "a proven path within ",
                         (", ".join(pretty_location(loc) for loc in c.locations), LOC)))
    if c.regex is not None:
        out.append(_line(indent, "text matching ", (pretty_regex(c.regex), RX),
                         ("  (a literal, or a variable after assert re.fullmatch with that regex)", DIM)))
    if c.literal:
        out.append(_line(indent, ("literal", "bold"),
                         (" -- spelled in the program text itself; never a value read from a file, argv, or an API", DIM)))
    out.extend(_atom_lines(c.atoms, ix, policy, indent))
    return out


def _dash_note(t: Template, name: HoleName) -> Text:
    if t.dash_exempt(name):
        return _line(("dash guard: a literal '--' precedes it; values may begin with '-'", DIM))
    return _line(("dash guard: no '--' precedes it; a value beginning with '-' is refused "
                  "unless it carries not-option", DIM))


def hole_card(p: Program, name: HoleName, hole: Hole, ix: dict[str, AtomInfo], policy: Policy) -> RenderableType:
    t = p.template
    assert t is not None
    parts: list[RenderableType] = [signature_text(p, selected=name), Text()]
    match hole:
        case Token(constraint=c):
            parts.append(_line("hole ", (name, HOLE_HERE), " -- one token; the value must be:"))
            parts.extend(constraint_block(c, ix, policy))
            parts.append(Text())
            parts.append(_dash_note(t, name))
        case Each(constraint=c, min=minimum):
            need = f", at least {minimum} of them" if minimum else ""
            parts.append(_line("hole ", (name + "...", HOLE_HERE), f" -- a list{need}; each element must be:"))
            parts.extend(constraint_block(c, ix, policy))
            parts.append(Text())
            parts.append(_dash_note(t, name))
        case Flags(flagset=fs):
            parts.append(_line("hole ", (name + "...", HOLE_HERE), " -- a list of flags; only these exist:"))
            parts.extend(_line("  ", (text, "")) for text in flagset_lines(fs, policy.source_atoms))
            if fs.any:
                parts.append(_line(("  the tool is trusted with its own options; this rule cannot claim what it writes", DIM)))
    if name in t.keyword_only:
        parts.append(_line(("bind by keyword: an earlier splice has no positional end, so this hole is "
                            "passed as ", DIM), (f"{name}=[...]", "bold"), ("", DIM)))
    return Group(*parts)


def rule_card(p: Program, ix: dict[str, AtomInfo], policy: Policy) -> RenderableType:
    parts: list[RenderableType] = [signature_text(p), Text()]
    if p.origin:
        parts.append(_line(("from ", DIM), (p.origin, "italic")))
    parts.append(_line("cwd within ", (pretty_locations(p.cwd), LOC)))
    if p.requires:
        parts.append(_line("the cwd must be validated by ",
                           (", ".join(sorted(p.requires)), ATOM),
                           ("  (certora.check right before)", DIM)))
    if p.source is not None:
        parts.append(_line("yields ", (str(p.source), ATOM),
                           (" -- values extracted from the result carry it (certora.extract / extract_all / lines)", DIM)))
    parts.append(_line((effects_line(policy, p), DIM)))
    t = p.template
    if t is None:
        parts.append(_line(("exactly these words: no further arguments", DIM)))
        return Group(*parts)
    interior = [piece for piece in t.pieces[len(t.leading_words):] if isinstance(piece, str)]
    if interior:
        parts.append(_line(("inserted by the host, the program does not spell: ", DIM),
                           (" ".join(interior), INS)))
    if t.keyword_only:
        parts.append(_line(("bind by keyword: ", DIM), (", ".join(t.keyword_only), "bold")))
    parts.append(Text())
    parts.append(_line(("holes (expand this rule in the tree to inspect each):", DIM)))
    for hname, hole in t.holes.items():
        match hole:
            case Token(constraint=c):
                parts.append(_line("  ", (hname, HOLE), ": ",
                                   (constraint_phrase(c, policy.source_atoms), "")))
            case Each(constraint=c, min=minimum):
                need = f", at least {minimum}" if minimum else ""
                parts.append(_line("  ", (hname + "...", HOLE), ": each ",
                                   (constraint_phrase(c, policy.source_atoms), ""), (need, DIM)))
            case Flags(flagset=fs):
                count = "any flag" if fs.any else f"{len(fs.bare) + len(fs.valued)} flags"
                parts.append(_line("  ", (hname + "...", HOLE), ": ", (count, "")))
    return Group(*parts)


def validation_card(v: Validation, ix: dict[str, AtomInfo], policy: Policy) -> RenderableType:
    params = "".join(f", {p}=<str>" for p in v.params)
    cwd = "" if v.cwd is None else f", cwd=<path within {pretty_locations(v.cwd)}>"
    parts: list[RenderableType] = [
        _line(("certora.check(", LIT), (f'"{v.name}"', "bold cyan"), (params + cwd, ""), (")", LIT)),
        Text(),
    ]
    argv = Text("runs: ")
    for i, piece in enumerate(v.argv):
        if i:
            argv.append(" ")
        if isinstance(piece, Param):
            argv.append("${" + piece.name + "}", style=HOLE)
        else:
            argv.append(piece, style=LIT if i == 0 else "")
    parts.append(argv)
    if v.cwd is not None:
        parts.append(_line("in a cwd within ", (pretty_locations(v.cwd), LOC),
                           ("  (the caller passes a proven cwd=)", DIM)))
    else:
        parts.append(_line(("cwd-free: runs at the root; cannot establish atoms on cwd", DIM)))
    for slot, atoms in v.establishes.items():
        where = "the cwd" if slot == CWD else f"param {slot}"
        parts.append(_line(f"success establishes on {where}:"))
        parts.extend(_atom_lines(atoms, ix, policy, "  "))
    parts.append(_line((effects_line(policy, v), DIM)))
    if len(v.params) == 1:
        parts.append(_line(("also as an expression: ", DIM),
                           (f'certora.check_single("{v.name}", value)', "")))
    return Group(*parts)


def network_card(r: NetworkRule, ix: dict[str, AtomInfo], policy: Policy) -> RenderableType:
    methods = ", ".join(sorted(r.methods)) if r.methods else "any method"
    schemes = "/".join(sorted(r.schemes))
    ports = ":" + ",".join(str(p) for p in sorted(r.ports)) if r.ports else ""
    parts: list[RenderableType] = [
        _line((methods, LIT), " ", (f"{schemes}://{r.host}{ports}", "bold"), (
            "" if r.ports else "  (default port only)", DIM)),
        Text(),
    ]
    if r.paths:
        parts.append(_line("URL path within ", (pretty_locations(r.paths), LOC)))
    if r.requires:
        parts.append(_line("the URL must carry, live, at the call:"))
        for ra in sorted(r.requires, key=lambda x: str(x.name)):
            mode = ra.on_redirect or "default: recheck when textual, else stop"
            parts.extend(_atom_lines(frozenset({ra.name}), ix, policy, "  "))
            parts.append(_line(("      on redirect: ", DIM), (mode, DIM)))
    if r.allow_nonpublic:
        parts.append(_line(("allow-nonpublic: loopback/private/link-local destinations permitted", "bold red")))
    caps = [
        f"{label} {value}"
        for label, value in (
            ("read timeout", r.read_timeout),
            ("total timeout", r.total_timeout),
            ("response cap", r.max_response_bytes),
        )
        if value is not None
    ]
    if caps:
        parts.append(_line(("overrides broker caps: " + ", ".join(caps), DIM)))
    if r.source is not None:
        parts.append(_line("responses yield ", (str(r.source), ATOM)))
    ws = policy.write_set(r)
    parts.append(_line(("effects: " + ("none" if ws.empty else writes_phrase(ws)), DIM)))
    parts.append(_line(("every redirect hop is re-checked by the broker against these rules", DIM)))
    return Group(*parts)


def atom_card(info: AtomInfo, policy: Policy) -> RenderableType:
    parts: list[RenderableType] = [
        _line((str(info.atom), ATOM), ("  " + info.kind + " atom", DIM)),
        Text(),
    ]
    match info.kind:
        case "defined":
            parts.append(_line("defined as ", (info.regex_text or "", RX)))
            parts.append(_line(("a literal matching it has it; so does a variable after assert "
                                "re.fullmatch with that exact regex; pure -- survives every call", DIM)))
        case "built-in":
            parts.append(_line((_BUILTIN_BY_ATOM.get(str(info.atom), ""), "")))
        case "pure":
            parts.append(_line(("a property of the value's text, established by a check; survives calls, "
                                "dies with the value", "")))
        case "source":
            parts.append(_line(("provenance: established only by extraction from the source that yields it "
                                "(certora.extract / extract_all / lines / field, or `for line in f`); any "
                                "string operation drops it; no literal has it", "")))
        case "environmental":
            state = policy.read_set(info.atom)
            if state == EVERYTHING:
                parts.append(_line(("a property of the environment; no reads declared, so it depends on "
                                    "everything and dies at any effectful call", "")))
            else:
                parts.append(_line("depends on ", (depends_phrase(state), "bold")))
                parts.append(_line("dies on: ", (dies_on(policy, info.atom), "")))
    for title, entries in (
        ("established by", info.established_by),
        ("consumed by", info.consumed_by),
        ("yielded by", info.yielded_by),
    ):
        if entries:
            parts.append(Text())
            parts.append(_line((title + ":", HEAD)))
            parts.extend(_line("  ", (e, "")) for e in entries)
    return Group(*parts)


def region_card(r: Region, policy: Policy) -> RenderableType:
    parts: list[RenderableType] = [
        _line((str(r.name), "bold"), (f"  {r.medium} region", DIM)),
        Text(),
    ]
    if r.medium == "network":
        parts.append(_line("remote state"))
    else:
        parts.append(_line("on disk at ", (pretty_locations(r.footprint), LOC),
                           (" below the establishing check's cwd, and everything under it", DIM)))
    if r.about:
        parts.append(_line((r.about, "italic")))
    readers = sorted(name for name, e in policy.reads.items() if r.name in e.regions)
    if readers:
        parts.append(Text())
        parts.append(_line(("atoms that depend on it: ", HEAD), (", ".join(readers), ATOM)))
    writers: list[str] = []
    for p in policy.programs:
        if p.writes is not None and (r.name in p.writes.regions or r.medium in p.writes.media):
            writers.append(" ".join(p.leading_words))
    for net in policy.network:
        if net.writes is not None and (r.name in net.writes.regions or r.medium in net.writes.media):
            writers.append(net.host)
    if writers:
        parts.append(_line(("declared writers: ", HEAD), (", ".join(writers), "")))
    parts.append(_line(("plus any grant reaching this medium with no declared write set", DIM)))
    return Group(*parts)


def source_card(s: Source) -> RenderableType:
    return Group(
        _line((str(s.name), ATOM), ("  source", DIM)),
        Text(),
        _line("reading under ", (pretty_locations(s.locations), LOC),
              " (read_text, open, f.read, for line in f)"),
        _line("yields a handle carrying ", (str(s.name), ATOM)),
        _line(("grants nothing: the read must still be permitted by the filesystem grants", DIM)),
    )


_FS_MEANING = {
    "read": "open / read_text / read_bytes on a proven path within",
    "write": "writes and creations on a proven path within",
    "list": "directory listings and existence probes within",
}


def program_group_card(name: str, rules: tuple[Program, ...]) -> RenderableType:
    parts: list[RenderableType] = [
        _line((name, LIT), (f"  {len(rules)} rules -- an exec selects exactly one by its "
                            "leading words; an unlisted or computed form fails closed", DIM)),
        Text(),
    ]
    parts.extend(signature_text(p) for p in rules)
    return Group(*parts)


def fs_card(kind: str, policy: Policy) -> RenderableType:
    locs = {"read": policy.read, "write": policy.write, "list": policy.listing}[kind]
    parts: list[RenderableType] = [_line((kind, LIT), (f"  {_FS_MEANING[kind]}:", DIM)), Text()]
    if not locs:
        parts.append(_line(("nothing", DIM)))
    parts.extend(_line("  ", (pretty_location(loc), LOC)) for loc in locs)
    return Group(*parts)


# ---------------------------------------------------------------------------
# the app
# ---------------------------------------------------------------------------


class ExplorerApp(App[None]):
    TITLE = "certorail policy explorer"

    CSS = """
    #nav { width: 44; min-width: 30; }
    #detail-scroll { padding: 1 2; }
    """

    BINDINGS = [
        ("q", "quit", "quit"),
        ("e", "expand_all", "expand all"),
        ("c", "collapse_all", "collapse"),
    ]

    def __init__(self, policy: Policy, origin: str, governs: str | None) -> None:
        super().__init__()
        self.policy = policy
        self.origin = origin
        self.governs = governs
        self.ix = atom_index(policy)
        self.sub_title = origin
        self._tree: Tree[Card] = Tree(Text("policy", style="bold"), id="nav")
        self._detail = Static(id="detail")

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            yield self._tree
            with VerticalScroll(id="detail-scroll"):
                yield self._detail
        yield Footer()

    def _overview(self) -> RenderableType:
        policy = self.policy
        parts: list[RenderableType] = [
            _line(("policy: ", DIM), (self.origin, "bold")),
        ]
        if self.governs:
            parts.append(_line(("governs ", DIM), (self.governs, LOC),
                               (" and every directory below it with no policy of its own", DIM)))
        parts.append(Text())
        counts = (
            ("filesystem grants", len(policy.read) + len(policy.write) + len(policy.listing)),
            ("program rules", len(policy.programs)),
            ("network rules", len(policy.network)),
            ("validations", len(policy.validations)),
            ("atoms mentioned", len(self.ix)),
            ("regions", len(policy.regions)),
            ("sources", len(policy.sources)),
        )
        parts.extend(_line(("  %3d " % n, "bold"), (label, "")) for label, n in counts if n)
        parts.append(Text())
        parts.append(_line(("everything not listed is denied. Arrow keys / mouse to explore; "
                            "a rule expands into its holes.", DIM)))
        return Group(*parts)

    def on_mount(self) -> None:
        policy, ix = self.policy, self.ix
        root = self._tree.root
        root.data = self._overview

        fs = root.add(Text("filesystem"), data=partial(fs_card, "read", policy))
        for kind, locs in (("read", policy.read), ("write", policy.write), ("list", policy.listing)):
            fs.add_leaf(_line((kind, ""), (f"  ({len(locs)})", DIM)), data=partial(fs_card, kind, policy))

        programs = root.add(_line("programs", (f"  ({len(policy.programs)} rules)", DIM)), data=self._overview)
        by_name: dict[str, list[Program]] = {}
        for p in policy.programs:
            by_name.setdefault(str(p.name), []).append(p)
        for name in sorted(by_name):
            rules = sorted(by_name[name], key=lambda p: p.leading_words)
            if len(rules) > 1:
                parent = programs.add(_line((name, LIT), (f"  ({len(rules)})", DIM)),
                                      data=partial(program_group_card, name, tuple(rules)))
            else:
                parent = programs
            for p in rules:
                label = signature_text(p)
                if p.template is None:
                    parent.add_leaf(label, data=partial(rule_card, p, ix, policy))
                    continue
                rule_node = parent.add(label, data=partial(rule_card, p, ix, policy))
                for hname, hole in p.template.holes.items():
                    suffix = "..." if isinstance(hole, (Each, Flags)) else ""
                    rule_node.add_leaf(_line((hname + suffix, HOLE)),
                                       data=partial(hole_card, p, hname, hole, ix, policy))

        net = root.add(_line("network", (f"  ({len(policy.network)})", DIM)), data=self._overview)
        for r in sorted(policy.network, key=lambda r: r.host):
            methods = "/".join(sorted(r.methods)) if r.methods else "any"
            net.add_leaf(_line((methods, DIM), " ", (r.host, LIT)), data=partial(network_card, r, ix, policy))

        vals = root.add(_line("validations", (f"  ({len(policy.validations)})", DIM)), data=self._overview)
        for v in sorted(policy.validations, key=lambda v: str(v.name)):
            vals.add_leaf(_line((str(v.name), LIT)), data=partial(validation_card, v, ix, policy))

        atoms = root.add(_line("atoms", (f"  ({len(ix)})", DIM)), data=self._overview)
        for kind in ("defined", "pure", "environmental", "source", "built-in"):
            infos = [i for i in ix.values() if i.kind == kind]
            if not infos:
                continue
            group = atoms.add(_line((kind, ""), (f"  ({len(infos)})", DIM)), data=self._overview)
            for info in infos:
                group.add_leaf(_line((str(info.atom), ATOM)), data=partial(atom_card, info, policy))

        if policy.regions:
            regions = root.add(_line("regions", (f"  ({len(policy.regions)})", DIM)), data=self._overview)
            for r in policy.regions:
                regions.add_leaf(_line((str(r.name), "")), data=partial(region_card, r, policy))

        if policy.sources:
            sources = root.add(_line("sources", (f"  ({len(policy.sources)})", DIM)), data=self._overview)
            for s in policy.sources:
                sources.add_leaf(_line((str(s.name), ATOM)), data=partial(source_card, s))

        root.expand()
        programs.expand()
        self._detail.update(self._overview())

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted[Card]) -> None:
        card = event.node.data
        self._detail.update(card() if card is not None else self._overview())

    def action_expand_all(self) -> None:
        self._tree.root.expand_all()

    def action_collapse_all(self) -> None:
        self._tree.root.collapse_all()
        self._tree.root.expand()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="certorail-explore",
        description="Browse what a certorail policy allows: rules, holes, constraints, atoms.",
    )
    parser.add_argument("--policy", type=pathlib.Path, default=None,
                        help="a policy file; omitted, the ambient policy for --root is found")
    parser.add_argument("--root", type=pathlib.Path, default=None,
                        help="the sandbox root (default: the working directory)")
    ns = parser.parse_args(argv)
    root = (ns.root or pathlib.Path.cwd()).resolve()
    policy = load_policy(ns.policy, root).policy
    origin, governs = policy_origin(ns.policy, root)
    ExplorerApp(policy, origin, governs).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
