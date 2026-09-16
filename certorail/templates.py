"""Command templates: the shape of a permitted command line (TEMPLATES.md).

A template is a sequence of *pieces* -- literal words and *holes*, ``${X}`` for one token and
``${X...}`` for a splice -- and it binds like a Python call: the leading literal words select
it, positionals fill holes in template order (a trailing variadic hole takes the rest; a
variadic hole that is not last, and every hole after it, is keyword-only), keywords fill holes
by name. **Holes are relies**: a ``Constraint`` says of one token what a parameter annotation
says of a value, and is checked the same way. The program never composes the argv; the broker
does, from the template's words and the checked values (``instantiate``).

Shared by the analysis (values are facts) and the broker (values are the concrete strings), so
the runtime re-check is the same check: ``bind`` and the constraint, flag and dash-guard
functions below take either.
"""
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field

from .analysis import (
    Exact,
    LocationFact,
    PseudoRegex,
    RegexLit,
    StrFact,
    ValidationFact,
    entails,
    known_text,
    locate,
    location_le,
    may_start_with_dash,
    pretty_location,
    pretty_regex,
)
from .dangerous import EXEC_CWD, EXEC_RESERVED_KEYWORDS
from .ids import NOT_OPTION, Atom, FlagName, HoleName

__all__ = ["NOT_OPTION", "may_start_with_dash"]  # re-exported for their old importers

# ---------------------------------------------------------------------------
# the vocabulary
# ---------------------------------------------------------------------------

type Value = str | ValidationFact | None  # one token as the analysis sees it (a str: known text)


@dataclass(frozen=True)
class HoleRef:
    """``${name}`` (one token) or ``${name...}`` (a splice) in a template's pieces."""

    name: HoleName
    variadic: bool = False


type Piece = str | HoleRef


CWD = EXEC_CWD  # the target of a demand on the exec's cwd; like every exec keyword, never a hole


@dataclass(frozen=True)
class Constraint:
    """What one token must be: a rely, in the annotation vocabulary. Three orthogonal kinds of
    claim: *shape* -- ``locations`` (a proven path within one of them) or ``regex`` (text known
    to match); *provenance* -- ``literal``: the text is statically known, so the program named
    it (a literal, a constant, a join of literals) rather than read it from a file, argv or an
    API -- the intent gate for destructive actions; *facts* -- ``atoms``, live validation facts.
    ``any`` admits anything -- an explicit, local statement that this position is data for the
    tool -- and combines with nothing. A located value is textless, so ``locations`` excludes
    ``regex``; everything else combines (``locations`` + ``literal`` is a constant path within).
    Empty says nothing."""

    locations: tuple[LocationFact, ...] = ()
    regex: PseudoRegex | None = None
    atoms: frozenset[Atom] = frozenset()
    literal: bool = False
    any: bool = False

    def __post_init__(self) -> None:
        if self.any and (self.locations or self.regex is not None or self.literal or self.atoms):
            raise ValueError("a constraint with any=True combines with nothing")
        if self.locations and self.regex is not None:
            raise ValueError("a located value is textless: location does not combine with matches/one-of")
        if not (self.any or self.locations or self.regex is not None or self.literal or self.atoms):
            raise ValueError("an empty constraint says nothing; use any = true to mean that")


@dataclass(frozen=True)
class Token:
    constraint: Constraint


@dataclass(frozen=True)
class Each:
    constraint: Constraint
    min: int = 0


# what a flag demands when present: atoms of the exec's cwd (under ``CWD``) or of another hole's
# value, by hole name
type Demands = Mapping[str, frozenset[Atom]]


@dataclass(frozen=True)
class Flagset:
    """A flag vocabulary: the bare flags, and the valued ones with the constraint on their
    value. Every flag name begins with ``-``. ``any`` is the open vocabulary -- any flag, any
    value, unknown values included -- for a tool the deployment trusts wholesale (under a jail,
    say) and does not care to enumerate; it stands alone, and a rule carrying it cannot say
    what it writes, since anything may reach the tool as an option.

    A flag may carry ``requires``: atoms demanded, when the flag is present, of the exec's cwd
    or of another hole's value (``--force`` requires ``not-default-branch`` of ``BRANCH``), on
    top of what the rule and that hole already ask. ``holes`` is a named flagset's contract with
    the templates that use it: the holes its demands reach, which every such template must
    have; an inline vocabulary names its own template's holes directly.

    ``expand_single_flags`` (opt-in: not every tool bundles) reads ``-lr`` as ``-l -r`` when
    every letter is a declared bare single-letter flag; a bundle with a valued or unknown letter
    is an error, and the tool receives the expanded words. It is refused on a vocabulary that
    declares any single-dash multi-letter flag (``find -name``): such a word is one flag to that
    tool, so the two readings cannot share a vocabulary and a bundle is never ambiguous."""

    bare: frozenset[FlagName] = frozenset()
    valued: Mapping[FlagName, Constraint] = field(default_factory=dict)
    any: bool = False
    requires: Mapping[FlagName, Demands] = field(default_factory=dict)
    holes: frozenset[HoleName] = frozenset()
    expand_single_flags: bool = False

    def __post_init__(self) -> None:
        names = set(self.bare) | set(self.valued)
        if self.any:
            if names or self.requires or self.holes:
                raise ValueError("an open flag vocabulary (any = true) lists no flags")
            if self.expand_single_flags:
                raise ValueError("expand-single-flags says nothing about an open flag vocabulary (any = true)")
            return
        if not names:
            raise ValueError("a flag vocabulary needs at least one flag, or any = true")
        for n in names:
            if not n.startswith("-"):
                raise ValueError(f"flag names begin with '-': {n!r}")
        both = self.bare & self.valued.keys()
        if both:
            raise ValueError(f"flags both bare and valued: {sorted(both)}")
        if self.expand_single_flags:
            long_single = sorted(n for n in names if _BUNDLE.fullmatch(n))
            if long_single:
                raise ValueError(
                    f"expand-single-flags: {long_single[0]!r} is a single-dash multi-letter flag, so this "
                    "tool does not bundle short flags"
                )
        for name in sorted(EXEC_RESERVED_KEYWORDS & self.holes):
            raise ValueError(f"{name!r} is reserved and cannot be a hole")
        for flag, demands in self.requires.items():
            if flag not in names:
                raise ValueError(f"requires on {flag!r}, which is not a flag of the vocabulary")
            for target in demands:
                if target != CWD and self.holes and target not in self.holes:
                    raise ValueError(
                        f"flag {flag!r} requires atoms of {target!r}, which is not among the "
                        f"flagset's holes ({', '.join(sorted(self.holes))})"
                    )

    def demands_of(self, present: Iterable[FlagName]) -> dict[str, frozenset[Atom]]:
        """What the *present* flags demand, by target, unioned."""
        out: dict[str, frozenset[Atom]] = {}
        for flag in present:
            for target, atoms in self.requires.get(flag, {}).items():
                out[target] = out.get(target, frozenset()) | atoms
        return out

    def declared(self, flag: str) -> bool:
        return flag in self.bare or flag in self.valued

    def words(self, text: str) -> tuple[str, ...] | str:
        """The flag words a flag-position *text* stands for: itself when declared, its letters
        when it is a bundle this vocabulary expands (the two never compete: an expanding
        vocabulary declares no multi-letter single-dash flag), else the problem with it."""
        if self.declared(text):
            return (text,)
        if not self.expand_single_flags or _BUNDLE.fullmatch(text) is None:
            return f"{text!r} is not a declared flag"
        letters = tuple(f"-{ch}" for ch in text[1:])
        for letter in letters:
            if letter in self.valued:
                return f"the bundle {text!r} contains the valued flag {letter!r}: spell it separately"
            if letter not in self.bare:
                return f"{letter!r} is not a declared flag (from the bundle {text!r})"
        return letters


# a bundle of short flags, ``-lr``: one dash, two or more characters that are not dashes
_BUNDLE = re.compile(r"-[^-]{2,}")


def expand_bundles(fs: Flagset, elements: Sequence[Value]) -> tuple[list[Value], str | None]:
    """*elements* with every bundle the vocabulary expands replaced by its letters, so that
    ``flags_failure``, ``present_flags`` and ``instantiate`` see one word per flag. Elements in
    value position are left alone; anything else undeclared is left for ``flags_failure`` to
    report. Returns (the elements, the problem with a bundle that does not expand)."""
    if fs.any or not fs.expand_single_flags:
        return list(elements), None
    out: list[Value] = []
    i = 0
    while i < len(elements):
        element = elements[i]
        text = known_text(element)
        if text is None or fs.declared(text):
            out.append(element)
            i += 1
            if text is not None and text in fs.valued and i < len(elements):
                out.append(elements[i])
                i += 1
            continue
        words = fs.words(text)
        if isinstance(words, str):
            if _BUNDLE.fullmatch(text) is not None:
                return out, words
            out.append(element)  # not a bundle: flags_failure names it
        else:
            out.extend(words)
        i += 1
    return out, None


@dataclass(frozen=True)
class Flags:
    flagset: Flagset


type Hole = Token | Each | Flags


@dataclass(frozen=True)
class Template:
    """One permitted command-line shape. ``pieces[0]`` is the program, a literal."""

    pieces: tuple[Piece, ...]
    holes: Mapping[HoleName, Hole]

    def __post_init__(self) -> None:
        if not self.pieces or not isinstance(self.pieces[0], str):
            raise ValueError("a template begins with the program, a literal word")
        refs = [p for p in self.pieces if isinstance(p, HoleRef)]
        names = [r.name for r in refs]
        if len(set(names)) != len(names):
            raise ValueError("a hole appears once in a template")
        for name in sorted(EXEC_RESERVED_KEYWORDS & self.holes.keys()):
            raise ValueError(f"{name!r} is reserved and cannot be a hole")
        for r in refs:
            hole = self.holes.get(r.name)
            if hole is None:
                raise ValueError(f"hole {r.name!r} is used but not declared")
            variadic_kind = isinstance(hole, (Each, Flags))
            if r.variadic != variadic_kind:
                spelled = "${" + r.name + ("...}" if r.variadic else "}")
                raise ValueError(f"{spelled} disagrees with its kind ({type(hole).__name__.lower()})")
        for name in self.holes:
            if name not in names:
                raise ValueError(f"hole {name!r} is declared but not used")
        # a flag's demands reach the cwd or a token/each hole of this template: a named flagset
        # declares the holes it reaches (its contract), an inline vocabulary names them directly
        for name, hole in self.holes.items():
            if not isinstance(hole, Flags):
                continue
            fs = hole.flagset
            reached = set(fs.holes) | {t for d in fs.requires.values() for t in d if t != CWD}
            for target in sorted(reached):
                if not isinstance(self.holes.get(HoleName(target)), (Token, Each)):
                    raise ValueError(
                        f"the flags of {name!r} require atoms of hole {target!r}, which this "
                        "template does not have (a token or each hole of that name)"
                    )

    @property
    def program(self) -> str:
        first = self.pieces[0]
        assert isinstance(first, str)
        return first

    @property
    def leading_words(self) -> tuple[str, ...]:
        """The maximal literal prefix, program included: what selects the template."""
        out: list[str] = []
        for p in self.pieces:
            if not isinstance(p, str):
                break
            out.append(p)
        return tuple(out)

    def variadic(self, name: HoleName) -> bool:
        return isinstance(self.holes[name], (Each, Flags))

    def terminable(self, name: HoleName) -> bool:
        """Can a positional tail bound to this variadic hole be ended without a marker? A flags
        hole with a closed vocabulary can: its elements are flags (known text beginning with
        ``-``) and their values, so the first positional that carries ``not-option`` is not in it
        and begins the next hole. An open vocabulary cannot -- which of its flags take a value is
        unknown -- and neither can an each hole, whose elements have no shape of their own."""
        hole = self.holes[name]
        return isinstance(hole, Flags) and not hole.flagset.any

    @property
    def keyword_only(self) -> tuple[HoleName, ...]:
        """The holes from the first non-last variadic hole that cannot terminate positionally
        onward: nothing marks where such a splice would end, so they are bound by name."""
        refs = [p for p in self.pieces if isinstance(p, HoleRef)]
        for i, r in enumerate(refs):
            if r.variadic and r is not self.pieces[-1] and not self.terminable(r.name):
                return tuple(x.name for x in refs[i:])
        return ()

    def dash_exempt(self, name: HoleName) -> bool:
        """A literal ``--`` earlier in the template makes a later hole safe from being read as
        an option, for tools that honour it."""
        for p in self.pieces:
            if p == "--":
                return True
            if isinstance(p, HoleRef) and p.name == name:
                return False
        return False


# ---------------------------------------------------------------------------
# binding: a template is a signature
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Many:
    """A variadic hole's value as a sequence of tokens: a display, or the positional tail."""

    elements: tuple[Value, ...]


@dataclass(frozen=True)
class Elements:
    """A variadic hole's value as a typed container: every element has this fact, the count is
    unknown (CONTAINERS.md: the splat, landing where it was always going to)."""

    elem: ValidationFact


type Binding = Value | Many | Elements


@dataclass(frozen=True)
class Bound:
    template: Template
    bindings: Mapping[HoleName, Binding]


@dataclass(frozen=True)
class BindError:
    reasons: tuple[str, ...]


def matches_leading(words: Sequence[str], arguments: Sequence[Value]) -> bool:
    """Do *arguments* (the positionals after the program) begin with the literal *words*?"""
    if len(arguments) < len(words):
        return False
    return all(known_text(arguments[i]) == w for i, w in enumerate(words))


def bind(
    template: Template, arguments: Sequence[Value], keywords: Mapping[str, Binding]
) -> Bound | BindError:
    """*arguments* are the positionals after the program, leading words included (the caller
    selected the template by them). Positionals fill holes in template order; a trailing
    variadic takes the rest; a flags hole that is not last takes the flags and flag values at
    the head of the remaining positionals and ends at the first that carries ``not-option``
    (``Template.terminable``) -- a positional that could be either is a binding error, never a
    guess; any other non-last variadic and everything after it is keyword-only; keywords fill by
    name. Interior literal words are never spelled by the program."""
    reasons: list[str] = []
    bindings: dict[HoleName, Binding] = {}
    lead = len(template.leading_words) - 1
    positionals = list(arguments[lead:])
    keyword_only = set(template.keyword_only)
    holes = [p for p in template.pieces[len(template.leading_words):] if isinstance(p, HoleRef)]
    for i, piece in enumerate(holes):
        if piece.name in keyword_only:
            continue
        if not piece.variadic:
            if positionals:
                bindings[piece.name] = positionals.pop(0)
            continue
        if piece is holes[-1] and piece is template.pieces[-1]:
            # the last piece: it takes whatever positionals remain
            if positionals:
                bindings[piece.name] = Many(tuple(positionals))
                positionals = []
            continue
        # a terminable flags hole with holes after it: take the flag-shaped head
        hole = template.holes[piece.name]
        assert isinstance(hole, Flags)
        following = holes[i + 1].name if i + 1 < len(holes) else None
        taken, consumed, problem = _flag_head(hole.flagset, positionals, piece.name, following)
        if problem is not None:
            reasons.append(problem)
            break
        if taken:  # an empty head leaves the hole to a keyword (or to its default, nothing)
            bindings[piece.name] = Many(tuple(taken))
            positionals = positionals[consumed:]
    if positionals:
        reasons.append(
            f"{len(positionals)} positional argument(s) too many"
            + (
                f"; the holes {', '.join(template.keyword_only)} are keyword-only"
                if keyword_only
                else ""
            )
        )
    for spelled, value in keywords.items():
        name = HoleName(spelled)  # the program's keyword, entering the template's domain
        if name not in template.holes:
            reasons.append(f"{name!r} is not a hole of this form")
        elif name in bindings:
            reasons.append(f"hole {name!r} is bound twice")
        elif template.variadic(name) and not isinstance(value, (Many, Elements)):
            reasons.append(f"hole {name!r} takes a list (a display, or a typed container)")
        elif not template.variadic(name) and isinstance(value, (Many, Elements)):
            reasons.append(f"hole {name!r} takes one value, not a list")
        else:
            bindings[name] = value
    for name in template.holes:
        if name not in bindings:
            if template.variadic(name):
                bindings[name] = Many(())
            else:
                reasons.append(f"hole {name!r} is unbound")
    # a flags display bound by keyword may spell bundles; the positional head already expanded
    for name, hole in template.holes.items():
        value = bindings.get(name)
        if isinstance(hole, Flags) and isinstance(value, Many):
            elements, problem = expand_bundles(hole.flagset, value.elements)
            if problem is not None:
                reasons.append(f"{name}: {problem}")
            else:
                bindings[name] = Many(tuple(elements))
    return BindError(tuple(reasons)) if reasons else Bound(template, bindings)


def _flag_head(
    fs: Flagset, positionals: Sequence[Value], name: HoleName, following: HoleName | None
) -> tuple[list[Value], int, str | None]:
    """The prefix of *positionals* a non-last flags hole takes: flags -- known text beginning
    with ``-`` -- each valued one with the positional after it, up to the first positional that
    carries ``not-option``, which begins the next hole. A positional that is neither a flag nor
    shown not to be one is ambiguous, and the answer is a binding error naming the fix rather
    than a guess. Returns (the elements taken, with a bundle expanded to its letters; how many
    positionals they came from; the problem)."""
    taken: list[Value] = []
    i = 0
    while i < len(positionals):
        value = positionals[i]
        text = known_text(value)
        if text is not None and text.startswith("-"):
            words = fs.words(text)
            if isinstance(words, str):
                if fs.expand_single_flags and _BUNDLE.fullmatch(text) is not None:
                    return taken, i, f"{name}: {words}"
                hint = f"; if it is the value of {following}, bind {following} by keyword" if following else ""
                return taken, i, f"{text!r} is not a flag of {name}{hint}"
            taken.extend(words if len(words) > 1 else (value,))
            i += 1
            if text in fs.valued and i < len(positionals):
                taken.append(positionals[i])  # the flag's value, whatever it is
                i += 1
            continue
        if not may_start_with_dash(value):
            return taken, i, None  # shown not to be an option: the next hole begins here
        where = "the next hole" if following is None else following
        return taken, i, (
            f"positional {i + 1} after the leading words could be a flag of {name} or the "
            f"value of {where} (it lacks not-option): bind by keyword to say which"
        )
    return taken, i, None


# ---------------------------------------------------------------------------
# checking a bound template
# ---------------------------------------------------------------------------

# atoms of *required* that *value* does not carry (``Vocabulary.missing``, partially applied:
# structure, regex definitions and literal checkers live there)
type AtomsMissing = Callable[[Value, frozenset[Atom]], frozenset[Atom]]


def _as_fact(value: str | ValidationFact) -> ValidationFact:
    return StrFact(regex=Exact(value)) if isinstance(value, str) else value


def constraint_failure(c: Constraint, value: Value, atoms_missing: AtomsMissing) -> str | None:
    """Why *value* does not satisfy *c*, or None."""
    if c.any:
        return None
    if value is None:
        return "is of unknown provenance"
    if c.locations:
        located = locate(_as_fact(value))
        if located is None or not any(location_le(located.location, loc) for loc in c.locations):
            names = ", ".join(pretty_location(loc) for loc in c.locations)
            return f"is not a proven path within {names}"
    if c.regex is not None and not entails(value, StrFact(regex=c.regex)):
        return f"is not known to match {pretty_regex(c.regex)}"
    if c.literal and known_text(value) is None:
        return "is not statically known text (the program must name it: a literal or a constant)"
    if c.atoms:
        missing = atoms_missing(value, c.atoms)
        if missing:
            return f"is not validated by: {', '.join(sorted(missing))}"
    return None


# The leading-dash guard (TEMPLATES.md): a token or each hole not preceded by a literal "--"
# requires the built-in ``not-option``, asked of the value like any other atom -- structure
# (``analysis.holds``), or a checker's ``establishes`` -- and denied with this reason
DASH_REASON = (
    "may begin with '-' and be read as an option (it lacks not-option): confine it under a named "
    "directory, guard its text, or have a checker that establishes not-option vouch for it"
)
_NOT_OPTION_ONLY: frozenset[Atom] = frozenset({NOT_OPTION})


def flags_failure(fs: Flagset, elements: Sequence[Value], atoms_missing: AtomsMissing) -> str | None:
    """Parse *elements* against the vocabulary, left to right."""
    if fs.any:
        return None  # the open vocabulary: whatever the program passes is the tool's business
    i = 0
    while i < len(elements):
        text = known_text(elements[i])
        if text is None:
            return f"element {i + 1} is in flag position but is not statically known text"
        name = FlagName(text)
        if name in fs.bare:
            i += 1
            continue
        c = fs.valued.get(name)
        if c is None:
            return f"{name!r} is not a declared flag"
        if i + 1 >= len(elements):
            return f"flag {name!r} needs a value"
        reason = constraint_failure(c, elements[i + 1], atoms_missing)
        if reason is not None:
            return f"the value of {name!r} {reason}"
        i += 2
    return None


def option_shaped(value: Value, atoms_missing: AtomsMissing) -> bool:
    """The leading-dash guard: may the tool read *value* as an option? Only while it lacks
    ``not-option``."""
    return bool(atoms_missing(value, _NOT_OPTION_ONLY))


# atoms of *required* that the exec's cwd does not carry
type CwdMissing = Callable[[frozenset[Atom]], frozenset[Atom]]


def present_flags(fs: Flagset, elements: Sequence[Value]) -> list[FlagName]:
    """The flags a well-formed (``flags_failure`` is None) flags list names."""
    out: list[FlagName] = []
    i = 0
    while i < len(elements):
        text = known_text(elements[i])
        if text is None:
            break
        name = FlagName(text)
        out.append(name)
        i += 1 if name in fs.bare else 2
    return out


def _demand_failures(bound: Bound, atoms_missing: AtomsMissing, cwd_missing: CwdMissing) -> list[str]:
    """What the present flags demand of the cwd and of other holes, and is not carried."""
    out: list[str] = []
    for name, hole in bound.template.holes.items():
        if not isinstance(hole, Flags):
            continue
        value = bound.bindings[name]
        if not isinstance(value, Many) or hole.flagset.any:
            continue
        flags = present_flags(hole.flagset, value.elements)
        for target, atoms in sorted(hole.flagset.demands_of(flags).items()):
            demanding = ", ".join(f for f in flags if target in hole.flagset.requires.get(f, {}))
            if target == CWD:
                missing = cwd_missing(atoms)
                if missing:
                    out.append(f"{demanding} requires the cwd validated by: {', '.join(sorted(missing))}")
                continue
            target_value = bound.bindings[HoleName(target)]
            missing = frozenset()
            match target_value:
                case Many(elements=elements):
                    for e in elements:
                        missing |= atoms_missing(e, atoms)
                case Elements(elem=elem):
                    missing = atoms_missing(elem, atoms)
                case _:
                    missing = atoms_missing(target_value, atoms)
            if missing:
                out.append(f"{demanding} requires {target} validated by: {', '.join(sorted(missing))}")
    return out


def hole_failures(bound: Bound, atoms_missing: AtomsMissing, cwd_missing: CwdMissing) -> list[str]:
    """Every way the bound values fall short of their holes, each naming the hole; then what
    the present flags demand of the cwd and of other holes."""
    out: list[str] = []
    template = bound.template
    for name, hole in template.holes.items():
        value = bound.bindings[name]
        guard = not template.dash_exempt(name)
        match hole:
            case Token(constraint=c):
                assert not isinstance(value, (Many, Elements))
                reason = constraint_failure(c, value, atoms_missing)
                if reason is None and guard and option_shaped(value, atoms_missing):
                    reason = DASH_REASON
                if reason is not None:
                    out.append(f"{name} {reason}")
            case Each(constraint=c, min=minimum):
                match value:
                    case Many(elements=elements):
                        if len(elements) < minimum:
                            out.append(f"{name} needs at least {minimum} element(s)")
                        for i, e in enumerate(elements):
                            reason = constraint_failure(c, e, atoms_missing)
                            if reason is None and guard and option_shaped(e, atoms_missing):
                                reason = DASH_REASON
                            if reason is not None:
                                out.append(f"{name}[{i}] {reason}")
                    case Elements(elem=elem):
                        reason = constraint_failure(c, elem, atoms_missing)
                        if reason is None and guard and option_shaped(elem, atoms_missing):
                            reason = DASH_REASON
                        if reason is not None:
                            out.append(f"the elements of {name} {reason}")
                    case _:
                        out.append(f"{name} takes a list")
            case Flags(flagset=fs):
                match value:
                    case Many(elements=elements):
                        reason = flags_failure(fs, elements, atoms_missing)
                        if reason is not None:
                            out.append(f"{name}: {reason}")
                    case _:
                        out.append(f"{name} takes a display of flags, not a container")
    if not out:
        out = _demand_failures(bound, atoms_missing, cwd_missing)
    return out


def instantiate(bound: Bound) -> list[str]:
    """The argv: literal words as themselves, a token hole as its string, a variadic hole
    spliced. Every binding must be concrete text (the broker's side)."""
    argv: list[str] = []
    for piece in bound.template.pieces:
        if isinstance(piece, str):
            argv.append(piece)
            continue
        value = bound.bindings[piece.name]
        match value:
            case str():
                argv.append(value)
            case Many(elements=elements):
                for e in elements:
                    if not isinstance(e, str):
                        raise ValueError(f"hole {piece.name!r}: not concrete text")
                    argv.append(e)
            case _:
                raise ValueError(f"hole {piece.name!r}: not concrete text")
    return argv
