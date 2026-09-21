"""The policy document's shape, as a schema.

This is the *shape* layer of the policy format (``policyfile`` is the loader): which sections exist,
which keys each table takes, what type each value has, and the local invariants a single table
must satisfy (``argv`` xor ``subcommand``; a constraint with ``any`` combines with nothing; a
region is a footprint or the network, not both). Every key set is closed, every value is read
strictly -- no coercion of ``"1"`` to ``1`` or ``1`` to ``true`` -- and every problem in a
document is reported at once, with its path.

What is deliberately NOT here is meaning: whether an atom a rule names is declared and of which
kind, whether a checker exists, whether two rules for one program overlap, how a ruleset's
parameters are substituted, how a composition of documents is deduplicated. Those are semantic
passes over the typed documents this module produces, and they stay plain code. So does anything
that touches the outside world: the models never read the filesystem.

Two top-level documents share every sub-model: a ``PolicyDoc`` (a root policy: grants,
network, ``root``) and a ``RulesetDoc`` (exec-side vocabulary with ``[params]``, TEMPLATES.md).
Inside a ruleset a location may be headed by a parameter (``${where}/**``), an atom list may
splice one (``${gate}``), a hole may *be* one (``holes.BRANCH = "${branch}"``), and ``when``
may read a bool parameter; the models accept those spellings everywhere (``reference`` reads
one) and leave "a root document may not use them" to the semantic pass, which knows which
document it is reading.

The JSON Schema (``json_schema()``) is the format's specification in a form editors and other
tooling can check.
"""
import re
from collections.abc import Callable, Mapping
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Discriminator,
    Field,
    PrivateAttr,
    Tag,
    ValidationError,
    field_validator,
    model_validator,
)

from .childjail import environment_spec
from .docpath import DocPath
from .effects import as_medium
from .ids import BUILTIN_ATOMS
from .locations import parse_location
from .dangerous import EXEC_CWD, EXEC_RESERVED_KEYWORDS

# ---------------------------------------------------------------------------
# scalars
# ---------------------------------------------------------------------------

# a parameter reference, whole: ``${name}``; names may carry dashes (``push-gate``)
_REF = re.compile(r"\$\{([\w-]+)\}")
# a parameter heading a location spelling: ``${where}`` or ``${where}/rest``
_HEAD_REF = re.compile(r"\$\{([\w-]+)\}(?:/(.+))?")
# a hole reference in an argv template: ``${X}`` (one token) or ``${X...}`` (a splice)
_HOLE_REF = re.compile(r"\$\{(\w+)(\.\.\.)?\}")
# a checker pin: the digest of the exact evaluator bytes a validation trusts
# (``integrity.py`` owns the checking; this is the format)
_PIN = re.compile(r"sha256:[0-9a-f]{64}")


def reference(text: str) -> str | None:
    """The name a whole ``${name}`` refers to, or None for any other text. One grammar, two
    namespaces: in a ruleset's tables it names a ``[params]`` parameter, in a validation's
    ``argv`` one of the validation's own ``params``; the field decides which."""
    m = _REF.fullmatch(text)
    return None if m is None else m.group(1)


def _location_text(text: str) -> str:
    """A location spelling (the ``locspec`` grammar): parsed to check it, kept as text. A
    parameter-headed spelling is checked past its head."""
    m = _HEAD_REF.fullmatch(text)
    if m is not None:
        rest = m.group(2)
        if rest is not None:
            parse_location(rest)  # raises ValueError, which pydantic reports at the field
        return text
    if "${" in text:
        raise ValueError("a parameter may only head a location spelling")
    parse_location(text)
    return text


def _regex_text(text: str) -> str:
    try:
        re.compile(text)
    except re.error as e:
        raise ValueError(f"bad regex: {e}") from None
    return text


def _atom_text(text: str) -> str:
    if not text:
        raise ValueError("an atom name is non-empty")
    if "${" in text and reference(text) is None:
        raise ValueError("a parameter is a whole atom entry")
    return text


def _argv_word(text: str) -> str:
    """A word of a template ``argv``: a literal, ``${X}`` or ``${X...}``; nothing in between."""
    if "${" in text and _HOLE_REF.fullmatch(text) is None:
        raise ValueError("hole references are whole words")
    return text


_CWD = EXEC_CWD  # the exec keyword, the `requires` target: never a hole


def _hole_name(text: str) -> str:
    """A hole's name: spelled as ``${X}``, so ``\\w+``; never a keyword of ``certora.exec``
    itself (``dangerous.EXEC_RESERVED_KEYWORDS``)."""
    if text in EXEC_RESERVED_KEYWORDS:
        raise ValueError(f"{text!r} is reserved and cannot be a hole")
    if not re.fullmatch(r"\w+", text):
        raise ValueError(f"hole names are letters, digits and '_': {text!r}")
    return text


def _demand_target(text: str) -> str:
    """A key of a ``requires`` table: ``cwd``, or a hole name."""
    return text if text == _CWD else _hole_name(text)


type HoleName = Annotated[str, AfterValidator(_hole_name)]
type DemandTarget = Annotated[str, AfterValidator(_demand_target)]


def _validation_argv_piece(text: str) -> str:
    """A piece of a validation ``argv``: a literal, a whole ``${param}``, or ``${checkers}/name``
    (resolved against the config directory by the semantic pass, not here)."""
    if text.startswith("${checkers}"):
        return text
    if "${checkers}" in text:
        raise ValueError("${checkers} may only head argv[0], as ${checkers}/<name>")
    if "${" in text and _REF.fullmatch(text) is None:
        raise ValueError("parameter references must be whole arguments")
    return text


type Location = Annotated[str, AfterValidator(_location_text)]
type Regex = Annotated[str, AfterValidator(_regex_text)]
type AtomName = Annotated[str, AfterValidator(_atom_text)]

def _listed(value: Any) -> Any:
    """One spelling stands for the list of one; the model always holds the list."""
    return [value] if isinstance(value, str) else value


# a location *slot*: one spelling or a non-empty list, meaning any-of; held as the list
type LocationSlot = Annotated[list[Location], BeforeValidator(_listed), Field(min_length=1)]
# an atom list, or one name standing for a list of one
type AtomList = list[AtomName]
# ``when``: a literal toggle, or a bool parameter (checked to be one by the semantic pass)
type When = bool | Annotated[str, AfterValidator(lambda s: s if reference(s) else _bad_when(s))]


def _bad_when(s: str) -> str:
    raise ValueError('expected true, false, or a bool parameter ("${flag}")')


# ---------------------------------------------------------------------------
# the common configuration: strict, closed, hyphenated keys
# ---------------------------------------------------------------------------


def _hyphenated(name: str) -> str:
    return name.rstrip("_").replace("_", "-")


class _Table(BaseModel):
    """A TOML table with a closed key set. Field names are the TOML keys with ``-`` as ``_``
    (``effect-free`` is ``effect_free``); a trailing underscore escapes a Python keyword or
    builtin (``list_`` is ``list``).

    Every table remembers the document it was read from (``where``), stamped from the
    validation context by ``parse_policy`` / ``parse_ruleset``, so a semantic pass working on
    tables from several documents at once can still say which file a problem is in without
    carrying the name beside every model. It survives ``model_copy``."""

    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        alias_generator=_hyphenated,  # documents are read by alias only; nothing builds these by name
    )

    _where: str = PrivateAttr(default="")

    def model_post_init(self, context: Any, /) -> None:
        if isinstance(context, dict) and isinstance(context.get("where"), str):
            self._where = context["where"]

    @property
    def where(self) -> str:
        """The document this table was read from, as the parser was told to name it."""
        return self._where


# ---------------------------------------------------------------------------
# constraints, flags, holes (TEMPLATES.md)
# ---------------------------------------------------------------------------


class ConstraintFields(_Table):
    """What one token must be. Shape (``location`` / ``matches`` / ``one-of``), provenance
    (``literal``) and facts (``atoms``) combine freely, except that a located value is textless
    (``location`` excludes ``matches`` and ``one-of``), ``matches`` excludes ``one-of``, and
    ``any`` stands alone. An empty constraint says nothing and is an error."""

    location: LocationSlot | None = None
    matches: Regex | None = None
    one_of: list[str] | None = None
    atoms: AtomList | None = None
    literal: bool = False
    any: bool = False

    @property
    def stated(self) -> bool:
        """Does the constraint claim anything besides ``any``?"""
        return (
            self.location is not None or self.matches is not None or self.one_of is not None
            or self.literal or bool(self.atoms)
        )

    @model_validator(mode="after")
    def _combines(self) -> "ConstraintFields":
        _check_constraint(self)
        return self


def _check_constraint(c: ConstraintFields) -> None:
    if c.any and c.stated:
        raise ValueError("a constraint with any = true combines with nothing")
    if c.location is not None and (c.matches is not None or c.one_of is not None):
        raise ValueError("a located value is textless: location does not combine with matches/one-of")
    if c.matches is not None and c.one_of is not None:
        raise ValueError("matches and one-of exclude each other")
    if not c.any and not c.stated:
        raise ValueError("an empty constraint says nothing; use any = true to mean that")


type Demands = dict[DemandTarget, AtomList]  # ``requires = { cwd = [...], HOLE = [...] }``


class FlagEntry(ConstraintFields):
    """One ``-x`` entry of a flag vocabulary: a constraint on the flag's value, or
    ``value = false`` for a bare flag spelled as a table; either may carry ``requires`` (atoms
    demanded of the cwd or another hole while the flag is present) and ``when``."""

    value: Literal[False] | None = None
    requires: Demands | None = None
    when: When | None = None

    @model_validator(mode="after")
    def _combines(self) -> "FlagEntry":  # a bare entry has no constraint at all
        if self.value is False:
            if self.stated or self.any:
                raise ValueError("value = false takes no constraint: a bare flag has no value")
        elif not self.stated and not self.any:
            raise ValueError("an empty table is not a bare flag: list bare flags under `bare`, or say value = false")
        else:
            _check_constraint(self)
        return self


def _lift(data: Any, into: str, taken: Callable[[str], bool]) -> Any:
    """A TOML table whose fixed keys sit beside entry keys the author chooses (a flag vocabulary's
    ``-x`` entries, an application's bindings): move the chosen keys under *into*, so the model
    is a closed table with one typed mapping field."""
    if not isinstance(data, dict) or into in data:
        return data
    lifted = {k: v for k, v in data.items() if taken(k)}
    if not lifted:
        return data
    rest = {k: v for k, v in data.items() if not taken(k)}
    return {**rest, into: lifted}


class FlagVocabulary(_Table):
    """``bare`` plus every ``-``-keyed entry, or ``any = true`` alone: the open vocabulary. In
    the document the entries are keys of the table itself (``"-n" = { matches = '\\d+' }``);
    the model holds them under ``flags``."""

    bare: list[str] | None = None
    any: bool = False
    flags: dict[str, FlagEntry] = Field(default_factory=dict)
    # read an undeclared ``-lr`` as ``-l -r`` (templates.Flagset); opt-in, since not every tool
    # bundles, and refused where a single-dash multi-letter flag shows this one does not
    expand_single_flags: bool = False

    @model_validator(mode="before")
    @classmethod
    def _entries(cls, data: Any) -> Any:
        return _lift(data, "flags", lambda k: k.startswith("-"))

    @property
    def inline(self) -> bool:
        """Does the table spell a vocabulary of its own?"""
        return self.bare is not None or self.any or bool(self.flags)

    @model_validator(mode="after")
    def _shape(self) -> "FlagVocabulary":
        _check_vocabulary(self)
        return self


def _check_vocabulary(v: FlagVocabulary) -> None:
    for b in v.bare or ():
        if not b.startswith("-"):
            raise ValueError(f"flag names begin with '-': {b!r}")
    if v.any and (v.bare or v.flags):
        raise ValueError("an open flag vocabulary (any = true) lists no flags")
    if not v.any and not v.bare and not v.flags:
        raise ValueError("a flag vocabulary needs at least one flag, or any = true")
    both = set(v.bare or ()) & set(v.flags)
    if both:
        raise ValueError(f"flags both bare and valued: {sorted(both)}")
    if v.expand_single_flags:
        if v.any:
            raise ValueError("expand-single-flags says nothing about an open flag vocabulary (any = true)")
        long_single = sorted(n for n in [*(v.bare or ()), *v.flags] if re.fullmatch(r"-[^-]{2,}", n))
        if long_single:
            raise ValueError(
                f"expand-single-flags: {long_single[0]!r} is a single-dash multi-letter flag, so this tool "
                "does not bundle short flags"
            )


class FlagsetDecl(FlagVocabulary):
    """``[[flagset]]``: a named vocabulary, private to its document; ``holes`` is its contract
    with the templates that use it -- the holes its flags' ``requires`` may reach."""

    name: str
    holes: list[HoleName] | None = None


class TokenHole(ConstraintFields):
    kind: Literal["token"] = "token"


class EachHole(ConstraintFields):
    kind: Literal["each"]
    min: int = Field(default=0, ge=0)


class FlagsHole(FlagVocabulary):
    """A flags hole with an inline vocabulary: ``kind = "flags"`` and the body."""

    kind: Literal["flags"]


class FlagsetRef(_Table):
    """A flags hole referencing a ``[[flagset]]``: ``kind = "flags"`` and ``flagset = "name"``,
    nothing else -- a reference carries no vocabulary of its own."""

    kind: Literal["flags"]
    flagset: str


def _hole_kind(value: Any) -> str | None:
    """The discriminator: ``kind``, defaulting to ``token``; a flags hole with a ``flagset`` key
    is a reference; a bare string is a parameter."""
    if isinstance(value, str):
        return "hole:param"
    if isinstance(value, dict):
        kind = value.get("kind", "token")
        if kind == "flags" and "flagset" in value:
            return "hole:flagset"
        return f"hole:{kind}" if isinstance(kind, str) else None
    if isinstance(value, FlagsetRef):
        return "hole:flagset"
    kind = getattr(value, "kind", None)
    return None if kind is None else f"hole:{kind}"


# the union tags appear in an error's path; they are named with a colon so ``_format`` can drop
# them (no document key -- a hole name is \w+, a region name has no colon -- looks like one)
type HoleSpec = Annotated[
    Annotated[TokenHole, Tag("hole:token")]
    | Annotated[EachHole, Tag("hole:each")]
    | Annotated[FlagsHole, Tag("hole:flags")]
    | Annotated[FlagsetRef, Tag("hole:flagset")]
    | Annotated[Annotated[str, AfterValidator(lambda s: s if reference(s) else _bad_hole_ref(s))], Tag("hole:param")],
    Discriminator(_hole_kind, custom_error_type="hole_kind", custom_error_message="kind must be one of token, each, flags"),
]


def _bad_hole_ref(s: str) -> str:
    raise ValueError('a hole is a table, or a constraint parameter ("${name}")')


# ---------------------------------------------------------------------------
# regions, atoms
# ---------------------------------------------------------------------------


class FootprintRegion(_Table):
    """A region on the filesystem (EFFECTS.md): its footprint, at or below each location."""

    footprint: LocationSlot
    about: str = ""


class NetworkRegion(_Table):
    """A region of remote state: ``network = true``."""

    network: Literal[True]
    about: str = ""


def _region_medium(value: Any) -> str | None:
    if isinstance(value, dict):
        fs, net = "footprint" in value, value.get("network") is True
        if fs and not net:
            return "region:fs"
        if net and not fs:
            return "region:net"
        return None  # neither, or both: the discriminator's own message
    if isinstance(value, FootprintRegion):
        return "region:fs"
    if isinstance(value, NetworkRegion):
        return "region:net"
    return None


type RegionDecl = Annotated[
    Annotated[FootprintRegion, Tag("region:fs")] | Annotated[NetworkRegion, Tag("region:net")],
    Discriminator(
        _region_medium,
        custom_error_type="region_medium",
        custom_error_message="a region has one medium: a footprint, or network = true, not both",
    ),
]


def _region_name(text: str) -> str:
    """A region's name: not a medium word, which stands for every region of the medium wherever
    a region may be named (``writes``, ``reads``)."""
    if as_medium(text) is not None:
        raise ValueError(f"{text!r} names a medium and is reserved")
    return text


def _atom_name_declared(text: str) -> str:
    """A key of ``[atoms]``: not one of the built-ins, which no policy declares."""
    if text in BUILTIN_ATOMS:
        raise ValueError(f"atom {text!r} is built in and cannot be declared")
    return _atom_text(text)


type RegionName = Annotated[str, AfterValidator(_region_name)]
type DeclaredAtomName = Annotated[str, AfterValidator(_atom_name_declared)]


class AtomDecl(_Table):
    """One ``[atoms]`` entry: environmental (``{}``, optionally ``reads``), pure (``pure = true``),
    or defined (``matches``, pure by construction)."""

    pure: bool | None = None
    matches: Regex | None = None
    reads: list[str] | None = None

    @model_validator(mode="after")
    def _kind(self) -> "AtomDecl":
        if self.matches is not None and self.pure is False:
            raise ValueError("a defined atom is pure by construction")
        if self.reads is not None:
            if self.pure or self.matches is not None:
                raise ValueError("a pure atom depends on no state; reads applies to environmental atoms")
            if not self.reads:
                raise ValueError("an atom that depends on nothing is pure; say pure = true")
        return self


# ---------------------------------------------------------------------------
# grants: validations, programs, sources, network
# ---------------------------------------------------------------------------


class ExecDecl(_Table):
    """``exec``: the rest of how the grant's child is run (JAILS.md, ``childjail``), beyond the
    media keys -- the environment (``env``: a list whose strings name variables passed through
    from the host and whose tables set variables to literal values; absent: the host's whole
    environment), whether it may create processes (``spawn``), and what it sees of the
    filesystem (``view``: ``"host"``, the host's whole filesystem, or ``"policy"``, only what the
    policy's filesystem section grants, MOUNTS.md). Enforced by the OS jail; all default to the
    unjailed baseline."""

    env: list[str | dict[str, str]] | None = None
    spawn: bool = True
    view: Literal["host", "policy"] = "host"
    # under view = "policy": locations this grant's child sees beyond the policy's filesystem
    # section (MOUNTS.md) -- mounted read-only, or writable (which needs write-fs = true). The
    # analysis never sees them: they widen the tool's world, not the program's
    mount_read: list[Location] | None = None
    mount_write: list[Location] | None = None

    @field_validator("env")
    @classmethod
    def _one_mapping(cls, items: list[str | dict[str, str]] | None) -> list[str | dict[str, str]] | None:
        if items is not None:
            environment_spec(items)  # names are names, each mentioned once, none the host's own
        return items

    @model_validator(mode="after")
    def _mounts_need_the_view(self) -> "ExecDecl":
        if self.view != "policy" and (self.mount_read is not None or self.mount_write is not None):
            raise ValueError('mount-read / mount-write widen the policy view: they need view = "policy"')
        return self


_RETIRED_MEDIA_KEYS = {
    "effect-free": "'effect-free' is no longer a key: spell writes = [] (the grant writes no region)",
    "write": "'write' is no longer a key: spell write-fs (the grant reaches the filesystem medium)",
}


class _Media(_Table):
    """The media a grant reaches -- enforced by its jail (``network``, ``write-fs``) -- what it
    writes within them (``writes``, EFFECTS.md), and the rest of the jail (``exec``)."""

    network: bool = True
    write_fs: bool = True
    writes: list[str] | None = None
    exec_: ExecDecl | None = None

    @model_validator(mode="before")
    @classmethod
    def _retired_media(cls, data: Any) -> Any:  # a distinct name: ProgramDecl._retired would shadow it
        if isinstance(data, dict):
            for key, message in _RETIRED_MEDIA_KEYS.items():
                if key in data:
                    raise ValueError(message)
        return data

    @model_validator(mode="after")
    def _writable_mounts_need_the_medium(self) -> "_Media":
        if self.exec_ is not None and self.exec_.mount_write is not None and not self.write_fs:
            raise ValueError("exec.mount-write on a grant with write-fs = false: nothing it mounts could be written")
        return self


class ValidationDecl(_Media):
    """``[[validation]]``: a runtime check -- its evaluator, where it may run, what its success
    establishes. ``cwd`` is optional: omitted, the check does not care where it runs and may not
    establish atoms on cwd."""

    name: str
    params: list[str] = Field(default_factory=list)
    argv: Annotated[list[Annotated[str, AfterValidator(_validation_argv_piece)]], Field(min_length=1)]
    cwd: LocationSlot | None = None
    establishes: dict[str, AtomList] = Field(default_factory=dict)
    # the sha256 of the evaluator this assertion was reviewed with (INSTALL.md): the establishing
    # behavior pinned to an implementation, checked before every run; absent, runs what is installed
    pin: str | None = None

    @field_validator("params")
    @classmethod
    def _referenceable(cls, params: list[str]) -> list[str]:
        """A parameter is referenced as ``${p}`` in argv, where ``${checkers}`` is taken."""
        for p in params:
            if p == "checkers":
                raise ValueError("'checkers' is ${checkers}, the checker directory, and cannot be a parameter")
            if _REF.fullmatch("${" + p + "}") is None:
                raise ValueError(f"parameter names are letters, digits, '_' and '-': {p!r}")
        return params

    @model_validator(mode="after")
    def _slots(self) -> "ValidationDecl":
        if len(set(self.params)) != len(self.params) or "cwd" in self.params:
            raise ValueError("parameters must be unique and may not be named 'cwd'")
        for key, atoms in self.establishes.items():
            if key != "cwd" and key not in self.params:
                raise ValueError(f"establishes references undeclared parameter {key!r}")
            if not atoms:
                raise ValueError("establishes entries need at least one atom")
        if self.cwd is None and "cwd" in self.establishes:
            raise ValueError("a check that does not care about its cwd cannot establish atoms on cwd")
        for piece in self.argv[1:]:
            if piece.startswith("${checkers}"):
                raise ValueError("${checkers} may only head argv[0]")
        if self.pin is not None:
            if _PIN.fullmatch(self.pin) is None:
                raise ValueError('pin is "sha256:" plus 64 lowercase hex digits')
            if not self.argv[0].startswith("${checkers}/"):
                raise ValueError("a pin binds an installed checker: it needs argv[0] = ${checkers}/<name>")
        return self


_RETIRED_PROGRAM_KEYS = ("argument-atoms", "unknown-arguments", "argument-locations")


class ProgramDecl(_Media):
    """``[[program]]``: a flat rule (``name`` plus ``subcommand``: exactly those words) or a
    template (``argv`` with ``${X}`` / ``${X...}`` pieces and a ``holes`` table). ``requires``
    is a list (atoms of the cwd) or a table ``{ cwd = [...], HOLE = [...] }``."""

    name: str
    cwd: LocationSlot
    subcommand: str | None = None
    argv: list[Annotated[str, AfterValidator(_argv_word)]] | None = None
    holes: dict[HoleName, HoleSpec] | None = None
    requires: AtomList | Demands | None = None
    source: str | None = None
    when: When | None = None
    # a root rule replacing every applied ruleset's rule its leading words overlap (root only;
    # the semantic pass checks there is one)
    override: bool = False

    @field_validator("subcommand")
    @classmethod
    def _words(cls, v: str | None) -> str | None:
        if v is not None and not v.split():
            raise ValueError("a subcommand is one or more words")
        return v

    @model_validator(mode="before")
    @classmethod
    def _retired(cls, data: Any) -> Any:
        if isinstance(data, dict):
            retired = [k for k in _RETIRED_PROGRAM_KEYS if k in data]
            if retired:
                raise ValueError(
                    f"{retired[0]!r} is no longer a rule key: a rule is its words alone, or a template "
                    "(argv + holes) whose holes say what each argument is (a location, a regex, "
                    "atoms, or any = true)"
                )
        return data

    @model_validator(mode="after")
    def _form(self) -> "ProgramDecl":
        if self.argv is not None:
            if self.subcommand is not None:
                raise ValueError("a templated rule carries no subcommand; its leading words are the argv's literal head")
            if not self.argv or _HOLE_REF.fullmatch(self.argv[0]) is not None:
                raise ValueError("a template begins with the program, a literal word")
            if self.argv[0] != self.name:
                raise ValueError(f"the template begins with {self.argv[0]!r}, not {self.name!r}")
            self._holes_agree(self.argv, self.holes or {})  # no holes: a template of words alone
        elif self.holes is not None:
            raise ValueError("holes need an argv template")
        elif isinstance(self.requires, dict) and any(k != _CWD for k in self.requires):
            raise ValueError("requires names holes, but the rule has no template")
        return self

    @staticmethod
    def _holes_agree(argv: list[str], holes: dict[str, HoleSpec]) -> None:
        """Every ``${X}`` / ``${X...}`` names a declared hole, once, of the matching kind; every
        declared hole is used. A hole given as ``"${p}"`` (a ruleset's constraint parameter, bound
        by the root) always instantiates as a token hole, so it must be spelled ``${X}``."""
        seen: set[str] = set()
        for word in argv:
            m = _HOLE_REF.fullmatch(word)
            if m is None:
                continue
            name, variadic = m.group(1), m.group(2) is not None
            if name in seen:
                raise ValueError(f"hole {name!r} appears more than once in argv")
            seen.add(name)
            spec = holes.get(name)
            if spec is None:
                raise ValueError(f"hole {name!r} is used but not declared")
            spliced = isinstance(spec, (EachHole, FlagsHole, FlagsetRef))
            if variadic != spliced:
                spelled = "${" + name + ("...}" if variadic else "}")
                kind = "a parameter" if isinstance(spec, str) else spec.kind
                raise ValueError(f"{spelled} disagrees with its kind ({kind})")
        unused = sorted(set(holes) - seen)
        if unused:
            raise ValueError(f"hole {unused[0]!r} is declared but not used")


class SourceDecl(_Table):
    """``[[source]]``: read locations whose contents yield a source atom (PROVENANCE.md)."""

    name: str
    location: LocationSlot


class RequiredAtom(_Table):
    atom: str
    on_redirect: Literal["recheck", "stop", "waive"] | None = None


class NetworkDecl(_Table):
    """``[[network]]``: one permitted destination of ``certora.network``."""

    host: str
    schemes: list[Literal["http", "https"]] | None = None
    ports: list[int] | None = None
    methods: list[str] | None = None
    allow_nonpublic: bool = False
    requires: list[str | RequiredAtom] | None = None
    read_timeout: float | int | None = None
    total_timeout: float | int | None = None
    max_response_bytes: int | None = None
    source: str | None = None
    path: LocationSlot | None = None
    writes: list[str] | None = None

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        if not v.strip().rstrip("."):
            raise ValueError("network rule needs a host")
        if "/" in v or ":" in v:
            raise ValueError("a host is a name (or *.suffix): no scheme, port or path")
        return v


# ---------------------------------------------------------------------------
# rulesets: parameters and applications (TEMPLATES.md)
# ---------------------------------------------------------------------------


# a ruleset parameter's kind (TEMPLATES.md): what it binds and where it may be substituted
type ParamKind = Literal["directory", "atom", "bool", "constraint"]


class ParamDecl(_Table):
    """``[params] x = { kind = ..., description = "..." }``. No defaults: an unbound bool is
    false, everything else a surviving piece references must be bound. The description is for
    whoever binds it: the installer's interview, ``--describe``, a policy author."""

    kind: ParamKind
    description: str | None = None


# a binding in an ``[[apply]]``: a directory or a list; an atom name or a list (``[]``: none);
# ``true``/``false``; a constraint table; or, in a nested apply, a parameter passed down whole.
# Which is right depends on the applied ruleset's parameter kind, so the shape is checked there
type Binding = Any


_APPLY_KEYS = frozenset({"ruleset", "when"})  # the keys of an [[apply]] that are not bindings


class ApplyDecl(_Table):
    """``[[apply]] ruleset = "x.toml"`` plus one key per parameter bound, held under
    ``bindings``. Which keys are parameters, and of which kind, is the applied ruleset's to
    say: the semantic pass checks the bindings against its ``[params]``."""

    ruleset: str
    when: When | None = None
    bindings: dict[str, Binding] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _entries(cls, data: Any) -> Any:
        return _lift(data, "bindings", lambda k: k not in _APPLY_KEYS)

    @field_validator("ruleset")
    @classmethod
    def _file(cls, v: str) -> str:
        if "/" in v or v in (".", "..") or not v.endswith(".toml"):
            raise ValueError("expected the name of a .toml file in the rulesets directory")
        return v


# ---------------------------------------------------------------------------
# the documents
# ---------------------------------------------------------------------------


def _literal_word(text: str) -> str:
    if not text or "${" in text:
        raise ValueError("the words of a shape are literal")
    return text


class DenyDecl(_Table):
    """``[[deny]] argv = ["git", "apply"]``: take back from the applied rulesets every rule whose
    leading words begin with these (root only)."""

    argv: Annotated[list[Annotated[str, AfterValidator(_literal_word)]], Field(min_length=1)]


class Protected(_Table):
    """``[filesystem] no-write``: locations no program write may touch, whatever ``write``
    grants -- a write that may lie at or below one is denied. A ruleset's obligation on every
    root that applies it (``${where}/**/.git``); a root may state its own."""

    no_write: list[Location] = Field(default_factory=list)


class Filesystem(Protected):
    """The root's grants. A kind left unwritten is None, distinct from a written ``[]``: without
    default-allow both mean nothing is permitted; with it, unwritten means the whole root and
    ``[]`` still means nothing."""

    read: list[Location] | None = None
    write: list[Location] | None = None
    list_: list[Location] | None = None  # the TOML key is ``list``


class _Vocabulary(_Table):
    """What a root policy and a ruleset share: the exec-side vocabulary, and a ``description``
    of the document for whoever picks it up (the installer's interview, ``--describe``)."""

    description: str | None = None
    regions: dict[RegionName, RegionDecl] = Field(default_factory=dict)
    atoms: dict[DeclaredAtomName, AtomDecl] = Field(default_factory=dict)
    flagset: list[FlagsetDecl] = Field(default_factory=list)
    validation: list[ValidationDecl] = Field(default_factory=list)
    program: list[ProgramDecl] = Field(default_factory=list)
    source: list[SourceDecl] = Field(default_factory=list)
    apply: list[ApplyDecl] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_names(self) -> "_Vocabulary":
        for section, names in (
            ("flagset", [f.name for f in self.flagset]),
            ("validation", [v.name for v in self.validation]),
        ):
            seen: set[str] = set()
            for n in names:
                if n in seen:
                    raise ValueError(f"{section} {n!r} is declared twice")
                seen.add(n)
        return self


class PolicyDoc(_Vocabulary):
    """A root policy: the grants, the network rules, the vocabulary, and the applications."""

    policy_version: Literal[1]
    root: str | None = None
    # apply the installed base ruleset (``rulesets/base.toml``); false: this policy is the whole
    # statement of what may run
    base: bool = True
    # a program no grant and no deny names runs, with any arguments, with the user's authority;
    # a named program keeps its shapes (fail closed). A `[filesystem]` kind left unwritten is
    # then `**`. Root policies only: a ruleset has no such key
    default_allow: bool = False
    filesystem: Filesystem = Field(default_factory=Filesystem)
    network: list[NetworkDecl] = Field(default_factory=list)
    deny: list[DenyDecl] = Field(default_factory=list)

    @field_validator("root")
    @classmethod
    def _absolute(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith("/"):
            raise ValueError("expected an absolute path")
        return v


class RulesetDoc(_Vocabulary):
    """A ruleset (TEMPLATES.md): exec-side vocabulary only, parameterised. No filesystem
    grants, no network, no root; it may *protect* locations (``[filesystem] no-write``)."""

    ruleset_version: Literal[1]
    params: dict[str, ParamDecl] = Field(default_factory=dict)
    filesystem: Protected = Field(default_factory=Protected)

    @field_validator("params")
    @classmethod
    def _bindable(cls, params: dict[str, ParamDecl]) -> dict[str, ParamDecl]:
        """A parameter is bound as a key of an ``[[apply]]`` beside ``ruleset`` and ``when``, and
        referenced as ``${name}``: a name that cannot do both is dead on arrival."""
        for name in params:
            if name in _APPLY_KEYS:
                raise ValueError(f"{name!r} is a key of [[apply]] itself and cannot be a parameter")
            if _REF.fullmatch("${" + name + "}") is None:
                raise ValueError(f"parameter names are letters, digits, '_' and '-': {name!r}")
        return params


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------


class SchemaError(Exception):
    """The document does not have the shape; every problem, one per line, each with its path."""

    def __init__(self, where: str, problems: list[str]) -> None:
        self.where = where
        self.problems = problems
        super().__init__("\n".join(f"{where}: {p}" for p in problems))


def _format(e: ValidationError) -> list[str]:
    """Each problem as ``path: message``, the path in the document's own terms
    (``DocPath.from_loc``). Three of pydantic's messages are reworded to what the format's
    documentation promises."""
    out: list[str] = []
    for err in e.errors():
        path = DocPath.from_loc(err["loc"])
        last = path.last
        match err["type"]:
            case "extra_forbidden":
                path, msg = path.parent, f"unknown key {last!r}"
            case "missing" if isinstance(last, str) and last.endswith("-version"):
                path, msg = path.parent, f"{last} = 1 is required"
            case "missing":
                path, msg = path.parent, f"{last} is required"
            case "literal_error" if isinstance(last, str) and last.endswith("-version"):
                path, msg = path.parent, f"unsupported {last}"
            case "literal_error" if last == "value":
                path, msg = path.parent, "value: expected false (the table form of a bare flag)"
            case "dict_type" | "model_type":
                msg = "expected a table"
            case "list_type":
                msg = "expected a list"
            case "string_type":
                msg = "expected a string"
            case "bool_type":
                msg = "expected true or false"
            case "int_type":
                msg = "expected an integer"
            case _:
                msg = err["msg"]
                if msg.startswith("Value error, "):
                    msg = msg[len("Value error, "):]
        out.append(f"{path}: {msg}" if path else msg)
    return out


def parse_policy(data: object, where: str = "<policy>") -> PolicyDoc:
    """The typed root document, or ``SchemaError`` with every shape problem."""
    try:
        return PolicyDoc.model_validate(data, context={"where": where})
    except ValidationError as e:
        raise SchemaError(where, _format(e)) from None


def parse_ruleset(data: object, where: str) -> RulesetDoc:
    """The typed ruleset document, or ``SchemaError`` with every shape problem."""
    try:
        return RulesetDoc.model_validate(data, context={"where": where})
    except ValidationError as e:
        raise SchemaError(where, _format(e)) from None


def parse_hole(table: Mapping[str, Any], where: str) -> TokenHole:
    """A constraint table on its own -- a root's binding of a ruleset's constraint parameter --
    read as the token hole it becomes where it lands."""
    try:
        return TokenHole.model_validate(dict(table), context={"where": where})
    except ValidationError as e:
        raise SchemaError(where, _format(e)) from None


def hole_reference(word: str) -> tuple[str, bool] | None:
    """``${X}`` -> (``X``, False); ``${X...}`` -> (``X``, True); a literal word -> None."""
    m = _HOLE_REF.fullmatch(word)
    return None if m is None else (m.group(1), m.group(2) is not None)


def json_schema() -> dict[str, Any]:
    """The root policy format as JSON Schema: the specification, for editors and other tools."""
    return PolicyDoc.model_json_schema(by_alias=True)
