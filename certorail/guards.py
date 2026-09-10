"""Abstract transformers for validation guards.

A *guard* is the boolean condition of an ``assert C``, of an ``if not C: raise ...``, or of any
other statement whose fall-through establishes ``C``. :func:`recognize` decomposes such a condition
into the facts it establishes about individual variables; :func:`apply` refines one variable's
fact with one of them. Neither knows anything about control flow or state: the caller decides
*where* a guard holds and *which* fact it refines, e.g.

    for guard in recognize(node.test, state):
        state[guard.subject] = apply(state.get(guard.subject), guard.refinement)

Recognized forms are the idiomatic ones (``"/" not in x``, ``re.fullmatch(r, x)``,
``p.resolve().is_relative_to(base)``, ``isinstance(x, str)``, ...). Anything unrecognized
establishes nothing, which is the intended failure mode: a guard the analysis does not understand
costs precision, never soundness.

Conditions are matched as :mod:`terms`, not ``ast`` nodes: ``lower`` resolves dotted names once,
so the recognizers below are plain structural patterns.
"""
import ast
from dataclasses import dataclass, replace
from typing import Literal, Sequence

from certorail.analysis import (
    ANY_STR,
    PATH_ATOMS,
    Alternation,
    AtomicFact,
    carried,
    DirSplat,
    Exact,
    Located,
    LocationFact,
    PathFact,
    PseudoRegex,
    RegexLit,
    StaticPath,
    StateMap,
    StrFact,
    UrlString,
    ValidationFact,
    _literal_location,
    alternation,
    both,
    concat,
    interpret_expr,
    locate,
    location_of,
    splat_under,
)
from certorail.ids import NO_PARENT_TRAVERSAL, NO_SLASH, NOT_ABSOLUTE, NOT_DOT_DOT, NOT_OPTION, Atom, AtomId
from certorail.locations import parse_location
from certorail.markers import NAMESPACE
from certorail.terms import (
    Attr,
    BinOp,
    Bool,
    Call,
    Compare,
    Const,
    Dotted,
    Items,
    Method,
    Not,
    Slice,
    Subscript,
    Term,
    Var,
    lower,
)

type TypeInfo = Literal["str", "path"]


@dataclass(frozen=True)
class Refinement:
    """What one recognized guard establishes about its subject. Every field is a conjunct."""

    type_info: TypeInfo | None = None
    atoms: frozenset[Atom] = frozenset()
    regex: PseudoRegex | None = None  # None: the guard says nothing about the regex
    containment: LocationFact | None = None
    # Atoms that must already hold on the subject for ``containment`` (and a ``url`` claim
    # carrying a path) to be trusted. Lexical containment checks (``p.is_relative_to(base)``,
    # ``x.startswith("data/")``, ``urlsplit(x).path.startswith("/v1/")``) only amount to
    # containment once ".." components are excluded; resolving checks (``p.resolve()...``)
    # need nothing.
    containment_requires: frozenset[AtomId] = frozenset()
    # claims about the subject's urlsplit reading (``urlsplit(x).netloc == "api.github.com"``)
    url: UrlString | None = None


NOTHING = Refinement()


@dataclass(frozen=True)
class Guard:
    subject: str
    refinement: Refinement


# ---------------------------------------------------------------------------
# apply: Refinement x fact -> fact
# ---------------------------------------------------------------------------


def _meet_regex(cur: PseudoRegex, new: PseudoRegex | None) -> PseudoRegex:
    """Both regexes hold of the value, so keep both: ``both`` is the meet (a finite one resolves
    against the other, an exact text absorbs everything). Keeping one by preference used to drop
    a ``re.fullmatch`` guard on any value whose text already had a shape."""
    return cur if new is None else both(cur, new)


def _prefer_containment(cur: LocationFact | None, new: LocationFact | None) -> LocationFact | None:
    # Both locations hold of the value; keep the more precise one. (A true meet would need the
    # ordering on LocationFact; this is a sound stand-in.)
    if cur is None:
        return new
    if new is None:
        return cur
    match cur, new:
        case StaticPath(), DirSplat():
            return cur
        case DirSplat(), StaticPath():
            return new
        case DirSplat(static_prefix=cp), DirSplat(static_prefix=np):
            return new if len(np) > len(cp) else cur
        case _:
            return cur


def _merge_url(cur: UrlString, new: UrlString) -> UrlString:
    # both claims hold of the value; keep the sharper one per component
    return UrlString(
        netloc=new.netloc if cur.netloc is None else _meet_regex(cur.netloc, new.netloc),
        path=_prefer_containment(cur.path, new.path),
        scheme=cur.scheme if cur.scheme is not None else new.scheme,
        atoms=cur.atoms,
    )


def apply(fact: ValidationFact | None, r: Refinement) -> ValidationFact | None:
    """Refine *fact* (``None`` = nothing known) with *r*; sound on the guard's fall-through path.

    A refinement whose type disagrees with the fact describes a dead path; the fact is returned
    unchanged rather than inventing a bottom element.
    """
    match fact, r.type_info:
        case None, None:
            return None  # a guard on a value of unknown type establishes nothing usable
        case None, "str":
            fact = StrFact()
        case None, "path":
            fact = PathFact()
        case (StrFact(), "path") | (PathFact(), "str"):
            return fact
        case (Located(repr="str"), "path") | (Located(repr="path"), "str"):
            return fact
        case _:
            ...
    assert fact is not None

    refined: StrFact | PathFact
    match fact:
        case Located(location=loc, repr=rp, atoms=atoms):
            # nothing is tracked about a located value's text, so text refinements are moot; only
            # an unconditional (resolving) containment can sharpen where it points
            if r.containment is not None and not r.containment_requires:
                return Located(_prefer_containment(loc, r.containment) or loc, rp, atoms)
            return fact
        case UrlString():
            # likewise textless; another URL claim merges, unless it is requires-gated (a
            # UrlString carries no atoms, so the gate cannot be shown)
            if r.url is not None and not r.containment_requires:
                return _merge_url(fact, r.url)
            return fact
        case StrFact(regex=regex, atoms=atoms):
            refined = StrFact(regex=_meet_regex(regex, r.regex), atoms=atoms | r.atoms)
        case PathFact(atoms=atoms):
            refined = PathFact(atoms=atoms | r.atoms)

    if (
        r.url is not None
        and isinstance(refined, StrFact)
        and all(a in refined for a in r.containment_requires)
    ):
        # the value gains its URL reading; the text reading is given up (as with containment),
        # and with it the built-ins that were about the text
        return UrlString(r.url.netloc, r.url.path, r.url.scheme, carried(refined.atoms))

    if r.containment is not None and all(a in refined for a in r.containment_requires):
        # the value gains its path reading; if its text already located it somewhere sharper
        # (an exact literal, say), keep that
        own = locate(refined)
        loc = _prefer_containment(None if own is None else own.location, r.containment)
        assert loc is not None
        return Located(loc, "str" if isinstance(refined, StrFact) else "path", carried(refined.atoms))
    return refined


# ---------------------------------------------------------------------------
# subjects and views
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Subject:
    """A variable seen through zero or more *views*: ``str(p)``, ``pathlib.Path(x)``,
    ``p.resolve()``, ``os.path.realpath(x)``..."""

    name: str
    # Any view at all: a type test on the view says nothing about the variable.
    viewed: bool = False
    # Went through resolve()/realpath, which follow symlinks: the view is the file the variable
    # actually names, so containment of the view is containment of the variable, unconditionally;
    # but the view is a different string, so none of its lexical atoms say anything about it.
    resolving: bool = False
    # Went through a PurePath/Path constructor, which normalizes lexically ("a/" and "./a" both
    # become "a"): absoluteness and ".." components survive that, a missing slash does not.
    normalizing: bool = False
    # Went through abspath/normpath, which collapse ".." *lexically*: "data/x/../y" becomes
    # "data/y", but the kernel resolves "data/x/.." physically, and if "data/x" is a symlink that
    # is somewhere else entirely. So containment of the view is containment of the variable only
    # if the collapse was a no-op, i.e. the variable itself has no "..", and nothing the view says
    # about ".." (or slashes) transfers.
    collapsing: bool = False


def subject_of(t: Term) -> Subject | None:
    match t:
        case Var(name):
            return Subject(name)
        case Method(inner, "resolve", (), ()):
            sub = subject_of(inner)
            return None if sub is None else replace(sub, viewed=True, resolving=True)
        case Call(("os", "path", "realpath"), (inner,), ()):
            sub = subject_of(inner)
            return None if sub is None else replace(sub, viewed=True, resolving=True)
        case Call(("os", "path", "abspath" | "normpath"), (inner,), ()):
            sub = subject_of(inner)
            return None if sub is None else replace(sub, viewed=True, collapsing=True)
        case Call(("pathlib", "Path" | "PurePath" | "PosixPath" | "PurePosixPath"), (inner,), ()):
            sub = subject_of(inner)
            return None if sub is None else replace(sub, viewed=True, normalizing=True)
        case Call(("str",) | ("os", "fspath"), (inner,), ()):
            sub = subject_of(inner)
            return None if sub is None else replace(sub, viewed=True)
        case _:
            return None


def _guard(sub: Subject | None, r: Refinement) -> list[Guard]:
    """Attribute *r* to the variable behind *sub*, discounting what the view invalidates."""
    if sub is None:
        return []
    if sub.viewed:
        r = replace(r, type_info=None)
    if sub.normalizing:
        # PurePath() rewrites the text ("h://a" becomes "h:/a"): URL claims about the view say
        # nothing about the variable
        r = replace(r, atoms=r.atoms - {"no-slash"}, url=None)
    if sub.collapsing:
        # the view is a different string (regex, slashes, "..") but keeps absoluteness; its
        # containment stays conditional on the variable's own no-parent-traversal
        r = replace(
            r, atoms=r.atoms - {"no-slash", "no-parent-traversal", "not-dot-dot"}, regex=None,
            url=None,
        )
    if sub.resolving:
        r = replace(
            r, atoms=frozenset(), regex=None, containment_requires=frozenset(), url=None
        )
    if r == NOTHING:
        return []
    return [Guard(sub.name, r)]


# ---------------------------------------------------------------------------
# operand helpers
# ---------------------------------------------------------------------------


def _fact_of(t: Term, st: StateMap) -> ValidationFact | None:
    return interpret_expr(t.node, st)


def _literals(t: Term) -> list[str] | None:
    """A string literal or a display of them (``"a"``, ``("a", "b")``); None otherwise."""
    if (s := t.as_str()) is not None:
        return [s]
    return t.str_items()


def _is_sep(t: Term) -> bool:
    match t:
        case Const("/") | Dotted(("os", "sep")):
            return True
        case _:
            return False


def _components_of(t: Term) -> Subject | None:
    """``x.split("/")``, ``x.split(os.sep)``, ``pathlib.PurePath(x).parts``, ``p.parts`` -> the subject."""
    match t:
        case Method(inner, "split", (sep,), ()) if _is_sep(sep):
            return subject_of(inner)
        case Attr(inner, "parts"):
            return subject_of(inner)
        case _:
            return None


def _location_of(t: Term, st: StateMap) -> LocationFact | None:
    """The location an operand names: a literal path (relative to the sandbox root, or absolute
    with a leading "/"), or an expression with a containment fact, looked at through any views
    (``BASE.resolve()``, ``str(BASE)``, ``os.path.realpath(BASE)``)."""
    match t:
        case Const(str() as s):
            return _literal_location(s)
        case Method(inner, "resolve", (), ()):
            return _location_of(inner, st)
        case Call(
            ("str",)
            | ("os", "fspath")
            | ("pathlib", "Path" | "PurePath" | "PosixPath" | "PurePosixPath")
            | ("os", "path", "realpath" | "abspath" | "normpath"),
            (inner,),
            (),
        ):
            return _location_of(inner, st)
        case _:
            return location_of(_fact_of(t, st))


def _prefix_location(t: Term, st: StateMap) -> LocationFact | None:
    """The location named by a ``startswith`` prefix: ``"data/"``, ``str(BASE) + "/"``,
    ``BASE + os.sep``. A prefix without a trailing separator names nothing (``/data`` vs
    ``/database``)."""
    match t:
        case Const(str() as s):
            if not s.endswith("/"):
                return None
            return _literal_location(s)  # PurePath drops the trailing slash
        case BinOp(left, ast.Add, right) if _is_sep(right):
            return _location_of(left, st)
        case _:
            return None


def _from_fact(fact: ValidationFact) -> Refinement:
    """Everything a fact says, as a refinement (for ``x == E`` transfer)."""
    match fact:
        case StrFact(regex=regex, atoms=atoms):
            return Refinement(
                type_info="str", atoms=atoms, regex=None if regex == ANY_STR else regex
            )
        case PathFact(atoms=atoms):
            return Refinement(type_info="path", atoms=atoms)
        case Located(location=loc, repr=rp):
            return Refinement(type_info=rp, containment=loc)
        case UrlString(netloc=netloc, path=path, scheme=scheme):
            return Refinement(type_info="str", url=UrlString(netloc, path, scheme))


def _exact_or_alternation(literals: Sequence[str]) -> PseudoRegex:
    return alternation(*(Exact(s) for s in literals))


def _within(loc: LocationFact) -> Refinement:
    """Containment at or below *loc*, as established by a *lexical* check: trusted only once ".."
    is excluded. (``_guard`` drops the requirement again for resolving subjects.)"""
    return Refinement(
        containment=splat_under(loc), containment_requires=frozenset({NO_PARENT_TRAVERSAL})
    )


def _url_view(t: Term) -> tuple[Term, str, bool] | None:
    """``urlsplit(x).<comp>`` / ``urlparse(x).<comp>`` -> (x, component, via urlsplit).

    The two agree on scheme and netloc, but urlparse shears ``;params`` off the last path
    segment, so a ``.path`` observed through urlparse is NOT evidence about the urlsplit path
    (which is what a ``UrlString`` claims and what the broker checks)."""
    match t:
        case Attr(Call(("urllib", "parse", ("urlsplit" | "urlparse") as fn), (inner,), ()), comp):
            return inner, comp, fn == "urlsplit"
        case _:
            return None


def _url_refinement(comp: str, from_split: bool, value: str) -> Refinement | None:
    """The claim ``urlsplit(x).<comp> == value`` makes about x, if it is one we can state."""
    match comp:
        case "netloc":
            return Refinement(type_info="str", url=UrlString(netloc=Exact(value)))
        case "scheme" if value in ("http", "https"):
            return Refinement(type_info="str", url=UrlString(scheme=value))
        case "path" if from_split:
            loc = _literal_location(value)  # rejects ".." (lexical claims only)
            return None if loc is None else Refinement(type_info="str", url=UrlString(path=loc))
        case _:
            return None


def _same_variable(a: Term, b: Term) -> bool:
    """Is *b* the bare variable that *a* is (a view of)? ``os.path.basename(x) == x``."""
    sa, sb = subject_of(a), subject_of(b)
    return sa is not None and sb is not None and sa.name == sb.name and not sb.viewed


# The typed nonsense a recognizer must see through. A comparison between a string literal and a
# pathlib object is ill-typed: ``".." in pathlib.Path(x)`` raises TypeError, ``Path(x) == ".."``
# is always false, ``Path(x) != ".."`` and ``Path(x) not in (".", "..")`` are vacuously true. None
# says anything about the text, so a guard built from one would be a fact the program never
# earned (John, 2026-09-21: ``assert ".." not in pathlib.Path(name)`` established
# no-parent-traversal). Likewise a str method on a pathlib object, or a pathlib method on text,
# raises AttributeError. What is known by construction (a constructor, a path-returning method)
# or from the state (a variable holding a path fact) decides; an unknown term may be either and
# is left to the shape rules.

_PATH_METHODS = frozenset({
    "resolve", "absolute", "expanduser", "with_name", "with_suffix", "with_stem", "joinpath",
    "relative_to", "readlink",
})


def _path_object(t: Term, st: StateMap) -> bool:
    """Does *t* evaluate to a pathlib object rather than text?"""
    match t:
        case Call(("pathlib", _), _, _):
            return True
        case Method(_, name, _, _) if name in _PATH_METHODS:
            return True
        case Attr(_, "parent"):
            return True
        case BinOp(left, op, _) if op is ast.Div:
            return _path_object(left, st)
        case Var(name):
            fact = st.get(name)
            return isinstance(fact, PathFact) or (isinstance(fact, Located) and fact.repr == "path")
        case _:
            return False


def _text_object(t: Term, st: StateMap) -> bool:
    """Does *t* evaluate to text rather than a pathlib object?"""
    match t:
        case Const(str()):
            return True
        case Call(("str",) | ("os", "fspath") | ("os", "path", _), _, _):
            return True
        case Var(name):
            fact = st.get(name)
            return isinstance(fact, (StrFact, UrlString)) or (isinstance(fact, Located) and fact.repr == "str")
        case _:
            return False


def _type_of(t: Term) -> TypeInfo | None:
    """The type named by the second argument of ``isinstance``; tuples name no single type."""
    match t:
        case Var("str"):
            return "str"
        case Dotted(("pathlib", "Path" | "PurePath" | "PosixPath" | "PurePosixPath")):
            return "path"
        case _:
            return None


# ---------------------------------------------------------------------------
# recognize: condition -> guards
# ---------------------------------------------------------------------------

# Negating a comparison.
_FLIP: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.Lt: ast.GtE,
    ast.GtE: ast.Lt,
    ast.Gt: ast.LtE,
    ast.LtE: ast.Gt,
}
# Swapping the operands of a comparison.
_MIRROR: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Lt: ast.Gt,
    ast.Gt: ast.Lt,
    ast.LtE: ast.GtE,
    ast.GtE: ast.LtE,
    ast.Eq: ast.Eq,
    ast.NotEq: ast.NotEq,
}

# ``str.is*()`` predicates: every character is alphanumeric-ish, so none is "/" or ".", and the
# string is non-empty. The regexes are the exact (or slightly wider) ``re`` equivalents; the
# predicates without one still yield the atoms.
_IS_PREDICATES: dict[str, PseudoRegex | None] = {
    "isalnum": RegexLit(r"[^\W_]+"),
    "isalpha": RegexLit(r"[^\W\d_]+"),
    "isdecimal": RegexLit(r"\d+"),
    "isidentifier": RegexLit(r"[^\W\d]\w*"),
    "isdigit": None,
    "isnumeric": None,
}

NO_SLASH_REF = Refinement(atoms=frozenset({NO_SLASH}))
NO_PARENT_REF = Refinement(atoms=frozenset({NO_PARENT_TRAVERSAL}))
NOT_ABSOLUTE_REF = Refinement(atoms=frozenset({NOT_ABSOLUTE}))
NOT_DOT_DOT_REF = Refinement(atoms=frozenset({NOT_DOT_DOT}))
# not x.startswith("-") ; x[0] != "-" ; x[:1] != "-": the text does not begin with "-"
NOT_OPTION_REF = Refinement(atoms=frozenset({NOT_OPTION}))
# basename(x) == x, dirname(x) == "", PurePath(x).name == x: no separator anywhere, hence not
# absolute either; ".." itself passes all three, so nothing about parent traversal.
BARE_NAME = Refinement(atoms=frozenset({NO_SLASH, NOT_ABSOLUTE}))


def recognize(cond: ast.expr | Term, st: StateMap) -> list[Guard]:
    """The guards established by *cond* being true. Unrecognized shapes yield nothing.

    Accepts a Term so a caller that lowers with its own module set can pass the result directly.
    """
    term = lower(cond) if isinstance(cond, ast.expr) else cond
    return _rec(term, True, st)


def _rec(t: Term, positive: bool, st: StateMap) -> list[Guard]:
    match t:
        case Not(inner):
            return _rec(inner, not positive, st)
        case Bool(ast.And, parts) if positive:
            return [g for p in parts for g in _rec(p, True, st)]
        case Bool(ast.Or, parts) if not positive:
            # not (A or B)  ==  not A and not B
            return [g for p in parts for g in _rec(p, False, st)]
        case Bool(ast.Or, parts):
            return _disjunction(parts, st)
        case Bool():
            return []  # not (A and B): a disjunction of negations, nothing useful
        case Compare(left, op, right):
            return _compare(left, op if positive else _FLIP[op], right, st)
        case Call() | Method():
            return _call(t, positive, st)
        case _:
            return []  # truthiness of a name, chained comparisons, ...


def _compare(
    left: Term, op: type[ast.cmpop], right: Term, st: StateMap
) -> list[Guard]:
    if (probed := _probe_compare(left, op, right)) is not None:
        return probed
    match op:
        case ast.NotIn:
            return _not_in(left, right, st)
        case ast.In:
            return _in(left, right, st)
        case ast.Eq:
            return _eq(left, right, st) + _eq(right, left, st)
        case ast.NotEq:
            return _neq(left, right, st) + _neq(right, left, st)
        case ast.IsNot:
            # ``re.fullmatch(...) is not None``: the truthiness of the left operand
            match left, right:
                case (Call() | Method()), Const(None):
                    return _call(left, True, st)
                case _:
                    return []
        case _:
            return []


def _slash_probe(t: Term) -> tuple[Subject | None, str] | None:
    """``x.find("/")``, ``x.rfind("/")``, ``x.count("/")`` -> (subject, method)."""
    match t:
        case Method(inner, ("find" | "rfind" | "count") as m, (sep,), ()) if _is_sep(sep):
            return subject_of(inner), m
        case _:
            return None


def _probe_compare(left: Term, op: type[ast.cmpop], right: Term) -> list[Guard] | None:
    """``x.find("/") == -1 | < 0 | <= -1``, ``x.count("/") == 0 | < 1 | <= 0``, and their mirror
    images. ``None`` when this is not a probe comparison at all."""
    probe, n = _slash_probe(left), right.as_int()
    if probe is None:
        probe, n = _slash_probe(right), left.as_int()
        mirrored = _MIRROR.get(op)
        if mirrored is None:
            return None
        op = mirrored
    if probe is None or n is None:
        return None
    sub, method = probe
    missing = -1 if method in ("find", "rfind") else 0  # the "no occurrence" value
    hit = (
        (op is ast.Eq and n == missing)
        or (op is ast.Lt and n == missing + 1)
        or (op is ast.LtE and n == missing)
    )
    return _guard(sub, NO_SLASH_REF) if hit else []


def _not_in(left: Term, right: Term, st: StateMap) -> list[Guard]:
    # "/" not in x ; os.sep not in x   (a substring test: on a pathlib object it raises)
    if _is_sep(left):
        return [] if _path_object(right, st) else _guard(subject_of(right), NO_SLASH_REF)
    # ".." not in x.split("/") ; ".." not in p.parts   (a component test)
    # ".." not in x   (substring: over-strict but sound -- for text; on a pathlib object it raises)
    if left.as_str() == "..":
        components = _components_of(right)
        if components is not None:
            return _guard(components, NO_PARENT_REF)
        return [] if _path_object(right, st) else _guard(subject_of(right), NO_PARENT_REF)
    # x not in (".", "..")   (vacuously true of a pathlib object: never equal to a str)
    lits = right.str_items()
    if lits is not None and ".." in lits and not _path_object(left, st):
        return _guard(subject_of(left), NOT_DOT_DOT_REF)
    return []


def _in(left: Term, right: Term, st: StateMap) -> list[Guard]:
    # x in ("a", "b")  (x in "literal" is a substring test and proves nothing)
    lits = right.str_items()
    if lits and (uv := _url_view(left)) is not None:
        # urlsplit(u).netloc in ("a.com", "b.com")
        inner, comp, _ = uv
        if comp != "netloc":
            return []
        return _guard(
            subject_of(inner),
            Refinement(type_info="str", url=UrlString(netloc=_exact_or_alternation(lits))),
        )
    if lits:
        return _guard(
            subject_of(left), Refinement(type_info="str", regex=_exact_or_alternation(lits))
        )
    # BASE in p.parents
    match right:
        case Attr(inner, "parents"):
            loc = _location_of(left, st)
            return [] if loc is None else _guard(subject_of(inner), _within(loc))
        case _:
            return []


def _eq(a: Term, b: Term, st: StateMap) -> list[Guard]:
    """``a == b`` with the "interesting" operand on the left; called in both orientations."""
    # urlsplit(x).netloc == "api.github.com" and friends: a claim about x's urlsplit reading
    if (uv := _url_view(a)) is not None:
        inner, comp, from_split = uv
        value = b.as_str()
        r = None if value is None else _url_refinement(comp, from_split, value)
        return [] if r is None else _guard(subject_of(inner), r)
    match a:
        # os.path.basename(x) == x
        case Call(("os", "path", "basename"), (inner,), ()):
            return _guard(subject_of(inner), BARE_NAME) if _same_variable(inner, b) else []
        # os.path.dirname(x) == ""
        case Call(("os", "path", "dirname"), (inner,), ()):
            return _guard(subject_of(inner), BARE_NAME) if b.as_str() == "" else []
        # pathlib.PurePath(x).name == x
        case Attr(inner, "name"):
            return _guard(subject_of(inner), BARE_NAME) if _same_variable(inner, b) else []
        # p.parent == BASE ; p.resolve().parent == BASE.resolve()
        case Attr(inner, "parent"):
            loc = _location_of(b, st)
            return [] if loc is None else _guard(subject_of(inner), _within(loc))
        # os.path.commonpath([v, BASE]) == BASE
        case Call(("os", "path", "commonpath"), (Items((v, base)),), ()):
            if base != b:  # terms compare structurally, positions excluded
                return []
            loc = _location_of(base, st)
            return [] if loc is None else _guard(subject_of(v), _within(loc))
        case Subscript():
            return []  # x[0] == "/" and friends only ever assert something bad
        case _:
            ...
    sub = subject_of(a)
    if sub is None:
        return []
    # x == "lit"   (never true of a pathlib object: the branch is dead, and says nothing)
    if (s := b.as_str()) is not None:
        return [] if _path_object(a, st) else _guard(sub, Refinement(type_info="str", regex=Exact(s)))
    # x == E: whatever is known about E is known about x
    other = subject_of(b)
    if other is not None and other.name == sub.name:
        return []
    fact = _fact_of(b, st)
    return [] if fact is None else _guard(sub, _from_fact(fact))


def _is_head_slice(t: Term) -> bool:
    match t:
        case Const(0):
            return True
        case Slice(None, Const(1), None):
            return True
        case _:
            return False


def _neq(a: Term, b: Term, st: StateMap) -> list[Guard]:
    """``a != b``; called in both orientations."""
    # x != ".."   (vacuously true of a pathlib object: never equal to a str)
    if b.as_str() == "..":
        return [] if _path_object(a, st) else _guard(subject_of(a), NOT_DOT_DOT_REF)
    # x[0] != "/" ; x[:1] != "/" ; x[0] != "-" ; x[:1] != "-"   (a pathlib object is not subscriptable)
    match a:
        case Subscript(inner, _) if _path_object(inner, st):
            return []
        case Subscript(inner, index) if _is_sep(b) and _is_head_slice(index):
            return _guard(subject_of(inner), NOT_ABSOLUTE_REF)
        case Subscript(inner, index) if b.as_str() == "-" and _is_head_slice(index):
            return _guard(subject_of(inner), NOT_OPTION_REF)
        case _:
            return []


def _pattern_of(callee: tuple[str, ...], pat: Term) -> PseudoRegex | None:
    r = pat.as_str()
    if r is None:
        return None
    if callee == ("re", "fullmatch"):
        return RegexLit(r)
    # re.match anchored at the very end is a fullmatch. "$" also admits a trailing newline, and a
    # top-level "|" would anchor only the last branch, so neither is accepted.
    if r.endswith(r"\Z") and "|" not in r:
        return RegexLit(r[:-2])
    return None


def _call(t: Term, positive: bool, st: StateMap) -> list[Guard]:
    match t:
        # bool(C)
        case Call(("bool",), (inner,), ()):
            return _rec(inner, positive, st)
        # isinstance(x, str) ; isinstance(p, pathlib.Path)  (negative form proves nothing tracked)
        case Call(("isinstance",), (x, ty), ()) if positive:
            ti = _type_of(ty)
            return [] if ti is None else _guard(subject_of(x), Refinement(type_info=ti))
        # re.fullmatch(r, x) ; re.match(r"...\Z", x)   (a flags argument changes the language: skip)
        case Call(("re", "fullmatch" | "match") as callee, (pat, x), ()) if positive:
            r = _pattern_of(callee, pat)
            return [] if r is None else _guard(subject_of(x), Refinement(type_info="str", regex=r))
        # not os.path.isabs(x)
        case Call(("os", "path", "isabs"), (x,), ()) if not positive:
            return _guard(subject_of(x), NOT_ABSOLUTE_REF)
        # certora.pathmatch(x, "<location>"): the policy's own spelling as a guard
        case Call((ns, "pathmatch"), (x, spec), ()) if positive and ns == NAMESPACE:
            return _pathmatch(x, spec)
        case Method(Var(ns), "pathmatch", (x, spec), ()) if positive and ns == NAMESPACE:
            return _pathmatch(x, spec)
        case Method(recv, name, args, ()):
            return _method(recv, name, args, positive, st)
        case _:
            return []


def _pathmatch(x: Term, spec: Term) -> list[Guard]:
    """``certora.pathmatch(x, "<location>")`` being true: *x* is at that location -- the very
    ``LocationFact`` the policy loader builds from the same spelling (``locations``). On a URL
    path view (``urlsplit(u).path``) it is a claim about the URL; on a path it is containment,
    unconditional, because the matcher itself refuses ``..`` and anchors must agree. A
    collapsing view (``normpath``/``abspath``) rewrote ``..`` away before the match, so it
    establishes nothing about the variable."""
    text = spec.as_str()
    if text is None:
        return []
    try:
        loc = parse_location(text)
    except ValueError:
        return []
    if (uv := _url_view(x)) is not None:
        inner, comp, from_split = uv
        if comp != "path" or not from_split or not loc.absolute:
            return []  # a URL path is server-absolute, and only urlsplit's reading is trusted
        return _guard(subject_of(inner), Refinement(type_info="str", url=UrlString(path=loc)))
    sub = subject_of(x)
    if sub is None or sub.collapsing:
        return []
    return _guard(sub, Refinement(type_info="str", containment=loc))


def _method(
    recv: Term,
    name: str,
    args: tuple[Term, ...],
    positive: bool,
    st: StateMap,
) -> list[Guard]:
    # re.compile(r"...").fullmatch(x) is a call on a pattern, not a method on a subject. (A compiled
    # pattern held in a name can't be resolved here.)
    if name == "fullmatch":
        match recv, args:
            case Call(("re", "compile"), (Const(str() as r),), ()), (x,) if positive:
                return _guard(subject_of(x), Refinement(type_info="str", regex=RegexLit(r)))
            case _:
                return []

    # urlsplit(u).path.startswith("/v1/"): the urlsplit path lies under /v1 -- lexically, so
    # like every prefix check it is trusted only once ".." is excluded
    if name == "startswith" and positive and (uv := _url_view(recv)) is not None:
        inner, comp, from_split = uv
        if comp != "path" or not from_split or len(args) != 1:
            return []
        prefix = args[0].as_str()
        if prefix is None or not prefix.endswith("/"):
            return []  # "/data" also prefixes "/database"
        loc = _literal_location(prefix)  # PurePath drops the trailing slash
        if loc is None or not loc.absolute:
            return []  # a URL path with a netloc is server-absolute; anything else is exotic
        return _guard(
            subject_of(inner),
            Refinement(
                type_info="str",
                url=UrlString(path=splat_under(loc)),
                containment_requires=frozenset({NO_PARENT_TRAVERSAL}),
            ),
        )

    sub = subject_of(recv)
    if sub is None:
        return []
    # a str method on a pathlib object, or a pathlib method on text, is an AttributeError, not a
    # guard
    if name in ("startswith", "endswith") or name in _IS_PREDICATES:
        if _path_object(recv, st):
            return []
    elif name in ("is_absolute", "is_relative_to") and _text_object(recv, st):
        return []
    match name, args:
        # not p.is_absolute()
        case "is_absolute", () if not positive:
            return _guard(sub, NOT_ABSOLUTE_REF)
        # not x.startswith("/")
        case "startswith", (arg,) if not positive and _is_sep(arg):
            return _guard(sub, NOT_ABSOLUTE_REF)
        # not x.startswith("-")
        case "startswith", (arg,) if not positive and arg.as_str() == "-":
            return _guard(sub, NOT_OPTION_REF)
        # x.startswith("pre") ; x.startswith(("a", "b")) ; x.startswith("data/") ; x.startswith(str(BASE) + "/")
        case "startswith", (arg,) if positive:
            return _startswith(sub, arg, st)
        # x.endswith(".json") ; x.endswith((".json", ".yaml"))
        case "endswith", (arg,) if positive:
            lits = _literals(arg)
            if not lits:
                return []
            return _guard(
                sub,
                Refinement(type_info="str", regex=concat(ANY_STR, _exact_or_alternation(lits))),
            )
        # p.is_relative_to(BASE) ; p.resolve().is_relative_to(BASE.resolve())
        case "is_relative_to", (base,) if positive:
            loc = _location_of(base, st)
            return [] if loc is None else _guard(sub, replace(_within(loc), type_info="path"))
        # x.isalnum() and friends: no "/" or "." anywhere, and no "-" either
        case m, () if positive and m in _IS_PREDICATES:
            return _guard(
                sub, Refinement(type_info="str", atoms=PATH_ATOMS | {NOT_OPTION}, regex=_IS_PREDICATES[m])
            )
        case _:
            return []


def _startswith(sub: Subject, arg: Term, st: StateMap) -> list[Guard]:
    guards: list[Guard] = []
    # the string begins with the literal(s): Concat([Exact|Alternation, AnyStr]); its Exact head
    # also lets __contains__ derive not-absolute
    lits = _literals(arg)
    if lits:
        guards += _guard(
            sub,
            Refinement(type_info="str", regex=concat(_exact_or_alternation(lits), ANY_STR)),
        )
    # x.startswith("data/") ; os.path.realpath(x).startswith(str(BASE) + os.sep)
    loc = _prefix_location(arg, st)
    if loc is not None:
        guards += _guard(sub, _within(loc))
    return guards


def _disjunction(parts: Sequence[Term], st: StateMap) -> list[Guard]:
    """``x == "a" or x == "b" or x in ("c", "d")`` -> one Alternation. Any other disjunction
    establishes nothing."""
    subject: str | None = None
    branches: list[PseudoRegex] = []
    for p in parts:
        guards = _rec(p, True, st)
        if len(guards) != 1:
            return []
        (g,) = guards
        r = g.refinement
        if r.regex is None or r != Refinement(type_info=r.type_info, regex=r.regex):
            return []  # only pure regex refinements can be unioned
        if not isinstance(r.regex, (Exact, Alternation)):
            return []
        if subject is not None and subject != g.subject:
            return []
        subject = g.subject
        branches.append(r.regex)
    if subject is None:
        return []
    return [Guard(subject, Refinement(type_info="str", regex=alternation(*branches)))]
