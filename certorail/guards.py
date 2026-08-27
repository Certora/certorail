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
from typing import Literal, Mapping, Sequence

from .analysis import (
    ALL_ATOMS,
    ANY_STR,
    Alternation,
    AnyStr,
    AtomicFact,
    Concat,
    DirSplat,
    Exact,
    LocationFact,
    Named,
    PathFact,
    PseudoRegex,
    RegexLit,
    StaticPath,
    StrFact,
    ValidationFact,
    _safe_path_extension,
    alternation,
    concat,
    interpret_expr,
    splat_under,
)
from .terms import (
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
    atoms: frozenset[AtomicFact] = frozenset()
    regex: PseudoRegex | None = None  # None: the guard says nothing about the regex
    containment: LocationFact | None = None
    # Atoms that must already hold on the subject for ``containment`` to be trusted. Lexical
    # containment checks (``p.is_relative_to(base)``, ``x.startswith("data/")``) only amount to
    # containment once ".." components are excluded; resolving checks (``p.resolve()...``) need
    # nothing.
    containment_requires: frozenset[AtomicFact] = frozenset()


NOTHING = Refinement()


@dataclass(frozen=True)
class Guard:
    subject: str
    refinement: Refinement


# ---------------------------------------------------------------------------
# apply: Refinement x fact -> fact
# ---------------------------------------------------------------------------


def _regex_rank(p: PseudoRegex) -> int:
    # Both regexes hold of the value, so keeping either is sound; prefer the one whose atoms
    # ``_explicit_check`` can see through.
    match p:
        case Exact():
            return 0
        case Alternation():
            return 1
        case Concat():
            return 2
        case RegexLit():
            return 3
        case AnyStr():
            return 4


def _prefer_regex(cur: PseudoRegex, new: PseudoRegex | None) -> PseudoRegex:
    if new is None:
        return cur
    return new if _regex_rank(new) < _regex_rank(cur) else cur


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
        case (StrFact(), "str" | None) | (PathFact(), "path" | None):
            ...
    assert fact is not None

    atoms = fact.atoms | r.atoms
    refined: ValidationFact
    if isinstance(fact, StrFact):
        refined = StrFact(
            regex=_prefer_regex(fact.regex, r.regex), containment=fact.containment, atoms=atoms
        )
    else:
        refined = PathFact(containment=fact.containment, atoms=atoms)

    if r.containment is not None and all(a in refined for a in r.containment_requires):
        refined = replace(
            refined, containment=_prefer_containment(refined.containment, r.containment)
        )
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
        r = replace(r, atoms=r.atoms - {"no-slash"})
    if sub.collapsing:
        # the view is a different string (regex, slashes, "..") but keeps absoluteness; its
        # containment stays conditional on the variable's own no-parent-traversal
        r = replace(r, atoms=r.atoms - {"no-slash", "no-parent-traversal", "not-dot-dot"}, regex=None)
    if sub.resolving:
        r = replace(r, atoms=frozenset(), regex=None, containment_requires=frozenset())
    if r == NOTHING:
        return []
    return [Guard(sub.name, r)]


# ---------------------------------------------------------------------------
# operand helpers
# ---------------------------------------------------------------------------


def _fact_of(t: Term, st: Mapping[str, ValidationFact]) -> ValidationFact | None:
    return interpret_expr(t.node, dict(st))


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


def _static(parts: tuple[str, ...]) -> StaticPath:
    return StaticPath(tuple(Named(p) for p in parts))


def _location_of(t: Term, st: Mapping[str, ValidationFact]) -> LocationFact | None:
    """The location an operand names: a literal path, or an expression with a containment fact,
    looked at through any views (``BASE.resolve()``, ``str(BASE)``, ``os.path.realpath(BASE)``)."""
    match t:
        case Const(str() as s):
            parts = _safe_path_extension(s)
            return None if parts is None else _static(parts)
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
            fact = _fact_of(t, st)
            return None if fact is None else fact.containment


def _prefix_location(t: Term, st: Mapping[str, ValidationFact]) -> LocationFact | None:
    """The location named by a ``startswith`` prefix: ``"data/"``, ``str(BASE) + "/"``,
    ``BASE + os.sep``. A prefix without a trailing separator names nothing (``/data`` vs
    ``/database``)."""
    match t:
        case Const(str() as s):
            if not s.endswith("/"):
                return None
            parts = _safe_path_extension(s)  # PurePath drops the trailing slash
            return None if parts is None else _static(parts)
        case BinOp(left, ast.Add, right) if _is_sep(right):
            return _location_of(left, st)
        case _:
            return None


def _from_fact(fact: ValidationFact) -> Refinement:
    """Everything a fact says, as a refinement (for ``x == E`` transfer)."""
    match fact:
        case StrFact(regex=regex, containment=cont, atoms=atoms):
            return Refinement(
                type_info="str",
                atoms=atoms,
                regex=None if regex == ANY_STR else regex,
                containment=cont,
            )
        case PathFact(containment=cont, atoms=atoms):
            return Refinement(type_info="path", atoms=atoms, containment=cont)


def _exact_or_alternation(literals: Sequence[str]) -> PseudoRegex:
    return alternation(*(Exact(s) for s in literals))


def _within(loc: LocationFact) -> Refinement:
    """Containment at or below *loc*, as established by a *lexical* check: trusted only once ".."
    is excluded. (``_guard`` drops the requirement again for resolving subjects.)"""
    return Refinement(
        containment=splat_under(loc), containment_requires=frozenset({"no-parent-traversal"})
    )


def _same_variable(a: Term, b: Term) -> bool:
    """Is *b* the bare variable that *a* is (a view of)? ``os.path.basename(x) == x``."""
    sa, sb = subject_of(a), subject_of(b)
    return sa is not None and sb is not None and sa.name == sb.name and not sb.viewed


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

NO_SLASH = Refinement(atoms=frozenset({"no-slash"}))
NO_PARENT = Refinement(atoms=frozenset({"no-parent-traversal"}))
NOT_ABSOLUTE = Refinement(atoms=frozenset({"not-absolute"}))
NOT_DOT_DOT = Refinement(atoms=frozenset({"not-dot-dot"}))
# basename(x) == x, dirname(x) == "", PurePath(x).name == x: no separator anywhere, hence not
# absolute either; ".." itself passes all three, so nothing about parent traversal.
BARE_NAME = Refinement(atoms=frozenset({"no-slash", "not-absolute"}))


def recognize(cond: ast.expr | Term, st: Mapping[str, ValidationFact]) -> list[Guard]:
    """The guards established by *cond* being true. Unrecognized shapes yield nothing.

    Accepts a Term so a caller that lowers with its own module set can pass the result directly.
    """
    term = lower(cond) if isinstance(cond, ast.expr) else cond
    return _rec(term, True, st)


def _rec(t: Term, positive: bool, st: Mapping[str, ValidationFact]) -> list[Guard]:
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
    left: Term, op: type[ast.cmpop], right: Term, st: Mapping[str, ValidationFact]
) -> list[Guard]:
    if (probed := _probe_compare(left, op, right)) is not None:
        return probed
    match op:
        case ast.NotIn:
            return _not_in(left, right)
        case ast.In:
            return _in(left, right, st)
        case ast.Eq:
            return _eq(left, right, st) + _eq(right, left, st)
        case ast.NotEq:
            return _neq(left, right) + _neq(right, left)
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
    return _guard(sub, NO_SLASH) if hit else []


def _not_in(left: Term, right: Term) -> list[Guard]:
    # "/" not in x ; os.sep not in x
    if _is_sep(left):
        return _guard(subject_of(right), NO_SLASH)
    # ".." not in x (substring: over-strict but sound) ; ".." not in x.split("/") ; ".." not in p.parts
    if left.as_str() == "..":
        return _guard(_components_of(right) or subject_of(right), NO_PARENT)
    # x not in (".", "..")
    lits = right.str_items()
    if lits is not None and ".." in lits:
        return _guard(subject_of(left), NOT_DOT_DOT)
    return []


def _in(left: Term, right: Term, st: Mapping[str, ValidationFact]) -> list[Guard]:
    # x in ("a", "b")  (x in "literal" is a substring test and proves nothing)
    lits = right.str_items()
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


def _eq(a: Term, b: Term, st: Mapping[str, ValidationFact]) -> list[Guard]:
    """``a == b`` with the "interesting" operand on the left; called in both orientations."""
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
    # x == "lit"
    if (s := b.as_str()) is not None:
        return _guard(sub, Refinement(type_info="str", regex=Exact(s)))
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


def _neq(a: Term, b: Term) -> list[Guard]:
    """``a != b``; called in both orientations."""
    # x != ".."
    if b.as_str() == "..":
        return _guard(subject_of(a), NOT_DOT_DOT)
    # x[0] != "/" ; x[:1] != "/"
    match a:
        case Subscript(inner, index) if _is_sep(b) and _is_head_slice(index):
            return _guard(subject_of(inner), NOT_ABSOLUTE)
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


def _call(t: Term, positive: bool, st: Mapping[str, ValidationFact]) -> list[Guard]:
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
            return _guard(subject_of(x), NOT_ABSOLUTE)
        case Method(recv, name, args, ()):
            return _method(recv, name, args, positive, st)
        case _:
            return []


def _method(
    recv: Term,
    name: str,
    args: tuple[Term, ...],
    positive: bool,
    st: Mapping[str, ValidationFact],
) -> list[Guard]:
    # re.compile(r"...").fullmatch(x) is a call on a pattern, not a method on a subject. (A compiled
    # pattern held in a name can't be resolved here.)
    if name == "fullmatch":
        match recv, args:
            case Call(("re", "compile"), (Const(str() as r),), ()), (x,) if positive:
                return _guard(subject_of(x), Refinement(type_info="str", regex=RegexLit(r)))
            case _:
                return []

    sub = subject_of(recv)
    if sub is None:
        return []
    match name, args:
        # not p.is_absolute()
        case "is_absolute", () if not positive:
            return _guard(sub, NOT_ABSOLUTE)
        # not x.startswith("/")
        case "startswith", (arg,) if not positive and _is_sep(arg):
            return _guard(sub, NOT_ABSOLUTE)
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
        # x.isalnum() and friends
        case m, () if positive and m in _IS_PREDICATES:
            return _guard(
                sub, Refinement(type_info="str", atoms=ALL_ATOMS, regex=_IS_PREDICATES[m])
            )
        case _:
            return []


def _startswith(sub: Subject, arg: Term, st: Mapping[str, ValidationFact]) -> list[Guard]:
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


def _disjunction(parts: Sequence[Term], st: Mapping[str, ValidationFact]) -> list[Guard]:
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
