"""Names, typed by the domain they belong to.

Atoms come in three kinds and the kind is part of the id (ATOMS.md), so the three are real
``str`` subclasses: a fact's atom set is a ``frozenset[Atom]`` whose members say what they are,
a function can ask for a ``SourceId`` where only provenance makes sense, and the type checker
keeps the kinds apart. They are still strings -- equal to and hashed as their text -- so every
string-keyed table works and a set holds one member per *name*: the kinds share a namespace
(built-in names are reserved, a policy declares each of its names once), and where a spelling
does not carry the kind (``certora.validated("x")`` in a program, ``constraint(atoms=["x"])`` in
the Python API) the vocabulary's kind table is authoritative.

- ``AtomId``: a **built-in** atom certorail defines -- ``no-slash``, ``no-parent-traversal``,
  ``not-absolute``, ``not-dot-dot``, ``not-option``. Structural: derivable from a value's shape.
  Declared by no file; nameable in any (a hole's ``atoms``, a checker's ``establishes``).
- ``CheckId``: an atom a policy declares in ``[atoms]`` and establishes by a validation, a
  regex definition, or a guard. Environmental or pure; the vocabulary knows which.
- ``SourceId``: an atom a policy declares and only extraction establishes (PROVENANCE.md).

The other names -- regions, validations, programs, flagsets, flags, holes, check parameters --
are phantom types: distinct ``str`` subclasses under the type checker, ``str`` itself at
runtime, converted where a string enters the domain with ``RegionId(text)`` (the identity at
runtime). The runtime branch is a plain alias on purpose: a ``type X = str`` statement produces
a ``TypeAliasType``, which is not callable.
"""
from collections.abc import Mapping
from typing import TYPE_CHECKING, Final, Literal

type AtomIdName = Literal["no-slash", "no-parent-traversal", "not-absolute", "not-dot-dot", "not-option"]


class AtomId(str):
    """A built-in atom: a structural property of a value's text or location, derivable by the
    analysis (``analysis.holds``) and nameable by a policy but declared by none."""

    if TYPE_CHECKING:
        def __init__(self, other: AtomIdName):
            ...

    __slots__ = ()


class CheckId(str):
    """A policy atom established by a check, a regex definition or a guard. Declared as a key of
    ``[atoms]``; spelled in a validation's ``establishes``, a rule's ``requires``, a constraint's
    ``atoms``, a network rule's ``requires``; and by a program as ``certora.validated("...")``."""

    __slots__ = ()


class SourceId(str):
    """A policy atom that extraction alone establishes: the ``source`` of a ``[[program]]`` or
    ``[[network]]`` rule, the ``name`` of a ``[[source]]``; spelled by a program as
    ``certora.source("...")``."""

    __slots__ = ()


type Atom = AtomId | CheckId | SourceId

NO_SLASH: Final = AtomId("no-slash")
NO_PARENT_TRAVERSAL: Final = AtomId("no-parent-traversal")
NOT_ABSOLUTE: Final = AtomId("not-absolute")
NOT_DOT_DOT: Final = AtomId("not-dot-dot")
# the value does not begin with "-", so a tool cannot read it as an option: what every token or
# each hole not preceded by a literal "--" requires (TEMPLATES.md, the leading-dash guard)
NOT_OPTION: Final = AtomId("not-option")

BUILTIN_ATOMS: Final[Mapping[str, AtomId]] = {
    a: a for a in (NO_SLASH, NO_PARENT_TRAVERSAL, NOT_ABSOLUTE, NOT_DOT_DOT, NOT_OPTION)
}


def spelled(name: str) -> Atom:
    """An atom as a program or the Python API spells it. An id already carrying its kind is kept
    (``constraint(atoms=[SourceId("gh-api")])`` demands provenance and says so); a bare name is a
    built-in by name, otherwise a policy atom labelled ``CheckId`` -- a label, since demands are
    met by name and the vocabulary's kind table decides whether the name is in fact a source."""
    if isinstance(name, (AtomId, CheckId, SourceId)):
        return name
    builtin = BUILTIN_ATOMS.get(name)
    return CheckId(name) if builtin is None else builtin


if TYPE_CHECKING:

    class RegionId(str):
        """A piece of state (EFFECTS.md). Declared as a key of ``[regions]``; spelled in the
        ``writes`` of a ``[[program]]``, ``[[validation]]`` or ``[[network]]`` rule and in an
        atom's ``reads`` -- where the two medium words ``fs`` and ``network`` are not regions but
        stand for every region of that medium (``effects.as_medium``)."""

    class ValidationName(str):
        """A runtime check. Declared as the ``name`` of a ``[[validation]]``; spelled by a
        program as the first argument of ``certora.check`` / ``certora.check_single``."""

    class ProgramName(str):
        """An executable the policy grants. Declared as the ``name`` of a ``[[program]]``, which
        is also ``argv[0]`` of its template; spelled by a program as the first argument of
        ``certora.exec``. Several rules share one name (they differ in leading words)."""

    class FlagsetId(str):
        """A named flag vocabulary. Declared as the ``name`` of a ``[[flagset]]``; referenced by
        a flags hole's ``flagset = "..."``. Private to the document that declares it."""

    class FlagName(str):
        """One flag of a vocabulary, ``-``-prefixed. Declared as an entry of ``bare`` or as a
        key of a ``[[flagset]]`` / inline flag table; spelled by a program as an element of the
        list bound to a flags hole."""

    class HoleName(str):
        """A slot of a command template. Declared as a key of a rule's ``holes`` table and
        referenced as ``${X}`` / ``${X...}`` in its ``argv``; spelled by a program as a keyword
        argument of ``certora.exec`` other than ``cwd``."""

    class ParamName(str):
        """A validation's input. Declared as an entry of its ``params`` and referenced as
        ``${p}`` in its ``argv``; a key of ``establishes`` (with ``cwd`` as the one name every
        validation has); spelled by a program as a keyword argument of ``certora.check``."""

else:
    RegionId = str
    ValidationName = str
    ProgramName = str
    FlagsetId = str
    FlagName = str
    HoleName = str
    ParamName = str
