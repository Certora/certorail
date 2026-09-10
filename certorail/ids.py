"""Phantom types for the policy's names.

An atom, a region, a validation, a program, a flagset, a flag, a hole and a check parameter are
all spelled as strings, and a ``Mapping[str, X]`` says nothing about which. Under the type
checker each name below is a distinct subclass of ``str``, so a region name cannot be looked up
in the atom table by accident and a signature says which domain it wants; at runtime each is
``str`` itself -- no wrapper object, no cost. Convert where a string *enters* a domain -- the
loader, the factories in ``policy.py``, the walker's lookup of a name the program spelled --
with ``AtomId(text)``, which is the identity at runtime.

The runtime branch is a plain alias on purpose: a ``type X = str`` statement produces a
``TypeAliasType``, which is not callable, and ``AtomId(text)`` has to work.

Each type is documented by where its strings come from in a policy document (``policyfile.py``)
and in a confined program.
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:

    class AtomId(str):
        """A validation fact. Declared as a key of ``[atoms]``; spelled in a validation's
        ``establishes`` values, a rule's ``requires`` and ``argument-atoms``, a constraint's
        ``atoms``, a network rule's ``requires`` (bare, or its ``atom =``), the ``source`` of a
        ``[[program]]`` or ``[[network]]`` rule and the ``name`` of a ``[[source]]``; and by a
        program as ``certora.validated("...")``."""

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
    AtomId = str
    RegionId = str
    ValidationName = str
    ProgramName = str
    FlagsetId = str
    FlagName = str
    HoleName = str
    ParamName = str
