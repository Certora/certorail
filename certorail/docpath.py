"""A location in a policy document, as a value.

Every problem the loader reports names where in the document it is: ``program[0].holes.A``,
``apply[1].branch``, ``regions.git.config.footprint``. Passes over a document build that name
as they descend, and pydantic hands back the same thing as an ``err["loc"]`` tuple. This module
is the one representation of it, so both are built and printed the same way and a path is
never a string a call site assembled by hand.

A path is built by attribute access that mirrors the document's own keys, checked by the type
checker against the document's grammar one level deep:

    Path().program(0).holes["A"].location       # program[0].holes.A.location
    Path().regions["git.config"].footprint      # regions.git.config.footprint
    Path().apply(1).key("branch")               # apply[1].branch

``__getattr__`` is overloaded on the key: an array section (``program``, ``apply``, ``argv``)
yields an ``Indexed`` that only an ``(int)`` turns back into a path; a table of tables
(``holes``, ``regions``, ``flags``) yields a ``Keyed`` that only a ``[name]`` does; a scalar or
single-table key yields a path. So ``Path().program.when`` and ``Path().holes(0)`` are type
errors, and so is a key the document does not have. Keys the grammar does not fix -- a hole's
name, a region's name, a flag entry -- go through ``[name]`` or ``.key(name)``; an index through
``(i)`` or ``.at(i)``. Three keys are both a section and a scalar elsewhere (``source``,
``network``, ``flagset``): the attribute is the section, the scalar is ``.key("source")``.

At runtime the three classes share one implementation and differ only in what they refuse.
"""
import re
from collections.abc import Sequence
from typing import Literal, overload

type Segment = str | int

# what pydantic adds to a ``loc`` for its own machinery -- union tags we named with a colon,
# validator wrappers, the type names it uses as branch labels -- none of which is a document key;
# and the two fields the schema lifts an author's own keys under (``flags`` of a vocabulary,
# ``bindings`` of an application), which the document spells inline. (A hole *named* ``flags``
# would lose that segment from its path in a message; the grammar allows it, nothing uses it.)
_INTERNAL_SEGMENT = re.compile(
    r"^([a-z]+:|function-(after|before|wrap|plain)|list\[|dict\[|str$|bool$|int$|float$|\[key\]$|flags$|bindings$)"
)


def _hyphenated(name: str) -> str:
    """An attribute spelling to the document's key: ``write_fs`` is ``write-fs``."""
    return name.replace("_", "-")


class DocPath:
    """A sequence of keys and indices from the document's root. Immutable, hashable, printed
    the way the documentation spells paths."""

    __slots__ = ("_segments",)

    def __init__(self, segments: Sequence[Segment] = ()) -> None:
        object.__setattr__(self, "_segments", tuple(segments))

    @property
    def segments(self) -> tuple[Segment, ...]:
        return self._segments

    def key(self, name: str) -> "Path":
        """A key the grammar does not fix: a hole's, a region's, a flag entry's, a binding's."""
        return Path((*self._segments, name))

    def at(self, index: int) -> "Path":
        """An index into a list the grammar does not name as a section (a ``requires`` list)."""
        return Path((*self._segments, index))

    @classmethod
    def from_loc(cls, loc: Sequence[Segment]) -> "Path":
        """The path pydantic reports, less the segments that are its own machinery."""
        return Path(tuple(s for s in loc if not (isinstance(s, str) and _INTERNAL_SEGMENT.match(s))))

    @property
    def parent(self) -> "Path":
        return Path(self._segments[:-1])

    @property
    def last(self) -> Segment | None:
        return self._segments[-1] if self._segments else None

    def __str__(self) -> str:
        out = ""
        for s in self._segments:
            out += f"[{s}]" if isinstance(s, int) else (f".{s}" if out else s)
        return out

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str(self)!r})"

    def __bool__(self) -> bool:
        return bool(self._segments)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, DocPath) and self._segments == other._segments

    def __hash__(self) -> int:
        return hash(self._segments)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __reduce__(self) -> tuple[type["DocPath"], tuple[tuple[Segment, ...]]]:
        # copy and pickle rebuild through the constructor, not by setting slots
        return type(self), (self._segments,)


# the document's grammar, one level deep: which keys hold arrays, which hold tables of tables,
# which hold one value or one table. A key here is spelled as an attribute, dashes as
# underscores. Everything else is a dynamic key and goes through ``[...]`` / ``.key(...)``.
type IndexedKey = Literal["program", "validation", "flagset", "apply", "source", "network", "argv", "bare"]
type KeyedKey = Literal["holes", "regions", "atoms", "params", "flags", "bindings", "establishes", "requires"]
type ScalarKey = Literal[
    "policy_version", "ruleset_version", "root", "filesystem", "read", "write", "list",
    "name", "cwd", "when", "kind", "subcommand", "min", "literal", "any", "location", "matches",
    "one_of", "footprint", "about", "pure", "reads", "writes", "write_fs", "exec", "env", "spawn", "ruleset", "host",
    "schemes", "ports", "methods", "allow_nonpublic", "read_timeout", "total_timeout",
    "max_response_bytes", "path", "value", "atom", "on_redirect",
]

_INDEXED: frozenset[str] = frozenset({"program", "validation", "flagset", "apply", "source", "network", "argv", "bare"})
_KEYED: frozenset[str] = frozenset({"holes", "regions", "atoms", "params", "flags", "bindings", "establishes", "requires"})
_SCALAR: frozenset[str] = frozenset({
    "policy_version", "ruleset_version", "root", "filesystem", "read", "write", "list",
    "name", "cwd", "when", "kind", "subcommand", "min", "literal", "any", "location", "matches",
    "one_of", "footprint", "about", "pure", "reads", "writes", "write_fs", "exec", "env", "spawn", "ruleset", "host",
    "schemes", "ports", "methods", "allow_nonpublic", "read_timeout", "total_timeout",
    "max_response_bytes", "path", "value", "atom", "on_redirect",
})


class Path(DocPath):
    """A path at which the document has a table: the root, a rule, a hole, a flag entry."""

    __slots__ = ()

    @overload
    def __getattr__(self, name: IndexedKey) -> "Indexed": ...
    @overload
    def __getattr__(self, name: KeyedKey) -> "Keyed": ...
    @overload
    def __getattr__(self, name: ScalarKey) -> "Path": ...

    def __getattr__(self, name: str) -> "Indexed | Keyed | Path":
        # only the grammar's keys; anything else -- a dunder copy/pickle probes for, a typo
        # -- is an attribute this object does not have, never a path segment
        if name in _INDEXED:
            return Indexed((*self._segments, _hyphenated(name)))
        if name in _KEYED:
            return Keyed((*self._segments, _hyphenated(name)))
        if name in _SCALAR:
            return Path((*self._segments, _hyphenated(name)))
        raise AttributeError(name)


class Indexed(DocPath):
    """A path at which the document has an array of tables: ``(i)`` names one of them."""

    __slots__ = ()

    def __call__(self, index: int) -> Path:
        return Path((*self._segments, index))


class Keyed(DocPath):
    """A path at which the document has a table of tables keyed by the author's names:
    ``[name]`` names one of them."""

    __slots__ = ()

    def __getitem__(self, name: str) -> Path:
        return Path((*self._segments, name))
