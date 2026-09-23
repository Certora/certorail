"""What a mechanism can say of one policy location: the vocabulary both spawners lower into.

Each location of a ``PolicyFilesystem`` (the section's and the rule's additions) becomes exactly
one of these, decided by the spawner for its mechanism, and the decision carries what the
location was for (its ``Role``) so the plan and the report need no second lookup:

- ``Bind``: a bind mount (bubblewrap) or a ``subpath`` filter (Seatbelt) of one concrete path
  (``locations.single_path``);
- ``RegexRule``: Seatbelt's anchored ERE over canonical paths, for a patterned location;
- ``Omitted``: neither mechanism can express it here; it is absent from the child's world and
  the host says so at startup, with the reason the spawner gave.

A location the FUSE view answers for (bubblewrap, a root-relative location of the section when
the run has a view) is not lowered at all: the view is one bind of the root, and the daemon
enforces the section behind it, so there is nothing per location for the mechanism to say.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from certorail.analysis import LocationFact

__all__ = ["Bind", "Lowered", "Omitted", "RegexRule", "Role", "readable", "writable"]

# what a location is for: the section's three kinds, and the rule's two additions (read and
# written exactly like the section's read and write, reported under their own names)
type Role = Literal["read", "write", "no-write", "mount-read", "mount-write"]


@dataclass(frozen=True)
class Bind:
    """One concrete path: with *subtree*, the path and everything below it (``dir/**``);
    without, the path alone (a literal location). A bind mount cannot say "alone" for a
    directory; Seatbelt can (``literal``)."""

    path: Path
    role: Role
    subtree: bool = True


@dataclass(frozen=True)
class RegexRule:
    pattern: str
    role: Role


@dataclass(frozen=True)
class Omitted:
    location: LocationFact
    role: Role
    reason: str


type Lowered = Bind | RegexRule | Omitted


def readable(role: Role) -> bool:
    return role in ("read", "write", "mount-read", "mount-write")


def writable(role: Role) -> bool:
    return role in ("write", "mount-write")
