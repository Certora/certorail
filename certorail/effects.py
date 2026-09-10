"""Effect regions (EFFECTS.md): the state an effect writes and an atom depends on, as sets.

A *region* is a name for a piece of state a checker can observe and a command can change, and it
has exactly one *medium*: ``fs`` (it lives on the local filesystem) or ``network`` (it is remote).
An ``Effects`` value is a set of state: named regions, plus whole media -- every region of that
medium, declared or not. Whole media are what an undeclared claim denotes ("this rule writes
anything on the filesystem") and what the shorthand ``reads = ["network"]`` denotes, so they are
tops of the lattice rather than the finite list of declared names: a policy that declares no
regions at all still has every rule writing everything and every environmental atom depending on
everything, which is today's kill exactly.

Stdlib-only; imported by the analysis and the policy alike.
"""
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Literal

from .ids import RegionId

type Medium = Literal["fs", "network"]
MEDIA: tuple[Medium, ...] = ("fs", "network")


def as_medium(name: str) -> Medium | None:
    """The medium a name spells, if it is one of the two reserved names."""
    if name == "fs":
        return "fs"
    if name == "network":
        return "network"
    return None


@dataclass(frozen=True)
class Effects:
    """A set of state: named regions, and whole media."""

    regions: frozenset[RegionId] = frozenset()
    media: frozenset[Medium] = frozenset()

    @property
    def empty(self) -> bool:
        return not self.regions and not self.media

    def meets(self, other: "Effects", medium_of: Mapping[RegionId, Medium]) -> bool:
        """Do the two sets share state? A region meets itself and the whole medium it belongs
        to; a whole medium meets the same whole medium. *medium_of* is the policy's region
        table."""
        if self.regions & other.regions or self.media & other.media:
            return True
        if any(medium_of[r] in other.media for r in self.regions):
            return True
        return any(medium_of[r] in self.media for r in other.regions)


NOTHING = Effects()
EVERYTHING = Effects(media=frozenset(MEDIA))


def effects_of(names: Iterable[str]) -> Effects:
    """Names as a policy writes them: a medium name stands for the whole medium, anything else
    is a region."""
    regions: set[RegionId] = set()
    media: set[Medium] = set()
    for n in names:
        m = as_medium(n)
        if m is None:
            regions.add(RegionId(n))
        else:
            media.add(m)
    return Effects(frozenset(regions), frozenset(media))


def whole(media: Iterable[Medium]) -> Effects:
    return Effects(media=frozenset(media))
