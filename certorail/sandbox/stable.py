"""The stability model against the filesystem (REDLINES.md, "Stability"): ``world.toml``'s
``stable`` -- selectors and paths (``world.Stable``) -- expanded to the names it says nothing
replaces while a jail lives, as the placement checker takes them (``Place.Stability``). A host
world's view of a redline sits at the innermost of them above the redline; a whole run binds a
grant plainly at one of them, where otherwise it would serve it through a view.

Trusted, never checked: the user's judgment about this machine. In a host world a wrong judgment
exposes a redline for the exec in which something outside replaced the directory; in a policy
world it pins a bind to an object the host has moved on from, for the run. Neither changes what the
grants mean, only which paths the kernel holds and which go through a view.
"""
import pathlib
from dataclasses import dataclass

from certorail.sandbox.facts import Facts, Kind
from certorail.world import Selector, Stable

__all__ = ["StableNames", "expand"]

_XDG = (pathlib.Path(".config"), pathlib.Path(".cache"), pathlib.Path(".local/share"), pathlib.Path(".local/state"))


@dataclass(frozen=True)
class StableNames:
    """The names nothing replaces: *names*, and every name in the directories *children_of*."""

    names: frozenset[pathlib.Path]
    children_of: frozenset[pathlib.Path]

    def fixed(self, path: pathlib.Path) -> bool:
        return path in self.names or (path != path.parent and path.parent in self.children_of)

    def above(self, path: pathlib.Path) -> list[pathlib.Path]:
        """The stable directories strictly above *path*."""
        out = [a for a in self.names if a != path and a in path.parents]
        for d in self.children_of:
            if d != path and d in path.parents:
                child = d / path.relative_to(d).parts[0]
                if child != path:
                    out.append(child)
        return out


def expand(stable: Stable, root: pathlib.Path | None, facts: Facts) -> StableNames:
    """*stable*'s names on this filesystem. *root*: the sandbox root, what the ``root`` selector
    names (None: a jail with no root, which it then names nothing). ``home-dots`` lists the home
    directory, a recorded fact: a dot directory made since is seen at the next spawn."""
    names: set[pathlib.Path] = set(stable.paths)
    children_of: set[pathlib.Path] = set()
    for selector in stable.selectors:
        match selector:
            case Selector.TOPS:
                children_of.add(pathlib.Path("/"))
            case Selector.HOME:
                names.add(stable.home)
            case Selector.HOME_DOTS:
                names.update(
                    stable.home / n for n in facts.children(stable.home)
                    if n.startswith(".") and facts.kind(stable.home / n) is Kind.DIRECTORY
                )
            case Selector.ROOT:
                if root is not None:
                    names.add(root)
            case Selector.XDG:
                names.update(stable.home / rel for rel in _XDG)
    return StableNames(frozenset(names), frozenset(children_of))
