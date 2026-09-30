"""What the jail compiler reads from the filesystem, and nothing else (LOWERING2.md, "What the
compiler reads from the filesystem"): the kind of a path, where a path resolves to, and the
names in a directory. Every pass asks through a ``Facts``, so the passes are pure given the
answers, a test can hand them a filesystem that does not exist, and a recipe can carry the
answers it was compiled against (``Recorded``) for linking to ask again."""
import enum
import os
import pathlib
import stat
from dataclasses import dataclass, field
from typing import Protocol

__all__ = ["ChildrenChanged", "Disk", "Facts", "Kind", "KindChanged", "Recorded", "ResolutionChanged"]


class Kind(enum.Enum):
    FILE = "a file"
    DIRECTORY = "a directory"
    SYMLINK = "a symbolic link"
    MISSING = "missing"


class Facts(Protocol):
    def kind(self, path: pathlib.Path) -> Kind:
        """What is at *path* itself, as ``lstat`` says: a link at *path* is not followed, the
        links above it are -- so a path under a link reads as what it leads to."""
        ...

    def resolve(self, path: pathlib.Path) -> pathlib.Path:
        """*path* with every link along it followed, as far as it exists."""
        ...

    def children(self, path: pathlib.Path) -> tuple[str, ...]:
        """The names in the directory at *path*, sorted; none when it is no directory."""
        ...


class Disk:
    """This machine's filesystem."""

    def children(self, path: pathlib.Path) -> tuple[str, ...]:
        try:
            return tuple(sorted(os.listdir(path)))
        except OSError:
            return ()

    def kind(self, path: pathlib.Path) -> Kind:
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            return Kind.MISSING
        except NotADirectoryError:
            return Kind.MISSING
        if stat.S_ISLNK(mode):
            return Kind.SYMLINK
        return Kind.DIRECTORY if stat.S_ISDIR(mode) else Kind.FILE

    def resolve(self, path: pathlib.Path) -> pathlib.Path:
        return pathlib.Path(os.path.realpath(path))


@dataclass(frozen=True)
class KindChanged:
    path: pathlib.Path
    before: Kind
    now: Kind

    def describe(self) -> str:
        return f"{self.path} was {self.before.value} when the jail was compiled and is {self.now.value} now"


@dataclass(frozen=True)
class ResolutionChanged:
    path: pathlib.Path
    before: pathlib.Path
    now: pathlib.Path

    def describe(self) -> str:
        return f"{self.path} resolved to {self.before} when the jail was compiled and resolves to {self.now} now"


@dataclass(frozen=True)
class ChildrenChanged:
    path: pathlib.Path

    def describe(self) -> str:
        return f"the names in {self.path} changed since the jail was compiled"


type Change = KindChanged | ResolutionChanged | ChildrenChanged


@dataclass
class Recorded:
    """*facts*, with every answer noted: what a compiled jail was compiled against."""

    facts: Facts
    kinds: dict[pathlib.Path, Kind] = field(default_factory=dict)
    resolutions: dict[pathlib.Path, pathlib.Path] = field(default_factory=dict)
    listings: dict[pathlib.Path, tuple[str, ...]] = field(default_factory=dict)

    def kind(self, path: pathlib.Path) -> Kind:
        if path not in self.kinds:
            self.kinds[path] = self.facts.kind(path)
        return self.kinds[path]

    def resolve(self, path: pathlib.Path) -> pathlib.Path:
        if path not in self.resolutions:
            self.resolutions[path] = self.facts.resolve(path)
        return self.resolutions[path]

    def children(self, path: pathlib.Path) -> tuple[str, ...]:
        if path not in self.listings:
            self.listings[path] = self.facts.children(path)
        return self.listings[path]

    def changed(self, now: Facts) -> tuple[Change, ...]:
        """Every recorded answer *now* gives differently."""
        out: list[Change] = []
        for path, before in self.kinds.items():
            if (after := now.kind(path)) is not before:
                out.append(KindChanged(path, before, after))
        for path, before_path in self.resolutions.items():
            if (after_path := now.resolve(path)) != before_path:
                out.append(ResolutionChanged(path, before_path, after_path))
        for path, names in self.listings.items():
            if now.children(path) != names:
                out.append(ChildrenChanged(path))
        return tuple(out)
