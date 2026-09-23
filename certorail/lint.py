"""Policy lints: things a policy says that are legal but probably not what its author meant.
Warnings for the human who writes the policy, printed by ``certorail describe`` and by ``certorail
policy install`` -- never errors, and never shown to the confined program.

The three follow from one rule of thumb (README, "names, not objects"): a grant or a protection
constrains the name a program spells, never the file behind it.

- ``shadowed-protection``: a relative ``no-write`` protection while an absolute write grant reaches
  into the root: the protection holds only for relative spellings of the same files.
- ``literal-directory``: a read or write grant naming a directory literally (``src``) grants the
  directory itself -- listing it -- and none of its files; ``src/**`` is the usual intent.
- ``spelling`` (macOS): a literal name in the policy that the directory stores under another
  spelling folding to the same name (``.Git`` for ``.git``): the jail matches the stored name.
"""
import os
import pathlib
import sys
import unicodedata
from dataclasses import dataclass
from typing import Literal

from certorail.analysis import DirSplat, LocationFact, Named, StaticPath, pretty_location
from certorail.footprints import intersect, items_of
from certorail.locations import single_path

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from certorail.policy import Policy

type LintKind = Literal["shadowed-protection", "literal-directory", "spelling"]


@dataclass(frozen=True)
class Lint:
    kind: LintKind
    location: LocationFact
    message: str

    def line(self) -> str:
        return f"lint ({self.kind}): {self.message}"


def _fold(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def lint(policy: "Policy", root: pathlib.Path, *, platform: str = sys.platform) -> list[Lint]:
    """Every lint of *policy* governing *root* (the directory as it is now, for the lints that
    look at it)."""
    out: list[Lint] = []
    real = pathlib.Path(os.path.realpath(root))
    root_tree = DirSplat(tuple(Named(n) for n in real.parts[1:]), None, absolute=True)
    relative_protections = [p for p in policy.no_write if not p.absolute]
    for grant in policy.write:
        if grant.absolute and relative_protections and intersect(items_of(grant), items_of(root_tree)):
            for p in relative_protections:
                out.append(Lint(
                    "shadowed-protection", p,
                    f"{pretty_location(p)} is protected as a relative name, but writable as an absolute "
                    f"path under {real} through the grant {pretty_location(grant)}",
                ))
    for grant in (*policy.read, *policy.write):
        path = single_path(grant, root)
        if isinstance(grant, StaticPath) and path is not None and path.is_dir():
            spelled = pretty_location(grant)
            out.append(Lint(
                "literal-directory", grant,
                f"{spelled} grants the directory itself (listing it) and none of its files; did you mean {spelled}/**?",
            ))
    if platform == "darwin":
        for loc in (*policy.read, *policy.write, *policy.no_write):
            if loc.absolute:
                continue
            parts = loc.path_components if isinstance(loc, StaticPath) else loc.static_prefix
            here = root
            for c in parts:
                if not isinstance(c, Named):
                    break
                try:
                    listed = os.listdir(here)
                except OSError:
                    break
                if c.name not in listed:
                    stored = [n for n in listed if _fold(n) == _fold(c.name)]
                    if stored:
                        out.append(Lint(
                            "spelling", loc,
                            f"{pretty_location(loc)} spells {c.name!r}, but {here} stores it as {stored[0]!r}: "
                            "the jail matches the stored name",
                        ))
                    break
                here = here / c.name
    return out
