"""What both spawners share: the child's environment, the executable, the scratch directory."""
import contextlib
import os
import shutil
import tempfile
from collections.abc import Iterator, Mapping, Sequence

from ..childjail import Environment
from ..confinement import Confinement


def environment(env: Environment | None, base: Mapping[str, str], scratch: str | None) -> dict[str, str]:
    """The child's environment: *base* whole, or only the names *env* passes through (a name
    the host lacks is skipped) plus the values it sets; ``TMPDIR`` pointing at the scratch
    directory when there is one, since that is the one place a write-jailed tool may write."""
    if env is None:
        out = dict(base)
    else:
        out = {k: base[k] for k in env.passed if k in base}
        out.update(env.sets)
    if scratch is not None:
        out["TMPDIR"] = scratch
    return out


def executable(argv: Sequence[str], env: Mapping[str, str]) -> str | None:
    """Where the tool the child runs lives, resolved as the child would resolve it: on the
    environment it will get. None: not found (the child will say so itself)."""
    return shutil.which(argv[0], path=env.get("PATH") or os.defpath)


@contextlib.contextmanager
def scratch_for(confinement: Confinement) -> Iterator[str | None]:
    """The per-spawn scratch directory when the confinement needs one, discarded after."""
    if not confinement.needs_scratch:
        yield None
        return
    with tempfile.TemporaryDirectory(prefix="certorail-scratch-") as scratch:
        yield scratch
