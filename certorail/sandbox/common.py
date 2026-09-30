"""What every spawn shares, whatever the backend: the child's environment, the executable, the
scratch directory."""
import contextlib
import os
import pathlib
import shutil
import tempfile
from collections.abc import Iterator, Mapping, Sequence

from certorail.childjail import Environment


def environment(env: Environment | None, base: Mapping[str, str], scratch: pathlib.Path | None) -> dict[str, str]:
    """The child's environment: *base* whole, or only the names *env* passes through (a name
    the host lacks is skipped) plus the values it sets; ``TMPDIR`` pointing at the scratch
    directory when there is one, since that is the one place a write-jailed tool may write."""
    if env is None:
        out = dict(base)
    else:
        out = {k: base[k] for k in env.passed if k in base}
        out.update(env.sets)
    if scratch is not None:
        out["TMPDIR"] = str(scratch)
    return out


def executable(argv: Sequence[str], env: Mapping[str, str], cwd: pathlib.Path) -> pathlib.Path | None:
    """Where the tool the child runs lives, absolute, resolved as the child would resolve it: on
    the environment it will get, a name with a slash from its working directory *cwd*. None: not
    found (the child will say so itself)."""
    name = argv[0]
    found = shutil.which(str(cwd / name)) if "/" in name else shutil.which(name, path=env.get("PATH") or os.defpath)
    return None if found is None else cwd / found


@contextlib.contextmanager
def scratch(needed: bool) -> Iterator[pathlib.Path | None]:
    """A private scratch directory for one spawn when *needed*, discarded after."""
    if not needed:
        yield None
        return
    with tempfile.TemporaryDirectory(prefix="certorail-scratch-") as directory:
        yield pathlib.Path(directory)
