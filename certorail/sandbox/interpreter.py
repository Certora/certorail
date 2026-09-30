"""The certorail process's interpreter's world (FLOORS.md): what it reads, for the policy view's
read-only mounts. Derived from the interpreter the jail will run, asked once unjailed at its real
path with ``-I -S``: its executable, its prefixes and stdlib directories, and the directory of every
shared object the loader maps while it imports every stdlib module the subset admits
(``/proc/self/maps`` on Linux; dyld's image list on macOS, whose system libraries live in the
shared cache under ``/System``). Paths the platform's toolchain already holds are dropped; the
certorail package is added, for the bootstrap; ``world.toml``'s ``[system.interpreter] read`` adds
what derivation misses. Validated by ``scripts/probe_interpreter_world.py``; it takes about a
tenth of a second, so it runs per launch."""
import json
import os
import pathlib
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from certorail.dangerous import FORBIDDEN_MODULES


@dataclass(frozen=True)
class Stdlib:
    pass


@dataclass(frozen=True)
class Loaded:
    image: str  # a shared object the interpreter mapped while importing the subset


@dataclass(frozen=True)
class Package:
    name: str   # certorail itself: the bootstrap imports from it


@dataclass(frozen=True)
class Configured:
    source: pathlib.Path  # the world.toml that lists it


type Reason = Stdlib | Loaded | Package | Configured


@dataclass(frozen=True)
class Need:
    path: pathlib.Path  # canonical; mounted read-only at the same path
    reason: Reason


@dataclass(frozen=True)
class InterpreterWorld:
    """What the interpreter needs to start and to import any admitted module: its real
    executable, the paths to mount read-only (a minimal cover), and the directories whose
    listing alone it reads (the package's parent, where the bootstrap puts it on ``sys.path``)."""

    executable: pathlib.Path
    needs: tuple[Need, ...]
    listed: tuple[pathlib.Path, ...]

    @property
    def paths(self) -> tuple[pathlib.Path, ...]:
        return tuple(n.path for n in self.needs)


class InterpreterUnavailable(Exception):
    """The interpreter could not say where it lives."""


_QUERY = r'''
import contextlib, importlib, io, json, os, sys, sysconfig
failed = []
with contextlib.redirect_stdout(io.StringIO()):
    for name in json.loads(sys.argv[1]):
        try:
            importlib.import_module(name)
        except Exception:
            failed.append(name)

def images():
    if sys.platform == "linux":
        out = set()
        with open("/proc/self/maps") as f:
            for line in f:
                fields = line.split(None, 5)
                if len(fields) < 6:
                    continue
                path = fields[5].strip()
                name = os.path.basename(path)
                if path.startswith("/") and (name.endswith(".so") or ".so." in name):
                    out.add(path)
        return sorted(out)
    import ctypes
    libc = ctypes.CDLL(None)
    libc._dyld_get_image_name.restype = ctypes.c_char_p
    libc._dyld_get_image_name.argtypes = [ctypes.c_uint32]
    return sorted({libc._dyld_get_image_name(i).decode() for i in range(libc._dyld_image_count())})

paths = sysconfig.get_paths()
print(json.dumps({
    "executable": os.path.realpath(sys.executable),
    "stdlib": sorted({paths["stdlib"], paths["platstdlib"]}),
    "prefixes": sorted({sys.base_prefix, sys.base_exec_prefix}),
    "images": images(),
    "failed": failed,
}))
'''


def subset_modules() -> list[str]:
    """Every public stdlib module a program may import."""
    return sorted(m for m in sys.stdlib_module_names if not m.startswith("_") and m not in FORBIDDEN_MODULES)


def _under(path: pathlib.Path, roots: Sequence[pathlib.Path]) -> bool:
    return any(r == path or r in path.parents for r in roots)


def _real(p: str | os.PathLike[str]) -> pathlib.Path:
    return pathlib.Path(os.path.realpath(p))


def discover(
    python: str, toolchain: Sequence[str], configured: Sequence[pathlib.Path] = (), source: pathlib.Path | None = None,
) -> InterpreterWorld:
    """The world of the interpreter *python* beyond *toolchain*, with *configured* paths added
    (from the world.toml at *source*)."""
    executable = _real(python)
    try:
        done = subprocess.run(
            [str(executable), "-I", "-S", "-c", _QUERY, json.dumps(subset_modules())],
            capture_output=True, text=True, timeout=60, check=True,
        )
        answer = json.loads(done.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        raise InterpreterUnavailable(f"{executable} could not say where it lives: {e}") from None
    covered = [_real(t) for t in toolchain if os.path.exists(t)]
    needs: list[Need] = []
    for p in (*answer["prefixes"], *answer["stdlib"]):
        path = _real(p)
        if not _under(path, covered):
            needs.append(Need(path, Stdlib()))
    held = [*covered, *(n.path for n in needs)]
    for image in answer["images"]:
        path = _real(image)
        if path.exists() and not _under(path, held):
            # outside the prefix and the toolchain (a Homebrew or Nix library): its directory, so
            # the soname link the loader opens resolves beside the file it names
            needs.append(Need(path.parent, Loaded(image)))
    import certorail

    package = pathlib.Path(certorail.__file__).resolve().parent
    needs.append(Need(package, Package("certorail")))
    needs.extend(Need(p, Configured(source if source is not None else pathlib.Path("world.toml"))) for p in configured)
    kept: list[Need] = []
    for need in sorted(needs, key=lambda n: len(n.path.parts)):
        if not any(k.path == need.path or k.path in need.path.parents for k in kept):
            kept.append(need)
    return InterpreterWorld(_real(answer["executable"]), tuple(kept), (package.parent,))
