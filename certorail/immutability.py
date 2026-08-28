"""Does a module access path (``os.sep``, ``sys.path``, ``pathlib.Path``) name immutable data?

Programs may read and copy constants out of modules (``sep = os.sep``) but must not get hold of
shared *mutable* state (``sys.path``, ``os.environ``, ``sys.modules``) or of classes, which are the
things whose mutation changes what everyone else's code means. Whether an attribute holds such a
thing is not decidable from the source of the analysed program, so it is answered empirically: the
path is resolved with ``importlib``/``getattr`` in a throwaway, isolated subprocess (``python -I
-S``), and the resulting object is classified.

    resolver = AccessResolver(allowed_roots={"os", "sys", "pathlib", "re"})
    resolver.classify(("os", "sep"))        -> Immutable(type_name="str", repr="'/'")
    resolver.classify(("sys", "path"))      -> Mutable(type_name="list", kind="container")
    resolver.classify(("pathlib", "Path"))  -> Mutable(type_name="type", kind="class")
    resolver.classify(("os", "path", "isabs")) -> Function(type_name="function")

Verdicts are distinct types rather than a bool so the caller decides what to allow; the
conservative reading is :func:`may_escape`. Resolution happens in the interpreter given by
``python`` (default: this one), which should be the interpreter the analysed program will run under,
since that is whose ``os.sep`` is being read.
"""
import json
import subprocess
import sys
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from .analysis import NameAccess


@dataclass(frozen=True)
class Immutable:
    """An instance of a known-immutable type (recursively, for tuples and frozensets)."""

    type_name: str
    repr: str


@dataclass(frozen=True)
class Function:
    """A routine or descriptor: functions, builtins, methods, ``classmethod``/``staticmethod``/
    ``property`` objects. Calling it is a separate question; as a *value* it carries no data."""

    type_name: str


@dataclass(frozen=True)
class Mutable:
    """Shared state: a module, a class, a mutable container, or any other object."""

    type_name: str
    kind: Literal["module", "class", "container", "object"]


@dataclass(frozen=True)
class Unresolvable:
    """The path does not resolve (unknown module, missing attribute, root not allowed, ...)."""

    error: str


@dataclass(frozen=True)
class Failed:
    """The subprocess itself failed (timeout, crash, unparsable output)."""

    error: str


type Verdict = Immutable | Function | Mutable | Unresolvable | Failed


def may_escape(v: Verdict) -> bool:
    """Conservative: only values proven immutable, or routines, may be read out of a module."""
    return isinstance(v, (Immutable, Function))


def access_path(access: NameAccess) -> tuple[str, ...] | None:
    """``unfold_attr`` result -> path; ``None`` for a ``super()``-rooted access."""
    if not access.is_var_base:
        return None
    return (access.base_name, *access.field_names)


# ---------------------------------------------------------------------------
# the child: stdlib only, reads {"paths": [...], "allowed_roots": [...] | null} on stdin,
# writes a JSON list of verdicts (one per path, same order) on stdout
# ---------------------------------------------------------------------------

_CHILD_SOURCE = r'''
import enum, importlib, inspect, json, pathlib, re, sys, types
from collections.abc import MutableMapping, MutableSequence, MutableSet

# exact types whose instances are immutable
ATOMIC = {
    type(None), bool, int, float, complex, str, bytes, range, slice,
    type(...), type(NotImplemented), types.MappingProxyType,
}
# base classes whose (stdlib) instances are immutable
ATOMIC_BASES = (enum.Enum, pathlib.PurePath, re.Pattern)
MAX_DEPTH, MAX_ITEMS = 8, 10_000

def immutable(obj, depth=0):
    if type(obj) in ATOMIC or isinstance(obj, ATOMIC_BASES):
        return True
    if isinstance(obj, (tuple, frozenset)):          # incl. struct sequences, namedtuples
        if depth >= MAX_DEPTH or len(obj) > MAX_ITEMS:
            return False
        return all(immutable(x, depth + 1) for x in obj)
    return False

def classify(obj):
    if inspect.ismodule(obj):
        return {"kind": "mutable", "type": type(obj).__name__, "why": "module"}
    if isinstance(obj, type):
        return {"kind": "mutable", "type": type(obj).__name__, "why": "class"}
    if inspect.isroutine(obj) or isinstance(obj, (classmethod, staticmethod, property)):
        return {"kind": "function", "type": type(obj).__name__}
    if immutable(obj):
        return {"kind": "immutable", "type": type(obj).__name__, "repr": repr(obj)[:80]}
    if isinstance(obj, (MutableSequence, MutableMapping, MutableSet, bytearray, memoryview)):
        return {"kind": "mutable", "type": type(obj).__name__, "why": "container"}
    return {"kind": "mutable", "type": type(obj).__name__, "why": "object"}

def resolve(path, allowed_roots):
    if not path:
        raise ValueError("empty path")
    if allowed_roots is not None and path[0] not in allowed_roots:
        raise ImportError(f"module {path[0]!r} is not allowed")
    obj = importlib.import_module(path[0])
    for i, name in enumerate(path[1:], 1):
        try:
            obj = getattr(obj, name)
        except AttributeError:
            if not inspect.ismodule(obj):
                raise
            obj = importlib.import_module(".".join(path[: i + 1]))   # a submodule not yet imported
    return obj

def main():
    request = json.load(sys.stdin)
    allowed = request.get("allowed_roots")
    allowed = None if allowed is None else set(allowed)
    out = []
    for path in request["paths"]:
        try:
            out.append(classify(resolve(path, allowed)))
        except BaseException as e:                      # a bad path must not poison the batch
            out.append({"kind": "unresolvable", "error": f"{type(e).__name__}: {e}"[:200]})
    json.dump(out, sys.stdout)

main()
'''


def _decode(raw: object) -> Verdict:
    if not isinstance(raw, dict):
        return Failed(f"malformed verdict: {raw!r}"[:200])
    match raw.get("kind"):
        case "immutable":
            return Immutable(type_name=str(raw.get("type")), repr=str(raw.get("repr")))
        case "function":
            return Function(type_name=str(raw.get("type")))
        case "mutable":
            why = raw.get("why")
            kind: Literal["module", "class", "container", "object"] = (
                why if why in ("module", "class", "container") else "object"
            )
            return Mutable(type_name=str(raw.get("type")), kind=kind)
        case "unresolvable":
            return Unresolvable(error=str(raw.get("error")))
        case other:
            return Failed(f"unknown verdict kind {other!r}")


class AccessResolver:
    """Classifies module access paths, one isolated subprocess per batch, with a cache.

    ``allowed_roots`` restricts which top-level modules the child may import (None: any);
    ``python`` is the interpreter to resolve in; ``python_args`` its isolation flags.
    """

    def __init__(
        self,
        *,
        allowed_roots: Collection[str] | None = None,
        python: str = sys.executable,
        python_args: Sequence[str] = ("-I", "-S"),
        timeout: float = 10.0,
    ) -> None:
        self.allowed_roots = None if allowed_roots is None else frozenset(allowed_roots)
        self.python = python
        self.python_args = tuple(python_args)
        self.timeout = timeout
        self._cache: dict[tuple[str, ...], Verdict] = {}

    def classify(self, path: Sequence[str]) -> Verdict:
        return self.classify_many([path])[tuple(path)]

    def classify_many(self, paths: Iterable[Sequence[str]]) -> dict[tuple[str, ...], Verdict]:
        wanted = {tuple(p) for p in paths}
        missing = sorted(p for p in wanted if p not in self._cache)
        if missing:
            verdicts = self._run(missing)
            if any(isinstance(v, Failed) for v in verdicts.values()) and len(missing) > 1:
                # the batch died (most likely a crashing import): isolate the culprit
                verdicts = {p: self._run([p])[p] for p in missing}
            self._cache.update(verdicts)
        return {p: self._cache[p] for p in wanted}

    def _run(self, paths: Sequence[tuple[str, ...]]) -> dict[tuple[str, ...], Verdict]:
        request = json.dumps(
            {
                "paths": [list(p) for p in paths],
                "allowed_roots": None if self.allowed_roots is None else sorted(self.allowed_roots),
            }
        )
        try:
            proc = subprocess.run(
                [self.python, *self.python_args, "-c", _CHILD_SOURCE],
                input=request,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return {p: Failed(f"timed out after {self.timeout}s") for p in paths}
        except OSError as e:
            return {p: Failed(f"could not start {self.python}: {e}") for p in paths}
        if proc.returncode != 0:
            tail = proc.stderr.strip().splitlines()[-1:] or ["no stderr"]
            return {p: Failed(f"exit {proc.returncode}: {tail[0]}"[:200]) for p in paths}
        try:
            decoded = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            return {p: Failed(f"unparsable output: {e}") for p in paths}
        if not isinstance(decoded, list) or len(decoded) != len(paths):
            return {p: Failed("verdict count does not match request") for p in paths}
        return {p: _decode(raw) for p, raw in zip(paths, decoded)}
