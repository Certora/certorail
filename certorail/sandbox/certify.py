"""The placement checker (``proofs/place``): every bubblewrap plan certified before anything runs in
it, by a checker proved to accept only plans that show, at every path and every moment of the
jail's life, what the grants mean of what is there then (``Place.run_sound``). The placer stays
free to change: a plan it gets wrong is refused, never run.

What the checker is handed (``document``): the grants; the plan's views and its mounts, flattened
as bubblewrap makes them; how long the jail lives; the names nothing replaces while it does
(``stability``); and the facts the placement read -- asked here, through the same record, of every
mount's path too, so that each spawn asks them again (``Recorded.changed``).

It runs as a native executable in a jail of its own (``Native``): bubblewrap holding the binary,
its loader and the libraries it names, and bubblewrap's minimal ``/dev`` -- no other file, no
network, no environment.
A run's plans are certified together, and a verdict is kept for the life of the process by its
document.
"""
import importlib.resources
import json
import os
import pathlib
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from certorail.locations import encode_location
from certorail.native import Unavailable, loader_binds
from certorail.sandbox.facts import Kind, Recorded
from certorail.sandbox.grants import (
    Exactly, Grant, Grants, HostGrants, Layer, Lifetime, Pattern, PolicyGrants, Region, Restriction, Subtree,
)
from certorail.sandbox.place import BwrapPlan, EmptyBase, HostBase, Serve, region_tops
from certorail.sandbox.stable import expand
from certorail.sandbox.tree import Own, Through, flatten

__all__ = [
    "CHECKER_ENV", "Certified", "Checker", "CheckerUnavailable", "Native", "Refused", "Verdict", "document",
    "locate", "stability",
]

CHECKER_ENV = "CERTORAIL_PLACE_CHECKER"
FORMAT = 1


@dataclass(frozen=True)
class Certified:
    pass


@dataclass(frozen=True)
class Refused:
    """The checker refused the plan: why, obligation by obligation."""

    reasons: tuple[str, ...]


type Verdict = Certified | Refused


class CheckerUnavailable(Exception):
    """No verdict can be had: the checker is not there, will not run, or answered nothing it can
    say. The message says why."""


class Checker(Protocol):
    def certify(self, documents: Sequence[Mapping[str, Any]]) -> list[Verdict]:
        """A verdict on each of *documents*, in order. Raises ``CheckerUnavailable``."""
        ...


# -- the document -------------------------------------------------------------------------------


def _key(pattern: Pattern) -> str:
    """A pattern as the checker tells patterns apart: by what it spells, and where."""
    return json.dumps({"location": encode_location(pattern.location), "anchor": str(pattern.anchor)}, sort_keys=True)


def _region(region: Region) -> dict[str, Any]:
    match region:
        case Subtree(path=p):
            return {"subtree": str(p)}
        case Exactly(path=p):
            return {"exactly": str(p)}
        case Pattern():
            return {"pattern": _key(region), "tops": [str(t) for t in region_tops(region)]}


def _layer(layer: Layer[Region]) -> dict[str, Any]:
    says = {"grant": layer.effect.access.value} if isinstance(layer.effect, Grant) else {"restrict": layer.effect.narrowing.value}
    return {"region": _region(layer.region), **says}


def stability(grants: Grants, facts: Recorded) -> dict[str, list[str]]:
    """The names the placement relies on nothing replacing while the jail lives -- the stability
    model, trusted, not checked (``world.toml``'s ``stable``; ``sandbox.stable``). The top-level
    names nothing replaces, the jail included: only root could on the host, and the policy world's
    root is bubblewrap's read-only tmpfs. So are, in a host world, the model's other names: the
    views of the redlines sit on them, mountpoints the jail cannot move. In a policy world those
    others are names nothing *outside* the jail replaces, with the working directory, and the
    stable grants (the toolchain, the interpreter) with everything below them; what the jail itself
    may do to them, its mounts say, and the checker asks."""
    names = expand(grants.stable, grants.root, facts)
    children_of = sorted(str(p) for p in names.children_of)
    match grants:
        case PolicyGrants(layers=layers, workdir=workdir):
            stable = [
                str(layer.region.path) for layer in layers
                if isinstance(layer.effect, Grant) and layer.effect.stable and isinstance(layer.region, Subtree)
            ]
            kept = dict.fromkeys([*([] if workdir is None else [workdir]), *sorted(names.names)])
            return {"names": [], "children-of": children_of, "kept": [str(p) for p in kept], "subtrees": stable}
        case HostGrants():
            return {"names": sorted(str(p) for p in names.names), "children-of": children_of, "kept": [], "subtrees": []}


def _source(path: pathlib.Path, source: Own | Through, views: Sequence[Serve], facts: Recorded) -> str | dict[str, Any]:
    facts.kind(path)
    resolved = facts.resolve(path)
    match source:
        case Own():
            if resolved == path:
                return "own"
            # bubblewrap follows every link on a bind's source: bound as it leads
            facts.kind(resolved)
            facts.resolve(resolved)
            return {"alias": str(resolved)}
        case Through(view=view, rel=rel):
            return {"view": views.index(view), "rel": str(rel)}


def document(grants: Grants, plan: BwrapPlan, facts: Recorded) -> dict[str, Any]:
    """*plan*, placed for *grants* against *facts*, as the checker reads it (``Place.Decode``). Asks
    *facts* what the checker needs of every mount: its kind, and where it resolves."""
    views = list(plan.views)
    mounts = [
        {"path": str(m.path), "state": m.state.value, "source": _source(m.path, m.source, views, facts)}
        for m in flatten(plan.base, plan.items)
    ]
    match plan.base:
        case HostBase(writable=writable):
            base = "host-writable" if writable else "host-read-only"
        case EmptyBase():
            base = "empty"
    return {
        "base": base,
        "layers": [_layer(layer) for layer in grants.layers],
        "views": [{"directory": str(v.directory), "layers": [_layer(layer) for layer in v.layers]} for v in views],
        "mounts": mounts,
        "lifetime": "exec" if grants.lifetime is Lifetime.EXEC else "run",
        "stability": stability(grants, facts),
        "facts": {
            "kinds": [[str(p), kind.name.lower()] for p, kind in facts.kinds.items()],
            "resolutions": [[str(p), str(r)] for p, r in facts.resolutions.items()],
        },
    }


# -- the checker --------------------------------------------------------------------------------


def _verdict(answer: Any) -> Verdict:
    if not isinstance(answer, dict):
        raise CheckerUnavailable(f"the placement checker gave a verdict of no known kind: {answer!r}")
    if answer.get("certified") is True:
        return Certified()
    reasons = answer.get("reasons")
    if answer.get("certified") is False and isinstance(reasons, list):
        return Refused(tuple(str(r) for r in reasons))
    raise CheckerUnavailable(f"the placement checker gave a verdict of no known kind: {answer!r}")


class Native:
    """The checker's executable, run in an empty world of its own: bubblewrap holding the binary,
    its loader and the libraries it names, and a minimal ``/dev`` -- no other file, no network, no
    environment. Each verdict is kept, by its document, for the life of the process."""

    def __init__(self, binary: pathlib.Path, bwrap: str) -> None:
        self.binary = binary
        self._bwrap = bwrap
        self._command: list[str] | None = None
        self._verdicts: dict[str, Verdict] = {}

    def command(self) -> list[str]:
        if self._command is None:
            try:
                binds = loader_binds(self.binary)
            except (Unavailable, OSError) as e:
                raise CheckerUnavailable(f"the placement checker {self.binary} cannot be jailed: {e}") from e
            self._command = [
                self._bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
                # bubblewrap's own minimal /dev: the Lean runtime reads /dev/urandom as it starts
                "--dev", "/dev",
                "--ro-bind", str(self.binary), "/place-check", *binds, "--chdir", "/", "--", "/place-check",
            ]
        return self._command

    def certify(self, documents: Sequence[Mapping[str, Any]]) -> list[Verdict]:
        keys = [json.dumps(d, sort_keys=True) for d in documents]
        todo = {k: d for k, d in zip(keys, documents) if k not in self._verdicts}
        if todo:
            payload = json.dumps({"format": FORMAT, "plans": list(todo.values())}).encode()
            try:
                done = subprocess.run(self.command(), input=payload, capture_output=True, timeout=120)
            except (OSError, subprocess.TimeoutExpired) as e:
                raise CheckerUnavailable(f"the placement checker did not run: {e}") from e
            try:
                answer = json.loads(done.stdout)
            except ValueError:
                raise CheckerUnavailable(
                    f"the placement checker answered nothing it can say (exit {done.returncode}): "
                    + (done.stderr.decode(errors="replace").strip() or done.stdout.decode(errors="replace").strip())
                ) from None
            if not isinstance(answer, dict) or "verdicts" not in answer:
                raise CheckerUnavailable(f"the placement checker could not read the plans: {answer.get('error') if isinstance(answer, dict) else answer!r}")
            verdicts = answer["verdicts"]
            if not isinstance(verdicts, list) or len(verdicts) != len(todo):
                raise CheckerUnavailable("the placement checker gave a verdict for other plans than it was asked about")
            for key, verdict in zip(todo, verdicts):
                self._verdicts[key] = _verdict(verdict)
        return [self._verdicts[k] for k in keys]


def _checkout_build() -> pathlib.Path | None:
    """A checkout's own build of the checker, beside the package (``lake -d proofs/place build``)."""
    package = importlib.resources.files("certorail")
    if not isinstance(package, pathlib.Path):
        return None
    built = package.parent / "proofs" / "place" / ".lake" / "build" / "bin" / "place-check"
    return built if built.is_file() else None


def locate(environ: Mapping[str, str] = os.environ) -> Native | str:
    """The placement checker: ``$CERTORAIL_PLACE_CHECKER``, else ``place-check`` on PATH, else a
    checkout's own build -- jailed by bubblewrap. A str: why there is none to run."""
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        return "bubblewrap (bwrap), which jails it, is not on PATH"
    named = environ.get(CHECKER_ENV)
    if named:
        binary = pathlib.Path(named)
        if not binary.is_file():
            return f"${CHECKER_ENV} names {named}, which is no file"
        return Native(binary.resolve(), bwrap)
    on_path = shutil.which("place-check")
    if on_path is not None and pathlib.Path(on_path).is_file():
        return Native(pathlib.Path(on_path).resolve(), bwrap)
    built = _checkout_build()
    if built is not None:
        return Native(built, bwrap)
    return (f"no place-check: set ${CHECKER_ENV}, put it on PATH, or build it in a checkout "
            "(lake -d proofs/place build place-check)")
