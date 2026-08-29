"""Inert runtime counterparts of the annotation markers.

``typing.Annotated[str, certora.within("data")]`` is evaluated when the ``def`` statement runs,
so the markers have to exist as ordinary Python objects. They carry their arguments and do
nothing; the analysis never looks at them -- it reads the annotation's *source* (see
``annotations.py``). Expose this module to the analysed program under the name ``NAMESPACE``.

Surface syntax::

    typing.Annotated[pathlib.Path, certora.within("data/uploads")]
    typing.Annotated[pathlib.Path, certora.within("archive", leaf=certora.matches(r"\\w+\\.tar"))]
    typing.Annotated[pathlib.Path, certora.exactly("archive", certora.one_of("2025", "2026"))]
    typing.Annotated[str, certora.matches(r"\\w+\\.tar"), certora.no_slash, certora.no_parent_traversal]
    typing.Annotated[str, certora.one_of("gz", "xz")]
    typing.Annotated[str, certora.seq("report-", certora.matches(r"\\d+"), ".txt")]
    typing.Annotated[str, certora.within(".")]
"""
import functools
import inspect
import pathlib
import subprocess
import typing
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

NAMESPACE = "certora"


class ContractViolation(Exception):
    """A value did not have its annotated type at runtime."""


# ---------------------------------------------------------------------------
# controlled APIs: the sandbox's replacements for forbidden surface
# ---------------------------------------------------------------------------


def exec(*cmd: str, cwd: pathlib.Path | str) -> subprocess.CompletedProcess[bytes]:
    """The only way to run a subprocess: no shell, output always captured, ``cwd`` mandatory.

    This is the runtime half. The static half (``walker``) additionally requires the program to
    be a string literal, refuses ``*args``/``**kwargs`` and any keyword but ``cwd``, and treats
    ``cwd`` as a sink whose location must be proven.
    """
    if not cmd:
        raise ValueError("exec: no program given")
    if not all(isinstance(part, str) for part in cmd):
        raise TypeError("exec: every part of the command must be a str")
    return subprocess.run(list(cmd), cwd=cwd, shell=False, capture_output=True, check=False)


@dataclass(frozen=True)
class Atom:
    name: str


no_slash = Atom("no-slash")
no_parent_traversal = Atom("no-parent-traversal")
not_absolute = Atom("not-absolute")
not_dot_dot = Atom("not-dot-dot")


@dataclass(frozen=True)
class Matches:
    regex: str


@dataclass(frozen=True)
class OneOf:
    names: tuple[str, ...]


@dataclass(frozen=True)
class Seq:
    pieces: tuple["Fragment", ...]


# A fragment describes a string: a literal, or a marker constraining its shape. At the top level
# of an Annotated it describes the whole value; inside within()/exactly() it describes a path
# component (and a literal may then name several components, "data/uploads").
type Fragment = str | Matches | OneOf | Seq


@dataclass(frozen=True)
class Within:
    prefix: Fragment
    leaf: Fragment | None = None


@dataclass(frozen=True)
class Exactly:
    components: tuple[Fragment, ...]


def matches(regex: str) -> Matches:
    return Matches(regex)


def one_of(*names: str) -> OneOf:
    return OneOf(names)


def seq(*pieces: Fragment) -> Seq:
    return Seq(pieces)


def within(prefix: Fragment, leaf: Fragment | None = None) -> Within:
    return Within(prefix, leaf)


def exactly(*components: Fragment) -> Exactly:
    return Exactly(components)


# ---------------------------------------------------------------------------
# the runtime half: plain types
#
# ``@certora.checked`` is prepended to every module-level function with a contract before the
# program runs (see rewrite.py). It checks the *types* -- the one part of an annotation the
# analysis deliberately does not establish. The markers are not looked at: a rely is discharged
# at every call site and a guarantee at every return, statically. Only scalar hints are checked;
# containers are not traversed.
# ---------------------------------------------------------------------------


def _check_type(hint: Any, value: Any, where: str) -> None:
    if typing.get_origin(hint) is typing.Annotated:
        hint = typing.get_args(hint)[0]
    if hint is None or hint is type(None):
        if value is not None:
            raise ContractViolation(f"{where}: expected None, got {type(value).__name__}")
    elif isinstance(hint, type) and not isinstance(value, hint):
        raise ContractViolation(f"{where}: expected {hint.__name__}, got {type(value).__name__}")
    # anything else (containers, unions, Any, ...) is not checked


def checked[F: Callable[..., Any]](f: F) -> F:
    """Check a function's arguments and return value against their annotated types on every call."""
    hints = typing.get_type_hints(f, include_extras=True)
    signature = inspect.signature(f)

    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        for name, value in bound.arguments.items():
            if name not in hints:
                continue
            where = f"{f.__name__}(): parameter {name}"
            match signature.parameters[name].kind:
                case inspect.Parameter.VAR_POSITIONAL:
                    for v in value:
                        _check_type(hints[name], v, where)
                case inspect.Parameter.VAR_KEYWORD:
                    for v in value.values():
                        _check_type(hints[name], v, where)
                case _:
                    _check_type(hints[name], value, where)
        result = f(*args, **kwargs)
        if "return" in hints:
            _check_type(hints["return"], result, f"{f.__name__}(): return value")
        return result

    return cast(F, wrapper)
