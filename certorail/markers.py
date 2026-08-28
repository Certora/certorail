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
import pathlib
import subprocess
from dataclasses import dataclass

NAMESPACE = "certora"


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
