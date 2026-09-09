"""The jq-subset paths of ``certora.extract`` / ``certora.extract_all`` (PROVENANCE.md).

    .              the document itself
    .name          a key (an identifier)
    ."any key"     a key, quoted (no escapes)
    [3]  [-1]      an index
    []             every element (at most once in a path: the result is then a flat list)

Chained: ``.data.repos[].name``, ``.[0].id``, ``.["quoted"]`` is NOT accepted (write ``."quoted"``).
No pipes, filters, functions or slices. Shared by the analysis (which needs the *shape* of the
path: scalar or plural) and the runtime in ``markers`` (which walks it), so it imports nothing of
either.
"""
import re
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class Key:
    name: str


@dataclass(frozen=True)
class Index:
    index: int


@dataclass(frozen=True)
class Each:
    """``[]``: every element of an array."""


type Step = Key | Index | Each

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_INT = re.compile(r"-?\d+")


def parse(path: str) -> tuple[Step, ...]:
    """The steps of *path*; ``ValueError`` for anything outside the subset."""
    if not path.startswith("."):
        raise ValueError(f"a path begins with '.': {path!r}")
    steps: list[Step] = []
    i = 1
    n = len(path)
    if i == n:
        return ()  # ".": the document
    # the leading "." introduces the first key, unless a bracket follows it: ".[0]", ".[]"
    expect_key = path[i] != "["
    while i < n:
        c = path[i]
        if expect_key:
            if c == '"':
                j = path.find('"', i + 1)
                if j < 0:
                    raise ValueError(f"unterminated quoted key in {path!r}")
                steps.append(Key(path[i + 1 : j]))
                i = j + 1
            else:
                m = _IDENT.match(path, i)
                if m is None:
                    raise ValueError(f"expected a key at offset {i} in {path!r}")
                steps.append(Key(m.group(0)))
                i = m.end()
            expect_key = False
            continue
        if c == ".":
            i += 1
            if i == n:
                raise ValueError(f"a trailing '.' in {path!r}")
            expect_key = True
            continue
        if c == "[":
            j = path.find("]", i)
            if j < 0:
                raise ValueError(f"unterminated '[' in {path!r}")
            inner = path[i + 1 : j]
            if inner == "":
                steps.append(Each())
            elif _INT.fullmatch(inner):
                steps.append(Index(int(inner)))
            else:
                raise ValueError(f"expected an index or [] in {path!r}, got [{inner}]")
            i = j + 1
            continue
        raise ValueError(f"unexpected {c!r} at offset {i} in {path!r}")
    if sum(isinstance(s, Each) for s in steps) > 1:
        raise ValueError(f"at most one [] in a path: {path!r}")
    return tuple(steps)


def plural(steps: Sequence[Step]) -> bool:
    """Does the path yield a list (it contains ``[]``)?"""
    return any(isinstance(s, Each) for s in steps)


def walk(steps: Sequence[Step], value: object) -> object:
    """The value(s) *steps* select in a parsed JSON document; ``ValueError`` when the document
    has no such path. With an ``Each`` the result is the flat list of what the remaining steps
    select in every element."""
    for k, step in enumerate(steps):
        match step:
            case Key(name=name):
                if not isinstance(value, dict) or name not in value:
                    raise ValueError(f"no key {name!r} at step {k + 1}")
                value = value[name]
            case Index(index=index):
                if not isinstance(value, list):
                    raise ValueError(f"not an array at step {k + 1}")
                try:
                    value = value[index]
                except IndexError:
                    raise ValueError(f"index {index} out of range at step {k + 1}") from None
            case Each():
                if not isinstance(value, list):
                    raise ValueError(f"not an array at step {k + 1}")
                rest = steps[k + 1 :]
                return [walk(rest, v) for v in value]
    return value
