"""Which identifiers are already in scope in a fresh interpreter?

Whether ``isinstance``, ``str``, ``open`` (or something more obscure a program might be cute
about, like ``aiter`` or ``__build_class__``) is a builtin is a fact about the interpreter the
program will run under, not something to maintain a list of. So a fresh interpreter is asked once,
with the same flags the sandbox uses, and the answer is cached::

    is_builtin_name("isinstance")   -> True
    is_builtin_name("pathlib")      -> False

The set is ``dir(builtins)`` plus the globals a top-level script starts with (``__name__``,
``__doc__``, ``__builtins__``, ...). Note that ``site`` is what installs ``exit``/``quit``/``help``/
``copyright``: under the default ``-S`` they are *not* in scope, which is correct if the sandbox
runs with ``-S`` too -- pass the sandbox's actual ``python_args`` if it doesn't.
"""
import functools
import json
import subprocess
import sys
from collections.abc import Sequence


class ScopeUnavailable(RuntimeError):
    """The fresh interpreter could not be consulted; callers should fail closed."""


_CHILD_SOURCE = r'''
import builtins, json, sys
json.dump(sorted(set(dir(builtins)) | set(globals())), sys.stdout)
'''


@functools.cache
def builtin_names(
    python: str = sys.executable,
    python_args: tuple[str, ...] = ("-I", "-S"),
    timeout: float = 10.0,
) -> frozenset[str]:
    """Every name a fresh ``python <python_args>`` has in scope before any statement runs."""
    try:
        proc = subprocess.run(
            [python, *python_args, "-c", _CHILD_SOURCE],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise ScopeUnavailable(f"{python} timed out after {timeout}s") from e
    except OSError as e:
        raise ScopeUnavailable(f"could not start {python}: {e}") from e
    if proc.returncode != 0:
        tail = proc.stderr.strip().splitlines()[-1:] or ["no stderr"]
        raise ScopeUnavailable(f"{python} exited {proc.returncode}: {tail[0]}")
    try:
        names = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScopeUnavailable(f"unparsable output from {python}: {e}") from e
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise ScopeUnavailable(f"unexpected output from {python}")
    return frozenset(names)


def is_builtin_name(
    name: str,
    python: str = sys.executable,
    python_args: Sequence[str] = ("-I", "-S"),
    timeout: float = 10.0,
) -> bool:
    return name in builtin_names(python, tuple(python_args), timeout)
