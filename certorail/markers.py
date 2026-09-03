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
import base64
import functools
import inspect
import json
import os
import pathlib
import socket
import struct
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


class ExecFailed(RuntimeError):
    """A brokered exec failed before completing: denied by the broker's re-check, over a
    cap, or transport trouble. (A child that ran and exited non-zero is NOT this: that is a
    normal ``CompletedProcess`` with its returncode.)"""


def exec(*cmd: str, cwd: pathlib.Path | str) -> subprocess.CompletedProcess[bytes]:
    """The only way to run a subprocess: tunneled to the host's broker, which re-checks the
    decidable half of the exec rules (program, fail-closed subcommand, cwd containment --
    defense in depth; the full rules were enforced statically), spawns the child outside the
    sandbox, drains its output, and returns it wholesale. No shell, output always captured,
    ``cwd`` mandatory: exactly the ``subprocess.run(..., capture_output=True)`` this once
    was, one socket away.

    This is the runtime half. The static half (``walker``) additionally requires the program to
    be a string literal, refuses ``*args``/``**kwargs`` and any keyword but ``cwd``, and treats
    ``cwd`` as a sink whose location must be proven.
    """
    if not cmd:
        raise ValueError("exec: no program given")
    if not all(isinstance(part, str) for part in cmd):
        raise TypeError("exec: every part of the command must be a str")
    socket_path = os.environ.get("CERTORAIL_BROKER_SOCKET")
    if socket_path is None:
        raise ExecFailed("no broker: the policy permits no programs")
    program, *arguments = cmd
    try:
        reply = _broker_roundtrip(
            socket_path,
            {"kind": "exec", "program": program, "arguments": arguments,
             "cwd": os.fspath(cwd)},
            timeout=None,
        )
    except OSError as exc:
        raise ExecFailed(f"broker transport failure: {exc}")
    if not reply.get("ok"):
        raise ExecFailed(f"{reply.get('error', 'error')}: {reply.get('detail', '')}")
    return subprocess.CompletedProcess(
        args=list(cmd),
        returncode=int(reply["returncode"]),
        stdout=base64.b64decode(reply.get("stdout_b64", "")),
        stderr=base64.b64decode(reply.get("stderr_b64", "")),
    )


class CheckFailed(Exception):
    """A ``certora.check`` evaluator refused the value (nonzero exit)."""


def check(name: str, *, cwd: pathlib.Path | str | None = None, **params: str) -> None:
    """Run the policy-declared evaluator for *name*; raise ``CheckFailed`` unless it exits 0.

    The runtime half of ``certora.check``, tunneled to the host's broker: the evaluator runs
    *outside* the jail, where whatever it consults -- an inventory service, credentials, the
    org's tooling -- actually lives. The broker holds the policy's declarations, so name,
    parameters and a declared cwd are all re-enforced there. The static half (``walker``)
    additionally requires the statement form, a literal name, keywords matching the declared
    parameters, and a proven ``cwd`` (unless the validation declares none) -- and is what
    turns falling through this call into facts.
    """
    _brokered_check(name, {"params": dict(params), "cwd": None if cwd is None else os.fspath(cwd)})


def check_single(name: str, value: str, *, cwd: pathlib.Path | str | None = None) -> str:
    """Run the single-parameter evaluator for *name* on *value*; return *value* on success,
    raise ``CheckFailed`` otherwise. The functional sibling of ``check``: an expression whose
    result carries the established atoms statically (the fact rides the value), which is
    what makes it usable inside comprehensions, where no name exists to establish on."""
    _brokered_check(
        name, {"single": value, "cwd": None if cwd is None else os.fspath(cwd)}
    )
    return value


def _brokered_check(name: str, request: dict[str, Any]) -> None:
    socket_path = os.environ.get("CERTORAIL_BROKER_SOCKET")
    if socket_path is None:
        raise CheckFailed("check: no broker (the policy declares no validations)")
    try:
        reply = _broker_roundtrip(
            socket_path, {"kind": "check", "name": name, **request}, timeout=None
        )
    except OSError as exc:
        raise CheckFailed(f"check: broker transport failure: {exc}")
    if not reply.get("ok"):
        if reply.get("error") == "bad_request":
            raise TypeError(str(reply.get("detail", "")))
        raise CheckFailed(f"check: {reply.get('detail', reply.get('error', 'error'))}")
    returncode = int(reply["returncode"])
    if returncode != 0:
        detail = (
            base64.b64decode(reply.get("stderr_b64", "")).decode(errors="replace").strip()
        )
        raise CheckFailed(
            f"check {name!r} failed ({returncode})" + (f": {detail}" if detail else "")
        )


class NetworkError(RuntimeError):
    """A brokered request failed: denied by policy, over a cap, or transport trouble."""


@dataclass(frozen=True)
class NetworkResponse:
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    url: str  # the final URL, after any redirects the broker followed


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _broker_roundtrip(
    socket_path: str, payload: dict[str, Any], timeout: float | None
) -> dict[str, Any]:
    """One framed exchange with the host's broker (one connection per request). Transport
    failures surface as OSError for the caller to wrap; closing the socket -- this timeout,
    the program dying -- is what cancels the request broker-side."""
    frame = json.dumps(payload).encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        # the broker always answers within its own deadlines; the slack keeps its precise
        # timeout error ahead of this blunt one
        s.settimeout(timeout + 30.0 if timeout is not None else None)
        s.connect(socket_path)
        s.sendall(struct.pack("!I", len(frame)) + frame)
        header = _recv_exact(s, 4)
        if header is None:
            raise ConnectionError("the broker closed the connection")
        (length,) = struct.unpack("!I", header)
        reply_frame = _recv_exact(s, length)
        if reply_frame is None:
            raise ConnectionError("the broker closed mid-frame")
    return json.loads(reply_frame)


class _Network:
    """The runtime half of ``certora.network``: one Unix-socket connection to the host's
    broker per request (the socket path arrives in ``CERTORAIL_BROKER_SOCKET``; absent, the
    policy granted no network). Closing the connection -- a timeout here, the program dying --
    is what cancels the in-flight request broker-side. The static half (walker) admits only
    these methods, a single URL argument whose scheme and netloc are proven, and the
    enumerated keywords."""

    def get(self, url: str, *, headers: dict[str, str] | None = None,
            timeout: float | None = None) -> NetworkResponse:
        return self._request("GET", url, headers, None, timeout)

    def head(self, url: str, *, headers: dict[str, str] | None = None,
             timeout: float | None = None) -> NetworkResponse:
        return self._request("HEAD", url, headers, None, timeout)

    def delete(self, url: str, *, headers: dict[str, str] | None = None,
               timeout: float | None = None) -> NetworkResponse:
        return self._request("DELETE", url, headers, None, timeout)

    def post(self, url: str, *, headers: dict[str, str] | None = None,
             body: bytes | None = None, timeout: float | None = None) -> NetworkResponse:
        return self._request("POST", url, headers, body, timeout)

    def put(self, url: str, *, headers: dict[str, str] | None = None,
            body: bytes | None = None, timeout: float | None = None) -> NetworkResponse:
        return self._request("PUT", url, headers, body, timeout)

    def patch(self, url: str, *, headers: dict[str, str] | None = None,
              body: bytes | None = None, timeout: float | None = None) -> NetworkResponse:
        return self._request("PATCH", url, headers, body, timeout)

    def _request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: bytes | None,
        timeout: float | None,
    ) -> NetworkResponse:
        socket_path = os.environ.get("CERTORAIL_BROKER_SOCKET")
        if socket_path is None:
            raise NetworkError("no broker: the policy grants no network access")
        payload: dict[str, Any] = {"method": method, "url": url}
        if headers:
            payload["headers"] = dict(headers)
        if body is not None:
            payload["body_b64"] = base64.b64encode(body).decode("ascii")
        if timeout is not None:
            payload["timeout"] = timeout
        try:
            reply = _broker_roundtrip(socket_path, payload, timeout)
        except OSError as exc:
            raise NetworkError(f"broker transport failure: {exc}")
        if not reply.get("ok"):
            raise NetworkError(f"{reply.get('error', 'error')}: {reply.get('detail', '')}")
        return NetworkResponse(
            status=int(reply["status"]),
            reason=str(reply.get("reason", "")),
            headers=tuple((str(k), str(v)) for k, v in reply.get("headers", [])),
            body=base64.b64decode(reply["body_b64"]) if reply.get("body_b64") else b"",
            url=str(reply.get("url", url)),
        )


network = _Network()


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


@dataclass(frozen=True)
class Validated:
    """The value has passed the named policy validations (see ``check``)."""
    tags: tuple[str, ...]


@dataclass(frozen=True)
class Url:
    """The value is a URL: claims about its urlsplit reading (``analysis.UrlString``). Each
    component given is a claim; an omitted one claims nothing."""
    scheme: str | None
    netloc: Fragment | None
    path_within: str | None


def validated(*tags: str) -> Validated:
    return Validated(tags)


def url(
    *,
    scheme: str | None = None,
    netloc: Fragment | None = None,
    path_within: str | None = None,
) -> Url:
    return Url(scheme, netloc, path_within)


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
