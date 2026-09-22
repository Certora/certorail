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
import sys
import typing
from collections.abc import Callable, Sequence
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
    normal ``ExecResult`` with its returncode.)"""


class ExecResult(subprocess.CompletedProcess[bytes]):
    """What ``certora.exec`` returns: a ``CompletedProcess`` (``args``, ``returncode``, the raw
    ``stdout``/``stderr`` bytes) plus the decoded views a program reaches for where it would
    otherwise pipe into ``head``/``tail``/``wc``. ``stdout_string()``, ``stdout_lines()`` and
    their stderr twins **raise ``CalledProcessError`` when the child exited non-zero**, so a
    pipeline over a failed command fails loudly instead of quietly processing empty output;
    a program that means to handle failure inspects ``returncode`` and the raw bytes instead.
    Text is UTF-8 with undecodable bytes replaced; lines are split as ``str.splitlines`` does
    (``\\r\\n`` handled, no trailing empty line)."""

    def stdout_string(self) -> str:
        self.check_returncode()
        return self.stdout.decode("utf-8", errors="replace")

    def stdout_lines(self) -> list[str]:
        return self.stdout_string().splitlines()

    def stderr_string(self) -> str:
        self.check_returncode()
        return self.stderr.decode("utf-8", errors="replace")

    def stderr_lines(self) -> list[str]:
        return self.stderr_string().splitlines()


# The exception the decoded views raise, re-exported so the subset -- which cannot import
# subprocess -- can spell it: ``except certora.CalledProcessError as e: e.returncode``.
CalledProcessError = subprocess.CalledProcessError


type Word = str | os.PathLike[str]  # one command word: text, or a path standing for its text


def exec(
    *cmd: Word, cwd: pathlib.Path | str, stream: bool = False, **holes: Word | Sequence[Word]
) -> ExecResult:
    """The only way to run a subprocess: tunneled to the host's broker, which re-checks the
    decidable half of the exec rules (program, fail-closed subcommand, cwd containment --
    defense in depth; the full rules were enforced statically), spawns the child outside the
    sandbox, drains its output, and returns it wholesale. No shell, output always captured,
    ``cwd`` mandatory: exactly the ``subprocess.run(..., capture_output=True)`` this once
    was, one socket away -- returned as an ``ExecResult``, whose decoded views raise on a
    non-zero exit.

    ``stream=True`` sends the child's stdout and stderr straight to the terminal the host is
    running on -- the same descriptors the program's own ``print`` reaches -- as it happens,
    instead of capturing them: for a build or a test run one wants to watch. The result then
    carries the exit code and empty ``stdout``/``stderr``; live output and extraction from the
    output are one or the other, per call.

    Keywords other than ``cwd`` and ``stream`` bind the *holes* of the policy's command template
    for the program (TEMPLATES.md): a string or a path for a token hole, a list of them for a
    splice. The broker binds the call like a signature and composes the argv itself.

    This is the runtime half. The static half (``walker``) additionally requires the program to
    be a string literal, refuses ``*args``/``**kwargs``, and treats ``cwd`` as a sink whose
    location must be proven.
    """
    if not cmd:
        raise ValueError("exec: no program given")
    # a command word is a str or a path (``os.fspath`` yields exactly the text the analysis
    # reasoned about for a located value); anything else -- a list, a number, an object -- is
    # not a word, and the static side let it through only as an unknown value under a rule
    # that admits those, so this is the backstop
    words = [_word(part, "every part of the command") for part in cmd]
    bindings: dict[str, str | list[str]] = {}
    for name, value in holes.items():
        if isinstance(value, (list, tuple)):
            bindings[name] = [_word(v, f"every element of {name}=") for v in value]
        else:
            bindings[name] = _word(value, f"{name}=")
    if not _broker.available():
        raise ExecFailed("no broker: the policy permits no programs")
    program, *arguments = words
    if stream:
        # the program's own prints may still sit in this process's buffers (block-buffered when
        # stdout is a pipe); push them out so the child's output lands after them, in order
        for out in (sys.stdout, sys.stderr):
            try:
                out.flush()
            except (OSError, ValueError):
                pass
    try:
        reply = _broker.call(
            {"kind": "exec", "program": program, "arguments": arguments,
             "kwargs": bindings, "cwd": os.fspath(cwd), "stream": bool(stream)},
            timeout=None,
        )
    except OSError as exc:
        raise ExecFailed(f"broker transport failure: {exc}")
    if not reply.get("ok"):
        raise ExecFailed(f"{reply.get('error', 'error')}: {reply.get('detail', '')}")
    return ExecResult(
        args=words,
        returncode=int(reply["returncode"]),
        stdout=base64.b64decode(reply.get("stdout_b64", "")),
        stderr=base64.b64decode(reply.get("stderr_b64", "")),
    )


def _word(value: object, what: str) -> str:
    """One command word: a ``str`` as is, a path as its text."""
    if isinstance(value, str):
        return value
    if isinstance(value, os.PathLike):
        text = os.fspath(value)
        if isinstance(text, str):
            return text
    raise TypeError(f"exec: {what} must be a str or a path")


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
    if not _broker.available():
        raise CheckFailed("check: no broker (the policy declares no validations)")
    try:
        reply = _broker.call({"kind": "check", "name": name, **request}, timeout=None)
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


class _BrokerChannel:
    """The program's one connection to the host's broker: the socketpair end the host handed it
    at spawn, named by descriptor number in ``CERTORAIL_BROKER_FD``. Requests are sequential (the
    subset has no threads), so one framed request-reply at a time over one connection. Transport
    failures surface as OSError for the caller to wrap. A timeout closes the channel -- that is
    the cancellation the broker acts on -- and every later call fails too: a program that has
    outlived one of its own requests has no broker any more."""

    def __init__(self) -> None:
        self._sock: socket.socket | None = None
        self._fd: int | None = None
        self._dead: str | None = None

    @staticmethod
    def available() -> bool:
        return "CERTORAIL_BROKER_FD" in os.environ

    def _socket(self) -> socket.socket:
        fd = int(os.environ["CERTORAIL_BROKER_FD"])
        if self._sock is not None and self._fd != fd:  # a test pointed us elsewhere
            self._sock.close()
            self._sock, self._dead = None, None
        if self._sock is None:
            # a duplicate: the inherited descriptor itself stays as it was handed over
            self._sock = socket.socket(fileno=os.dup(fd))
            self._fd = fd
        return self._sock

    def call(self, payload: dict[str, Any], timeout: float | None) -> dict[str, Any]:
        if self._dead is not None:
            raise ConnectionError(self._dead)
        sock = self._socket()
        frame = json.dumps(payload).encode("utf-8")
        # the broker always answers within its own deadlines; the slack keeps its precise
        # timeout error ahead of this blunt one
        sock.settimeout(timeout + 30.0 if timeout is not None else None)
        try:
            sock.sendall(struct.pack("!I", len(frame)) + frame)
            header = _recv_exact(sock, 4)
            if header is None:
                raise ConnectionError("the broker closed the connection")
            (length,) = struct.unpack("!I", header)
            reply_frame = _recv_exact(sock, length)
            if reply_frame is None:
                raise ConnectionError("the broker closed mid-frame")
        except OSError as exc:
            self._dead = f"the broker channel is closed after a failed request ({exc})"
            sock.close()
            self._sock = None
            raise
        return json.loads(reply_frame)


_broker = _BrokerChannel()


class _Network:
    """The runtime half of ``certora.network``: a request over the program's one channel to
    the host's broker (``_BrokerChannel``; no channel, no network). Closing the channel -- a
    timeout here, the program dying -- is what cancels the in-flight request broker-side. The
    static half (walker) admits only these methods, a single URL argument whose scheme and
    netloc are proven, and the enumerated keywords."""

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
        if not _broker.available():
            raise NetworkError("no broker: the policy grants no network access")
        payload: dict[str, Any] = {"method": method, "url": url}
        if headers:
            payload["headers"] = dict(headers)
        if body is not None:
            payload["body_b64"] = base64.b64encode(body).decode("ascii")
        if timeout is not None:
            payload["timeout"] = timeout
        try:
            reply = _broker.call(payload, timeout)
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


# ---------------------------------------------------------------------------
# extractors: how data gets out of a source with its provenance intact (PROVENANCE.md)
#
# The static half binds a *source atom* to what these return: a value extracted from the result
# of a source-bearing rule is something that source produced, unmodified. Any string operation
# on it yields a fresh value with no provenance -- the identity semantics -- so these four are
# the only constructors. Runtime-wise they are plain functions in the child.
# ---------------------------------------------------------------------------


class ExtractError(Exception):
    """The path misses, selects null or a non-scalar, the text is not JSON, or the source is not
    something extractable (a failed response, an object with no text)."""


def _source_text(x: object) -> str:
    match x:
        case ExecResult():
            return x.stdout_string()  # a failed child raises CalledProcessError here
        case NetworkResponse():
            if not 200 <= x.status < 300:
                raise ExtractError(f"response status {x.status} {x.reason}".rstrip())
            return x.body.decode("utf-8", errors="replace")
        case str():
            return x
        case bytes():
            return x.decode("utf-8", errors="replace")
        case _ if callable(getattr(x, "read", None)):
            data = getattr(x, "read")()
            return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
        case _:
            raise ExtractError(f"not a source: {type(x).__name__}")


def _scalar(value: object, path: str) -> str:
    match value:
        case bool():
            return "true" if value else "false"
        case int() | float():
            return str(value)
        case str():
            return value
        case None:
            raise ExtractError(f"{path}: null")
        case _:
            raise ExtractError(f"{path}: not a scalar ({type(value).__name__})")


def _select(x: object, path: str, want_plural: bool) -> object:
    from certorail import jqpath  # stdlib-only; imported lazily to keep the namespace's import light

    try:
        steps = jqpath.parse(path)
    except ValueError as exc:
        raise ExtractError(str(exc)) from None
    if jqpath.plural(steps) != want_plural:
        raise ExtractError(
            f"{path}: a plural path ([]) needs extract_all" if not want_plural
            else f"{path}: extract_all needs a plural path (one [])"
        )
    try:
        document = json.loads(_source_text(x))
    except json.JSONDecodeError as exc:
        raise ExtractError(f"not JSON: {exc}") from None
    try:
        return jqpath.walk(steps, document)
    except ValueError as exc:
        raise ExtractError(str(exc)) from None


def extract(x: object, path: str) -> str:
    """The scalar *path* selects in the JSON text of *x* -- an exec result (stdout), a response
    (body), a file object, or text -- as a string. Numbers and booleans are stringified; null,
    a missing path and a non-scalar are ``ExtractError``."""
    return _scalar(_select(x, path, want_plural=False), path)


def extract_all(x: object, path: str) -> list[str]:
    """The scalars a plural *path* (one ``[]``) selects, each as a string."""
    found = _select(x, path, want_plural=True)
    assert isinstance(found, list)
    return [_scalar(v, path) for v in found]


def lines(x: object) -> list[str]:
    """The lines of a source's text, newline stripped."""
    return _source_text(x).splitlines()


def field(line: str, index: int, sep: str | None = None) -> str:
    """One field of a line (``str.split`` semantics); ``ExtractError`` when there is none."""
    parts = line.split(sep)
    try:
        return parts[index]
    except IndexError:
        raise ExtractError(f"field {index} of {len(parts)}") from None


def reveal_fact(value: object) -> None:
    """Show what the analysis knows about a variable at this point of the program.

    ``certora.reveal_fact(x)`` -- a bare name, nothing else -- makes ``certorail --check`` (and
    a run, on stderr) print the fact the analysis holds for ``x`` there: its location, the text
    shape it matches, the atoms it carries, or that nothing is known. It changes nothing: no fact
    is established or killed, and at runtime it does nothing at all. For finding out why a sink
    was denied."""
    return None


def pathmatch(text: str, location: str) -> bool:
    """Is *text* -- a filesystem path (relative to the sandbox root, or absolute) or a URL path
    -- at the *location*, spelled the way the policy spells locations: ``repos/**``,
    ``repos/*/foundry.toml``, ``/repos/*/*/issues/<\\d+>/comments``, ``{a,b}/x``?

    As the condition of a guard (``assert certora.pathmatch(p, "repos/*/foundry.toml")``, or
    ``if ... and certora.pathmatch(urllib.parse.urlsplit(u).path, "/repos/**"):``) it
    establishes exactly that location on the variable statically; at runtime it is the same
    matcher on the concrete text. A ``..`` anywhere is within nothing."""
    if not isinstance(text, str):
        raise TypeError("pathmatch: the path must be a str (use str(p) for a pathlib path)")
    from certorail import locspec  # stdlib-only

    return locspec.matches(locspec.parse(location), text)


@dataclass(frozen=True)
class Atom:
    name: str


no_slash = Atom("no-slash")
no_parent_traversal = Atom("no-parent-traversal")
not_absolute = Atom("not-absolute")
not_dot_dot = Atom("not-dot-dot")
not_option = Atom("not-option")  # the text does not begin with "-": no tool reads it as an option


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
class Source:
    """The value came, unmodified, from the rule that yields the named source atom(s)
    (``extract`` and friends): provenance, never established by a check or a literal."""
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


def source(*tags: str) -> Source:
    return Source(tags)


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
