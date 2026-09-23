"""The broker: the runtime half of ``certora.network`` and ``certora.exec``.

The confined program runs jailed -- no network (an empty network namespace on Linux, a
Seatbelt deny on macOS) and no subprocesses; the broker is the host-side half that acts on its
behalf, over one Unix socket the host created as a socketpair and handed to the program as an
inherited descriptor -- the single, auditable hole in the wall, with no name on disk for
anything else to find. TLS
terminates here: the sandboxed program never sees a certificate, a proxy variable, or a DNS
answer. Exec'd children are spawned here, outside the program's jail, after re-checking the decidable
half of the exec rules (program, fail-closed subcommand, cwd containment -- defense in depth;
the full validation rules were enforced statically), and their output is drained and returned
wholesale: ``certora.exec`` keeps its ``CompletedProcess`` contract to the byte. A grant's media
(``network = false``, ``write-fs = false``) and its ``exec`` table (a scrubbed environment, no
process creation) put its child in a jail of its own (``childjail``); each is opt-in and
enforced. A client hangup mid-exec kills the child's whole process group.

One connection lives for the whole run and carries one request at a time: the program, which
has no threads, sends a framed request and blocks on the framed reply. Hanging up is the
cancellation protocol. When the connection drops -- the program's call timed out and it closed
the channel, or the program died -- the broker shuts down the upstream socket, so the blocked
read fails at once and the origin sees the connection drop. (Cancellation saves the response
transfer; it cannot un-send a request whose side effects the origin has already committed.)

Every request, and every redirect hop, is checked against the policy's ``network`` rules
(``policy.network``, see :class:`certorail.policy.NetworkRule`) and logged. Deny by default.
Credential headers never survive a change of host: a token sent to an allowed API is not
forwarded along a redirect to some other host (the redirect URL carries its own
authorization).

There is no CLI and no configuration file: the host builds a :class:`Broker` around the policy
it already holds (:func:`build_broker`) and serves one end of a socketpair for the lifetime of
one confined program; the other end is the program's by inheritance, and that is the whole
authentication.

Wire protocol (both directions): 4-byte big-endian length prefix + UTF-8 JSON.

  request   {"method": "GET", "url": "https://...", "headers": {...},
             "body_b64": "...", "timeout": 30}
  response  {"ok": true, "status": 200, "reason": "OK",
             "headers": [[name, value], ...], "body_b64": "...",
             "url": "<final URL after redirects>"}
  exec req  {"kind": "exec", "program": "git", "arguments": ["log"], "cwd": "repos/x"}
  exec resp {"ok": true, "returncode": 0, "stdout_b64": "...", "stderr_b64": "..."}
  check req {"kind": "check", "name": "org-repo", "params": {...}, "cwd": "repos/x"}
  check rsp {"ok": true, "returncode": 0, "stderr_b64": "..."}
        or  {"ok": false, "error": "policy_denied", "detail": "..."}

``certora.check`` evaluators run through here too, and for the same reason in reverse: a
validation like "is not a production database" consults inventory the jail deliberately
cannot reach. The check's declaration is its whole runtime contract, so the broker enforces
it completely: declared name, exact parameters, cwd within the declared location.
"""
import base64
import contextlib
import http.client
import ipaddress
import json
import logging
import os
import pathlib
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from certorail.analysis import _literal_static, location_le, url_path_location
from certorail.childjail import JailUnavailable
from certorail.confinement import Confinement
from certorail.sandbox import Spawner, unprovisioned
from certorail.enforcement import Discharge
from certorail.integrity import materialize
from certorail.policy import (
    NetworkRule,
    Policy,
    Refusal,
    matches_endpoint,
    path_permitted,
    pretty_locations,
)

log = logging.getLogger("certorail.broker")

# Request headers the client may not smuggle through to the origin.
_STRIPPED_HEADERS = {
    "host", "connection", "content-length", "transfer-encoding", "keep-alive",
    "upgrade", "te", "trailer", "expect", "proxy-authorization",
    "proxy-connection",
}
# Headers additionally dropped on any redirect hop whose origin -- scheme, host or port --
# differs from the original, as curl does (``proxy-authorization`` never passes at all).
_CREDENTIAL_HEADERS = {"authorization", "cookie"}

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# Global caps; a network rule may override the last three per destination.
MAX_REQUEST_BYTES = 16 * 2**20   # cap on the request *frame* (bodies are base64: ~3/4 of this)
MAX_RESPONSE_BYTES = 16 * 2**20
MAX_REDIRECTS = 5
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 600.0    # the longest permitted *silence* between bytes of a response
TOTAL_TIMEOUT = 900.0   # wall clock for the whole request, redirects included

# Exec tunnel caps. The output cap bounds the reply frame, not the broker's memory: the child
# is policy-approved software, so an over-cap drain is an error, not an attack surface.
MAX_OUTPUT_BYTES = 8 * 2**20     # per stream (stdout, stderr)
EXEC_TIMEOUT = 900.0             # wall clock for one exec'd child


class BrokerError(Exception):
    code = "broker_error"


class PolicyDenied(BrokerError):
    code = "policy_denied"


class BadRequest(BrokerError):
    """A malformed invocation (wrong check parameters): the client maps this to TypeError."""

    code = "bad_request"


class ResponseTooLarge(BrokerError):
    code = "response_too_large"


class ClientGone(BrokerError):
    code = "client_disconnected"


# ---------------------------------------------------------------------------
# policy checks
# ---------------------------------------------------------------------------


def _rule_refusal(
    policy: Policy,
    rule: NetworkRule,
    url: str,
    initial: bool,
    discharge: Discharge | None,
) -> str | None:
    """Why an endpoint-matching *rule* refuses this *url*, or None. The initial request's
    ``requires`` were proven statically; the broker's own obligations are the redirect hops:
    a "recheck" atom is re-discharged from the URL text (a defined atom's regex, a literal
    checker), a "stop" atom refuses hops outright, a "waive" atom asks nothing of them."""
    if not initial:
        stops = sorted(ra.name for ra in rule.requires if ra.on_redirect == "stop")
        if stops:
            return (
                f"redirect refused: {', '.join(stops)} cannot vouch for a URL the analysis "
                "never saw"
            )
    to_recheck = frozenset(ra.name for ra in rule.requires if ra.on_redirect == "recheck")
    missing = policy._missing_atoms(url, to_recheck, discharge)
    if missing:
        return f"{url} is not validated by: {', '.join(sorted(missing))}"
    return None


def _check(
    policy: Policy,
    method: str,
    url: str,
    initial: bool,
    discharge: Discharge | None,
) -> tuple[str, str, int, NetworkRule]:
    """The (scheme, host, port, rule) permitting *method* on *url*, or ``PolicyDenied``.
    Applied to every redirect hop, so a redirect cannot escape the allowlist. The endpoint
    semantics live in ``policy.matches_endpoint``, shared with the static evaluation; the
    per-hop treatment of a rule's ``requires`` is ``_rule_refusal``'s."""
    parts = urllib.parse.urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise PolicyDenied(f"scheme {scheme!r} is not allowed")
    host = parts.hostname
    if not host:
        raise PolicyDenied(f"no host in URL {url!r}")
    host = host.lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        raise PolicyDenied(f"invalid port in URL {url!r}")
    port = port or (443 if scheme == "https" else 80)
    refusal: str | None = None
    # the path read exactly as the analysis reads it (``url_path_location``): one reading, so
    # the rule the broker finds is the rule the analysis proved
    url_path = url_path_location(parts.path)
    for rule in policy.network:
        if not matches_endpoint(rule, scheme, host, port, method):
            continue
        if not path_permitted(rule, url_path):
            refusal = refusal or (
                f"path {parts.path!r} is outside the permitted {pretty_locations(rule.paths)}"
            )
            continue
        why = _rule_refusal(policy, rule, url, initial, discharge)
        if why is None:
            return scheme, host, port, rule
        refusal = refusal or why
    raise PolicyDenied(refusal or f"{method} {scheme}://{host}:{port} matches no network rule")


def _screen_addresses(host: str, port: int) -> None:
    """Refuse hosts that are, or resolve to, non-public addresses (loopback, RFC1918,
    link-local, cloud metadata ranges, ...).

    Best-effort by construction: the connect that follows resolves again, so a hostile
    *allowlisted* domain could answer differently the second time (DNS rebinding). This
    screens against an allowlisted-but-compromised name, not a malicious allowlisted host."""
    try:
        ips = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise PolicyDenied(f"cannot resolve {host!r}: {exc}")
        ips = {ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]) for info in infos}
    for ip in ips:
        if not ip.is_global:
            raise PolicyDenied(f"{host} resolves to non-public address {ip}")


def _tls_context() -> ssl.SSLContext:
    """System trust: an explicit bundle wins; otherwise truststore's OS-native verification if
    installed (the macOS keychain case); otherwise OpenSSL's default paths -- the distro store,
    honoring SSL_CERT_FILE / SSL_CERT_DIR. certifi is deliberately not used: it *replaces* the
    system store, breaking locally trusted CAs (corporate proxies, private CAs)."""
    bundle = os.environ.get("CERTORAIL_CA_BUNDLE")
    if bundle:
        return ssl.create_default_context(cafile=bundle)
    try:
        import truststore #type: ignore[reportMissingImports]
        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except ImportError:
        return ssl.create_default_context()


# ---------------------------------------------------------------------------
# cancellation
# ---------------------------------------------------------------------------


class _HangupWatcher:
    """Watches the client socket while the handler is blocked on upstream work -- a network
    hop's socket reads, an exec'd child's ``communicate``.

    Under one-request-per-connection the client has nothing more to say after its request
    frame, so *any* readability on its socket is a hangup (or a protocol violation -- equally
    moot). On hangup, *cancel* is invoked until it reports that the cancellation landed (a
    False buys a retry: a network hop's upstream socket may not exist yet mid-connect).

    A context manager scoped to the blocked work: entering starts the watch, exiting joins it
    and raises ``ClientGone`` -- superseding whatever error the cancellation provoked in the
    blocked call -- if the client hung up. Enter it only while everything *cancel* touches
    strictly outlives the with-block; that ordering is the whole race-freedom argument."""

    _POLL = 0.5

    def __init__(self, client: socket.socket, cancel: Callable[[], bool]):
        self._client = client
        self._cancel = cancel
        self._done = threading.Event()
        self.cancelled = False
        self._thread = threading.Thread(
            target=self._run, name="certorail-broker-hangup", daemon=True
        )

    def __enter__(self) -> "_HangupWatcher":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._done.set()
        self._thread.join()
        if self.cancelled:
            raise ClientGone("client disconnected") from None

    def _run(self) -> None:
        while not self._done.is_set():
            readable, _, _ = select.select([self._client], [], [], self._POLL)
            if self._done.is_set():
                return
            if readable:
                self.cancelled = True
                if self._cancel():
                    return
                while not self._done.wait(0.05):
                    if self._cancel():
                        return
                return


# ---------------------------------------------------------------------------
# executing requests
# ---------------------------------------------------------------------------


def _read_capped(resp: http.client.HTTPResponse, conn: http.client.HTTPConnection,
                 limit: int, deadline: float) -> bytes:
    """Read the whole body, enforcing the size cap and the wall-clock budget between chunks,
    and tightening the socket timeout so that no single read can outlive the budget either."""
    chunks, total = [], 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrokerError("total_timeout exceeded while reading response")
        sock = conn.sock
        if sock is not None:
            current = sock.gettimeout()
            sock.settimeout(max(0.01, min(current if current is not None else remaining,
                                          remaining)))
        # read1() returns as soon as *any* data is available; read(amt) blocks until amt bytes
        # or EOF, which on a trickling origin means never returning to this loop
        chunk = resp.read1(65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ResponseTooLarge(f"response body exceeds max_response_bytes={limit}")


def _hop(
    tls: ssl.SSLContext,
    client: socket.socket,
    scheme: str,
    host: str,
    port: int,
    target: str,
    method: str,
    headers: dict,
    body: bytes | None,
    connect_timeout: float,
    read_timeout: float,
    limit: int,
    deadline: float,
) -> tuple[int, str, list, str | None, bytes]:
    """One request on a fresh connection, watched for client hangup for its whole lifetime.
    Returns (status, reason, headers, location, body); a redirect returns its Location and no
    body, anything else a capped body and no Location."""
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=connect_timeout, context=tls)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=connect_timeout)

    def shutdown_upstream() -> bool:
        # shutdown() from another thread wakes a blocked recv, close() does not; the socket
        # may not exist yet mid-connect, in which case the watcher retries
        sock = conn.sock
        if sock is None:
            return False
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass          # already torn down
        return True

    # exit order: the watcher joins before closing() touches the connection it watches
    with contextlib.closing(conn), _HangupWatcher(client, shutdown_upstream):
        try:
            conn.request(method, target, body=body, headers=headers)
            if conn.sock is not None:
                conn.sock.settimeout(read_timeout)
            resp = conn.getresponse()
            location = resp.getheader("Location")
            if resp.status in _REDIRECT_STATUSES and location is not None:
                return resp.status, resp.reason or "", [], location, b""
            data = _read_capped(resp, conn, limit, deadline)
            return resp.status, resp.reason or "", list(resp.getheaders()), None, data
        except TimeoutError:
            # a hangup-induced failure is not a timeout; the watcher's __exit__ supersedes
            # this with ClientGone when the client is gone
            if time.monotonic() >= deadline - 0.05:
                raise BrokerError("total_timeout exceeded") from None
            raise BrokerError(f"read timeout: no data for {read_timeout:g}s") from None


def _execute(
    policy: Policy,
    tls: ssl.SSLContext,
    discharge: Discharge | None,
    client: socket.socket,
    method: str,
    url: str,
    headers: dict | None,
    body: bytes | None,
    timeout_hint: float | None,
) -> dict:
    headers = {k: v for k, v in (headers or {}).items()
               if k.lower() not in _STRIPPED_HEADERS}
    current, hops = url, 0
    first_origin: tuple[str, str, int] | None = None
    deadline: float | None = None
    total_cap = TOTAL_TIMEOUT
    while True:
        # policy is enforced on EVERY hop, so a redirect cannot escape the allowlist
        scheme, host, port, rule = _check(policy, method, current, hops == 0, discharge)
        if not rule.allow_nonpublic:
            _screen_addresses(host, port)
        if first_origin is None:
            first_origin = (scheme, host, port)
        if deadline is None:
            # the wall-clock budget is fixed by the first hop's rule and spans redirects:
            # read_timeout bounds only *silence*, so on its own a trickling origin could
            # hold a handler forever
            total_cap = rule.total_timeout or TOTAL_TIMEOUT
            deadline = time.monotonic() + total_cap
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrokerError(f"total_timeout ({total_cap:g}s) exceeded")
        # caps come from the matched rule, falling back to the globals; the client's timeout
        # hint can only tighten the read cap, never raise it
        read_cap = rule.read_timeout or READ_TIMEOUT
        read_timeout = min(timeout_hint, read_cap) if timeout_hint else read_cap
        read_timeout = min(read_timeout, remaining)
        hop_headers = headers
        if (scheme, host, port) != first_origin:
            # credentials never survive a change of origin: a token for the API must not follow
            # a redirect to the CDN, nor go out in the clear after a downgrade to http or a move
            # to another port (the redirect URL carries its own authorization)
            hop_headers = {k: v for k, v in headers.items()
                           if k.lower() not in _CREDENTIAL_HEADERS}
        parts = urllib.parse.urlsplit(current)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        status, reason, resp_headers, location, data = _hop(
            tls, client, scheme, host, port, target, method, hop_headers, body,
            min(CONNECT_TIMEOUT, remaining), read_timeout,
            rule.max_response_bytes or MAX_RESPONSE_BYTES, deadline,
        )
        if location is not None:
            hops += 1
            if hops > MAX_REDIRECTS:
                raise BrokerError(f"more than {MAX_REDIRECTS} redirects")
            if status == 303 or (status in (301, 302) and method not in ("GET", "HEAD")):
                method, body = "GET", None
                headers = {k: v for k, v in headers.items()
                           if k.lower() != "content-type"}
            current = urllib.parse.urljoin(current, location)
            continue
        log.info("ALLOW %s %s -> %d (%d bytes%s)", method, url, status, len(data),
                 f", final={current}" if current != url else "")
        return {
            "status": status,
            "reason": reason,
            "headers": [[k, v] for k, v in resp_headers],
            "body_b64": base64.b64encode(data).decode("ascii"),
            "url": current,
        }


# ---------------------------------------------------------------------------
# the exec tunnel
# ---------------------------------------------------------------------------


def _resolve(root: pathlib.Path, cwd: str) -> pathlib.Path:
    given = pathlib.Path(cwd)
    return given if given.is_absolute() else root / given


def _spawn_drained(
    client: socket.socket,
    argv: list[str],
    workdir: pathlib.Path,
    confinement: Confinement,
    spawner: Spawner,
    stream_to: tuple[int, int] | None = None,
) -> tuple[int, bytes, bytes]:
    """Spawn host-side, under the grant's *confinement* as this run's *spawner* realises it (the
    OS-enforced reach the grant's media and ``exec`` table allow the child), and drain the output
    wholesale -- or, with *stream_to* (the host's stdout and stderr descriptors), let the child
    write straight to them and return empty output. A client hangup kills the child's whole
    process group (it gets its own, so descendants die with it). A confinement the platform
    cannot enforce is a broker error before anything runs."""
    if stream_to is not None:
        # the host's own buffered output goes first, so the terminal reads in order
        for stream in (sys.stdout, sys.stderr):
            with contextlib.suppress(Exception):
                stream.flush()
    try:
        with spawner.spawn(confinement, argv, workdir) as spawn:
            try:
                proc = subprocess.Popen(
                    spawn.argv,
                    cwd=workdir,
                    env=spawn.env,
                    pass_fds=spawn.pass_fds,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE if stream_to is None else stream_to[0],
                    stderr=subprocess.PIPE if stream_to is None else stream_to[1],
                    shell=False,
                    start_new_session=True,
                )
            except OSError as exc:
                raise BrokerError(f"spawn: {exc}")

            def kill_child() -> bool:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass          # already gone
                return True

            with _HangupWatcher(client, kill_child):
                try:
                    out, err = proc.communicate(timeout=EXEC_TIMEOUT)
                except subprocess.TimeoutExpired:
                    kill_child()
                    proc.communicate()
                    raise BrokerError(f"timeout ({EXEC_TIMEOUT:g}s) exceeded") from None
    except JailUnavailable as exc:
        raise BrokerError(f"jail: {exc}")
    out, err = out or b"", err or b""  # None when streamed
    if len(out) > MAX_OUTPUT_BYTES or len(err) > MAX_OUTPUT_BYTES:
        raise ResponseTooLarge(f"output exceeds {MAX_OUTPUT_BYTES} bytes per stream")
    return proc.returncode, out, err


def _run_exec(
    policy: Policy,
    root: pathlib.Path | None,
    client: socket.socket,
    program: str,
    arguments: list[str],
    keywords: dict[str, str | list[str]],
    cwd: str,
    discharge: Discharge | None,
    stream: bool,
    stream_to: tuple[int, int] | None,
    spawner: Spawner,
) -> dict:
    """One brokered ``certora.exec``: re-check the decidable half of the exec rules
    (``Policy.exec_command`` -- defense in depth; the full rules were enforced statically),
    let the policy's template compose the argv, spawn the child host-side (under the policy's
    filesystem view plus the rule's own mounts, when the rule confines it), and return its
    drained output wholesale -- or stream it to the host's terminal (*stream*) and return the
    exit code alone."""
    command = policy.exec_command(program, arguments, keywords, cwd, discharge)
    if isinstance(command, Refusal):
        raise PolicyDenied(command.reason)
    if root is None:
        raise BrokerError("exec: the broker was built without a root")
    if stream and stream_to is None:
        raise BrokerError("stream: the host has no terminal to stream to")
    returncode, out, err = _spawn_drained(
        client, command.argv, _resolve(root, cwd), policy.confinement(command.rule, root),
        spawner, stream_to if stream else None,
    )
    log.info("EXEC %s (cwd=%s) -> %d (%s)",
             " ".join(command.argv), cwd, returncode,
             "streamed" if stream else f"out {len(out)} bytes, err {len(err)} bytes")
    return {
        "returncode": returncode,
        "stdout_b64": base64.b64encode(out).decode("ascii"),
        "stderr_b64": base64.b64encode(err).decode("ascii"),
    }


@dataclass(frozen=True)
class ByName:
    """``certora.check(name, **params)``: every declared parameter, by name."""
    params: dict[str, str]


@dataclass(frozen=True)
class Single:
    """``certora.check_single(name, value)``: the value binds the one declared parameter."""
    value: str


type CheckArguments = ByName | Single


def _check_arguments(name: str, req: dict) -> CheckArguments:
    """The arguments of a check frame, decoded once at the edge: the single-value form or the
    by-name form, str values only. Anything else is a malformed frame."""
    single, params = req.get("single"), req.get("params") or {}
    if single is not None:
        if params:
            raise BadRequest(f"check {name!r}: the single-value form takes no other parameters")
        if not isinstance(single, str):
            raise BadRequest(f"check {name!r}: the value must be a str")
        return Single(single)
    if not isinstance(params, dict):
        raise BadRequest(f"check {name!r}: the parameters must be a mapping")
    typed = {k: v for k, v in params.items() if isinstance(k, str) and isinstance(v, str)}
    if len(typed) != len(params):
        raise BadRequest(f"check {name!r}: every parameter must be a str")
    return ByName(typed)


def _run_check(
    policy: Policy,
    root: pathlib.Path | None,
    client: socket.socket,
    name: str,
    arguments: CheckArguments,
    cwd: str | None,
    spawner: Spawner,
) -> dict:
    """One brokered ``certora.check``: run the declared evaluator host-side -- outside the
    jail, where whatever it consults (an inventory service, credentials, the org's tooling)
    actually lives, or under the policy's filesystem view plus its own mounts when its rule
    confines it -- and return its verdict. Unlike exec's rules, a check's declaration IS its
    whole runtime contract, so this re-check is complete: name, parameters and cwd are all
    decidable here."""
    declared = next((v for v in policy.validations if v.name == name), None)
    if declared is None:
        raise PolicyDenied(f"check: no validation named {name!r}")
    match arguments:
        case Single(value=value):
            if len(declared.params) != 1:
                raise BadRequest(
                    f"check {name!r}: check_single needs exactly one declared parameter, "
                    f"it has {len(declared.params)}"
                )
            params = {declared.params[0]: value}
        case ByName(params=params):
            pass
    if set(params) != set(declared.params):
        raise BadRequest(
            f"check {name!r}: expected str arguments {sorted(declared.params)}, "
            f"got {sorted(params)}"
        )
    if root is None:
        raise BrokerError("check: the broker was built without a root")
    if declared.cwd is not None:
        if cwd is None:
            raise PolicyDenied(f"check {name!r}: cwd= is required")
        loc = _literal_static(cwd)
        if loc is None or not any(location_le(loc, allowed) for allowed in declared.cwd):
            raise PolicyDenied(
                f"check {name!r} may not run at {cwd!r} "
                f"(permitted: {pretty_locations(declared.cwd)})"
            )
    workdir = root if cwd is None else _resolve(root, cwd)
    argv = [piece if isinstance(piece, str) else params[piece.name]
            for piece in declared.argv]
    if declared.evaluator is not None:
        # exec the load-time snapshot: the installed checker drifting mid-run changes nothing,
        # because the file in checkers/ is not what runs (integrity.materialize)
        argv[0] = materialize(declared.evaluator)
    returncode, _, err = _spawn_drained(client, argv, workdir, policy.confinement(declared, root), spawner)
    log.info("CHECK %s (cwd=%s) -> %d", name, cwd if cwd is not None else ".", returncode)
    return {
        "returncode": returncode,
        "stderr_b64": base64.b64encode(err).decode("ascii"),
    }


# ---------------------------------------------------------------------------
# framed-JSON server over a Unix socket
# ---------------------------------------------------------------------------


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            if not buf:
                return None            # clean EOF before the frame
            raise ConnectionError("peer closed mid-frame")
        buf += chunk
    return buf


def _send_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(struct.pack("!I", len(payload)) + payload)


class Broker:
    """The host-side half for one confined run: the policy, the TLS context, the literal
    discharger, where a streamed exec writes, and the run's spawner (``certorail.sandbox``: the
    platform mechanism with the run's FUSE view, when one is attached). ``serve`` speaks the wire
    protocol on one connected socket until the peer closes it."""

    def __init__(
        self,
        policy: Policy,
        discharge: Discharge | None,
        root: pathlib.Path | None,
        stream_to: tuple[int, int] | None,
        spawner: Spawner,
    ):
        self.policy = policy
        self.tls = _tls_context()
        self.discharge = discharge
        self.root = root
        self.stream_to = stream_to
        self.spawner = spawner

    def serve(self, conn: socket.socket) -> None:
        """Serve *conn* -- the host's end of the program's socketpair -- until the program closes
        it or dies: one framed request at a time, its reply framed back. An oversized frame is
        answered with an error and ends the connection, since the stream is no longer known to
        be in sync."""
        try:
            while True:
                header = _recv_exact(conn, 4)
                if header is None:
                    return
                (length,) = struct.unpack("!I", header)
                if length > MAX_REQUEST_BYTES:
                    _send_frame(conn, json.dumps({
                        "ok": False, "error": "broker_error",
                        "detail": "request frame too large"}).encode())
                    return
                payload = _recv_exact(conn, length)
                if payload is None:
                    return
                reply = self.respond(conn, payload)
                if reply is None:
                    return  # the client is gone: nobody is left to read it
                _send_frame(conn, reply)
        except OSError:                  # client went away mid-frame
            return
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def respond(self, conn: socket.socket, payload: bytes) -> bytes | None:
        """The framed reply, or None when the client is gone and nobody is left to read it."""
        what = "?"
        try:
            req = json.loads(payload)
            if req.get("kind") == "exec":
                program = str(req.get("program", "?"))
                arguments = [str(a) for a in req.get("arguments", [])]
                keywords: dict[str, str | list[str]] = {
                    str(k): v if isinstance(v, str) else [str(x) for x in v]
                    for k, v in (req.get("kwargs") or {}).items()
                }
                what = "exec " + " ".join([program, *arguments]) + "".join(
                    f" {k}={v!r}" for k, v in keywords.items()
                )
                result = _run_exec(self.policy, self.root, conn,
                                   program, arguments, keywords, str(req.get("cwd", "")),
                                   self.discharge, bool(req.get("stream", False)),
                                   self.stream_to, self.spawner)
            elif req.get("kind") == "check":
                name = str(req.get("name", "?"))
                what = f"check {name}"
                cwd_value = req.get("cwd")
                if cwd_value is not None and not isinstance(cwd_value, str):
                    raise BadRequest(f"check {name!r}: cwd must be a str")
                result = _run_check(self.policy, self.root, conn,
                                    name, _check_arguments(name, req), cwd_value, self.spawner)
            else:
                method = str(req.get("method", "GET")).upper()
                url = req["url"]
                what = f"{method} {url}"
                body = (base64.b64decode(req["body_b64"])
                        if req.get("body_b64") else None)
                timeout = float(req["timeout"]) if req.get("timeout") else None
                result = _execute(self.policy, self.tls, self.discharge,
                                  conn, method, url, req.get("headers"), body, timeout)
            return json.dumps({"ok": True, **result}).encode()
        except ClientGone:
            log.info("ABORT %s :: client disconnected; upstream work cancelled", what)
            return None
        except BrokerError as exc:
            tag = "DENY" if exc.code == "policy_denied" else "FAIL"
            log.info("%s  %s :: %s", tag, what, exc)
            return json.dumps({"ok": False, "error": exc.code,
                               "detail": str(exc)}).encode()
        except Exception as exc:
            log.warning("ERROR %s :: %s: %s", what, type(exc).__name__, exc)
            return json.dumps({"ok": False, "error": "broker_error",
                               "detail": f"{type(exc).__name__}: {exc}"}).encode()


def terminal_descriptors() -> tuple[int, int] | None:
    """The host's stdout and stderr descriptors, for streaming execs -- None when either is not
    a real descriptor (captured by a test harness, say), in which case streaming is refused."""
    try:
        return sys.stdout.fileno(), sys.stderr.fileno()
    except (AttributeError, ValueError, OSError):
        return None


def build_broker(
    policy: Policy,
    root: str | os.PathLike[str] | None = None,
    stream_to: tuple[int, int] | None = None,
    spawner: Spawner | None = None,
) -> Broker:
    """The broker for one confined run, enforcing *policy*: the host hands ``Broker.serve`` its
    end of the program's socketpair, on a thread, for the lifetime of the program. *root*
    anchors the exec tunnel's relative cwds and enables literal-checker discharge of network
    rules' ``requires`` atoms (``Policy.discharger``); without it only defined atoms discharge
    and exec is refused. *stream_to* is where a ``stream=True`` exec's child writes (the host's
    own stdout and stderr descriptors, ``terminal_descriptors()``); without it streaming execs
    are refused. *spawner* is the run's (``sandbox.provision``); without one, children are
    spawned by ``sandbox.unprovisioned()``, with no FUSE view."""
    runner = spawner if spawner is not None else unprovisioned()
    return Broker(
        policy,
        None if root is None else policy.discharger(root, runner),
        None if root is None else pathlib.Path(root),
        stream_to,
        runner,
    )
