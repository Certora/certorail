"""The network broker: the runtime half of ``certora.network``.

The confined program runs with no network at all (an empty network namespace on Linux, a
Seatbelt deny on macOS); the broker is the host-side process that talks to the network on its
behalf, over a Unix socket -- the single, auditable hole in the wall. TLS terminates here:
the sandboxed program never sees a certificate, a proxy variable, or a DNS answer.

One connection carries exactly one request. The client connects, sends one framed request,
and blocks on the framed response; hanging up is the cancellation protocol. When the client
disconnects -- its call timed out, the program moved on or died -- the broker shuts down the
upstream socket, so the blocked read fails at once and the origin sees the connection drop.
(Cancellation saves the response transfer; it cannot un-send a request whose side effects the
origin has already committed.)

Every request, and every redirect hop, is checked against the policy's ``network`` rules
(``policy.network``, see :class:`certorail.policy.NetworkRule`) and logged. Deny by default.
Credential headers never survive a change of host: a token sent to an allowed API is not
forwarded along a redirect to some other host (the redirect URL carries its own
authorization).

There is no CLI and no configuration file: the host builds a :func:`build_server` around the
policy it already holds and runs it for the lifetime of one confined program. The socket is
created mode 0600 in a 0700 directory -- filesystem permission is the authentication; the
sandbox can reach the socket only because the host put it inside the sandbox's world.

Wire protocol (both directions): 4-byte big-endian length prefix + UTF-8 JSON.

  request   {"method": "GET", "url": "https://...", "headers": {...},
             "body_b64": "...", "timeout": 30}
  response  {"ok": true, "status": 200, "reason": "OK",
             "headers": [[name, value], ...], "body_b64": "...",
             "url": "<final URL after redirects>"}
        or  {"ok": false, "error": "policy_denied", "detail": "..."}
"""
import base64
import contextlib
import http.client
import ipaddress
import json
import logging
import os
import select
import socket
import socketserver
import ssl
import struct
import threading
import time
import urllib.parse

from .policy import NetworkRule, Policy

log = logging.getLogger("certorail.broker")

# Request headers the client may not smuggle through to the origin.
_STRIPPED_HEADERS = {
    "host", "connection", "content-length", "transfer-encoding", "keep-alive",
    "upgrade", "te", "trailer", "expect", "proxy-authorization",
    "proxy-connection",
}
# Headers additionally dropped on any redirect hop whose host differs from the original.
_CREDENTIAL_HEADERS = {"authorization", "cookie"}

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# Global caps; a rule may override the last three per destination.
MAX_REQUEST_BYTES = 16 * 2**20   # cap on the request *frame* (bodies are base64: ~3/4 of this)
MAX_RESPONSE_BYTES = 16 * 2**20
MAX_REDIRECTS = 5
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 600.0    # the longest permitted *silence* between bytes of a response
TOTAL_TIMEOUT = 900.0   # wall clock for the whole request, redirects included


class BrokerError(Exception):
    code = "broker_error"


class PolicyDenied(BrokerError):
    code = "policy_denied"


class ResponseTooLarge(BrokerError):
    code = "response_too_large"


class ClientGone(BrokerError):
    code = "client_disconnected"


# ---------------------------------------------------------------------------
# policy checks
# ---------------------------------------------------------------------------


def _host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]              # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    return host == pattern


def _check(policy: Policy, method: str, url: str) -> tuple[str, str, int, NetworkRule]:
    """The (scheme, host, port, rule) permitting *method* on *url*, or ``PolicyDenied``.
    Applied to every redirect hop, so a redirect cannot escape the allowlist."""
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
    default_port = 443 if scheme == "https" else 80
    port = port or default_port
    for rule in policy.network:
        if not _host_matches(rule.host, host):
            continue
        if scheme not in rule.schemes:
            continue
        if rule.ports:
            if port not in rule.ports:
                continue
        elif port != default_port:
            continue
        if rule.methods and method not in rule.methods:
            continue
        return scheme, host, port, rule
    raise PolicyDenied(f"{method} {scheme}://{host}:{port} matches no network rule")


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
        ips = {ipaddress.ip_address(info[4][0].split("%", 1)[0]) for info in infos}
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
        import truststore
        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except ImportError:
        return ssl.create_default_context()


# ---------------------------------------------------------------------------
# cancellation
# ---------------------------------------------------------------------------


class _HangupWatcher:
    """Watches the client socket while the handler is blocked on one upstream hop.

    Under one-request-per-connection the client has nothing more to say after its request
    frame, so *any* readability on its socket is a hangup (or a protocol violation -- equally
    moot). On hangup, shut down the upstream socket: shutdown() from another thread wakes a
    blocked recv, close() does not.

    A context manager scoped to the hop: entering starts the watch, exiting joins it and
    raises ``ClientGone`` -- superseding whatever error the shutdown provoked in the blocked
    I/O -- if the client hung up. Nest it *inside* ``closing(conn)`` so the join happens
    before the sockets it touches are closed; that ordering is the whole race-freedom
    argument."""

    _POLL = 0.5

    def __init__(self, client: socket.socket, upstream: http.client.HTTPConnection):
        self._client = client
        self._upstream = upstream
        self._done = threading.Event()
        self.cancelled = False
        self._thread = threading.Thread(
            target=self._run, name="certorail-broker-hangup", daemon=True
        )

    def __enter__(self) -> "_HangupWatcher":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._done.set()
        self._thread.join()
        if self.cancelled:
            raise ClientGone("client disconnected") from None
        return False

    def _run(self) -> None:
        while not self._done.is_set():
            readable, _, _ = select.select([self._client], [], [], self._POLL)
            if self._done.is_set():
                return
            if readable:
                self.cancelled = True
                # the hangup may arrive while the connect is still in flight and the socket
                # does not exist yet; wait for it so the cancel actually lands
                while not self._done.wait(0.05):
                    sock = self._upstream.sock
                    if sock is not None:
                        try:
                            sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass          # already torn down
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
    # exit order: the watcher joins before closing() touches the connection it watches
    with contextlib.closing(conn), _HangupWatcher(client, conn):
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
    first_host: str | None = None
    deadline: float | None = None
    total_cap = TOTAL_TIMEOUT
    while True:
        # policy is enforced on EVERY hop, so a redirect cannot escape the allowlist
        scheme, host, port, rule = _check(policy, method, current)
        if not rule.allow_nonpublic:
            _screen_addresses(host, port)
        if first_host is None:
            first_host = host
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
        if host != first_host:
            # credentials never survive a change of host: a token for the API must not follow
            # a redirect to the CDN (the redirect URL carries its own authorization)
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


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        conn = self.request
        try:
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
            reply = self._respond(conn, payload)
            if reply is not None:
                _send_frame(conn, reply)
        except OSError:                  # client went away mid-frame
            return

    def _respond(self, conn: socket.socket, payload: bytes) -> bytes | None:
        """The framed reply, or None when the client is gone and nobody is left to read it."""
        method, url = "?", "?"
        try:
            req = json.loads(payload)
            method = str(req.get("method", "GET")).upper()
            url = req["url"]
            body = (base64.b64decode(req["body_b64"])
                    if req.get("body_b64") else None)
            timeout = float(req["timeout"]) if req.get("timeout") else None
            result = _execute(self.server.policy, self.server.tls, conn,
                              method, url, req.get("headers"), body, timeout)
            return json.dumps({"ok": True, **result}).encode()
        except ClientGone:
            log.info("ABORT %s %s :: client disconnected; upstream connection closed",
                     method, url)
            return None
        except BrokerError as exc:
            tag = "DENY" if exc.code == "policy_denied" else "FAIL"
            log.info("%s  %s %s :: %s", tag, method, url, exc)
            return json.dumps({"ok": False, "error": exc.code,
                               "detail": str(exc)}).encode()
        except Exception as exc:
            log.warning("ERROR %s %s :: %s: %s", method, url, type(exc).__name__, exc)
            return json.dumps({"ok": False, "error": "broker_error",
                               "detail": f"{type(exc).__name__}: {exc}"}).encode()


class _Server(socketserver.ThreadingUnixStreamServer):
    """One thread per connection; one connection is one request."""

    daemon_threads = True

    def __init__(self, socket_path: str, policy: Policy):
        self.policy = policy
        self.tls = _tls_context()
        super().__init__(socket_path, _Handler)


def build_server(socket_path: str | os.PathLike[str], policy: Policy) -> _Server:
    """A broker server on *socket_path*, enforcing *policy*'s ``network`` rules. The caller
    runs it (``serve_forever`` on a thread) for the lifetime of one confined program and
    tears it down after. The socket is created mode 0600 in a 0700 directory: filesystem
    permission is the authentication."""
    path = os.fspath(socket_path)
    sock_dir = os.path.dirname(path)
    if sock_dir:
        os.makedirs(sock_dir, mode=0o700, exist_ok=True)
        os.chmod(sock_dir, 0o700)
    if os.path.exists(path):
        os.unlink(path)
    old_umask = os.umask(0o177)
    try:
        return _Server(path, policy)
    finally:
        os.umask(old_umask)


def request(
    socket_path: str | os.PathLike[str],
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: float | None = None,
) -> dict:
    """One brokered request: the client half of the wire protocol, as the runtime half of
    ``certora.network`` will speak it. Closing the socket (a timeout, an exception in the
    caller) is what cancels the request broker-side."""
    payload: dict = {"method": method, "url": url}
    if headers:
        payload["headers"] = dict(headers)
    if body is not None:
        payload["body_b64"] = base64.b64encode(body).decode("ascii")
    if timeout is not None:
        payload["timeout"] = timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(os.fspath(socket_path))
        _send_frame(s, json.dumps(payload).encode())
        header = _recv_exact(s, 4)
        if header is None:
            raise BrokerError("broker closed the connection")
        (length,) = struct.unpack("!I", header)
        frame = _recv_exact(s, length)
        if frame is None:
            raise BrokerError("broker closed mid-frame")
    return json.loads(frame)
