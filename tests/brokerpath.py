"""Test scaffolding: the broker behind a *named* Unix socket, one connection per request, and
plain client helpers for it. The host never creates a socket path any more -- it hands the
program one end of a socketpair (``host._run``) -- but tests want to drive one broker from the
same process through several client calls, and to point the markers' runtime half at a broker
over the inherited-descriptor channel it expects (``channel``)."""
import base64
import json
import os
import pathlib
import socket
import socketserver
import struct
import threading
from collections.abc import Sequence

from certorail.broker import Broker, BrokerError, _recv_exact, _send_frame, build_broker
from certorail.policy import Policy


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        assert isinstance(self.server, PathServer)
        self.server.broker.serve(self.request)


class PathServer(socketserver.ThreadingUnixStreamServer):
    """One thread per connection, each served by the same broker until the client hangs up."""

    daemon_threads = True

    def __init__(self, socket_path: str, broker: Broker):
        self.broker = broker
        super().__init__(socket_path, _Handler)


def build_server(
    socket_path: str | os.PathLike[str],
    policy: Policy,
    root: str | os.PathLike[str] | None = None,
    stream_to: tuple[int, int] | None = None,
    view: pathlib.Path | None = None,
) -> PathServer:
    path = os.fspath(socket_path)
    if os.path.exists(path):
        os.unlink(path)
    return PathServer(path, build_broker(policy, root, stream_to, view))


def channel(broker: Broker) -> socket.socket:
    """A socketpair served by *broker* on a daemon thread; the returned end is the program's, to
    be named in ``CERTORAIL_BROKER_FD``. The caller closes it when done."""
    host_end, program_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    threading.Thread(target=broker.serve, args=(host_end,), daemon=True).start()
    return program_end


def _roundtrip(socket_path: str | os.PathLike[str], payload: dict) -> dict:
    """One framed request-reply exchange over a fresh connection. Closing the socket (a
    timeout, an exception in the caller) is what cancels the request broker-side."""
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


def request(
    socket_path: str | os.PathLike[str],
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    body: bytes | None = None,
    timeout: float | None = None,
) -> dict:
    """One brokered network request: the client half of the wire protocol, as the runtime
    half of ``certora.network`` speaks it."""
    payload: dict = {"method": method, "url": url}
    if headers:
        payload["headers"] = dict(headers)
    if body is not None:
        payload["body_b64"] = base64.b64encode(body).decode("ascii")
    if timeout is not None:
        payload["timeout"] = timeout
    return _roundtrip(socket_path, payload)


def exec_request(
    socket_path: str | os.PathLike[str],
    program: str,
    arguments: Sequence[str] = (),
    *,
    cwd: str,
    kwargs: dict[str, str | list[str]] | None = None,
    stream: bool = False,
) -> dict:
    """One brokered exec: the client half of the exec tunnel, as ``certora.exec``'s runtime
    speaks it. *kwargs* bind the holes of a templated form; *stream* asks for the child's
    output on the host's terminal instead of in the reply."""
    return _roundtrip(socket_path, {
        "kind": "exec",
        "program": program,
        "arguments": list(arguments),
        "kwargs": dict(kwargs or {}),
        "cwd": cwd,
        "stream": stream,
    })
