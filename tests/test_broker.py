"""End-to-end tests for the network broker: local HTTP origins, a policy with ``network``
rules, and the framed-JSON protocol over a real Unix socket.

Two origins on loopback play distinct "hosts" by being addressed as ``localhost`` and
``127.0.0.1``: same interface, different names, which is what the cross-host credential
stripping keys on.
"""
import base64
import http.server
import os
import tempfile
import threading
import unittest

from certorail.broker import build_server, request
from certorail.policy import Policy, network


class _Origin(http.server.BaseHTTPRequestHandler):
    other_port = 0   # the second origin's port, for the cross-host redirect

    def log_message(self, *args) -> None:
        pass

    def _reply(self, status: int, body: bytes = b"", headers=()) -> None:
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        match self.path:
            case "/ok":
                self._reply(200, b"hello")
            case "/big":
                self._reply(200, b"x" * 4096)
            case "/auth":
                self._reply(200, b"auth" if self.headers.get("Authorization") else b"anon")
            case "/bounce":
                self._reply(302, headers=[("Location", "/ok")])
            case "/bounce-auth":
                self._reply(302, headers=[("Location", "/auth")])
            case "/hop":
                self._reply(302, headers=[
                    ("Location", f"http://127.0.0.1:{self.other_port}/auth")])
            case "/hop-unlisted":
                self._reply(302, headers=[
                    ("Location", f"http://127.0.0.1:{self.server.server_address[1]}/ok")])
            case _:
                self._reply(404)

    def do_POST(self) -> None:
        self._reply(200, b"posted")


def _body(reply: dict) -> bytes:
    return base64.b64decode(reply["body_b64"])


class TestBroker(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.origin1 = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
        cls.origin2 = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
        cls.p1 = cls.origin1.server_address[1]
        cls.p2 = cls.origin2.server_address[1]
        _Origin.other_port = cls.p2
        for origin in (cls.origin1, cls.origin2):
            threading.Thread(target=origin.serve_forever, daemon=True).start()

        policy = Policy.allow(network=[
            # "localhost" and "127.0.0.1" are distinct hosts to the policy (and to the
            # cross-host credential stripping), same loopback interface underneath
            network("localhost", schemes=["http"], ports=[cls.p1], methods=["GET"],
                    allow_nonpublic=True, max_response_bytes=1024),
            network("127.0.0.1", schemes=["http"], ports=[cls.p2], allow_nonpublic=True),
            # a literal loopback rule WITHOUT allow_nonpublic: the address screen must refuse
            network("127.0.0.1", schemes=["http"], ports=[cls.p1]),
        ])
        cls.sock = os.path.join(tempfile.mkdtemp(), "broker.sock")
        cls.server = build_server(cls.sock, policy)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.origin1.shutdown()
        cls.origin2.shutdown()

    def get(self, url: str, **kwargs) -> dict:
        return request(self.sock, "GET", url, **kwargs)

    def test_allowed_request(self) -> None:
        reply = self.get(f"http://localhost:{self.p1}/ok")
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["status"], 200)
        self.assertEqual(_body(reply), b"hello")

    def test_unlisted_host_is_denied(self) -> None:
        # localhost is allowed only on p1; 127.0.0.1 only on p2
        reply = self.get(f"http://localhost:{self.p2}/ok")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")

    def test_method_constraint(self) -> None:
        reply = request(self.sock, "POST", f"http://localhost:{self.p1}/ok")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")
        # the same method is fine where the rule does not constrain it
        reply = request(self.sock, "POST", f"http://127.0.0.1:{self.p2}/ok")
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(_body(reply), b"posted")

    def test_same_host_redirect_is_followed(self) -> None:
        reply = self.get(f"http://localhost:{self.p1}/bounce")
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(_body(reply), b"hello")
        self.assertTrue(reply["url"].endswith("/ok"))

    def test_same_host_redirect_keeps_credentials(self) -> None:
        reply = self.get(f"http://localhost:{self.p1}/bounce-auth",
                         headers={"Authorization": "token hunter2"})
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(_body(reply), b"auth")

    def test_cross_host_redirect_strips_credentials(self) -> None:
        reply = self.get(f"http://localhost:{self.p1}/hop",
                         headers={"Authorization": "token hunter2"})
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(_body(reply), b"anon")

    def test_redirect_hops_are_policy_checked(self) -> None:
        # /hop-unlisted redirects to 127.0.0.1:p1, which no nonpublic-permitting rule covers
        reply = self.get(f"http://localhost:{self.p1}/hop-unlisted")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")

    def test_response_size_cap(self) -> None:
        reply = self.get(f"http://localhost:{self.p1}/big")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "response_too_large")

    def test_nonpublic_screen(self) -> None:
        # the 127.0.0.1:p1 rule exists but does not set allow_nonpublic
        reply = self.get(f"http://127.0.0.1:{self.p1}/ok")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")
        self.assertIn("non-public", reply["detail"])


if __name__ == "__main__":
    unittest.main()
