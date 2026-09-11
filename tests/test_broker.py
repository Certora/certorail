"""End-to-end tests for the network broker: local HTTP origins, a policy with ``network``
rules, and the framed-JSON protocol over a real Unix socket.

Two origins on loopback play distinct "hosts" by being addressed as ``localhost`` and
``127.0.0.1``: same interface, different names, which is what the cross-host credential
stripping keys on.
"""
import base64
import http.server
import os
import pathlib
import tempfile
import threading
import unittest

from certorail import markers
from certorail.broker import build_server, exec_request, request
from certorail.policy import Policy, atom, constraint, network, param, program, pure, splice, validation, waived
from certorail.templates import Each


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
            case "/bounce-bad":
                self._reply(302, headers=[("Location", "/big")])
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


class TestBrokerRequires(unittest.TestCase):
    """A rule's ``requires`` atoms are re-discharged from the URL text on every hop: a
    redirect the analysis never saw meets the same bar as the first request."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
        cls.port = cls.origin.server_address[1]
        threading.Thread(target=cls.origin.serve_forever, daemon=True).start()
        policy = Policy.allow(
            atoms=[
                atom(
                    "ok-path",
                    markers.matches(rf"http://localhost:{cls.port}/(ok|bounce|bounce-bad)"),
                )
            ],
            network=[
                network("localhost", schemes=["http"], ports=[cls.port],
                        allow_nonpublic=True, requires=["ok-path"])
            ],
        )
        cls.sock = os.path.join(tempfile.mkdtemp(), "broker.sock")
        cls.server = build_server(cls.sock, policy)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.origin.shutdown()

    def test_a_discharged_url_is_allowed(self) -> None:
        reply = request(self.sock, "GET", f"http://localhost:{self.port}/ok")
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(_body(reply), b"hello")

    def test_an_undischarged_url_is_denied(self) -> None:
        reply = request(self.sock, "GET", f"http://localhost:{self.port}/big")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")
        self.assertIn("not validated by: ok-path", reply["detail"])

    def test_a_redirect_hop_meets_the_same_bar(self) -> None:
        # /bounce carries the atom and lands on /ok, which also carries it
        reply = request(self.sock, "GET", f"http://localhost:{self.port}/bounce")
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(_body(reply), b"hello")
        # /bounce-bad itself carries the atom, but it hops to /big, which does not: the
        # hop -- a URL the static analysis never saw -- is refused
        reply = request(self.sock, "GET", f"http://localhost:{self.port}/bounce-bad")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")
        self.assertIn("not validated by: ok-path", reply["detail"])


class TestBrokerRedirectModes(unittest.TestCase):
    """Non-textual atoms: "stop" (the default for them) refuses hops outright; "waive" asks
    nothing of them. Either way the initial request rides on its static proof."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Origin)
        cls.port = cls.origin.server_address[1]
        threading.Thread(target=cls.origin.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.origin.shutdown()

    def _broker(self, requires) -> str:
        policy = Policy.allow(
            validations=[
                validation(
                    "vetting",
                    argv=("vet", param("value")),
                    params=("value",),
                    establishes={"value": [pure("vetted")]},
                )
            ],
            network=[
                network("localhost", schemes=["http"], ports=[self.port],
                        allow_nonpublic=True, requires=requires)
            ],
        )
        sock = os.path.join(tempfile.mkdtemp(), "broker.sock")
        server = build_server(sock, policy)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return sock

    def test_a_stop_atom_permits_the_initial_request(self) -> None:
        sock = self._broker(["vetted"])  # non-textual: redirects default to "stop"
        reply = request(sock, "GET", f"http://localhost:{self.port}/ok")
        self.assertTrue(reply["ok"], reply)

    def test_a_stop_atom_refuses_redirect_hops(self) -> None:
        sock = self._broker(["vetted"])
        reply = request(sock, "GET", f"http://localhost:{self.port}/bounce")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")
        self.assertIn("cannot vouch", reply["detail"])

    def test_a_waived_atom_lets_redirects_through(self) -> None:
        sock = self._broker([waived("vetted")])
        reply = request(sock, "GET", f"http://localhost:{self.port}/bounce")
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(_body(reply), b"hello")


class TestBrokerExec(unittest.TestCase):
    """The exec tunnel: the broker re-checks the decidable half of the exec rules, spawns the
    child host-side, and returns the drained output wholesale."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.root = pathlib.Path(tempfile.mkdtemp())
        (cls.root / "repos" / "x").mkdir(parents=True)
        policy = Policy.allow(
            programs=[
                program(
                    "echo", cwd=markers.within("."), argv=["echo", splice("WORDS")],
                    holes={"WORDS": Each(constraint(any=True))},
                ),
                program("pwd", cwd=markers.within("repos")),
                program("git", subcommand="log", cwd=markers.within("repos")),
            ],
        )
        cls.sock = os.path.join(tempfile.mkdtemp(), "broker.sock")
        cls.server = build_server(cls.sock, policy, cls.root)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_an_allowed_program_runs_and_returns_output(self) -> None:
        reply = exec_request(self.sock, "echo", ["hi"], cwd=".")
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["returncode"], 0)
        self.assertEqual(base64.b64decode(reply["stdout_b64"]), b"hi\n")

    def test_an_unlisted_program_is_denied_unspawned(self) -> None:
        reply = exec_request(self.sock, "rm", ["-rf", "everything"], cwd=".")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")
        self.assertIn("not permitted", reply["detail"])

    def test_subcommands_fail_closed(self) -> None:
        reply = exec_request(self.sock, "git", ["status"], cwd="repos/x")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")
        self.assertIn("fail closed", reply["detail"])

    def test_cwd_containment(self) -> None:
        reply = exec_request(self.sock, "pwd", [], cwd=".")
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"], "policy_denied")
        self.assertIn("not within", reply["detail"])

    def test_a_relative_cwd_resolves_against_the_root(self) -> None:
        reply = exec_request(self.sock, "pwd", [], cwd="repos/x")
        self.assertTrue(reply["ok"], reply)
        out = base64.b64decode(reply["stdout_b64"]).decode().strip()
        self.assertTrue(out.endswith("repos/x"), out)

    def test_markers_exec_round_trip(self) -> None:
        os.environ["CERTORAIL_BROKER_SOCKET"] = self.sock
        self.addCleanup(os.environ.pop, "CERTORAIL_BROKER_SOCKET", None)
        result = markers.exec("echo", "hi there", cwd=".")
        self.assertIsInstance(result, markers.ExecResult)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"hi there\n")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.args, ["echo", "hi there"])
        self.assertEqual(result.stdout_lines(), ["hi there"])
        self.assertEqual(result.stderr_string(), "")


class TestExecResult(unittest.TestCase):
    """The decoded views on an exec's result: text and lines of a successful child, a loud
    ``CalledProcessError`` for a failed one."""

    def test_the_views_of_a_success(self) -> None:
        r = markers.ExecResult(["git", "log"], 0, b"a\r\nb\n\xff\n", b"warn\n")
        self.assertEqual(r.stdout_string(), "a\r\nb\n�\n")
        self.assertEqual(r.stdout_lines(), ["a", "b", "�"])
        self.assertEqual(r.stderr_lines(), ["warn"])
        self.assertEqual(r.stderr_string(), "warn\n")

    def test_a_failure_raises_from_every_view(self) -> None:
        r = markers.ExecResult(["git", "log"], 128, b"partial\n", b"fatal: not a repo\n")
        for view in (r.stdout_string, r.stdout_lines, r.stderr_string, r.stderr_lines):
            with self.subTest(view=view.__name__), self.assertRaises(markers.CalledProcessError) as cm:
                view()
            self.assertEqual(cm.exception.returncode, 128)
            self.assertEqual(cm.exception.stderr, b"fatal: not a repo\n")
        # the raw CompletedProcess surface stays available for handling failure by hand
        self.assertEqual(r.returncode, 128)
        self.assertEqual(r.stdout, b"partial\n")


if __name__ == "__main__":
    unittest.main()
