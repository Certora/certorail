#!/usr/bin/env python3
"""The testbed's local API, on 127.0.0.1:8765 and :8766 (the same handler on both, so a redirect
from one to the other changes origin by port alone). Standard library only; run.py starts it for
the network probes, or run it by hand:

    python3 serve.py

  GET /pub/hello.txt    text
  GET /pub/branch.json  {"name": "feature-x"}: what the provenance probe extracts
  GET /private/note     text no rule's path admits
  GET /hop-same         302 to /headers on the same origin: request headers survive
  GET /hop-port         302 to http://127.0.0.1:8766/headers: another origin, credentials dropped
  GET /hop-private      302 to /private/note: a hop the broker must refuse (no rule's path)
  GET /hop-percent      302 to /pub/%2e%2e/private/note: a hop whose path has no location
  GET /headers          the request's headers as JSON, names lowercased
"""
import http.server
import json
import sys
import threading

PORTS = (8765, 8766)
OTHER = "http://127.0.0.1:8766/headers"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        match self.path:
            case "/pub/hello.txt":
                self.reply(200, "text/plain", b"hello from the api\n")
            case "/pub/branch.json":
                self.reply(200, "application/json", json.dumps({"name": "feature-x"}).encode())
            case "/private/note":
                self.reply(200, "text/plain", b"no rule admits this path\n")
            case "/hop-same":
                self.redirect("/headers")
            case "/hop-port":
                self.redirect(OTHER)
            case "/hop-private":
                self.redirect("/private/note")
            case "/hop-percent":
                self.redirect("/pub/%2e%2e/private/note")
            case "/headers":
                headers = {k.lower(): v for k, v in self.headers.items()}
                self.reply(200, "application/json", json.dumps(headers, sort_keys=True).encode())
            case _:
                self.reply(404, "text/plain", f"no such testbed path: {self.path}\n".encode())

    def reply(self, status: int, kind: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        sys.stderr.write(f"serve.py [{self.server.server_address[1]}] {format % args}\n")


def main() -> int:
    servers = [http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler) for port in PORTS]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"serving on {', '.join(f'127.0.0.1:{p}' for p in PORTS)}", flush=True)
    try:
        servers[0].serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
