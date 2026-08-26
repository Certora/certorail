"""tsp_typed_ast — a synchronous typed-AST reader backed by any TSP server.

    import ast
    from tsp_typed_ast import typed_ast

    with typed_ast('x = [i * 2 for i in range(3)]') as reader:
        for node in ast.walk(reader.tree):
            if isinstance(node, ast.expr):
                print(ast.dump(node), '->', reader.type_of(node))

`reader.tree` is a stdlib `ast` tree parsed from your source; `type_of()`
accepts any node carrying position attributes (every `ast.expr` does) and
returns a `TypeInfo` wrapping the server's structured type object, or None
when the server has no answer for that range. Nodes from a tree you parsed
yourself work too, as long as it was parsed from the *same source string*.

Engines (anything speaking the Type Server Protocol over stdio):
    typed_ast(src)                                    # default: pyrefly tsp
    typed_ast(src, server=("node", "pyright-typeserver.js", "--stdio"))

Blocking by construction: one subprocess, request/response over pipes, no
event loop. (A daemon thread drains the server's stderr purely so crash
messages survive into exceptions; it never touches the API.)

Known limits: TSP is 0.x and may break between engine releases; one RPC per
distinct node range (memoized); the source is sent as an in-memory LSP
document, so nothing is written to disk.
"""
from __future__ import annotations

import ast
import collections
import json
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path

__all__ = ["typed_ast", "TypedAstReader", "TypeInfo", "TSPError"]

KIND = {0: "BuiltIn", 1: "Declared", 2: "Function", 3: "Class", 4: "Union",
        5: "Module", 6: "TypeVar", 7: "Overloaded", 8: "Synthesized", 9: "TypeRef"}


class TSPError(RuntimeError):
    """The type server misbehaved (died, spoke garbage, refused the handshake)."""


class TypeInfo:
    """A structured type answer. `.raw` is the server's full JSON object."""

    __slots__ = ("raw",)

    def __init__(self, raw: dict):
        self.raw = raw

    @property
    def kind(self) -> int | None:
        return self.raw.get("kind")

    @property
    def kind_name(self) -> str:
        return KIND.get(self.kind, f"?{self.kind}")

    @property
    def name(self) -> str | None:
        decl = self.raw.get("declaration") or {}
        return self.raw.get("name") or decl.get("name")

    @property
    def literal(self):
        return self.raw.get("literalValue")

    @property
    def type_args(self) -> list["TypeInfo"]:
        return [TypeInfo(a) for a in (self.raw.get("typeArgs") or [])]

    @property
    def return_type(self) -> "TypeInfo | None":
        rt = self.raw.get("returnType")
        return TypeInfo(rt) if rt else None

    @property
    def declaration(self) -> dict | None:
        """Where this type is declared: {'name', 'node': {'uri', 'range'}, ...}."""
        return self.raw.get("declaration")

    def render(self) -> str:
        name = self.name or self.kind_name
        if self.kind == 2:  # Function
            rt = self.return_type
            return f"def {name}(…) -> {rt.render() if rt else '?'}"
        if self.literal is not None:
            name += f" = Literal[{self.literal!r}]"
        if self.raw.get("typeArgs"):
            name += "[" + ", ".join(a.render() for a in self.type_args) + "]"
        return name

    __str__ = render

    def __repr__(self):
        return f"<TypeInfo {self.render()}>"


class TypedAstReader:
    def __init__(self, source: str, *, server=("pyrefly", "tsp"),
                 filename: str = "source.py"):
        self.source = source
        self.tree: ast.Module = ast.parse(source)  # fail fast on syntax errors
        self._server_cmd = list(server)
        self._filename = filename
        # ast col offsets are UTF-8 *byte* offsets; TSP wants UTF-16 code units.
        self._line_bytes = [ln.encode("utf-8") for ln in source.splitlines()]
        self._proc = None
        self._tmpdir = None
        self._stderr_tail = collections.deque(maxlen=40)
        self._cache: dict[tuple, TypeInfo | None] = {}
        self._next_id = 0
        self.protocol_version: str | None = None
        self.snapshot = None

    # -- wire plumbing -------------------------------------------------------
    def _send(self, msg: dict):
        data = json.dumps(msg).encode()
        self._proc.stdin.write(b"Content-Length: %d\r\n\r\n%s" % (len(data), data))
        self._proc.stdin.flush()

    def _read_msg(self) -> dict:
        headers = {}
        while True:
            line = self._proc.stdout.readline()
            if not line:
                raise TSPError(
                    f"type server exited (code {self._proc.poll()}); stderr tail:\n"
                    + "".join(self._stderr_tail))
            if line in (b"\r\n", b"\n"):
                break
            key, val = line.decode().split(":", 1)
            headers[key.strip().lower()] = val.strip()
        return json.loads(self._proc.stdout.read(int(headers["content-length"])))

    def _notify(self, method: str, params: dict | None = None):
        self._send({"jsonrpc": "2.0", "method": method,
                    **({"params": params} if params is not None else {})})

    def _request(self, method: str, params: dict | None = None):
        self._next_id += 1
        rid = self._next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                    **({"params": params} if params is not None else {})})
        while True:
            msg = self._read_msg()
            if msg.get("id") == rid and ("result" in msg or "error" in msg):
                if "error" in msg:
                    raise TSPError(f"{method} failed: {msg['error']}")
                return msg["result"]
            if "method" in msg and "id" in msg:  # server -> client request
                result = None
                if msg["method"] == "workspace/configuration":
                    result = [{}] * len(msg["params"]["items"])
                self._send({"jsonrpc": "2.0", "id": msg["id"], "result": result})
            # notifications (diagnostics, logs) are dropped

    # -- lifecycle -----------------------------------------------------------
    def __enter__(self) -> "TypedAstReader":
        # Real (empty) temp dir as workspace root so servers that peek at the
        # root for config don't trip; the document itself stays in memory.
        self._tmpdir = tempfile.mkdtemp(prefix="tsp_typed_ast_")
        root = Path(self._tmpdir)
        self._uri = (root / f"{uuid.uuid4().hex}_{self._filename}").as_uri()

        self._proc = subprocess.Popen(
            self._server_cmd, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        threading.Thread(target=self._drain_stderr, daemon=True).start()

        self._request("initialize", {"processId": None,
                                     "rootUri": root.as_uri(),
                                     "capabilities": {}})
        self._notify("initialized", {})
        self._notify("textDocument/didOpen", {"textDocument": {
            "uri": self._uri, "languageId": "python",
            "version": 1, "text": self.source}})
        self.protocol_version = self._request("typeServer/getSupportedProtocolVersion")
        self.snapshot = self._request("typeServer/getSnapshot")
        return self

    def _drain_stderr(self):
        for line in self._proc.stderr:
            self._stderr_tail.append(line.decode(errors="replace"))

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            self._proc.wait(timeout=2)
        except Exception:
            self._proc.kill()
        finally:
            self._proc = None
            if self._tmpdir:
                try:
                    Path(self._tmpdir).rmdir()
                except OSError:
                    pass

    # -- the point of it all -------------------------------------------------
    def _utf16_col(self, line0: int, byte_col: int) -> int:
        line = self._line_bytes[line0]
        return len(line[:byte_col].decode("utf-8").encode("utf-16-le")) // 2

    def type_of(self, node: ast.AST) -> TypeInfo | None:
        """Structured type of `node`, or None if the server has no answer."""
        if self._proc is None:
            raise TSPError("reader is closed (use inside the `with` block)")
        if getattr(node, "lineno", None) is None:
            raise ValueError(f"{type(node).__name__} carries no source position")
        key = (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
        if key not in self._cache:
            rng = {"start": {"line": node.lineno - 1,
                             "character": self._utf16_col(node.lineno - 1,
                                                          node.col_offset)},
                   "end": {"line": node.end_lineno - 1,
                           "character": self._utf16_col(node.end_lineno - 1,
                                                        node.end_col_offset)}}
            raw = self._request("typeServer/getComputedType",
                                {"arg": {"uri": self._uri, "range": rng},
                                 "snapshot": self.snapshot})
            self._cache[key] = TypeInfo(raw) if raw is not None else None
        return self._cache[key]



def typed_ast(source: str, *, server=("pyrefly", "tsp"),
              filename: str = "source.py") -> TypedAstReader:
    """`with typed_ast(src) as reader: reader.type_of(node)` — see module docs."""
    return TypedAstReader(source, server=server, filename=filename)