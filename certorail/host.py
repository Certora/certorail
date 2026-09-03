"""The host: analyse a program, evaluate the security policy, rewrite, run -- jailed.

    certorail program.py [--root DIR] [--policy policy.py] [--check] [--no-jail] [-- ARG ...]

(``certorail`` is the ``[project.scripts]`` entry point, installed by ``uv tool install .``;
``python -m certorail.host`` is the same thing.)

1. ``walker.analyze``: the lexical rules and the dataflow. Any violation, or any sink whose
   location is not proven, rejects the program with the messages.
2. ``Policy.evaluate``: every proven sink and every ``certora.exec`` against the policy. Any
   denial rejects the program.
3. ``rewrite``: ``assert`` hardened, ``@certora.checked`` on contracted functions.
4. Run: the rewritten source in a fresh interpreter (``-I -P``: no environment, no cwd on
   ``sys.path``) with the sandbox root as cwd, ``certora`` bound to ``certorail.markers`` and
   ``sys.argv`` set to the program's arguments -- wrapped, when ``srt`` (sandbox-runtime) is
   installed, in an OS jail: no network, writes confined to the root, the broker's unix
   socket as the single door out. The static analysis is the primary confinement; the jail
   is where anything it missed goes to die. Without srt the run proceeds with a loud
   warning (or quietly with ``--no-jail``).

The policy file is trusted Python defining ``POLICY`` (a ``certorail.policy.Policy``); without one,
``policy.DEFAULT_POLICY`` applies: read, write and list anywhere within the root, and ``git``/``gh``
with a cwd within the root. Exit status: the program's own when it ran; 1 when rejected; 2 when the
program does not parse.
"""
import argparse
import ast
import json
import os
import pathlib
import runpy
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field

from .analysis import Named, StaticPath
from .broker import build_server
from .policy import DEFAULT_POLICY, Denial, Policy
from .policyfile import PolicyFileError, load_policy_file
from .rewrite import rewrite
from .safepy import FunctionAnalysis
from .walker import Report, analyze, describe_sink, where


@dataclass(frozen=True)
class Rejected:
    report: Report
    violations: list[tuple[ast.AST, str]] = field(default_factory=list)
    denials: list[Denial] = field(default_factory=list)

    def describe(self, filename: str) -> list[str]:
        lines = [f"{where(filename, node)}: violation: {what}" for node, what in self.violations]
        lines += [
            f"{where(filename, d.site.node)}: denied: {d.site.what}: {d.reason}" for d in self.denials
        ]
        return lines


@dataclass(frozen=True)
class Accepted:
    report: Report
    source: str  # the rewritten program

    def describe(self, filename: str) -> list[str]:
        return [f"{where(filename, s.node)}: {s.what}: {describe_sink(s)}" for s in self.report.sinks]


def check(
    source: str, filename: str, policy: Policy, root: pathlib.Path | None = None
) -> Accepted | Rejected:
    """Analyse and evaluate; on success, the program as it will run. Raises ``SyntaxError``.

    With *root*, the policy's literal checkers may run (under it) to discharge pure atoms on
    statically-known text; without it, only regex-defined atoms are discharged statically."""
    tree = ast.parse(source, filename)
    discharge = None if root is None else policy.discharger(root)
    report = analyze(source, filename, policy.vocabulary(), discharge)
    if report.violations:
        return Rejected(report, violations=report.violations)
    denials = policy.evaluate(report, discharge)  # includes sinks whose location is not proven
    if denials:
        return Rejected(report, denials=denials)
    functions = FunctionAnalysis()
    functions.visit(tree)
    contracted = {
        name for name, (_, contract) in functions.contracts.items()
        if contract.params or contract.returns is not None
    }
    return Accepted(report, rewrite(tree, contracted))


# The child interpreter: bind the marker namespace, set argv, run the program as __main__.
_BOOTSTRAP = r'''
import os
import sys
program, filename, *args = sys.argv[1:]
sys.path.insert(0, __CERTORAIL_PARENT__)
import certorail.markers
if os.environ.get("CERTORAIL_SELF_JAIL"):
    import certorail.selfjail
    warning = certorail.selfjail.deny_process_creation()
    if warning is not None:
        print("certorail: process-creation denial not installed: " + warning, file=sys.stderr)
with open(program, encoding="utf-8") as f:
    source = f.read()
sys.argv = [filename, *args]
namespace = {"__name__": "__main__", "__file__": filename, "certora": certorail.markers}
exec(compile(source, filename, "exec"), namespace)
'''


def _jail_write_paths(policy: Policy, root: pathlib.Path, tmp: pathlib.Path) -> list[str]:
    """The jail's write allowance: the sandbox root and the run's scratch dir -- which cover
    every root-relative write location -- plus the concrete prefix of every *absolute* write
    location the policy grants (a statically-approved ``/home/.../verisafe/**`` write must
    not die in the jail). Coarser than the policy on purpose: precision is the analysis'
    job, the jail is the backstop."""
    paths = [str(root), str(tmp)]
    for loc in policy.write:
        if not loc.absolute:
            continue
        parts = loc.path_components if isinstance(loc, StaticPath) else loc.static_prefix
        names = []
        for component in parts:
            if not isinstance(component, Named):
                break  # the concrete prefix ends at the first wildcard-ish component
            names.append(component.name)
        paths.append("/" + "/".join(names))
    return paths


def _srt_settings(
    policy: Policy, root: pathlib.Path, tmp: pathlib.Path, socket_path: pathlib.Path | None
) -> dict:
    """The srt (sandbox-runtime) profile for one confined run: no network at all -- the
    broker socket is the single door -- no local binding, and writes confined to the
    policy's write surface (``_jail_write_paths``). Reads stay default-allowed: the
    interpreter needs its stdlib from everywhere, and read confinement is the static
    analysis' stronger half anyway."""
    return {
        "network": {
            "allowedDomains": [],
            "allowLocalBinding": False,
            "allowUnixSockets": [str(socket_path)] if socket_path is not None else [],
        },
        "filesystem": {
            "allowWrite": _jail_write_paths(policy, root, tmp),
        },
    }


def run(
    source: str,
    filename: str,
    policy: Policy,
    root: pathlib.Path,
    args: Sequence[str] = (),
    python: str = sys.executable,
    jail: bool = True,
) -> subprocess.CompletedProcess[bytes] | Rejected:
    outcome = check(source, filename, policy, root)
    if isinstance(outcome, Rejected):
        return outcome
    certorail_parent = str(pathlib.Path(__file__).resolve().parent.parent)
    # the runtime halves of check/exec/network all live in the broker: the confined program
    # never sees the policy, only the socket
    bootstrap = _BOOTSTRAP.replace("__CERTORAIL_PARENT__", repr(certorail_parent))
    with tempfile.TemporaryDirectory(prefix="certorail_") as tmp:
        tmpdir = pathlib.Path(tmp)
        program = tmpdir / pathlib.Path(filename).name
        program.write_text(outcome.source, encoding="utf-8")
        # the bootstrap goes to a file rather than -c so the jailed command line stays
        # trivially quotable
        boot = tmpdir / "_bootstrap.py"
        boot.write_text(bootstrap, encoding="utf-8")
        env = dict(os.environ)
        server = None
        socket_path = None
        if policy.network or policy.programs or policy.validations:
            # the broker: the single, policy-enforcing hole in the wall -- network requests,
            # exec'd children and check evaluators alike -- for the lifetime of this one
            # program (broker.py). The child finds it by env var.
            socket_path = tmpdir / "broker.sock"
            server = build_server(socket_path, policy, root)
            threading.Thread(
                target=server.serve_forever, name="certorail-broker", daemon=True
            ).start()
            env["CERTORAIL_BROKER_SOCKET"] = str(socket_path)
        if jail:
            # the self-jail: process creation denied from inside (seccomp / sandbox_init),
            # since srt restricts reach, not operations. Everything the program may
            # legitimately do to the world goes through the broker socket.
            env["CERTORAIL_SELF_JAIL"] = "1"
        command = [python, "-I", "-P", str(boot), str(program), filename, *args]
        if jail:
            srt = shutil.which("srt")
            if srt is None:
                print(
                    "certorail: srt not found: running WITHOUT the OS jail "
                    "(npm install -g @anthropic-ai/sandbox-runtime; or pass --no-jail "
                    "to accept this)",
                    file=sys.stderr,
                )
            else:
                settings = tmpdir / "srt-settings.json"
                settings.write_text(
                    json.dumps(_srt_settings(policy, root, tmpdir, socket_path), indent=2),
                    encoding="utf-8",
                )
                # srt takes the confined command as one shell-quoted string
                command = [srt, "--settings", str(settings), shlex.join(command)]
        try:
            return subprocess.run(command, cwd=root, env=env, check=False)
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()


def load_policy(path: pathlib.Path | None) -> Policy:
    if path is None:
        return DEFAULT_POLICY
    if path.suffix in (".toml", ".json"):
        try:
            return load_policy_file(path)
        except PolicyFileError as e:
            raise SystemExit(str(e))
    namespace = runpy.run_path(str(path))
    policy = namespace.get("POLICY")
    if not isinstance(policy, Policy):
        raise SystemExit(f"{path}: expected POLICY to be a certorail.policy.Policy")
    return policy


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="certorail", description="Analyse a program, check it against a policy, and run it."
    )
    parser.add_argument("program", type=pathlib.Path, help="the Python source file")
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd(), help="the sandbox root (cwd of the program)")
    parser.add_argument("--policy", type=pathlib.Path, default=None, help="a policy: a .toml/.json document, or a Python file defining POLICY (default: the built-in policy)")
    parser.add_argument("--check", action="store_true", help="analyse and evaluate only; do not run")
    parser.add_argument(
        "--no-jail",
        action="store_true",
        help="run without the srt OS jail (the static analysis and the broker still apply)",
    )
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments for the program (after --)")
    ns = parser.parse_args(argv)

    filename = str(ns.program)
    policy = load_policy(ns.policy)
    args = ns.args[1:] if ns.args[:1] == ["--"] else ns.args
    try:
        source = ns.program.read_text(encoding="utf-8")
        if ns.check:
            outcome: Accepted | Rejected | subprocess.CompletedProcess[bytes] = check(
                source, filename, policy, ns.root.resolve()
            )
        else:
            outcome = run(
                source, filename, policy, ns.root.resolve(), args, jail=not ns.no_jail
            )
    except SyntaxError as e:
        print(f"{filename}:{e.lineno}: syntax error: {e.msg}", file=sys.stderr)
        return 2

    match outcome:
        case Rejected():
            print(f"{filename}: rejected", file=sys.stderr)
            for line in outcome.describe(filename):
                print(line, file=sys.stderr)
            return 1
        case Accepted():
            print(f"{filename}: accepted")
            for line in outcome.describe(filename):
                print(line)
            return 0
        case _:
            return outcome.returncode


if __name__ == "__main__":
    sys.exit(main())
