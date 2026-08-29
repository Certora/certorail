"""The host: analyse a program, evaluate the security policy, rewrite, run.

    certorail program.py [--root DIR] [--policy policy.py] [--check] [-- ARG ...]

(``certorail`` is the ``[project.scripts]`` entry point, installed by ``uv tool install .``;
``python -m certorail.host`` is the same thing.)

1. ``walker.analyze``: the lexical rules and the dataflow. Any violation, or any sink whose
   location is not proven, rejects the program with the messages.
2. ``Policy.evaluate``: every proven sink and every ``certora.exec`` against the policy. Any
   denial rejects the program.
3. ``rewrite``: ``assert`` hardened, ``@certora.checked`` on contracted functions.
4. Run: the rewritten source in a fresh interpreter (``-I -P``: no environment, no cwd on
   ``sys.path``) with the sandbox root as cwd, ``certora`` bound to ``certorail.markers`` and
   ``sys.argv`` set to the program's arguments.

The policy file is trusted Python defining ``POLICY`` (a ``certorail.policy.Policy``); without one,
``policy.DEFAULT_POLICY`` applies: read, write and list anywhere within the root, and ``git``/``gh``
with a cwd within the root. Exit status: the program's own when it ran; 1 when rejected; 2 when the
program does not parse.
"""
import argparse
import ast
import pathlib
import runpy
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field

from .policy import DEFAULT_POLICY, Denial, Policy
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


def check(source: str, filename: str, policy: Policy) -> Accepted | Rejected:
    """Analyse and evaluate; on success, the program as it will run. Raises ``SyntaxError``."""
    tree = ast.parse(source, filename)
    report = analyze(source, filename)
    if report.violations:
        return Rejected(report, violations=report.violations)
    denials = policy.evaluate(report)  # includes sinks whose location is not proven
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
import sys
program, filename, *args = sys.argv[1:]
sys.path.insert(0, __CERTORAIL_PARENT__)
import certorail.markers
with open(program, encoding="utf-8") as f:
    source = f.read()
sys.argv = [filename, *args]
namespace = {"__name__": "__main__", "__file__": filename, "certora": certorail.markers}
exec(compile(source, filename, "exec"), namespace)
'''


def run(
    source: str,
    filename: str,
    policy: Policy,
    root: pathlib.Path,
    args: Sequence[str] = (),
    python: str = sys.executable,
) -> subprocess.CompletedProcess[bytes] | Rejected:
    outcome = check(source, filename, policy)
    if isinstance(outcome, Rejected):
        return outcome
    certorail_parent = str(pathlib.Path(__file__).resolve().parent.parent)
    bootstrap = _BOOTSTRAP.replace("__CERTORAIL_PARENT__", repr(certorail_parent))
    with tempfile.TemporaryDirectory(prefix="certorail_") as tmp:
        program = pathlib.Path(tmp) / pathlib.Path(filename).name
        program.write_text(outcome.source, encoding="utf-8")
        return subprocess.run(
            [python, "-I", "-P", "-c", bootstrap, str(program), filename, *args],
            cwd=root,
            check=False,
        )


def load_policy(path: pathlib.Path | None) -> Policy:
    if path is None:
        return DEFAULT_POLICY
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
    parser.add_argument("--policy", type=pathlib.Path, default=None, help="a Python file defining POLICY (default: the built-in policy)")
    parser.add_argument("--check", action="store_true", help="analyse and evaluate only; do not run")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="arguments for the program (after --)")
    ns = parser.parse_args(argv)

    filename = str(ns.program)
    policy = load_policy(ns.policy)
    args = ns.args[1:] if ns.args[:1] == ["--"] else ns.args
    try:
        source = ns.program.read_text(encoding="utf-8")
        if ns.check:
            outcome: Accepted | Rejected | subprocess.CompletedProcess[bytes] = check(source, filename, policy)
        else:
            outcome = run(source, filename, policy, ns.root.resolve(), args)
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
