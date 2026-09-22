"""The host: analyse a program, evaluate the security policy, rewrite, run -- jailed.

    certorail program.py [--root DIR] [--policy policy.py] [--check] [--no-jail] [-- ARG ...]
    certorail -c SOURCE  [same options]     # inline source: the agentic path

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

The policy is a TOML (or JSON) document (``policyfile``), given with ``--policy`` or discovered
ambiently for the root (``policydir``); without one, ``policyfile.default_policy`` applies: read,
write and list anywhere within the root, and no programs of its own. Either way the installed
base ruleset (``rulesets/base.toml``) is applied unless the policy says ``base = false``. Exit
status: the program's own when it ran; 1 when rejected; 2 when the program does not parse.
"""
import argparse
import ast
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field

from .analysis import Named, StaticPath
from .childjail import Mounts, View
from .viewdaemon import Attachment, ViewUnavailable, attach
from .broker import build_server, terminal_descriptors
from .describe import describe
from .policy import Denial, Policy, Program
from .policydir import AmbientPolicyError, find_policy
from .policyfile import BASE_RULESET, PolicyFileError, default_policy, load_policy_file
from .rewrite import rewrite
from .safepy import FunctionAnalysis
from .walker import Report, analyze, describe_sink, where


@dataclass(frozen=True)
class Rejected:
    report: Report
    violations: list[tuple[ast.AST, str]] = field(default_factory=list)
    denials: list[Denial] = field(default_factory=list)

    def describe(self, filename: str) -> list[str]:
        lines = reveal_lines(self.report, filename)
        lines += [f"{where(filename, node)}: violation: {what}" for node, what in self.violations]
        lines += [
            f"{where(filename, d.site.node)}: denied: {d.site.what}: {d.reason}" for d in self.denials
        ]
        return lines


def reveal_lines(report: Report, filename: str) -> list[str]:
    """What the program asked the analysis to show (``certora.reveal_fact``), first in any
    report: the reader wants the facts before the verdict they explain."""
    return [f"{where(filename, r.node)}: reveal: {r.name}: {r.fact}" for r in report.reveals]


@dataclass(frozen=True)
class Accepted:
    report: Report
    source: str  # the rewritten program

    def describe(self, filename: str) -> list[str]:
        return reveal_lines(self.report, filename) + [
            f"{where(filename, s.node)}: {s.what}: {describe_sink(s)}" for s in self.report.sinks
        ]


def check(
    source: str, filename: str, policy: Policy, root: pathlib.Path | None = None,
    view: pathlib.Path | None = None,
) -> Accepted | Rejected:
    """Analyse and evaluate; on success, the program as it will run. Raises ``SyntaxError``.

    With *root*, the policy's literal checkers may run (under it, a confined one through the
    FUSE *view* when attached) to discharge pure atoms on statically-known text; without it,
    only regex-defined atoms are discharged statically."""
    tree = ast.parse(source, filename)
    discharge = None if root is None else policy.discharger(root, view)
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
    location the policy grants (a statically-approved ``/srv/checkouts/**`` write must
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


def _jail_deny_paths(mounts: Mounts) -> list[str]:
    """The jail's write denials: every protected location (``no-write``) that is one concrete
    path, as ``fsview`` lowered it. A protection with a wildcard in it (``repos/**/.git``) is
    the analysis' alone: srt denies paths, not patterns."""
    return [str(p) for p in mounts.no_write]


def _attach_view(policy: Policy, root: pathlib.Path) -> Attachment | None:
    """The FUSE view of the root for this run, when a confined grant needs one (a root-relative
    pattern in the filesystem section that no bind expresses) and the host can serve it; None
    otherwise, with the reason on stderr when it was needed (MOUNTS.md, ``viewdaemon``)."""
    if not (policy.confines and policy.mounts(root).needs_view):
        return None
    try:
        attached = attach(policy.view_spec(root))
    except ViewUnavailable as e:
        print(f"certorail: the policy filesystem view cannot be served here ({e}):", file=sys.stderr)
        return None
    return attached  # a spawn is not news: `certorail view status` shows the daemons


def _announce_view(policy: Policy, root: pathlib.Path, view: pathlib.Path | None) -> None:
    """A confined grant's view is the policy's filesystem section as binds (or the FUSE view of
    the root, *view*), plus the rule's own mounts; whatever neither expresses is absent from it,
    and that is never silent (MOUNTS.md)."""
    if not policy.confines:
        return
    base = policy.mounts(root, view=view)
    per_rule = [
        (" ".join(rule.leading_words) if isinstance(rule, Program) else f"validation {rule.name}", extra)
        for rule in (*policy.programs, *policy.validations)
        if rule.view is View.POLICY
        for extra in [tuple(o for o in policy.mounts(root, rule, view).omitted if o not in base.omitted)]
        if extra
    ]
    if not (base.omitted or per_rule):
        return
    print(
        "certorail: a grant runs under the policy filesystem view (exec.view = \"policy\"), and "
        "these locations have no native mount, so the view OMITS them:",
        file=sys.stderr,
    )
    for entry in base.omitted:
        print(f"certorail:   {entry}", file=sys.stderr)
    for name, extras in per_rule:
        for entry in extras:
            print(f"certorail:   {name}: {entry}", file=sys.stderr)
    print(
        "certorail:   (a literal path or a literal prefix ending in ** is mountable; a pattern "
        + ("outside the root has no view)" if view is not None else "needs the FUSE view: the certorail[fuse] extra)"),
        file=sys.stderr,
    )


def _srt_settings(
    policy: Policy, root: pathlib.Path, tmp: pathlib.Path, socket_path: pathlib.Path | None
) -> dict:
    """The srt (sandbox-runtime) profile for one confined run: no network at all -- the
    broker socket is the single door -- no local binding, and writes confined to the
    policy's write surface (``_jail_write_paths``). Reads stay default-allowed: the
    interpreter needs its stdlib from everywhere, and read confinement is the static
    analysis' stronger half anyway."""
    # The deny lists are required by sandbox-runtime's schema even when they are empty, and it
    # refuses the whole configuration without them rather than defaulting: leaving them out
    # makes every jailed run die before the program starts.
    #
    # Unix sockets: ``allowUnixSockets`` (a path allowlist) is honoured on macOS only; on Linux
    # srt denies socket() outright, and the only carve-out is ``allowAllUnixSockets``. The
    # broker socket lives in a per-run private tempdir, so the wider allowance costs little
    # here; a jail-independent transport (an inherited fd) is the proper fix, see JAILS.md.
    return {
        "network": {
            "allowedDomains": [],
            "deniedDomains": [],
            "allowLocalBinding": False,
            "allowUnixSockets": [str(socket_path)] if socket_path is not None else [],
            "allowAllUnixSockets": socket_path is not None,
        },
        "filesystem": {
            "allowWrite": _jail_write_paths(policy, root, tmp),
            "denyWrite": _jail_deny_paths(policy.mounts(root)),
            "denyRead": [],
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
    attached = _attach_view(policy, root)
    view = None if attached is None else attached.mountpoint
    _announce_view(policy, root, view)
    try:
        return _run(source, filename, policy, root, args, python, jail, view)
    finally:
        if attached is not None:
            attached.close()  # the lease: the daemon may retire once no run holds one


def _run(
    source: str,
    filename: str,
    policy: Policy,
    root: pathlib.Path,
    args: Sequence[str],
    python: str,
    jail: bool,
    view: pathlib.Path | None,
) -> subprocess.CompletedProcess[bytes] | Rejected:
    outcome = check(source, filename, policy, root, view)
    if isinstance(outcome, Rejected):
        return outcome
    for line in reveal_lines(outcome.report, filename):
        print(line, file=sys.stderr)  # asked for in the source: shown even when the run proceeds
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
            # a stream=True exec writes to the descriptors this host holds for its terminal
            server = build_server(socket_path, policy, root, stream_to=terminal_descriptors(), view=view)
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
                # srt's option parser re-serialises the command it parsed and runs it through a
                # shell -- a piece with a space is split, a piece beginning with ``-`` is read as
                # an srt option -- unless ``--`` ends its parsing, after which the pieces arrive
                # verbatim. Nothing after it needs quoting: every piece is a host-chosen path or
                # flag, except the program's own arguments, which srt now passes through as is.
                command = [srt, "--settings", str(settings), "--", *command]
        try:
            return subprocess.run(command, cwd=root, env=env, check=False)
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()


@dataclass(frozen=True)
class Loaded:
    """The policy for a run, and where it came from. A security tool composing configuration
    the program did not name is never silent about it -- but not on every accepted run either,
    where the lines are tokens in an agent's context and say nothing new. The provenance is
    printed under ``--check`` and ``--describe``, with every rejection (the denial tells the
    agent to edit the named policy file), and by the session hook; an accepted run is quiet."""

    policy: Policy
    provenance: tuple[str, ...]


def _provenance(policy: Policy, origin: str | None) -> tuple[str, ...]:
    lines: list[str] = []
    if origin is not None:
        lines.append(f"certorail: policy from {origin}")
    if BASE_RULESET in policy.applied:
        lines.append(
            f"certorail: base ruleset {BASE_RULESET} applied from the config directory "
            "(base = false in the policy opts out)"
        )
    if policy.default_allow:
        lines.append(
            "certorail: default-allow is on: a program the policy does not name runs with your "
            "authority, unconfined"
        )
    return tuple(lines)


def load_policy(path: pathlib.Path | None, root: pathlib.Path | None = None) -> Loaded:
    if path is None:
        if root is not None:
            try:
                found = find_policy(root)
            except AmbientPolicyError as e:
                raise SystemExit(str(e))
            if found is not None:
                policy_file, prefix = found
                try:
                    policy = load_policy_file(policy_file)
                except PolicyFileError as e:
                    raise SystemExit(str(e))
                return Loaded(policy, _provenance(policy, f"{policy_file} (root {prefix})"))
        try:
            policy = default_policy()  # the built-in posture, plus the base ruleset if installed
        except PolicyFileError as e:
            raise SystemExit(str(e))
        return Loaded(policy, _provenance(policy, None))
    if path.suffix not in (".toml", ".json"):
        raise SystemExit(f"{path}: a policy is a .toml or .json document")
    try:
        policy = load_policy_file(path)
    except PolicyFileError as e:
        raise SystemExit(str(e))
    return Loaded(policy, _provenance(policy, None))


def policy_origin(path: pathlib.Path | None, root: pathlib.Path) -> tuple[str, str | None]:
    """Where the policy for this run comes from, and the prefix it governs (ambient only)."""
    if path is not None:
        return str(path), None
    try:
        found = find_policy(root)
    except AmbientPolicyError as e:
        raise SystemExit(str(e))
    if found is not None:
        policy_file, prefix = found
        return str(policy_file), str(prefix)
    return "the built-in default policy", None


def main(argv: Sequence[str] | None = None) -> int:
    # verbs, dispatched before the run parser: ``policy`` is a reserved first word
    # (INSTALL.md) -- a program literally named ``policy`` is spelled ``./policy``. Imported
    # lazily so a plain run never pays for the installer.
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "policy":
        from .install import main as policy_main

        return policy_main(args[1:])
    if args and args[0] == "session-hook":
        # the Claude Code SessionStart hook: the ambient policy into the session's context
        from .session_hook import main as hook_main

        return hook_main()
    if args and args[0] == "view":
        # the FUSE view daemons: status, stop (MOUNTS.md)
        from .viewdaemon import main as view_main

        return view_main(args[1:])
    if args and args[0] == "init":
        # first-run setup: the base, the packs, a policy for the root -- as an interview
        from .init import main as init_main

        return init_main(args[1:])
    parser = argparse.ArgumentParser(
        prog="certorail", description="Analyse a program, check it against a policy, and run it."
    )
    parser.add_argument(
        "program", type=pathlib.Path, nargs="?", default=None, help="the Python source file"
    )
    parser.add_argument(
        "-c",
        "--command",
        metavar="SOURCE",
        default=None,
        help="run the program given inline instead of from a file (the agentic path)",
    )
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd(), help="the sandbox root (cwd of the program)")
    parser.add_argument(
        "--policy",
        type=pathlib.Path,
        default=None,
        help="a policy: a .toml or .json document "
        "(default: the nearest ambient policy under ~/.certorail/policy for this root, "
        "else the built-in policy)",
    )
    parser.add_argument("--check", action="store_true", help="analyse and evaluate only; do not run")
    parser.add_argument(
        "--describe",
        action="store_true",
        help="print what the policy for --root permits, for the program author (no program)",
    )
    parser.add_argument(
        "--no-jail",
        action="store_true",
        help="run without the srt OS jail (the static analysis and the broker still apply)",
    )
    # not REMAINDER: that would swallow every option after the program path (`prog.py --check`
    # would RUN prog.py with argv ["--check"] under the default policy). With "*", argparse
    # keeps parsing options anywhere, and `--` is the documented way to pass option-like
    # arguments through to the program.
    parser.add_argument("args", nargs="*", help="arguments for the program (after --)")
    ns = parser.parse_args(args)

    if ns.describe:
        if ns.program is not None or ns.command is not None or ns.args:
            parser.error("--describe takes no program")
        root = ns.root.resolve()
        loaded = load_policy(ns.policy, root)
        for line in loaded.provenance:
            print(line, file=sys.stderr)
        print(describe(loaded.policy, *policy_origin(ns.policy, root)))
        return 0
    if ns.program is None and ns.command is None:
        parser.error("exactly one of PROGRAM or -c SOURCE is required")
    args = ns.args[1:] if ns.args[:1] == ["--"] else ns.args
    if ns.command is not None:
        source, filename = ns.command, "<command>"
        if ns.program is not None:
            # with -c there is no program file: every positional is an argument for the
            # program, as with `python -c` (`certorail -c SOURCE -- a b`)
            args = [str(ns.program), *args]
    else:
        assert ns.program is not None  # the pair-is-required check above
        source, filename = ns.program.read_text(encoding="utf-8"), str(ns.program)
    root = ns.root.resolve()
    loaded = load_policy(ns.policy, root)
    policy = loaded.policy
    if ns.check:
        for line in loaded.provenance:
            print(line, file=sys.stderr)
    try:
        if ns.check:
            outcome: Accepted | Rejected | subprocess.CompletedProcess[bytes] = check(
                source, filename, policy, root
            )
        else:
            outcome = run(source, filename, policy, root, args, jail=not ns.no_jail)
    except SyntaxError as e:
        print(f"{filename}:{e.lineno}: syntax error: {e.msg}", file=sys.stderr)
        return 2

    match outcome:
        case Rejected():
            if not ns.check:
                for line in loaded.provenance:  # the denial says "edit the policy": name it
                    print(line, file=sys.stderr)
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
