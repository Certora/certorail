"""The host: analyse a program, evaluate the security policy, rewrite, run -- jailed.

    certorail run      (FILE | -c SOURCE) [--root DIR] [--policy FILE] [--no-jail] [-- ARG ...]
    certorail check    (FILE | -c SOURCE) [--root DIR] [--policy FILE]
    certorail describe [--root DIR] [--policy FILE]
    certorail explore | init | policy … | view …     # their own parsers (explorer, certorail.control, viewdaemon)
    certorail-run [--check] (-c SOURCE | FILE) [-- ARG ...]   # the agent's closed entry point (run_main)

(``certorail`` and ``certorail-run`` are the ``[project.scripts]`` entry points, installed by
``uv tool install .``; ``python -m certorail.host`` is the first. ``certorail -c SOURCE …`` with
the old flat options still works as a legacy spelling of ``run``/``check``; ``session-hook`` is
the plugin's hook, kept out of ``--help``.)

1. ``walker.analyze``: the lexical rules and the dataflow. Any violation, or any sink whose
   location is not proven, rejects the program with the messages.
2. ``Policy.evaluate``: every proven sink and every ``certora.exec`` against the policy. Any
   denial rejects the program.
3. ``rewrite``: ``assert`` hardened, ``@certora.checked`` on contracted functions.
4. Run: the rewritten source in a fresh interpreter (``-I -P``: no environment, no cwd on
   ``sys.path``) with the sandbox root as cwd, ``certora`` bound to ``certorail.markers`` and
   ``sys.argv`` set to the program's arguments -- inside an OS jail: no network, writes
   confined to the policy's write surface, no fork or exec, and the broker reached over one
   inherited socket, the single door out. Nothing of the run is a file anyone could name: the
   bootstrap is the command line (``-c``), and the program source and, on macOS, the Seatbelt
   profile reach the child as inherited descriptors to unlinked files, so what runs is what
   was analysed. On Linux the jail is bubblewrap around the interpreter plus the bootstrap's
   seccomp filter; on macOS the bootstrap itself installs the whole jail with one
   ``sandbox_init`` (``selfjail``), since a process already inside a Seatbelt sandbox cannot
   sandbox itself again, so nothing may wrap it first. The static analysis is the primary
   confinement; the jail is where anything it missed goes to die. Without bubblewrap a Linux
   run proceeds with a loud warning (or quietly with ``--no-jail``).

The policy is a TOML (or JSON) document (``policyfile``), given with ``--policy`` or discovered
ambiently for the root (``policydir``); without one, ``policyfile.default_policy`` applies: read,
write and list anywhere within the root, and no programs of its own. Either way the installed
base ruleset (``rulesets/base.toml``) is applied unless the policy says ``base = false``. Exit
status: the program's own when it ran; 1 when rejected; 2 when the program does not parse.
"""
import argparse
import ast
import contextlib
import os
import pathlib
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import IO

from certorail.analysis import Named, StaticPath
from certorail.childjail import Mounts, View
from certorail.viewdaemon import Attachment, ViewUnavailable, attach
from certorail.broker import build_broker, terminal_descriptors
from certorail.describe import describe
from certorail.policy import Denial, Policy, Program
from certorail.policydir import AmbientPolicyError, find_policy
from certorail.policyfile import BASE_RULESET, PolicyFileError, default_policy, load_policy_file
from certorail.rewrite import rewrite
from certorail.safepy import FunctionAnalysis
from certorail.walker import Report, analyze, describe_sink, where


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


# The child interpreter, run as `python -I -P -c BOOTSTRAP FILENAME ARGS...`: jail itself, bind
# the marker namespace, read the program over the descriptor the host handed over, set argv,
# run it as __main__.
_BOOTSTRAP = r'''
import os
import sys
filename, *args = sys.argv[1:]
sys.path.insert(0, __CERTORAIL_PARENT__)
if os.environ.get("CERTORAIL_SELF_JAIL"):
    # first, before anything else runs: on macOS this one call is the whole jail, its profile
    # read from the descriptor the host handed over
    import certorail.selfjail
    profile_fd = os.environ.get("CERTORAIL_SEATBELT_FD")
    warning = certorail.selfjail.install(None if profile_fd is None else int(profile_fd))
    if warning is not None:
        print("certorail: self-jail not installed: " + warning, file=sys.stderr)
import certorail.markers
# the program as the host analysed it, over an inherited descriptor: no file in between
with os.fdopen(int(os.environ["CERTORAIL_PROGRAM_FD"]), encoding="utf-8") as f:
    source = f.read()
sys.argv = [filename, *args]
namespace = {"__name__": "__main__", "__file__": filename, "certora": certorail.markers}
exec(compile(source, filename, "exec"), namespace)
'''


def _handover(prefix: str, text: str) -> IO[bytes]:
    """*text* in an unlinked temporary file, positioned at its start, for the child to inherit
    (``pass_fds``) and read: a handover nothing else on the machine can name, so nothing else
    can edit it on the way."""
    f = tempfile.TemporaryFile(prefix=prefix)
    f.write(text.encode("utf-8"))
    f.flush()
    f.seek(0)
    return f


def _jail_write_paths(policy: Policy, root: pathlib.Path) -> list[str]:
    """The jail's write allowance: the sandbox root -- which covers every root-relative write
    location -- plus the concrete prefix of every *absolute* write location the policy grants
    (a statically-approved ``/srv/checkouts/**`` write must not die in the jail). Coarser than
    the policy on purpose: precision is the analysis' job, the jail is the backstop."""
    paths = [str(root)]
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
    the analysis' alone: a jail binds paths, not patterns."""
    return [str(p) for p in mounts.no_write]


def _bwrap_command(bwrap: str, policy: Policy, root: pathlib.Path, mounts: Mounts, command: list[str]) -> list[str]:
    """The Linux jail around the interpreter: the host's filesystem read-only, the policy's
    write surface (``_jail_write_paths``) bound writable, every concrete protection remounted
    read-only on top (later mounts win), no network. Reads stay open: the interpreter needs its
    stdlib from everywhere, and read confinement is the analysis' stronger half. Process
    creation is the bootstrap's own seccomp filter, which composes with these namespaces; the
    broker's socket is an inherited descriptor, which bubblewrap passes through."""
    argv = [bwrap, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
    for path in _jail_write_paths(policy, root):
        argv += ["--bind-try", path, path]
    for path in _jail_deny_paths(mounts):
        argv += ["--ro-bind-try", path, path]
    argv += ["--unshare-net", "--die-with-parent", "--", *command]
    return argv


def _sb_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _seatbelt_profile(policy: Policy, root: pathlib.Path, mounts: Mounts) -> str:
    """The macOS jail, which the bootstrap installs on itself with one ``sandbox_init`` (a
    sandboxed process cannot sandbox itself again, so nothing may wrap the interpreter first):
    everything allowed except writes outside the policy's write surface, the network, fork and
    exec. Real paths, since Seatbelt matches those (``/var`` is ``/private/var``); later rules
    win, so the allowances follow the broad denial and the protections come last."""
    allowed = " ".join(f"(subpath {_sb_string(os.path.realpath(p))})" for p in _jail_write_paths(policy, root))
    lines = ["(version 1)", "(allow default)", "(deny file-write*)", f"(allow file-write* {allowed})"]
    for path in _jail_deny_paths(mounts):
        lines.append(f"(deny file-write* (subpath {_sb_string(os.path.realpath(path))}))")
    lines += ["(deny network*)", "(deny process-fork)", "(deny process-exec*)"]
    return "\n".join(lines) + "\n"


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
    env = dict(os.environ)
    # what the child inherits -- unlinked files and a socket end, nothing anyone else can name:
    # the program as analysed, the broker's door and, on macOS, the jail itself. So what runs
    # is what was analysed, whatever happens on the machine between here and the bootstrap.
    handover: list[IO[bytes] | socket.socket] = []
    program = _handover("certorail-program-", outcome.source)
    handover.append(program)
    env["CERTORAIL_PROGRAM_FD"] = str(program.fileno())
    host_end: socket.socket | None = None
    serving: threading.Thread | None = None
    if policy.network or policy.programs or policy.validations:
        # the broker: the single, policy-enforcing hole in the wall -- network requests, exec'd
        # children and check evaluators alike -- for the lifetime of this one program
        # (broker.py), over a socketpair: the child finds its end by descriptor number
        host_end, child_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        handover.append(child_end)
        # a stream=True exec writes to the descriptors this host holds for its terminal
        broker = build_broker(policy, root, stream_to=terminal_descriptors(), view=view)
        serving = threading.Thread(target=broker.serve, args=(host_end,), name="certorail-broker", daemon=True)
        serving.start()
        env["CERTORAIL_BROKER_FD"] = str(child_end.fileno())
    # the bootstrap is the command line itself; the program's name is for tracebacks and argv
    command = [python, "-I", "-P", "-c", bootstrap, filename, *args]
    if jail:
        # the self-jail the bootstrap installs on itself before the program runs: on Linux the
        # seccomp exec denial inside bubblewrap's namespaces, on macOS the whole Seatbelt
        # profile, since nothing may sandbox the interpreter before it does
        env["CERTORAIL_SELF_JAIL"] = "1"
        if sys.platform == "linux":
            bwrap = shutil.which("bwrap")
            if bwrap is None:
                print(
                    "certorail: bwrap not found: running WITHOUT the OS jail "
                    "(install bubblewrap; or pass --no-jail to accept this)",
                    file=sys.stderr,
                )
            else:
                command = _bwrap_command(bwrap, policy, root, policy.mounts(root), command)
        elif sys.platform == "darwin":
            profile = _handover("certorail-seatbelt-", _seatbelt_profile(policy, root, policy.mounts(root)))
            handover.append(profile)
            env["CERTORAIL_SEATBELT_FD"] = str(profile.fileno())
    try:
        try:
            proc = subprocess.Popen(command, cwd=root, env=env, pass_fds=[h.fileno() for h in handover])
        finally:
            # the child holds its own copies now (or nothing does, if the spawn failed): the
            # socket end's death is EOF to the broker, and the files have no other name anywhere
            for h in handover:
                h.close()
        proc.wait()
        done: subprocess.CompletedProcess[bytes] = subprocess.CompletedProcess(command, proc.returncode)
        return done
    finally:
        if host_end is not None:
            with contextlib.suppress(OSError):
                host_end.close()  # EOF for the serve loop, should the program have left it hanging
        if serving is not None:
            serving.join(timeout=5)


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


# the verbs that own a parser of their own (certorail.control, viewdaemon, explorer): listed by
# `certorail --help`, handed the rest of the command line untouched, imported lazily so a run
# never pays for them
_FORWARDED: dict[str, str] = {
    "init": "set up this machine and the current directory's policy, as a short interview",
    "policy": "install policies and ruleset packs; apply a ruleset; edit, list, verify",
    "view": "the FUSE view daemons: status, stop",
    "explore": "the policy as a navigable tree (a terminal UI)",
}
_PARSED = ("run", "check", "describe")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["-c"]:
        # legacy: `certorail -c SOURCE …` as spelled before the verbs, kept because shell
        # allow-rules were written against that prefix; `certorail run -c` is the spelling
        return _legacy(args)
    if args[:1] == ["session-hook"]:
        # the Claude Code SessionStart hook: plumbing the plugin runs, not a verb in --help
        from certorail.control.session_hook import main as hook_main

        return hook_main()
    if args and args[0] in _FORWARDED:
        return _forward(args[0], args[1:])
    parser = _parser()
    if args and not args[0].startswith("-") and args[0] not in _PARSED:
        parser.error(f"unknown verb {args[0]!r}; a program is run with `certorail run {args[0]}`")
    head, tail = _split_at_dashdash(args)
    ns = parser.parse_args(head)
    if ns.verb == "describe":
        if tail:
            parser.error("describe takes no program arguments")
        root = ns.root.resolve()
        loaded = load_policy(ns.policy, root)
        for line in loaded.provenance:
            print(line, file=sys.stderr)
        print(describe(loaded.policy, *policy_origin(ns.policy, root)))
        return 0
    source, filename, program_args = _program(parser, ns, tail)
    return _execute(
        source, filename, program_args,
        root=ns.root.resolve(), policy_path=ns.policy,
        check_only=ns.verb == "check", jail=not getattr(ns, "no_jail", False),
    )


def _forward(verb: str, rest: list[str]) -> int:
    if verb == "init":
        from certorail.control.init import main as init_main

        return init_main(rest)
    if verb == "policy":
        from certorail.control.install import main as policy_main

        return policy_main(rest)
    if verb == "view":
        from certorail.viewdaemon import main as view_main

        return view_main(rest)
    from certorail.explorer import main as explore_main

    return explore_main(rest)


def _where() -> argparse.ArgumentParser:
    """``--root`` and ``--policy``, which policy: shared by every verb that reads one."""
    where = argparse.ArgumentParser(add_help=False)
    where.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd(),
                       help="the sandbox root, the program's working directory (default: the current directory)")
    where.add_argument("--policy", type=pathlib.Path, default=None,
                       help="a policy document (.toml or .json) instead of the ambient one for the root")
    return where


def _split_at_dashdash(args: list[str]) -> tuple[list[str], list[str]]:
    """The command line before the first ``--`` and everything after it: the latter is the
    program's, option-like or not, and never reaches argparse (whose own ``--`` handling differs
    between a flat parser and a subparser)."""
    if "--" in args:
        at = args.index("--")
        return args[:at], args[at + 1:]
    return args, []


def _program_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("program", type=pathlib.Path, nargs="?", default=None, help="the Python source file")
    p.add_argument("-c", "--command", metavar="SOURCE", default=None, help="the program inline, instead of a file")
    # not REMAINDER: that would swallow every option after the program path. With "*", argparse
    # keeps parsing options anywhere; option-like program arguments go after `--`, which is
    # split off before parsing (_split_at_dashdash)
    p.add_argument("args", nargs="*", help="arguments for the program (option-like ones after --)")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="certorail",
        description="Analyse Python programs against a security policy and run them jailed.",
    )
    verbs = parser.add_subparsers(dest="verb", required=True, metavar="VERB")
    where = _where()
    run = verbs.add_parser("run", parents=[where], help="analyse a program, check it against the policy, run it in the jail")
    _program_arguments(run)
    run.add_argument("--no-jail", action="store_true",
                     help="run without the OS jail (the analysis and the broker still apply)")
    _program_arguments(verbs.add_parser("check", parents=[where], help="analyse and evaluate a program; run nothing"))
    verbs.add_parser("describe", parents=[where], help="print what the policy permits, for the program author")
    for verb, text in _FORWARDED.items():  # listed here; dispatched before parsing, with their own parsers
        verbs.add_parser(verb, help=text, add_help=False)
    return parser


def _program(parser: argparse.ArgumentParser, ns: argparse.Namespace, tail: list[str]) -> tuple[str, str, list[str]]:
    """The program of a run or a check -- a file, or inline source -- with its arguments: the
    positionals argparse collected, then everything that followed ``--``."""
    if ns.program is None and ns.command is None:
        parser.error("exactly one of PROGRAM or -c SOURCE is required")
    args: list[str] = [*ns.args, *tail]
    if ns.command is not None:
        if ns.program is not None:
            # with -c there is no program file: every positional is an argument for the
            # program, as with `python -c` (`certorail run -c SOURCE a -- -b`)
            args = [str(ns.program), *args]
        return ns.command, "<command>", args
    assert ns.program is not None  # the pair-is-required check above
    return ns.program.read_text(encoding="utf-8"), str(ns.program), args


def _legacy(args: list[str]) -> int:
    """``certorail -c SOURCE [--root DIR] [--policy FILE] [--check] [--no-jail] [-- ARG ...]``:
    the spelling before the verbs, kept because shell allow-rules were written against it. New
    text says ``certorail run -c`` and ``certorail check -c``."""
    parser = argparse.ArgumentParser(prog="certorail -c", parents=[_where()], add_help=False)
    _program_arguments(parser)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--no-jail", action="store_true")
    head, tail = _split_at_dashdash(args)
    ns = parser.parse_args(head)
    source, filename, program_args = _program(parser, ns, tail)
    return _execute(
        source, filename, program_args,
        root=ns.root.resolve(), policy_path=ns.policy, check_only=ns.check, jail=not ns.no_jail,
    )


_RUN_USAGE = "usage: certorail-run [--check] (-c SOURCE | FILE) [-- ARG ...]"


def run_main(argv: Sequence[str] | None = None) -> int:
    """``certorail-run [--check] (-c SOURCE | FILE) [-- ARG ...]``: the agentic entry point, with
    a closed interface. The program is inline or a file, the policy is the ambient one for the
    working directory, the jail is on. ``--check`` is the only option and comes first; there is
    no ``--policy``, ``--root`` or ``--no-jail`` to reach, so a shell allow-rule on this
    command's prefix admits a program and its arguments and nothing else. Everything after the
    source or the file is an argument for the program, options included (``--`` may precede
    them, as with ``certorail``). Parsed by hand: argparse would read an option after
    ``-c SOURCE`` as its own."""
    words = list(sys.argv[1:] if argv is None else argv)
    if words[:1] in (["-h"], ["--help"]):
        print(_RUN_USAGE)
        return 0
    check_only = False
    if words[:1] == ["--check"]:
        check_only = True
        words = words[1:]
    if words[:1] in (["-c"], ["--command"]):
        if len(words) < 2:
            print(_RUN_USAGE, file=sys.stderr)
            return 2
        source, filename, rest = words[1], "<command>", words[2:]
    elif words and not words[0].startswith("-"):
        program = pathlib.Path(words[0])
        try:
            source = program.read_text(encoding="utf-8")
        except OSError as e:
            print(f"certorail-run: {e}", file=sys.stderr)
            return 2
        filename, rest = str(program), words[1:]
    else:
        print(_RUN_USAGE, file=sys.stderr)
        return 2
    args = rest[1:] if rest[:1] == ["--"] else rest
    return _execute(
        source, filename, args,
        root=pathlib.Path.cwd().resolve(), policy_path=None, check_only=check_only, jail=True,
    )


def _execute(
    source: str,
    filename: str,
    args: Sequence[str],
    *,
    root: pathlib.Path,
    policy_path: pathlib.Path | None,
    check_only: bool,
    jail: bool,
) -> int:
    """Load the policy, check (and run) the program, report; the exit status."""
    loaded = load_policy(policy_path, root)
    policy = loaded.policy
    if check_only:
        for line in loaded.provenance:
            print(line, file=sys.stderr)
    try:
        if check_only:
            outcome: Accepted | Rejected | subprocess.CompletedProcess[bytes] = check(
                source, filename, policy, root
            )
        else:
            outcome = run(source, filename, policy, root, args, jail=jail)
    except SyntaxError as e:
        print(f"{filename}:{e.lineno}: syntax error: {e.msg}", file=sys.stderr)
        return 2

    match outcome:
        case Rejected():
            if not check_only:
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
