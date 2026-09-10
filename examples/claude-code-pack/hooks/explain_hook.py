#!/usr/bin/env python3
"""A Claude Code hook: turn a certorail rejection into an explanation and hand it back.

Reads the hook payload on stdin and stays completely silent -- no output, exit 0 -- unless all of
these hold:

  * the payload names a Bash command that invoked ``certorail`` (parsed with shlex, not matched
    as text);
  * the tool's output carries certorail's own rejection marker, ``": rejected"``;
  * a ``certorail`` is on PATH;
  * ``certorail explain``, run on that invocation's own arguments, itself reports a rejection.

The marker is a heuristic -- any output quoting another tool's refusal carries it too -- so the
verdict is taken from ``explain``'s exit status, not from the text that got the hook this far.

It runs ``certorail explain`` with that invocation's own arguments -- the program, --root,
--policy -- minus the ones that only mean something for a run, and returns the explanation as
additional context. It never runs the program: ``explain`` cannot.

Silence is the default for every other outcome: no certorail on PATH, an unrecognised payload, a
command it cannot re-derive, an explain that fails or says nothing. A hook must never be the
reason a session breaks.

``CERTORAIL_BIN`` names the binary to call, for a certorail that is not on the hook process's
PATH under that name. A ``python -m certorail.host`` invocation is deliberately not recognised.
"""
import json
import os
import shlex
import shutil
import subprocess
import sys

REJECTION_MARKER = ": rejected"

# arguments that mean something to a run and nothing to an explanation
RUN_ONLY_FLAGS = ("--check", "--no-jail")

PREAMBLE = """[certorail: the program was rejected before it ran]

Nothing executed. This is a static confinement refusal, not a filesystem permission error and not
a bug in the program's logic. Retrying it, moving the file, or reaching the same data by another
path will be refused identically.

`certorail explain` says exactly why, below, and for each problem it names two remedies. Those
are the only two legitimate ones:

1. Change the program so the fact is provable. The analysis does not guess: it refused because it
   could not prove the fact, not because it disliked the spelling, so the same shape written again
   is refused again. Build paths from literals under the root, guard an untrusted component before
   using it, spell a subcommand out, call the declared validation that establishes the atom. The
   "program:" line of each problem says which.

2. Change the policy, deliberately. The policy is the trusted, reviewed artifact, so widening it
   is a security decision rather than a build fix. The "policy:" line gives an edit that would
   permit the site. Where it says the edit covers more than the site needs, narrow it first. Show
   the user the edit and get their agreement before making it.

Do neither of these: do not disable, bypass or re-invoke certorail without it; do not move the
work into a subprocess, a shell, or an unconfined script; do not ask the user to run the command
for you outside the sandbox.

"""


def tool_output(payload: dict) -> str:
    """Everything the tool said, as one string. The key and the shape both vary by event."""
    pieces = []
    for key in ("tool_response", "tool_result", "tool_output"):
        value = payload.get(key)
        if isinstance(value, str):
            pieces.append(value)
        elif isinstance(value, dict):
            pieces.extend(v for v in value.values() if isinstance(v, str))
    return "\n".join(pieces)


def explain_arguments(argv: list[str], start: int) -> list[str]:
    """The tail of a certorail invocation, as ``explain`` takes it: the program or -c, --root and
    --policy pass through; the program's own arguments after a bare ``--`` do not."""
    rest = argv[start + 1:]
    if "--" in rest:
        rest = rest[: rest.index("--")]
    return [a for a in rest if a not in RUN_ONLY_FLAGS]


def main() -> None:
    payload = json.load(sys.stdin)
    command = payload.get("tool_input", {}).get("command")
    if not isinstance(command, str):
        return

    argv = shlex.split(command)
    start = next(
        (i for i, a in enumerate(argv) if os.path.basename(a) == "certorail"), None
    )
    if start is None:
        return
    if REJECTION_MARKER not in tool_output(payload):
        return

    binary = shutil.which(os.environ.get("CERTORAIL_BIN", "certorail"))
    if binary is None:
        return

    result = subprocess.run(
        [binary, "explain", *explain_arguments(argv, start)],
        capture_output=True,
        text=True,
        timeout=25,
        cwd=payload.get("cwd") or None,
        check=False,
    )
    # 1 is the rejected verdict; 0 is accepted and 2 unparsable, and injecting a refusal preamble
    # over either would tell the model something that did not happen
    if result.returncode != 1 or not result.stdout.strip():
        return

    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": payload.get("hook_event_name", "PostToolUseFailure"),
                "additionalContext": PREAMBLE + result.stdout,
            }
        },
        sys.stdout,
    )


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        # every failure mode of this script is the same failure mode: say nothing
        pass
    sys.exit(0)
