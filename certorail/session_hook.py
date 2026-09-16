"""``certorail session-hook``: a Claude Code ``SessionStart`` hook.

Prints, to stdout, what an agent working in this project needs to know before it runs
anything: a short statement of how certorail is used here, followed by ``--describe``'s
rendering of the ambient policy -- the interface ``Policy.evaluate`` will enforce. Claude Code
adds a SessionStart hook's stdout to the session context, so the agent starts every session,
resume and compaction knowing what is permitted instead of guessing (the alternative is the
agent probing the policy by being denied).

Where nothing applies it stays silent: no certorail policy governs most directories a global
hook fires in, and an empty stdout adds no context. A policy that exists but fails to load is
reported *as context* rather than to stderr -- the agent is the one who needs to know its runs
will fail. Exit code is always 0: a missing or broken policy must never block a session.

The hook reads nothing from stdin and needs only ``CLAUDE_PROJECT_DIR`` (falling back to the
working directory, which Claude Code sets to the project root).
"""
import os
import pathlib

from .describe import describe
from .policydir import AmbientPolicyError, find_policy
from .policyfile import PolicyFileError, load_policy_file

PREAMBLE = """\
# certorail governs script execution in this project

certorail runs LLM-written Python inside a jail after statically checking every filesystem,
subprocess and network operation against the policy below. Use it instead of raw shell for
build/test/tool commands: `certorail -c SOURCE --check` analyses without running (do this
first); `certorail -c SOURCE` or `certorail file.py` analyses and runs. Programs are written
in the confined subset: `certora.exec(...)` for subprocesses, `certora.network.<method>(url)`
for HTTP, `certora.check(...)` for the validations named below, pathlib for files. Everything
the policy does not list is denied, and the denial says why.
"""


def main() -> int:
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    root = pathlib.Path(project) if project else pathlib.Path.cwd()
    try:
        found = find_policy(root)
    except AmbientPolicyError as e:
        print(f"certorail: the ambient policy for {root} is unusable and runs will refuse: {e}")
        return 0
    if found is None:
        return 0
    policy_file, prefix = found
    try:
        policy = load_policy_file(policy_file)
    except PolicyFileError as e:
        print(f"certorail: the ambient policy at {policy_file} fails to load, and runs will "
              f"fail the same way:\n{e}")
        return 0
    print(PREAMBLE)
    print(describe(policy, str(policy_file), governs=str(prefix)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
