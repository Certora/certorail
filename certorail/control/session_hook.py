"""``certorail session-hook``: a Claude Code ``SessionStart`` hook.

Prints, to stdout, what an agent working in this project needs before it runs anything: how
certorail is invoked and what to do when a run is denied; the program-author guide
(``SUBSET_PROMPT.md``, shipped in this package: the confined subset and the policy vocabulary);
and then ``--describe``'s rendering of the ambient policy -- the interface ``Policy.evaluate``
will enforce. Claude Code adds a SessionStart hook's stdout to the session context, so the agent
starts every session, resume and compaction knowing what is permitted instead of guessing (the
alternative is the agent probing the policy by being denied).

Where nothing applies it stays silent: no certorail policy governs most directories a global
hook fires in, and an empty stdout adds no context. A policy that exists but fails to load is
reported *as context* rather than to stderr -- the agent is the one who needs to know its runs
will fail. Exit code is always 0: a missing or broken policy must never block a session.

The hook reads nothing from stdin and needs only ``CLAUDE_PROJECT_DIR`` (falling back to the
working directory, which Claude Code sets to the project root).
"""
import importlib.resources
import os
import pathlib

from certorail.describe import describe
from certorail.policydir import AmbientPolicyError, config_dir, find_policy
from certorail.policyfile import BASE_RULESET, PolicyFileError, load_policy_file

# What an agent needs before its first run: what certorail is, how to invoke it, and what to do
# when a run is denied. The guide (the subset and the policy vocabulary) and the policy's own
# interface (--describe) follow this text.
PREAMBLE = """\
# certorail governs script execution in this project

certorail runs Python you write inside an OS jail, after statically checking every filesystem,
subprocess and network operation in it against the policy at the end of this note. Use it
instead of raw shell for build, test and tool commands. Two commands:

    certorail-run --check -c 'SOURCE'        # analyse only: do this first, it is free
    certorail-run -c 'SOURCE' [-- ARG ...]   # analyse, then run in the jail (or: certorail-run file.py)

The program's working directory is the sandbox root, {prefix}; relative paths are relative to
it. A rejection names a line: `violation:` means the program breaks the subset described below
or the analysis could not follow it, `denied:` means the program is fine but the policy does not
permit that operation. Fix the line, or change the policy (see "When you are denied"). Never
work around the checker.

## When you are denied

The policy is a file you can read and edit: **{policy_file}**. It governs {prefix} and every
directory below it without a policy of its own. To get something permitted:

1. Read the denial. It names the operation and the rule or grant it failed against.
2. Decide whether the program should be doing that at all. If the task needs it, edit the
   policy file to grant the narrowest thing that works: a location under `[filesystem]`, a
   `[[program]]` rule with the words and typed holes the command needs (not `any = true` unless
   the argument really is opaque data), a `[[network]]` host with the methods used. Comment the
   grant with the need it serves. The human reviews that edit as a diff; that review is the
   point, so make the diff say what it is for.
3. Reload to check the policy: `certorail-run --check -c 'pass'` reports every problem with its
   line. Then re-check your program.

Do **not** disable certorail, run the command outside it, pass `--no-jail`, or reshape the
program to slip past the analysis; each of those defeats the review the human asked for. If the
policy is not yours to change, say what you need and why and stop. The shared vocabularies
(rulesets) and checkers a policy applies live in {config_dir}; a ruleset's rule cannot be edited
in place -- override it in the policy (`override = true`) or take it back (`[[deny]]`).{base_note}
"""

BASE_NOTE = """

The read-only tools below marked `[from {base}]` come from the config directory's base ruleset,
applied to every project here; `base = false` at the top of the policy opts this project out."""


def preamble(policy_file: str, prefix: str, applied: tuple[str, ...]) -> str:
    base_note = BASE_NOTE.format(base=BASE_RULESET) if BASE_RULESET in applied else ""
    return PREAMBLE.format(policy_file=policy_file, prefix=prefix, config_dir=config_dir(), base_note=base_note)


def guide() -> str:
    """The program-author guide shipped with the package: the confined subset (SafePy) and how
    to work within a policy, in the vocabulary ``--describe`` uses."""
    return importlib.resources.files("certorail").joinpath("SUBSET_PROMPT.md").read_text(encoding="utf-8")


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
    print(preamble(str(policy_file), str(prefix), policy.applied))
    print(guide())
    print(describe(policy, str(policy_file), governs=str(prefix)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
