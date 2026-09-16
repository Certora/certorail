"""``certorail session-hook``: a Claude Code ``SessionStart`` hook.

Prints, to stdout, what an agent working in this project needs to know before it runs
anything: what certorail is and how it is invoked, the confined subset the program must be
written in (condensed from SUBSET_PROMPT.md: the rules programs trip over), what to do when a
run is denied -- edit the named policy file, never bypass the tool -- and then ``--describe``'s
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
from .policydir import AmbientPolicyError, config_dir, find_policy
from .policyfile import BASE_RULESET, PolicyFileError, load_policy_file

# What an agent needs before its first run: what certorail is, how to invoke it, the subset it
# must write in (the rules a program trips over, condensed from SUBSET_PROMPT.md), and what to
# do when a run is denied. The policy's own interface (--describe) follows this text.
PREAMBLE = """\
# certorail governs script execution in this project

certorail runs Python you write inside an OS jail, after statically checking every filesystem,
subprocess and network operation in it against the policy at the end of this note. Use it
instead of raw shell for build, test and tool commands. Two commands:

    certorail -c 'SOURCE' --check      # analyse only: do this first, it is free
    certorail -c 'SOURCE' [-- ARG ...] # analyse, then run in the jail (or: certorail file.py)

The program's working directory is the sandbox root, {prefix}; relative paths are relative to
it. A rejection names a line: `violation:` means the program breaks the subset below or the
analysis could not follow it, `denied:` means the program is fine but the policy does not permit
that operation. Fix the line, or change the policy (see "When you are denied"). Never work
around the checker.

## The subset: what a certorail program may contain

- **Imports**: `import x` / `import x.y` only -- no `from`, no `as`. Standard library only, and
  not: `os` (except `os.path.{{join,basename,dirname,split,splitext,isabs,normpath,abspath,
  realpath,commonpath,exists,isfile,isdir}}`, `os.listdir`, `os.walk`, `os.sep`, `os.fspath`),
  `subprocess`, `shutil`, `tempfile`, `glob`, `socket`, `http`, `urllib` (except `urllib.parse`),
  `threading`, `asyncio`, `importlib`, `pickle`, `ctypes`, `logging`, `platform`, `inspect`,
  `types`, or any archive/compression module. A module name or `certora` may appear only as the
  receiver of a call (`json.loads(...)`), never as a value (`f = json.loads` is a violation).
- **Names**: never rebind an imported name, a builtin, `certora`, or a class you defined. No
  dunders anywhere -- there is no `if __name__ == "__main__":`, call `main()` at top level. No
  `getattr`/`setattr`/`vars`/`globals`/`eval`/`exec`/`compile`. No `async`, `:=`, `global`,
  `nonlocal`. Callees are a name or an attribute chain (`f()()` is a violation). Decorators are
  only `@staticmethod`, `@classmethod`, `@property`, `@dataclasses.dataclass`,
  `@functools.cache`/`lru_cache`, `@enum.unique`, `@abc.abstractmethod`. Class bases are names:
  your own classes, `object`, `dict`/`list`/`tuple`/`set`/`int`/`float`, `enum.Enum` and kin,
  `abc.ABC`, `typing.NamedTuple`/`TypedDict`/`Protocol`, exception classes. Not `str`, not
  `pathlib.*`, no `metaclass=`.
- **Files**: only the bare builtin `open(...)` or a `pathlib.Path` method (`.open`, `.read_text`,
  `.read_bytes`, `.write_text`, `.write_bytes`, `.iterdir`, `.glob`, `.rglob`, `.exists`,
  `.is_file`, `.is_dir`, `.mkdir`, `.touch`, `.chmod`, `.replace`), plus `os.listdir`/`os.walk`/
  `os.path.exists`. **Every path must have a proven location**: a relative literal without `..`;
  `pathlib.Path(...)` of literals; `located / "literal"` or `located / safe_name`; a loop
  variable of `.iterdir()`/`.glob()`/`os.listdir()`/`os.walk()` over a located base; a parameter
  annotated `typing.Annotated[pathlib.Path, certora.within("repos")]`. For text of unknown
  origin (`sys.argv`, JSON, a file), guard it first, in this order: `assert isinstance(s, str)`,
  then `assert certora.pathmatch(s, "repos/*/foundry.toml")` using a spelling the policy below
  shows -- or `".." not in s and s.startswith("data/")`. A bare name from untrusted text is safe
  after `assert "/" not in name and name not in (".", "..")`. Facts belong to a variable: any
  string method (`strip`, `format`, `+`) yields a plain string, reassignment drops them, and
  nothing established inside a `try`, loop or `with` body survives it. Prefer relative paths; a
  leading `/` is the filesystem root and needs an absolute grant.
- **Subprocesses**: only `certora.exec(program, *args, cwd=<located path>)`. `program` and each
  argument are separate strings (or located paths); no shell, no pipes, no `*`/`**` splats; `cwd`
  is required. Filter output in Python (`head`, `grep`, `wc` on the lines), not with a pipe.
  Which programs, subcommands, flags and argument shapes exist is exactly what the policy below
  lists; the notation line explains holes. The result has `.returncode`, `.stdout`, `.stderr`
  (bytes) and `.stdout_lines()`/`.stdout_string()`, which **raise** on a non-zero exit. For a
  build or test run you want to watch, `stream=True` writes the output to the terminal as it
  happens and returns only the exit code.
- **Network**: only `certora.network.get/head/delete(url, headers=, timeout=)` and
  `post/put/patch(url, headers=, body=<bytes>, timeout=)`, one positional argument. A literal URL
  is proven; a built one needs guards on `urllib.parse.urlsplit(u).scheme`, `.netloc` and `.path`
  (or `certora.pathmatch(urllib.parse.urlsplit(u).path, "/repos/**")`).
- **Validations**: `certora.check("name", key=var, cwd=located)` runs a policy-declared check as
  a bare statement and raises on failure; the facts land on the variables passed. Facts about
  the environment die at the next effectful call (any `certora.exec`, network request, or call
  to your own function), so check immediately before the operation that needs the fact, inside
  the loop if in a loop. `x = certora.check_single("name", value)` is the expression form.
- Ordinary Python is otherwise fine: functions, dataclasses, enums, comprehensions, `match`,
  `try`/`except`, f-strings, `json`, `re`, `math`, `collections`, `itertools`, `datetime`.

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
3. Reload to check the policy: `certorail -c 'pass' --check` reports every problem with its line.
   Then re-check your program.

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
    print(describe(policy, str(policy_file), governs=str(prefix)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
