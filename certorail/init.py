"""``certorail init``: an ambient policy for a directory, as a short interview. Deterministic,
no model involved: every question has a fixed default, and nothing is written but the one
policy file, through the installer.

    certorail init                 # for the current directory
    certorail init --root DIR
    certorail init --yes           # every question answered with its default

1. If an ambient policy already governs the directory: say so, do nothing.
2. If a base ruleset is installed (``rulesets/base.toml``): summarise what it applies, from the
   ``description`` of each ruleset it names, and ask whether this root wants it. No writes
   ``base = false`` into the policy. Skipped when there is no base.
3. Ask whether programs get full read, write and list access under the root. Yes: every
   ``[filesystem]`` kind is ``["**"]`` and the policy is done.
4. Otherwise, ask for the locations of each kind in turn, in the location micro-syntax
   (``src/**``, ``*.md``, ``/srv/data/**``; empty for none), each checked as it is typed.
5. Ask whether to allow all programs the policy does not name (``default-allow``: any
   arguments, unjailed, the user's authority). Default no.

Installing and applying rulesets is not this verb's business: the installer
(``certorail policy install-pack``) installs, ``certorail policy apply`` applies. ``init`` ends
by listing the installed rulesets the base does not already apply, with their descriptions and
the ``apply`` command that would bring each in.
"""
import argparse
import pathlib
import sys
import tempfile
from collections.abc import Callable, Sequence

from .apply import applied_by, base_applies, description_of, document, installed_rulesets, params_of
from .install import InstallError, install_policy
from .locations import parse_location
from .policydir import AmbientPolicyError, config_dir, find_policy
from .policyfile import BASE_RULESET, rulesets_dir

type Ask = Callable[[str, bool], bool]   # a yes/no question and its default -> the answer
type Prompt = Callable[[str], str]       # a question -> the raw text answered
type Say = Callable[[str], None]

KINDS = ("read", "write", "list")

POLICY_TEXT = """\
# Ambient policy for {root}, written by `certorail init`. Refine it with `certorail policy
# edit`; see it composed with `certorail --describe --root {root}`; `certorail policy list`
# shows the installed rulesets an [[apply]] could bring in.
policy-version = 1
root = "{root}"
{base}{default_allow}
[filesystem]
read  = {read}
write = {write}
list  = {list}
"""

DEFAULT_ALLOW = """\
# Allow all: a program no rule and no [[deny]] names runs with any arguments, with your
# authority, unjailed, and its effects unknown to the analysis. A named program keeps its
# shapes. Delete the line to fail closed on unnamed programs.
default-allow = true
"""

BASE_OPT_OUT = """\
# This root opts out of the machine's base ruleset (rulesets/base.toml in the config directory):
# only what this file applies reaches programs here. Delete the line to inherit the base.
base = false
"""


# ---------------------------------------------------------------------------------------------
# what is installed comes from ``apply`` (read raw, so a document that would not load still
# describes itself)
# ---------------------------------------------------------------------------------------------


def manifest(covered: tuple[str, ...]) -> list[str]:
    """The installed rulesets the base does not apply, one paragraph each: the description, the
    parameters to bind, and the ``certorail policy apply`` that brings it in. Rulesets another
    installed ruleset applies are marked as such, so the umbrellas stand out."""
    installed = installed_rulesets()
    by_ruleset: dict[str, list[str]] = {}
    for name in installed:
        data = document(rulesets_dir() / name)
        for inner in applied_by(data) if data is not None else ():
            by_ruleset.setdefault(inner, []).append(name)
    lines: list[str] = []
    for name in installed:
        if name == BASE_RULESET or name in covered:
            continue
        lines.append(f"  {name}: {description_of(name) or '(no description)'}")
        if name in by_ruleset:
            lines.append(f"    applied by {', '.join(by_ruleset[name])}")
        params = params_of(name)
        if params:
            lines.append("    parameters: " + "; ".join(
                f"{p} ({d})" if d else p for p, (_, d) in params.items()
            ))
        lines.append(f"    certorail policy apply {name}" + (" where=." if "where" in params else ""))
    return lines


# ---------------------------------------------------------------------------------------------
# the interview
# ---------------------------------------------------------------------------------------------


def _locations(kind: str, root: pathlib.Path, prompt: Prompt, say: Say) -> list[str]:
    """The locations of one kind, typed as a comma-separated list in the location micro-syntax
    and checked as typed; an entry that does not parse is said and the question repeated."""
    while True:
        raw = prompt(f"{kind} locations under {root} (comma-separated; ** for everything, empty for none): ")
        entries = [e.strip() for e in raw.split(",") if e.strip()]
        problems = []
        for entry in entries:
            try:
                parse_location(entry)
            except ValueError as e:
                problems.append(f"{entry!r}: {e}")
        if not problems:
            return entries
        for line in problems:
            say(f"  {line}")


def interview(*, root: pathlib.Path, ask: Ask, prompt: Prompt, say: Say) -> int:
    resolved = root.resolve()
    say(f"config directory: {config_dir()}")
    try:
        found = find_policy(resolved)
    except AmbientPolicyError as e:
        say(f"ambient discovery for {resolved} fails: {e}")
        return 1
    if found is not None:
        file, prefix = found
        where = "this directory" if prefix == resolved else f"{prefix}, above this directory"
        say(f"already set up: {file} governs {where}; nothing to do (`certorail policy edit` changes it)")
        return 0

    covered = base_applies()
    inherit = True
    if covered is not None:
        say(f"base ruleset: {rulesets_dir() / BASE_RULESET} applies to every root that does not opt out. It applies:")
        for name in covered:
            say(f"  {name}: {description_of(name) or '(no description)'}")
        if not covered:
            say("  (nothing)")
        inherit = ask("Apply the base ruleset to this root?", True)

    if ask(f"Give programs full read, write and list access under {resolved}?", True):
        grants = {kind: ["**"] for kind in KINDS}
    else:
        say("The location micro-syntax: `src/**` a subtree, `*.md` one name pattern, `docs/**/<.*\\.md>` a")
        say("regex leaf, `/srv/data/**` an absolute subtree, `.` the root itself.")
        grants = {kind: _locations(kind, resolved, prompt, say) for kind in KINDS}
    say("Allow all: a program no rule names runs with any arguments, unjailed, with your authority")
    say("(default-allow). Named programs keep their shapes; a [[deny]] blacklists a first word.")
    allow_all = ask("Allow all programs the policy does not name?", False)

    def toml_string(entry: str) -> str:
        # a literal string keeps a regex leaf's backslashes as typed; a basic string only when the
        # entry itself holds a single quote
        if "'" not in entry:
            return f"'{entry}'"
        return '"' + entry.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def toml_list(entries: list[str]) -> str:
        return "[" + ", ".join(toml_string(e) for e in entries) + "]"

    text = POLICY_TEXT.format(
        root=resolved,
        base="" if inherit else "\n" + BASE_OPT_OUT,
        default_allow="\n" + DEFAULT_ALLOW if allow_all else "",
        read=toml_list(grants["read"]),
        write=toml_list(grants["write"]),
        list=toml_list(grants["list"]),
    )
    with tempfile.TemporaryDirectory(prefix="certorail-init-") as tmp:
        draft = pathlib.Path(tmp) / "policy.toml"
        draft.write_text(text, encoding="utf-8")
        try:
            report = install_policy(draft, name="policy.toml")
        except InstallError as e:
            say(f"policy not installed: {e}")
            return 1
    for line in report.lines():
        say(line)

    extra = manifest(covered or ())
    if extra:
        say("installed rulesets the base does not apply; `certorail policy apply` brings one in:")
        for line in extra:
            say(line)
    return 0


# ---------------------------------------------------------------------------------------------
# the command
# ---------------------------------------------------------------------------------------------


def _tty_ask(question: str, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        try:
            answer = input(f"{question} [{hint}] ").strip().lower()
        except EOFError:
            print()
            raise SystemExit("certorail init: aborted") from None
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("please answer y or n")


def _tty_prompt(question: str) -> str:
    try:
        return input(question)
    except EOFError:
        print()
        raise SystemExit("certorail init: aborted") from None


def _interactive() -> bool:
    """Is someone there to answer? (A captured or redirected stdin is not a terminal.)"""
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="certorail init",
        description="Create the ambient policy for a directory, as a short interview. Deterministic.",
    )
    parser.add_argument("--yes", action="store_true", help="answer every question with its default")
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd(),
                        help="the directory the policy is for (default: the current directory)")
    ns = parser.parse_args(argv)
    if ns.yes:
        ask: Ask = lambda question, default: default  # noqa: E731
        prompt: Prompt = lambda question: ""  # noqa: E731  -- unreachable: the defaults never quiz
    elif _interactive():
        ask, prompt = _tty_ask, _tty_prompt
    else:
        raise SystemExit("certorail init is an interview; with no terminal, pass --yes to take every default")
    return interview(root=ns.root, ask=ask, prompt=prompt, say=print)


if __name__ == "__main__":
    raise SystemExit(main())
