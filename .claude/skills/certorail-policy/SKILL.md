---
name: certorail-policy
description: Derive a certorail security policy (policy.toml) from what the user's agent-authored scripts need to do, and author the checker programs its runtime validations run. Use when the user wants to write, tighten, review or debug a certorail policy; define atoms or validations; decide what confined programs may read, write, list, exec or fetch; or install a policy ambiently for a sandbox root.
---

# Deriving a certorail policy

certorail confines LLM-written Python: a program is analysed statically, every filesystem,
subprocess and network operation it can perform is evaluated against a **policy**, and only a
program whose every operation the policy permits is run. The policy is the user's statement of
what their scripts are *allowed* to do. You are helping them write it, plus the small host-side
programs ("checkers") that its runtime validations execute.

Read `reference.md` (next to this file) for the exact schema and the checker runtime contract.
Read `examples/SUBSET_PROMPT.md` in the certorail repository when you need to write a probe
program in the confined subset.

## What you deliver

1. `policy.toml` — data, default-deny, every grant commented with the need it serves.
2. One executable per validation that is not a plain regex, installed in
   `~/.certorail/checkers/<name>` and referenced from `argv` by **absolute path**. The config
   directory is the one auditable place for everything the analysis trusts: the policies under
   `~/.certorail/policy/`, the checkers they run under `~/.certorail/checkers/`. Do not scatter
   checkers into repositories or `PATH`.
3. Evidence: the policy loads; each checker accepts and refuses sample inputs; a probe program
   exercising each grant is accepted with `--check`; a probe that oversteps is denied.
4. Installation: ambient under `~/.certorail/policy/` (the default), or `--policy path` for a
   one-off.
5. A program-author note: the validation names, parameters, atoms and regexes programs must use.
   Whoever writes the confined programs (usually a model prompted with `SUBSET_PROMPT.md`) needs
   this vocabulary appended to their prompt.

## Principles

- **Default deny, least privilege.** Nothing is permitted until listed. Grant the narrowest
  location (`repos/**`, not `**`), the narrowest program rule (`git log`, not `git`), the
  narrowest network rule (one host, `GET` only). A grant that cannot be traced to a stated need
  does not go in.
- **Trusted assertions.** `matches`, `pure`, `effect-free`, the checkers themselves and the
  location grants are believed by the analysis without proof. A wrong one is a soundness hole,
  not a bug report. Apply the honesty rules in step 3 literally.
- **Static where possible, runtime where necessary.** Locations, literal arguments and regex
  atoms are discharged at analysis time for free. Add a checker only for a property the text
  of a value cannot decide.
- **Never widen to make a program pass.** When a probe is denied, first ask whether the program
  should be doing that at all. The policy is reviewed; the programs are not.

## Step 1: interview

Ask, in one batch (use AskUserQuestion when available), then propose a draft rather than
interrogating further:

1. **Tasks.** In plain words, what will the scripts do? Which of those actions worry you?
2. **Root.** Which directory is the sandbox root (`--root`)? Everything relative lives under it.
3. **Filesystem.** Which directories get read, written, listed? Any outside the root?
4. **Programs.** Which executables, which subcommands, run from where? Do they take paths as
   arguments? Do they take opaque arguments (API queries, JSON) the analysis cannot read?
5. **Network.** Which hosts, which methods? Is plain `http` or a private/loopback address needed?
6. **Preconditions.** What must be true before a dangerous action ("only push to org repos",
   "never touch the prod database", "tree must be clean", "branch name is not a flag")? These
   become atoms and validations.
7. **Effects.** For each tool: does it reach the network, does it write the filesystem, and
   which state does it change (the remote, the refs, the index, the working tree)? Which of the
   preconditions depend on which of that state? These become regions, media and `writes`.
8. **Placement.** One policy passed with `--policy`, or ambient for the root so `certorail` finds
   it on its own?

## Step 2: map needs to grants

| Need | Grant |
|---|---|
| read / write / list files under a directory | `[filesystem]` `read` / `write` / `list` location lists; `list` covers directory listing and existence probes |
| only certain file types | a regex leaf: `reports/**/<\w+\.json>` |
| a directory outside the root | a leading-`/` location (`/srv/data/**`); absolute and relative grants never relate |
| run a program with fixed words and no arguments | a flat `[[program]]` per (name, subcommand) with the narrowest `cwd`; anything after the words needs a template |
| run a tool with flags and paths (`find`, `grep`, `rg`, `ls`, `tar`) | a **template**: `argv` with holes, a flagset listing exactly the permitted flags. A closed flags hole may sit before other holes (`tar FLAGS... -f ARCHIVE FILES...`): positionally it ends at the first value that provably is not a flag, and an ambiguous value is rejected, not guessed. An `each` hole that is not last, or an open (`any = true`) flags hole that is not last, makes it and everything after it keyword-only. See "Calling a template" in `reference.md` |
| the same tools under several roots, or across policies | a **ruleset** in `~/.certorail/rulesets/`, applied with `[[apply]] ruleset = "unix.toml" where = ["repos", "/srv/data"]`. Its parameters are the root's decisions: bind every atom list (`[]` for none) and constraint a rung you enable reaches; bools are off unless you say `= true`. Nothing has a default |
| a flag that is fine only in a vouched-for state (`--force` on a non-default branch, `-delete` under a scratch tree) | a flag entry with `requires = { HOLE = [...] }` or `{ cwd = [...] }`: demanded only while the flag is present; `value = false` spells a bare flag in table form |
| program takes paths | `location` on the hole |
| program takes opaque arguments (`gh api -f q=...`) | `any = true` on that one hole, or an open flag vocabulary (`holes.FLAGS = { kind = "flags", any = true }`) for a tool trusted with all its options |
| program takes runtime-checked values (a checked branch name) | a hole with `atoms = [...]`; have the checker also establish the built-in `not-option`, or the dash guard denies text whose head it cannot see |
| a destructive action the agent must have chosen itself (drop a database, delete a branch) | a hole with `literal = true` plus the shape (`matches`/`one-of`/`location`): the value must appear in the program text, never come from a file, argv or an API |
| an action only on what a trusted query returned (terminate the runners the inventory listed, push to branches the API listed, email the on-call roster) | mark the query's rule `source = "atom"` (or a `[[source]]` location) and put `atoms = ["atom"]` on the hole: only a value extracted unmodified from that result satisfies it. Identifiers all look alike; which query said so is the whole property |
| talk to an API | one `[[network]]` per host: `methods`, default `https`, default port; `allow-nonpublic` only for loopback/private targets |
| gate an action on a property | atoms + validations (step 3), consumed by `requires` / a hole's `atoms` / `[[network]].requires` |
| a check that must survive an intervening command (check the checkout, then commit, then push) | regions: `writes` on the command, `reads` on the atom (step 3b). Without them every command kills every environmental fact |
| a tool that never touches the network, or never writes files | `network = false` / `write = false` on its rule: a claim that bounds what it can kill with no region named; `effect-free = true` for both |

Subcommand rules for one program are prefix-free, cannot mix with a bare rule for that program,
and **fail closed**: an unlisted or computed subcommand is denied.

## Step 3: design atoms and validations

For each precondition, classify the property and pick the cheapest honest mechanism:

**A. A regex over the value's text decides it** (branch is not a flag, name is a slug, URL is a
dev/staging endpoint) → a *defined atom*: `no-flag = { matches = '[^-].*' }`. No validation, no
checker. Literals satisfy it automatically; a program establishes it on a dynamic value with
`assert re.fullmatch(r"<the same regex text>", value)` or with a validation that establishes it.
Publish the regex text in the program-author note: a different guard for the same property is
not recognised.

**B. The text alone decides it, but not by a regex** (a checksum, a fixed list too long for a
regex, a version-string parse) → `atom = { pure = true }` plus a `[[validation]]` with exactly one
`params` entry, `effect-free = true`, no `cwd`. This is a *literal checker*: the host runs it at
analysis time on constants, so literal arguments need no `certora.check`; the broker runs it for
dynamic values. It also qualifies for `on-redirect = "recheck"`.

**C. The state of a place decides it** (cwd is an org checkout, working tree is clean, on branch
`main`) → an *environmental atom* plus a validation with `cwd = <location>`, usually no
`params`, `establishes = { cwd = ["org-checkout"] }`. The checker inspects its working
directory. Consumed by `[[program]].requires`. It dies at every call that may change what it
depends on: everything, for `org-checkout = {}`; only what writes `git.config`, for
`org-checkout = { reads = ["git.config"] }` (step 3b).

**D. The state of the world decides something about a value** (URL host is not in the live prod
inventory, repo exists on the remote) → an environmental atom plus a validation with `params`,
established on the parameter. For network rules it defaults to `on-redirect = "stop"`.

Honesty rules:

- `pure = true` iff the verdict depends on the characters of the value and nothing else, forever.
  "Not in today's inventory" is not pure even though it is a function of the text.
- `effect-free = true` iff the checker changes nothing another validation or program could observe.
  Reading files and querying a read-only API is effect-free; `git fetch` is not. Without it, a
  checker kills the environmental atoms established before it, so two checks cannot stack.
- `matches` is the atom's *definition*: anything matching the regex has the property. If a
  matching string could lack the property, it is not a defined atom.
- A defined atom cannot also be established by an environmental route; it is pure by construction.

## Step 3b: regions, media and `writes`

By default every command kills every environmental fact, so a program must check immediately
before each use and can never batch: check, act, check, act. Regions make the kill precise
(EFFECTS.md): a rule declares what it **writes**, an atom what it **reads**, and the fact dies
only where the two meet. Skip this step when the tasks are check-then-act pairs; do it when a
checked fact must outlive an intervening command, or when the same fact gates several commands.

1. **Name the state.** One `[regions]` entry per piece of state a checker can observe and a
   command can change, each with one medium: a `footprint` (where it lives, relative to the
   checking validation's cwd, that path and everything below: `.git/config`, `.git/refs`, `.`
   for the whole working tree) or `network = true`. Give each an `about` line; `--describe`
   prints it. Reuse a shipped vocabulary when one exists (the git pack's `git.*` regions) rather
   than coining a second name for the same state: two names for one piece of state is a missed
   kill.
2. **Say what each atom depends on.** `reads` on every environmental atom, as a property of
   what the atom *asserts*, whatever the checker does: "origin belongs to the org" reads
   `git.config`; "the remote branch is unprotected" reads `network`. An atom without `reads`
   depends on everything.
3. **Bound each tool by medium.** `network = false` on local tools, `write = false` on query
   tools, `effect-free = true` on pure queries. These need no knowledge of regions and already
   preserve the other medium's facts wholesale.
4. **Narrow within the medium** only where the batch needs it: `writes = ["git.refs",
   "git.index"]` on `git commit` is what lets a commit sit between the org check and the push.
   `writes` is admissible only on a rule whose arguments cannot smuggle an option past the shape
   (no open flag vocabulary, no `any` hole outside a flag value or after `--`).

Honesty rules, in addition to the ones above: `writes` is complete when it names every declared
region the tool can change, not every file it touches (`cargo build` writes registries and
caches nobody declared; its write set is `["git.worktree"]` or nothing); `network = false` is a
promise about the tool, not about this invocation. Both are trusted like the rest of the policy.
Read the `dies on:` line `--describe` computes for each atom and confirm it says what you meant.

## Step 4: author the checkers

The contract (details in `reference.md`): the broker runs `argv` with each `${param}` replaced by
the program's argument as one token, no shell, stdin closed, in the validation's `cwd` resolved
under the root (the root itself for a cwd-free validation), on the **host**, as the invoking
user, with the host's environment, outside the jail. Exit `0` establishes the atoms; anything
else refuses, and stderr becomes the error the program sees. Stdout is discarded. Literal
checkers additionally run during analysis, possibly several times per program, so they must be
fast, idempotent and side-effect free.

Rules:

- Parameters come from the confined program: **untrusted**. Compare and parse them; never
  interpolate them into a shell string or pass them to `eval`.
- Fail closed: `set -euo pipefail`; check the argument count; any unexpected condition exits
  non-zero with a one-line reason on stderr.
- Install checkers in `~/.certorail/checkers/<name>`, mode `0755`, and reference them as
  `argv = ["${checkers}/<name>", ...]`: the loader resolves it against the config directory and
  fails at load if the checker is missing, so the policy spells no home directory and travels
  between users.
- Checkers are trusted code with the host's authority. Review them like the policy; the whole
  of `~/.certorail/` is the review unit.

Templates:

```bash
#!/usr/bin/env bash
# org-checkout: the working directory is a checkout whose origin is in the certora org.
# Validation: cwd = "repos/**", no params, establishes = { cwd = ["org-checkout"] }, effect-free.
set -euo pipefail
[ "$#" -eq 0 ] || { echo "org-checkout: takes no arguments" >&2; exit 2; }
url="$(git -C . remote get-url origin 2>/dev/null)" || { echo "not a git checkout" >&2; exit 1; }
case "$url" in
  https://github.com/certora/*|git@github.com:certora/*) exit 0 ;;
  *) echo "origin is $url, not a certora repository" >&2; exit 1 ;;
esac
```

```python
#!/usr/bin/env python3
"""not-prod-db: the URL's host is not in the production inventory.
Validation: params = ["url"], no cwd, establishes = { url = ["not-prod-db"] }, effect-free.
The inventory changes, so the atom is ENVIRONMENTAL (not pure): programs check right before use."""
import json
import pathlib
import sys
import urllib.parse

INVENTORY = pathlib.Path("/etc/org/prod-hosts.json")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: not-prod-db URL", file=sys.stderr)
        return 2
    host = urllib.parse.urlsplit(sys.argv[1]).hostname or ""
    prod = set(json.loads(INVENTORY.read_text(encoding="utf-8")))
    if host in prod:
        print(f"{host} is a production database host", file=sys.stderr)
        return 1
    return 0


sys.exit(main())
```

A trivial text predicate can be a `test` one-liner with no script at all:
`argv = ["test", "${value}", "!=", "--force"]`. Anything beyond an equality belongs in a script.

## Step 5: verify

1. **Load.** `certorail -c "pass" --check --policy policy.toml --root ROOT`. Every schema
   error is reported at once; fix them all.
2. **Checkers.** Run each directly with a good and a bad input; confirm exit codes and the stderr
   line.
3. **Probes.** Write a small program in the subset per grant (see `SUBSET_PROMPT.md`) and
   `certorail probe.py --check --policy policy.toml --root ROOT`. The accepted report lists every
   sink with its proven location: read it. Then write one probe that oversteps each grant and
   confirm the `denied:` line. Literal checkers run during `--check` under `--root`, so the root
   and any directory a cwd-slot checker names must exist. If the policy declares regions, one
   probe should be the batch they exist for (check, then the preserving commands, then the
   gated one) and one its rejection (check, a killing command, the gated one).
4. **Install.** The config directory is `$CERTORAIL_CONFIG_DIR`, else
   `$XDG_CONFIG_HOME/certorail`, else `~/.certorail`. Checkers go in `checkers/` under it.
   Policies go in `policy/<munged root>/`, the root with `/` turned into `-`
   (`/srv/work/repo` → `policy/-srv-work-repo/`), as `*.toml` files each carrying
   `root = "/srv/work/repo"`. A run rooted there, or below, then prints
   `certorail: policy from …`. Two files claiming the same root is an error. `--policy path`
   bypasses discovery for a one-off.
5. **Put the policy in the agent's context.** `certorail --describe --root ROOT` renders the
   loaded policy as the program author's interface. Install it as a Claude Code `SessionStart`
   hook in the project's `.claude/settings.json` (the JSON is in `reference.md`), so every
   session, resume and compaction re-reads what is permitted instead of guessing.
6. **Hand over.** The commented TOML, the checkers, the run commands, and an explicit list of
   what is *not* granted. The program-author note is now `--describe`'s output; add only what it
   cannot know (which checker to prefer, conventions).

## Pitfalls

- A flat rule takes no arguments at all; the moment a program needs one, the rule is a template.
  A hole with `location` denies a computed argument — an f-string, `.strip()` — since that is no
  proven path; a hole with `atoms` denies a value nothing checked.
- Atoms are declared once in `[atoms]`; a name used in `establishes`, `requires`, a hole's
  `atoms` or `[[network]].requires` without a declaration is an error. The five built-ins
  (`not-option`, `no-slash`, `no-parent-traversal`, `not-absolute`, `not-dot-dot`) may be named
  anywhere an atom may and may not be declared.
- A program spells provenance as `certora.source("x")`, a checked property as
  `certora.validated("x")`; mixing them up is a contract error the report names.
- A cwd-free validation cannot establish atoms on `cwd`; a validation with `cwd` requires the
  program to pass a proven `cwd=`.
- `certora.check_single` needs a validation with exactly one parameter; inside a comprehension
  only pure atoms accumulate.
- `<regex>` components are full matches. `**` appears once, last or followed by one leaf. `.` is
  the root directory itself; `**` is at or below the root.
- `[[network]]` `schemes` defaults to `https` only; an empty `ports` means the scheme's default
  port only; `requires` with an explicit `on-redirect = "recheck"` on a non-textual atom is an
  error.
- A guarantee from a contracted function lands only when the call is the whole right side of an
  assignment; probes that inline the call (`base / f(x)`) see an unknown value.
- A template with a variadic hole that is not last binds by keyword: the program spells
  `certora.exec("tar", FLAGS=[...], FILES=[...], cwd=root)`, not a positional list. Put the
  variadic hole last when the tool allows it.
- Regions are declared once in `[regions]`; a `writes` or `reads` naming an undeclared region is
  an error, and so is a `writes` outside the rule's media, or on a rule with an open flag
  vocabulary / an unguarded `any` hole.
- A validation without `cwd` cannot establish an atom that reads a filesystem region.
- The program's own file writes still kill every environmental atom that reads any filesystem
  region; only exec, network and check rules have precise write sets today.

## Worked example

Need: scripts clone repositories under `repos/`, inspect them, write reports, commit and push
to branches whose names come from the command line, but only to certora-org checkouts and never
with a flag-shaped branch argument; they read the GitHub API. Commit-then-push must work
without re-checking in between. Sandbox root `/srv/work/audit`, so the file is
`~/.certorail/policy/-srv-work-audit/audit.toml` and the checker is
`~/.certorail/checkers/org-checkout`.

```toml
policy-version = 1
root = "/srv/work/audit"

[filesystem]
read  = ["repos/**", "reports/**"]           # inspect clones, re-read earlier reports
write = ["repos/**", 'reports/**/<\w+\.md>'] # clones + markdown reports only
list  = ["repos/**", "reports/**"]

[regions]                                    # step 3b: the state the checks depend on
git.config = { footprint = ".git/config", about = "remotes, hooks: everything git reads from config" }
git.refs   = { footprint = [".git/refs", ".git/packed-refs"], about = "local and remote-tracking refs" }
git.index  = { footprint = ".git/index",  about = "the staging area" }
git.remote = { network = true, about = "the remote repository" }

[atoms]
org-checkout = { reads = ["git.config"] }    # C: dies only when git.config may have changed
no-flag      = { matches = '[^-].*' }        # A: a branch argument is not an option

[[validation]]
name        = "org-repo"
argv        = ["${checkers}/org-checkout"]
cwd         = "repos/**"
effect-free = true
establishes = { cwd = ["org-checkout"] }

[[program]]                                  # clone into repos/ from its parent
name      = "git"
argv      = ["git", "clone", "--", "${URL}", "${DIR}"]   # the "--" exempts URL from the dash guard
cwd       = "repos"
holes.URL = { any = true }                   # clone URLs come from the API; so no `writes`
holes.DIR = { location = "*" }               # one name, directly under repos/

[[program]]
name        = "git"
subcommand  = "log"
cwd         = "repos/**"
effect-free = true

[[program]]                                  # local: no network, and within the fs only these
name       = "git"
subcommand = "add"
cwd        = "repos/**"
network    = false
writes     = ["git.index"]

[[program]]
name       = "git"
subcommand = "commit"
cwd        = "repos/**"
network    = false
writes     = ["git.refs", "git.index"]       # not git.config: a commit preserves org-checkout

[[program]]                                  # a template: the shape, with the branch a hole
name         = "git"
cwd          = "repos/**"
requires     = ["org-checkout"]
argv         = ["git", "push", "origin", "${BRANCH}"]
holes.BRANCH = { atoms = ["no-flag"] }       # certora.exec("git", "push", "origin", branch, cwd=repo)
writes       = ["git.remote", "git.refs"]

[[program]]                                  # find, with exactly these flags and nothing else
name  = "find"
cwd   = "."
argv  = ["find", "${WHERE}", "${FLAGS...}"]  # certora.exec("find", where, "-name", "*.md", "-print", cwd=root)
holes.WHERE = { location = "repos/**" }
holes.FLAGS = { kind = "flags", bare = ["-print"], "-name" = { matches = '[^/]+' }, "-maxdepth" = { matches = '\d+' } }
effect-free = true

[[network]]
host    = "api.github.com"
methods = ["GET"]                            # GET/HEAD only: writes nothing by default
```

`--describe` then reports, for `org-checkout`, `depends on git.config; dies on: git clone; file
writes under .git/config (below the check's cwd)`: the commit and the push are not on the list,
so `check("org-repo")`, `git add`, `git commit`, `git push` is one accepted sequence.

Program-author note to append to their prompt (the rest is `--describe`'s output): *"Call
`certora.check("org-repo", cwd=<path under repos/>)` once per repository before the git
sequence; `git add`/`commit` preserve it, `git clone` and any file write do not. Atom
`no-flag` is `[^-].*`: guard branch names with `assert re.fullmatch(r"[^-].*", branch)`; the
same guard shows the name does not begin with `-`, which the push's `BRANCH` hole requires.
Clone as `certora.exec("git", "clone", "--", url, name, cwd=pathlib.Path("repos"))`."*
