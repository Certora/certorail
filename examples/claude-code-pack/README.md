# The certorail Claude Code pack

A certorail rejection reaches a coding agent as an exit code and one line of prose, which is
nothing it can act on -- so it retries the command, moves the file, or reaches for a shell, and
all three are refused identically. This pack runs `certorail explain` at that moment and hands
the explanation back to the model, with the two legitimate remedies named.

Nothing here is specific to a machine, a checkout or a workspace: every path comes from an
argument or an environment variable with a documented default.

## Install

```
python3 examples/claude-code-pack/install.py
```

| Argument | Default | Meaning |
|---|---|---|
| `--pack-dir DIR` | the directory holding `install.py` | which pack to install |
| `--home DIR` | `$HOME` | the home directory to install into |
| `--claude-dir DIR` | `$CLAUDE_HOME`, else `<home>/.claude` | Claude Code's config directory |
| `--dry-run` | off | print the plan, write nothing |
| `--uninstall` | off | undo a previous install, from its record |
| `--quiet` | off | print only errors |

`pack.toml` is the manifest and the source of truth: every path the installer touches is a wiring
step in it. `install.py` knows three verbs -- `write_file`, `symlink`, `json_merge` -- and nothing about
Claude Code. Variables in the manifest are `$PACK_DIR`, `$REPO_DIR`, `$HOME` and `$CLAUDE_DIR`;
any other `$NAME` is an error rather than an empty string, because a wiring step that quietly
wrote to the wrong place would be worse than one that refused.

Installing twice is a no-op. What the install did is recorded in `$CLAUDE_DIR/certorail-pack.json`.

## What each wiring step touches

| Step | Destination | Without it |
|---|---|---|
| `write_file` | `$CLAUDE_DIR/certorail/explain_hook.py` | there is no hook script to run |
| `symlink` | `$CLAUDE_DIR/skills/certorail-policy` → `$REPO_DIR/.claude/skills/certorail-policy` | the model has no reference for the policy language when it goes to widen one |
| `json_merge` | `$CLAUDE_DIR/settings.json` | nothing calls the hook |

The symlink means the checkout stays the single copy: pulling the repo updates the skill.

## Why it merges

`~/.claude/settings.json` belongs to the user and usually already holds their own hooks,
environment and permissions. The installer deep-merges into it and *appends* to its arrays rather
than replacing them, and records exactly what it appended so uninstall removes exactly that.
Overwriting that file -- or replacing the array that holds every hook configured for an event this
pack also uses -- is the failure this example exists to prevent.

The installer also refuses to overwrite a file it did not write, or one that has changed since it
wrote it. Move such a file aside and install again.

## Uninstall

```
python3 examples/claude-code-pack/install.py --uninstall
```

The records are replayed in reverse, so nothing has to be re-derived and a `pack.toml` that has
moved on since the install cannot strand anything. The settings file gets back exactly the entries
that were added, and keeps everything else. A written file that has been edited since the install
is left in place and reported, rather than deleted.

## The hook's contract

It fires on `PostToolUse` and `PostToolUseFailure` for `Bash`, and stays silent -- no output,
exit 0 -- unless all of these hold:

1. the payload names a Bash command that invoked `certorail` (parsed with `shlex`, not matched as
   text; `python -m certorail.host` is deliberately not recognised);
2. the tool's output carries certorail's own rejection marker, `": rejected"`;
3. a `certorail` is on PATH;
4. `certorail explain`, run on that invocation's own arguments, exits 1 -- rejected.

It runs `certorail explain` with that invocation's own arguments -- the program or `-c`, `--root`,
`--policy` -- minus `--check` and `--no-jail`, and minus anything after a bare `--`, which belongs
to the program rather than to certorail. `explain` never runs the program.

The marker in (2) is a heuristic: output that quotes some other tool's refusal carries it too, and
so does a confined program that printed it. (4) is what makes the injection honest -- the preamble
tells the model its program was refused, so the verdict comes from `explain`'s own exit status.

Every other outcome is silence: an unrecognised payload, no certorail, an explain that fails or
says nothing. A hook should never be the reason a session breaks. `CERTORAIL_BIN` names the
binary to call when it is not on the hook process's PATH as `certorail`.

Two events for one script because a `certorail` run that exits 1 may reach the agent as a failed
tool call or as a successful call whose output carries the rejection; the script echoes back
whichever event name the payload gave it.

## Running the smoke test

```
python3 -m unittest tests.test_claude_code_pack -v
```

from the repo root. Every install it runs is given an explicit `--home` and `--claude-dir` under
a temporary directory, so it touches nothing of the user's -- not even with `$CLAUDE_HOME` set.

## A policy to try it against

```toml
policy-version = 1

[filesystem]
read  = ["data/**"]
write = ["data/**"]
list  = ["data/**"]
```

Against that policy, from a sandbox root with a `data/` directory:

```
certorail -c 'import pathlib
pathlib.Path("secrets.txt").read_text()
' --root . --policy policy.toml --check
```

is rejected with `read of secrets.txt is not permitted`, and

```
certorail explain -c 'import pathlib
pathlib.Path("secrets.txt").read_text()
' --root . --policy policy.toml
```

says the same thing with the two remedies: `add "secrets.txt" to [filesystem] read`, or move the
read under `data/**`. With the hook installed, an agent that ran the first command gets the second
command's output without having to know it exists.
