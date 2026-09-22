# Setting up certorail

Four steps: install the tool, install the shipped ruleset packs, give each project a policy,
and put the policy into your agent's context. Everything trusted lands in one auditable place,
the config directory (`$CERTORAIL_CONFIG_DIR`, else `$XDG_CONFIG_HOME/certorail`, else
`~/.certorail`), and everything gets there through `certorail policy …`, which validates
before it places and refuses conflicts instead of overwriting them.

## 1. The tool

From a checkout of this repository:

```
uv tool install .
npm install -g @anthropic-ai/sandbox-runtime   # srt: the OS jail around the program; certorail warns without it
sudo apt install bubblewrap                    # Linux: the jail around the tools a policy grants (see below)
```

`certorail --help` for the run commands; `certorail policy --help` for the installer.

**Step 3 has a short way**: `certorail init` from the project directory is a deterministic
interview that writes the directory's policy through the installer -- inherit the base ruleset
or opt out, full access or locations per kind -- and then lists the installed rulesets the base
does not apply. `certorail policy apply git.toml where=. ...` brings one into the policy with
its bindings, asking for any the load says are missing; `certorail policy list` describes what is
installed. `init` installs nothing itself; steps 1 and 2 are still yours.

**Two jails, two prerequisites.** srt confines the *program* certorail runs; bubblewrap
(`bwrap`, on macOS the system's `sandbox-exec`, nothing to install) confines the *tools* a
policy grants whenever a rule says `network = false`, `write-fs = false` or `exec.spawn =
false`. Those keys are enforced, not declared: a rule carrying one runs its tool inside
bubblewrap, and if `bwrap` is missing the tool does not run at all -- the program gets a broker
error naming it -- rather than running unconfined. Every rule in the coreutils pack carries
all three, so without bubblewrap the first `ls` or `grep` under it fails closed. Any packaged
bubblewrap works (Ubuntu 24.04 ships 0.9); the optional writable overlay for build tools
(`MOUNTS.md`) wants 0.10, which is a source build today. Running inside a container, note that
bubblewrap needs unprivileged user namespaces, which some container runtimes disable.

## 2. The shipped packs

Ruleset packs are directories under `rulesets/` in this repository -- parameterised exec-side
vocabulary plus the checker programs it runs:

```
certorail policy install-pack rulesets/git         # the git rungs + seven checkers + git.md
certorail policy install-pack rulesets/coreutils   # read-only coreutils, every rule OS-jailed
```

Install validates the pack before anything lands: every ruleset's shape, the checker closure
in both directions (everything referenced supplied, nothing supplied unreferenced), and any
validation `pin` against the exact checker bytes. `certorail policy list` shows what is
installed; `certorail policy verify` re-hashes every pinned checker later.

Installing a pack grants nothing by itself: nothing applies a ruleset until a policy does.

**Optional, recommended: a base ruleset.** Create `rulesets/base.toml` *in your config
directory* (no repository ships one -- turning it on is your act) to give every root the
read-only tools agents reach for everywhere:

```toml
ruleset-version = 1

[[apply]]
ruleset = "coreutils-ro.toml"
where   = "."
```

`--check`, `--describe` and every rejection say when it was composed in, and `base = false` in
any policy opts that root out.

## 3. A policy per project

A policy is a TOML file declaring what confined programs may read, write, list, exec and
fetch, rooted at one directory. Author it with the `certorail-policy` skill (below) or by the
reference in `plugins/certorail/skills/certorail-policy/`; then:

```
certorail policy install my-policy.toml
```

The full load runs first -- against your installed rulesets and checkers -- and the validated
bytes are placed for the absolute `root` the file declares. Two files claiming one root are
refused. From then on, any `certorail` run at or below that root finds the policy ambiently;
`--check` and every rejection name the file, an accepted run stays quiet.

To change an installed policy, `certorail policy edit` (from anywhere under its root, or with
`--root DIR`) opens it in `$VISUAL` or `$EDITOR` on a copy. When the editor exits, the copy is
loaded against the installed tree; it replaces the original only if it loads and still declares
the same root. Otherwise you see the problems and choose to edit again or discard.

## 4. Claude Code integration

The plugin ships the two pieces an agent needs -- the ambient policy injected into every
session's context (a `SessionStart` hook running `certorail session-hook`, silent in projects
no policy governs), and the `certorail-policy` authoring skill:

```
claude plugin marketplace add certora/certorail     # or the path to your checkout
claude plugin install certorail@certorail
```

For development, `claude --plugin-dir /path/to/certorail/plugins/certorail` loads it without
installing. Without the plugin, register the hook yourself in `.claude/settings.json`:

```json
{"hooks": {"SessionStart": [{"matcher": "startup|resume|clear|compact",
  "hooks": [{"type": "command", "command": "certorail session-hook"}]}]}}
```

A useful pairing in your permission settings: allow `certorail-run` (running work through the
jail should be the path of least resistance, and its interface is closed: `Bash(certorail-run *)`
admits a program and its arguments and nothing else, where `certorail -c` would also admit
`--policy`, `--root` and `--no-jail`) and leave `certorail policy` prompting (changing what is
trusted should never be frictionless).

## Day two

- `certorail --describe --root DIR` -- the policy's interface, as the program author sees it.
- `certorail-explore --root DIR` -- the same policy as a navigable tree: drill into a rule,
  its holes, each constraint, and every atom's cross-references.
- `certorail policy verify` -- re-hash every pinned checker; run it whenever the config
  directory might have been touched by hands other than the installer's.
