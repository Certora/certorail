# Setting up certorail

Two commands, the second an interview:

```
uv tool install certorail          # or, from a checkout of this repository: uv tool install .
certorail init                     # from the directory you want governed
```

`certorail init` is deterministic and asks before it writes anything. Its first half is for the
machine and happens once: it reports any prerequisite the jails need, with the command that
installs it; installs the ruleset pack shipped with certorail (`coreutils`: the read-only
coreutils, every rule OS-jailed); offers the base ruleset that gives every project those tools;
and, when Claude Code is on PATH, offers to register the certorail plugin and to allow
`certorail-run` without a prompt. Its second half writes the directory's policy: inherit the base
or opt out, full access or locations per kind, allow unnamed programs or not. Every question has
a default; `certorail init --yes` takes them all, and a step already done is not asked again.

Everything trusted lands in one auditable place, the config directory (`$CERTORAIL_CONFIG_DIR`,
else `$XDG_CONFIG_HOME/certorail`, else `~/.certorail`), and everything gets there through
`certorail policy …`, which validates before it places and refuses conflicts instead of
overwriting them. `certorail --help` for the run commands; `certorail policy --help` for the
installer.

## Prerequisites

`init` reports what is missing and never runs `sudo` or `npm` itself.

- `uv` installs and runs the tool.
- `bwrap` (bubblewrap), on Linux, is the jail: around the program certorail runs and around the
  tools a policy grants. `sudo apt install bubblewrap` on Debian and Ubuntu, or your
  distribution's package. macOS needs nothing: the system's Seatbelt does both jobs.

The program certorail runs is always jailed: no network, writes only within the policy's write
grants, no processes of its own; on Linux certorail warns and runs the program unjailed when
`bwrap` is missing. The tools a policy grants are jailed whenever a rule says `network = false`,
`write-fs = false` or `exec.spawn = false`. Those keys are enforced, not declared: a rule carrying
one runs its tool inside the jail, and if the jail is missing the tool does not run at all (the
program gets a broker error naming it) rather than running unconfined. Every rule in the coreutils
pack carries all three, so without bubblewrap the first `ls` or `grep` under it fails closed. Any
packaged bubblewrap works (Ubuntu 24.04 ships 0.9); the optional writable overlay for build tools
(`MOUNTS.md`) wants 0.10, a source build today. Inside a container, bubblewrap needs
unprivileged user namespaces, which some container runtimes disable.

## Ruleset packs

A pack is a directory of ruleset TOML plus the checker programs it runs. `certorail policy
install` takes a shipped pack by name, a pack directory, or a policy file:

```
certorail policy install coreutils          # shipped in the wheel: init does this for you
certorail policy install rulesets/git       # from a checkout: the git rungs, seven checkers, git.md
```

The git pack is not in the wheel yet; a checkout is its install path for now. Install validates
the pack before anything lands: every ruleset's shape, the checker closure in both directions
(everything referenced supplied, nothing supplied unreferenced), and any validation `pin` against
the exact checker bytes. `certorail policy list` shows what is installed and names the shipped
packs that are not; `certorail policy verify` re-hashes every pinned checker later.

Installing a pack grants nothing by itself: nothing applies a ruleset until a policy does. The
**base ruleset** is the exception `init` offers: `rulesets/base.toml` in the config directory
applies `coreutils-ro.toml` to every root that does not say `base = false`, so agents have the
read-only tools they reach for everywhere. By hand it is two lines:

```toml
ruleset-version = 1

[[apply]]
ruleset = "coreutils-ro.toml"
where   = "."
```

`--check`, `--describe` and every rejection say when it was composed in.

## A policy per project

A policy is a TOML file declaring what confined programs may read, write, list, exec and fetch,
rooted at one directory. `init` writes the first one; author or refine it with the
`certorail-policy` skill (below) or by the reference in `plugins/certorail/skills/certorail-policy/`;
then:

```
certorail policy install my-policy.toml
```

The full load runs first, against your installed rulesets and checkers, and the validated bytes
are placed for the absolute `root` the file declares. Two files claiming one root are refused. From
then on, any `certorail` run at or below that root finds the policy ambiently; `--check` and every
rejection name the file, an accepted run stays quiet. `certorail policy apply git.toml where=. ...`
brings an installed ruleset into the policy with its bindings, asking for any the load says are
missing.

To change an installed policy, `certorail policy edit` (from anywhere under its root, or with
`--root DIR`) opens it in `$VISUAL` or `$EDITOR` on a copy. When the editor exits, the copy is
loaded against the installed tree; it replaces the original only if it loads and still declares
the same root. Otherwise you see the problems and choose to edit again or discard.

## Claude Code integration

The plugin ships two pieces for two readers. For the agent that writes programs: a
`SessionStart` hook running `certorail session-hook`, which injects the program-author guide
(the confined subset and the policy vocabulary) followed by the ambient policy's description,
and stays silent in projects no policy governs. For whoever writes policies: the
`certorail-policy` authoring skill.

The plugin ships inside the package, as the marketplace directory `certorail/plugin/`, and
`init` registers it from there when `claude` is on PATH:

```
claude plugin marketplace add <site-packages>/certorail/plugin
claude plugin install certorail@certorail
```

Claude Code loads a plugin from a local marketplace in place, so the installed package is the
plugin: upgrading the tool upgrades it, nothing is fetched, and no repository is involved. The
checkout works the same way (`claude plugin marketplace add /path/to/checkout`, whose manifest
points at the same files), and `claude --plugin-dir /path/to/checkout/certorail/plugin/plugins/certorail`
loads it for one session without installing. Without the plugin, register the hook yourself in
`.claude/settings.json`:

```json
{"hooks": {"SessionStart": [{"matcher": "startup|resume|clear|compact",
  "hooks": [{"type": "command", "command": "certorail session-hook"}]}]}}
```

`init` also offers the permission rule `Bash(certorail-run *)`, merged into `permissions.allow`
of your user settings. Running work through the jail should be the path of least resistance, and
`certorail-run`'s interface is closed: the rule admits a program and its arguments and nothing
else, where `certorail -c` would also admit `--policy`, `--root` and `--no-jail`. Leave
`certorail policy` prompting: changing what is trusted should never be frictionless.

## Day two

- `certorail describe --root DIR` -- the policy's interface, as the program author sees it.
- `certorail explore --root DIR` -- the same policy as a navigable tree: drill into a rule,
  its holes, each constraint, and every atom's cross-references.
- `certorail policy verify` -- re-hash every pinned checker; run it whenever the config
  directory might have been touched by hands other than the installer's.
