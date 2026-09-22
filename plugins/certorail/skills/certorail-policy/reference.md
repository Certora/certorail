# certorail policy reference

The policy is a TOML document (JSON with the same shape is accepted too). The schema is strict
and fails closed: unknown keys, undeclared atoms or regions, malformed locations and mistyped
values are errors, and every error in the document is reported, not just the first. Every key
that takes a list of strings also takes one string, meaning the list of one (`read = "**"`,
`writes = "git.refs"`, `requires = "org-checkout"`); `ports` likewise takes one integer.

```toml
policy-version = 1
root = "/srv/work/repo"            # ambient policies only: the sandbox root this file governs
base = true                        # the default: the installed base ruleset applies (below)
default-allow = false              # the default: a program the policy does not name is denied (below)

[filesystem]
read  = ["**"]
write = ["repos/**"]
list  = ["repos/**"]

[regions]                          # the state checks depend on and commands change (quote dotted names)
"git.config" = { footprint = ".git/config", about = "remotes, hooks: everything git reads from config" }
"git.refs"   = { footprint = [".git/refs", ".git/packed-refs"], about = "local and remote-tracking refs" }
"git.remote" = { network = true, about = "the remote repository" }

[atoms]
org-checkout = { reads = ["git.config"] }  # environmental: dies when git.config may have changed
not-force    = { pure = true }             # pure, established by a checker
no-flag      = { matches = '[^-].*' }      # defined: the regex is its meaning (pure)

[[validation]]
name        = "not-force-check"
params      = ["value"]
argv        = ["test", "${value}", "!=", "--force"]
writes      = []                           # a pure text predicate changes nothing
establishes = { value = ["not-force", "not-option"] }   # also vouches the value is no option

[[program]]
name       = "git"
subcommand = "commit"
cwd        = "repos/**"
network    = false                         # a claim about the tool: it writes no network region
writes     = ["git.refs"]                  # and within the filesystem, only this

[[program]]
name         = "git"
argv         = ["git", "push", "origin", "${BRANCH}"]
cwd          = "repos/**"
requires     = ["org-checkout"]
holes.BRANCH = { atoms = ["not-force"] }
writes       = ["git.remote", "git.refs"]

[[network]]
host    = "api.github.com"
methods = ["GET"]
```

## Locations

Components separated by `/`. Each component is a literal name, `*` (any one name), `{a,b}`
(one of the names), or `<regex>` (a full match of one name; raw regex, may contain `/`). Note
that `*.py` is a literal name: only a bare `*` is a wildcard, so "any `.py` file" is
`<.*\.py>`.

A `<regex>` is a Python regex. Under `exec.view = "policy"` on macOS it is also handed to
Seatbelt, which reads POSIX ERE, and the two dialects agree only on a subset: literals, `.`,
`[...]` of literals and ranges, `|`, plain groups, greedy `* + ? {n,m}`, `^` and `$`. A `<regex>`
using anything else (`\d`, `\w`, `\s`, `(?...)`, lookarounds, backreferences, lazy or
possessive quantifiers, non-ASCII) has no Seatbelt spelling: the location is omitted from the
view and the host says so at startup. Write `[0-9]` where you would write `\d`. The translation
is generated from Python's own parse of the pattern, so what does translate means the same
thing on both sides, with one known exception: `.` in ERE also matches a newline.

| Spelling | Meaning |
|---|---|
| `.` or `""` | the root directory itself |
| `data/x.txt` | exactly that path |
| `repos/*` | any direct child of `repos` |
| `repos/{a,b}` | `repos/a` or `repos/b` |
| `repos/**` | `repos` and anything at or below it |
| `repos/**/*` | anything strictly below `repos`, not `repos` itself |
| `reports/**/<\w+\.json>` | a `.json`-named entry anywhere below `reports` (the leaf after `**` is exactly one component) |
| `/srv/data/**` | anchored at the *filesystem* root |

`**` appears at most once, as the last component or followed by exactly one leaf. No `..`, no
empty components. Programs use the same spelling to prove a dynamic path is at a location:
`assert certora.pathmatch(p, "repos/*/foundry.toml")`, and for a URL
`certora.pathmatch(urllib.parse.urlsplit(u).path, "/repos/**")`; the description hands them the
text to quote. A relative location is under the sandbox root (`--root`, the program's working
directory). Absolute and relative locations never relate: an absolute grant says nothing about
relative paths and vice versa. A program's literal beginning with `/` is an absolute path.

## `default-allow`

`default-allow = true` at the top of a root policy (a ruleset has no such key) flips the
posture for programs the policy does not speak about: a `certora.exec` of a program that **no
`[[program]]` rule and no `[[deny]]` names** runs, with any arguments, with the user's
authority -- unjailed, its effects unknown, so every environmental fact dies at it. A program
the policy *does* name is governed exactly as without the key: its listed shapes and nothing
else, fail closed. `[[deny]] argv = ["rm"]` names a program without granting it a shape, which
under default-allow is the first-verb blacklist.

The classification is the **leading program name and nothing finer**. That is deliberate: a
`git log` grant beside default-allow does not mean "other git invocations are allowed", because
`git -C x push` accomplishes a `git push` without ever parsing as one, and no shape matching
could say so soundly. Naming a program takes responsibility for all of it.

What the key does not change: the cwd is still a sink that must be proven; the program's own
filesystem operations are still held to `[filesystem]` (whose `read`/`write`/`list` default to
the whole root under this key, matching an agent's ordinary permissions, while a written `[]`
stays nothing and `no-write` protections still bind); network is still `[[network]]` only. Every
run says on stderr that default-allow is on, and `--describe` lists the rule last under
Programs.

## `[filesystem]`

`read`, `write`, `list`: lists of locations; absent means nothing of that kind is permitted
(under `default-allow`, below, absent means the whole root, and a written `[]` still means
nothing).
`no-write`: locations **protected** from program writes whatever `write` grants -- a write whose
path *may* lie at or below one is denied, by an at-or-below alignment of the two locations. A
`*` component may be anything, `.git` included, so under `repos/**/.git` a
dynamic component needs a regex that cannot spell the name in any case: prove the path with
`certora.pathmatch(p, r"repos/x/<\w+>")` or `"repos/<[^.].*>/README.md"`, not `"repos/x/*"`.
An applied ruleset may protect
too (`[filesystem] no-write = ["${where}/**/.git"]`), which is how the git pack keeps a program
out of repository configuration and hooks without asking the root to spell the exclusion; a
protection that is one concrete directory is also lowered into the OS jail's write denials.
The kinds, as the analysis classifies program operations:

| Kind | Operations |
|---|---|
| read | `open` for reading, `Path.open` for reading, `read_text`, `read_bytes` |
| write | `open` with a writing mode, `write_text`, `write_bytes`, `mkdir`, `touch`, `chmod`, `replace` (the path *and* its target), `link_to` (the target) |
| list | `os.listdir`, `os.walk`, `os.path.exists/isfile/isdir`, `iterdir`, `glob`, `rglob`, `exists`, `is_file`, `is_dir` |

Everything else on the filesystem (`unlink`, `rename`, `shutil`, archives, …) is unavailable to
programs regardless of policy.

## `[regions]`

A region names a piece of state that a checker can observe and a command can change. Regions
are the vocabulary in which a rule says what it **writes** and an environmental atom says what
it **reads**; an environmental fact dies at a call exactly when the call's write set meets the
atom's read set (EFFECTS.md). Declare every region before use, once; two files (a policy and a
ruleset, two rulesets) declaring the same name identically mean the same region, differently is
an error.

| Key | Type | Meaning |
|---|---|---|
| `footprint` | location or list | the region's medium is the **filesystem**: where its state lives (`.git/config`), for the reader. A footprint means that path *and every descendant*: write `.git/refs`, never `.git/refs/**`. The kill does not consult it: a program's own file write is a write of the whole filesystem medium, wherever it lands |
| `network` | `true` | the region's medium is the **network**: its state is remote |
| `about` | string | one line for `--describe` |

Exactly one of `footprint` and `network = true`. The two medium names, `fs` and `network`, are
reserved and stand in any `reads` or `writes` list for every region of that medium.

## `[atoms]`

Every fact name used anywhere is declared here, once. A name maps to a table:

| Form | Meaning |
|---|---|
| `name = {}` | environmental: true of the world; depends on everything, so it dies at every call that writes anything |
| `name = { reads = ["git.config"] }` | environmental, with its dependencies named: dies only at a call whose write set meets these regions (or the medium named: `reads = ["network"]`). The set is a property of what the atom *asserts*, however it is checked |
| `name = { pure = true }` | pure: a property of the value's text; survives calls, dies with the value. Equivalent to `reads = []` |
| `name = { matches = 'regex' }` | defined: the regex *is* the property; pure by construction (`pure = false` or `reads` here is an error). Any value whose text is known to match carries it with no check; a program guard `re.fullmatch(r"<same regex text>", v)` establishes it on a dynamic value |

## `[[validation]]`

| Key | Type | Meaning |
|---|---|---|
| `name` | string, required, unique | what programs name in `certora.check(name, …)` |
| `params` | list of strings | the keyword parameters programs pass; unique; `cwd` is not allowed as a name |
| `argv` | list of strings, required | the checker command; the first piece is a literal program: `${checkers}/<name>` (the executable `<name>` in the config directory's `checkers/`, resolved at load, which must exist), an absolute path, or a name on `PATH`; a piece that is exactly `${param}` is replaced by that argument; `${…}` inside a larger piece is an error |
| `cwd` | location or list | where the check may run (any of them); programs must pass a proven `cwd=` within one. **Omit** for a check that does not care where it runs: programs then omit `cwd=` and the check cannot establish on `cwd`. A validation without `cwd` cannot establish an atom that reads a filesystem region (the read would have no place) |
| `establishes` | table: param name or `cwd` → list of atom names | what success establishes on which argument |
| `network`, `write-fs` | bool, default true | the media the checker reaches; `false` is **enforced**: the checker runs jailed out of that medium (Media and `writes`, below) |
| `writes` | list of regions | what the checker's run writes, within its media; `[]` for a checker that changes nothing (below) |
| `exec` | table | the rest of the jail: `env`, `spawn` (Jailing a grant, below) |
| `pin` | string | optional: `"sha256:"` + 64 hex, the digest of the evaluator bytes this assertion was reviewed with (`certorail policy pin` computes it; only a `${checkers}/` evaluator is pinnable). Verified at load against the installed checker, and the run executes a snapshot of the verified bytes, so the installed file drifting afterwards changes nothing |

A validation is a **literal checker** when it is effect-free (its write set is empty: `writes =
[]`, or both media `false`), establishes a pure atom, and has exactly one input slot (one param,
or no params plus `cwd`). The host then runs it at analysis time on statically-known text, so
constants carry the atom without any `certora.check` in the program (cached per atom and text;
for the `cwd` slot the directory `root/<text>` must exist). It runs under the validation's jail.

## Media and `writes`

The evaluator a validation spawns, the tool a `[[program]]` grant runs and a `[[network]]`
request are all effects; what each one may change is its **write set**, and it is declared in
two layers. The first is enforced, the second trusted like the rest of the policy:

- **Media** (`[[program]]`, `[[validation]]`): `network = false` says the tool does not reach the
  network, `write-fs = false` that it does not write the filesystem. Each removes every region of
  that medium from the write set with no region named, and each is a property of the process:
  the broker runs the tool in an OS jail that denies the medium (bubblewrap on Linux, Seatbelt on
  macOS). Local git work is `network = false`; `grep` is both.
- **`writes = [regions]`** (`[[program]]`, `[[validation]]`, `[[network]]`): the regions the
  effect may change, within the media. A claim, since no jail can see regions. A region outside
  the declared media is a load error (`git add` cannot write `git.remote` under
  `network = false`). Undeclared means *every* region of the media, so a bare grant with neither
  key kills every environmental atom. `writes = []` is the empty write set: the grant reaches its
  media and changes nothing an atom depends on -- a query tool that phones an API (`gh pr view`),
  a checker that reads the inventory, `cargo metadata` writing only its caches. A medium name
  stands for the whole medium: `writes = ["network"]`.

There is no key for "changes nothing": a grant is **effect-free** (kills no atoms) when its write
set is empty, whether by `writes = []` or by reaching neither medium. The retired spellings
`effect-free = true` and `write = false` are load errors that name their replacements.

Only a rule whose arguments cannot smuggle an option or a subcommand past the shape may declare
`writes`: no open flag vocabulary (`any = true` on a flags hole), and no `any` hole except where
the leading-dash guard already exempts it (a flag's value, a hole after a literal `--`). Media
need no such condition: the jail does not depend on the arguments.

A `[[network]]` rule is network medium by construction. Its default write set is every network
region; a rule whose methods are only `GET` and `HEAD` defaults to writing nothing. The
program's own file writes are filesystem medium: each writes every filesystem region, wherever
it lands. `--describe` renders the result per rule
(`effects: writes git.refs (no network)`, then `jailed (enforced by the OS): no network`) and
per environmental atom the computed `dies on:` list, which is what the program author reads.

## Jailing a grant: the media keys and `exec`

The host enforces what a grant's child may reach with the OS sandbox: bubblewrap on Linux,
Seatbelt (`sandbox-exec`) on macOS. The media keys are two of the five knobs; the `exec` table
holds the other three. Every knob defaults to the unjailed baseline; a grant that sets none runs
as the host does.

```toml
[[program]]
name = "grep"
argv = ["grep", "${FLAGS...}", "--", "${PATTERN}", "${FILES...}"]
cwd  = "."
network    = false                       # no network at all, loopback included
write-fs   = false                       # no filesystem writes; only a private TMPDIR, discarded after
exec.env   = ["PATH", "HOME", "LANG",    # passed through from the host; every other variable is scrubbed
              { GREP_COLORS = "" }]      # set to a literal value
exec.spawn = false                       # no process creation (threads are fine)
exec.view  = "policy"                    # sees only what the policy's [filesystem] grants
```

| Key | Type | Meaning |
|---|---|---|
| `network` | bool, default true | `false`: the child runs in an empty network namespace |
| `write-fs` | bool, default true | `false`: the whole filesystem is read-only to the child, except a fresh scratch directory `TMPDIR` names, thrown away after the run |
| `exec.env` | list of names and tables | the child's environment is exactly this: a string passes that variable through from the host's environment (skipped if the host lacks it), a table `{ NAME = "value", ... }` sets each key to a literal. A variable is mentioned once, either way; values are literal, no `${...}`; `TMPDIR` may not be listed (the host sets it under `write-fs = false` and under `exec.view = "policy"`). Absent: the host's whole environment; `[]`: an empty one |
| `exec.spawn` | bool, default true | `false`: the child cannot create processes (no hooks, no `-exec`, no helpers, no shells). It can still replace itself with another program, which is not creation |
| `exec.mount-read`, `exec.mount-write` | lists of locations | under `exec.view = "policy"` only: what this rule's child sees beyond the policy's `[filesystem]` section, mounted read-only or writable (`mount-write` needs `write-fs = true`; either without the policy view is a load error). The analysis never reads them: they widen the tool's world, not the program's, and a call cannot widen them further. `no-write` still applies on top. Absolute in a root policy; in a ruleset headed by a directory parameter the root binds (`credentials = { kind = "directory" }`, `exec.mount-read = ["${credentials}/**"]`). Patterns follow the platform rule below. `--describe` prints them as `also sees:` on the jail line |
| `exec.view` | `"host"` (default) or `"policy"` | what the child sees of the filesystem. `"host"`: the host's whole filesystem; the tool is trusted as granted. `"policy"`: an empty world holding the system toolchain, the tool itself, a private `TMPDIR`, the exec's cwd as an empty directory, and the applying policy's `[filesystem]` section as mounts: `read` grants read-only, `write` grants writable iff `write-fs = true`, `no-write` protections remounted read-only on top. Nothing else exists: on Linux a path outside the view is "No such file", not "Permission denied". On macOS Seatbelt takes every location, patterns as anchored regexes (a `<regex>` must stay within the subset Python and ERE share, see "Locations"; one that does not is omitted and reported), and `list` grants as the directory alone. On Linux a literal path or a literal prefix ending in `**` is a bind mount; when the section holds a pattern (`*`, `<regex>`, a `**/leaf` tail) the root is served through the **FUSE view** instead, a long-lived per-(root, policy) mount that filters names, listings and writes by the section exactly (`list` grants make a directory listable there; the `certorail[fuse]` extra plus `fusermount3`; `certorail view status` / `stop`). Without the extra, patterned locations are omitted from the view and the host says so on stderr at startup; absolute patterned locations outside the root are omitted either way |

A jailed grant whose sandbox is not installed does not run at all (the program gets a broker
error), unlike the confined program itself, which runs with a warning when `srt` is missing. So
`network = false` on a rule is also a requirement on the host. Tools that write caches or state
where they run fail under `write-fs = false` unless told not to, or told to use `TMPDIR`: that
is what the set form of `exec.env` is for (`{ PYTHONDONTWRITEBYTECODE = "1" }`,
`{ GIT_OPTIONAL_LOCKS = "0" }`, `{ PIP_DISABLE_PIP_VERSION_CHECK = "1" }`); a tool with no such
knob (`go` without a writable `GOCACHE`) declares `writes = []` or its regions instead and keeps
the medium.

`exec.view = "policy"` is for the tools whose whole value is reading what the program may read
(`cat`, `grep`, `ls`, `find`, `diff`: the shipped coreutils rung sets it on every rule). It is
wrong for a tool that reads its own configuration or caches from the home directory (`git`
reads `~/.gitconfig`, `cargo` needs `~/.cargo` and `~/.rustup`): under the policy view those do
not exist. Such a tool keeps `"host"`, or names what it needs with `exec.mount-read` /
`exec.mount-write` (a `git push` rule mounting the deploy key its root binds as
`credentials`): a trust statement about the tool, in the rule's own hand, that the program
never sees. The policy view needs the same sandbox as the other knobs and the same rule
applies: no bubblewrap or `sandbox-exec`, no run.

## `[[program]]`

Two forms. The **flat** form (`name` plus `subcommand`) permits exactly those words and nothing
after them; the **templated** form (`argv` + `holes`) states the shape of a command line that
takes arguments, each hole saying what its argument is. There is no third form: a rule that
takes arguments it does not describe cannot be written. A program's rules, of either form, must
be prefix-free in their leading literal words, so an exec selects exactly one and an unlisted
form fails closed: once any rule for a program names a subcommand or a template, an exec matching
none of them (unlisted, or not literal) is denied, and subcommands cannot mix with a bare rule for
the same program. `cwd` is a location *slot* on both: one location or a list meaning any-of.

| Key | Type | Meaning |
|---|---|---|
| `name` | string, required | the executable, as programs spell it in `certora.exec(name, …)` |
| `cwd` | location or list, required | the exec's `cwd=` must be proven within one of them |
| `requires` | list of atoms, or a table `{ cwd = [...], HOLE = [...] }` | the cwd must carry these, live, at the exec; a hole entry demands atoms of that hole's value, folded into its constraint (into `any` it leaves an atoms-only constraint) |
| `when` | `true`/`false`, or `"${flag}"` in a ruleset | false drops the rule at load |
| `override` | bool, root only | this rule replaces every applied ruleset's rule for the same program whose leading words overlap its own (`[[apply]]` and rulesets, below); overriding nothing is an error |
| `source` | atom name | the rule's output yields this pure atom on extraction (Sources, below) |
| `network`, `write-fs`, `writes` | | the write set (Media and `writes`, above); the media are enforced |
| `exec` | table | the rest of the jail: `env`, `spawn` (Jailing a grant, above) |
| `argv` | list of words | templated form: literal words, `${X}` (one token), `${X...}` (a splice); the first is the program |
| `holes` | table | templated form: one table per hole named in `argv` (below) |

Flat-form key (not allowed together with `argv`):

| Key | Type | Meaning |
|---|---|---|
| `subcommand` | string | the leading literal words after the program (`"push origin"`); the exec must spell exactly these and no more |

A tool trusted with its own options -- under a jail, or because enumerating them buys nothing --
gets a template with an **open flag vocabulary**: `holes.FLAGS = { kind = "flags", any = true }`
admits any flag and any value, unknown values included. It is the one place the policy says
"whatever the program passes"; `--describe` renders it as such, and a rule carrying it cannot
declare `writes`.

### Holes

`holes.X = { ... }`, or `holes.X.key = ...` dotted.

| `kind` | spelling | binds to | carries |
|---|---|---|---|
| `token` (default) | `${X}` | one expression | one constraint |
| `each` | `${X...}` | a list/tuple display, or a tracked typed container | one constraint for every element; optional `min` (checked at runtime for a container) |
| `flags` | `${X...}` | a list/tuple display | `flagset = "name"` referencing a `[[flagset]]`, or inline `bare = [...]` plus `"-x" = { constraint }` keys, optionally `expand-single-flags = true` |

A **constraint** is one table, used for a token hole, an each hole's elements and a valued flag:
`location` (one or a list: a proven path within one of them), `matches` (a regex the text is
known to fullmatch), `one-of` (a list of strings), `atoms` (validation facts the value must
carry), `literal = true` (statically known text: the program *named* the value, it did not read
it from a file, argv or an API), `any = true` (anything). Shape (`location`/`matches`/`one-of`),
provenance (`literal`) and facts (`atoms`) combine freely except that `location` excludes
`matches`/`one-of`, `matches` excludes `one-of`, and `any` stands alone; an empty constraint is
an error. `{ matches = 'dev-\w+', literal = true }` is the intent gate for a destructive
command: only a database the program itself named, of the dev shape.

**`[[flagset]]`**: `name`, `bare = [...]` (flags taking no value), and `"-x" = { constraint }`
for each valued flag. `{}` is not a bare flag. A flag both bare and valued is an error.

`expand-single-flags = true` (on a `[[flagset]]` or an inline `holes.FLAGS`) reads `-lr` as
`-l -r`: every letter must be a declared bare single-letter flag, a bundle containing a valued
letter (`-rn 5`, `-n5`) or an unknown one is a denial telling the program to spell it
separately, and the tool receives the expanded words. Opt-in, because not every tool bundles:
it is a load error on a vocabulary that declares a single-dash multi-letter flag (`find -name`,
`tar xf`), where such a word is one flag, so a bundle is never ambiguous with a declared flag.

A flag entry may also be `{ value = false }` (a bare flag in table form) and either form may
carry `requires = { cwd = [...], HOLE = [...] }`: atoms demanded of the cwd or of another hole's
value **while the flag is present**, on top of what the hole asks (`--force` requires
`not-default-branch` of `BRANCH`). A named flagset lists the holes its demands reach as
`holes = ["BRANCH"]`; a template using it must have a token or each hole of each name. In a
ruleset a flag entry may carry `when = "${flag}"` (below).

```toml
[[flagset]]
name = "find-ro"
bare = ["-print"]
"-mindepth" = { matches = '\d+' }
"-newer"    = { location = "repos/**" }
"-delete"   = { value = false, requires = { cwd = ["scratch-tree"] } }   # only where a check said so

[[program]]
name = "find"
cwd  = "."
argv = ["find", "${WHERE}", "${FLAGS...}"]
holes.WHERE = { location = "repos/**" }
holes.FLAGS = { kind = "flags", flagset = "find-ro" }
```

### Calling a template

A template binds like a Python call, and the confined program spells the call accordingly. The
leading literal words select the template; positionals then fill holes in template order, a
token hole taking one, a variadic hole (`each` or `flags`) taking every remaining positional
**only if it is the last piece**. A `flags` hole that is not last takes the flag-shaped head of
the positionals (flags of its vocabulary, each valued flag with the positional after it) and
**ends at the first positional that carries `not-option`** (a literal, a located value, a
guarded variable), which begins the next hole. A positional that could be either, unknown text
right after the flags, is rejected with the fix named: bind by keyword to say which hole it
fills. It is never guessed. An `each` hole that is not last, or a flags hole over an open
vocabulary (`any = true`, so which flags take values is unknown), cannot end on its own: it and
every hole after it are **keyword-only**. An unbound variadic hole is empty; an unbound token
hole is a violation. Interior literal words (`--`, `-f`) are emitted by the host and never
spelled by the program. The shapes, from the templates they call:

```toml
argv = ["git", "push", "origin", "${BRANCH}"]           # one token hole
argv = ["find", "${WHERE}", "${FLAGS...}"]              # a token, then a trailing variadic
argv = ["tar", "${FLAGS...}", "-f", "${ARCHIVE}", "${FILES...}"]  # a closed flags hole not last: ends at the first non-flag
argv = ["git", "log", "${REVS...}", "--", "${PATHS...}"]  # an each hole not last: REVS and PATHS keyword-only
```

```python
certora.exec("git", "push", "origin", branch, cwd=repo)
certora.exec("find", where, "-mindepth", "1", "-name", pattern, cwd=root)   # the tail is the flags display
certora.exec("tar", "-c", "-z", out, a, b, cwd=root)                        # out is a path: the flags end there
certora.exec("tar", "-c", ARCHIVE=out, FILES=files, cwd=root)               # mixing is fine
certora.exec("grep", "-r", pattern, repo, cwd=root)          # rejected if pattern is unknown text: could be a flag
certora.exec("grep", FLAGS=["-r"], PATTERN=pattern, FILES=[repo], cwd=root) # the fix
certora.exec("git", "log", REVS=["main..HEAD"], PATHS=[src], cwd=repo)
```

A flags display is read left to right: an element in flag position must be a string literal
naming a flag of the vocabulary (a computed flag is a violation, an unlisted one a denial); a
valued flag consumes the next element as its value. `--describe` prints `bind by keyword: …` on
every template with keyword-only holes, and `FLAGS... ends at the first positional that is not
a flag; ARCHIVE begins there` on every non-last flags hole that binds positionally.

**The leading-dash guard.** A value in a token or each hole must carry the built-in atom
`not-option`, "the text does not begin with `-`". Structure supplies it for a located value
whose first component is a literal name (`repos/…`) or an absolute path, and for text whose
known regex cannot begin with `-`; a guard supplies it (`assert not s.startswith("-")`,
`s[0] != "-"`, `s.isalnum()`, a `re.fullmatch` whose pattern excludes a leading dash); a
checker supplies it for text the analysis cannot see the head of, by listing `not-option` in
`establishes` beside the atom it checks (every text checker should). A value known only to lie
somewhere under `**`, or unguarded, unchecked text, is denied with the fix in the message. Flag
*values* are exempt (the flag consumed the slot), and so is every hole after a literal `--` in
the template, for tools that honour it (`argv = ["grep", "--", "${PATTERN}", "${FILES...}"]`).
**Spell that `--` for every tool that honours it** -- all of coreutils, git, nearly everything
but `find` -- so the guard does its work where a value could be read as an option and nowhere
else: a file that happens to be named `-R` is then spellable (`FILES=["-R"]`), and the tool
itself guarantees it is read as a file. The shipped coreutils rung does this throughout.

**Built-in atoms.** `not-option` is one of five certorail defines -- with `no-slash`,
`no-parent-traversal`, `not-absolute`, `not-dot-dot` -- that no policy declares (an `[atoms]`
entry is an error) and any policy may name: in a hole's `atoms`, a flag's `requires`, a
checker's `establishes`. Programs name them as markers (`certora.not_option`) and establish
them with guards.

## Sources: `source = "…"` and `[[source]]`

A rule may name a **source atom** its results yield: `source = "gh-api"` on a `[[program]]` or
`[[network]]` rule, or a `[[source]] name = "manifest" location = "dist/manifest.json"` for a
readable location (which grants nothing: the read must still be permitted). The atom is declared
in `[atoms]` with `pure = true`, and only extraction establishes it: `certora.extract(...)`,
`extract_all`, `lines`, `field`, or `for line in f` over a handle. Consume it like any atom:
`holes.BRANCH = { atoms = ["gh-api"] }` means "a value the GitHub API returned, unmodified" --
never a literal, never something read elsewhere and massaged. This is the dual of `literal`:
`literal` for what the agent chose, a source atom for what a trusted query produced. See
`PROVENANCE.md`.

## `[[apply]]` and rulesets

A **ruleset** is a reusable, parameterised bundle of exec-side vocabulary in
`~/.certorail/rulesets/<name>.toml`: `ruleset-version = 1`, `[params]`, `[regions]`, `[atoms]`,
`[[flagset]]`, `[[program]]`, `[[validation]]`, `[[source]]`, `[[apply]]`, and
`[filesystem] no-write` (a protection, never a grant). No `read`/`write`/`list`, no
`[[network]]`, no `root`, no `[[deny]]`; no absolute locations, in footprints included. The root
policy applies it:

```toml
[[apply]]
ruleset    = "git.toml"
where      = ["repos", "/srv/data"]   # directory: set-valued
branch     = { atoms = ["my-branch"] } # constraint: any table a hole accepts ({ any = true }, { one-of = [...] }, ...)
push-gate  = ["org-checkout"]         # atom list; [] is "no gate", said in the root's own hand
force      = true                     # bool; unbound means false
force-gate = ["not-default-branch"]   # needed only because force = true enables the flag that uses it
```

A ruleset (and a root policy) may carry a top-level `description = "..."`, one sentence on what
it grants, and each parameter a `description` of what binding it decides: `[params] where = {
kind = "directory", description = "the directory holding repositories" }`. Neither changes what
loads; `certorail init` reads a pack's description from its documents (the one named like the
pack directory, `git/git.toml`, else its only document) when offering it, and a policy author
binding parameters reads theirs. The shipped packs carry both.

`[params] x = { kind = "directory" | "atom" | "constraint" | "bool" }`. A **directory** binds one
directory or a list (plain paths, no `**`); the ruleset writes `${where}` for the directory and
`${where}/**` for its subtree, and every location slot so written becomes a one-of list over the
bound directories. An **atom** list is spliced where it stands in an atom list (`requires`, a
hole's `atoms`, `establishes`, a flag's `requires`). A **constraint** is a whole hole
(`holes.BRANCH = "${branch}"`), checked where it lands. A **bool** is read by `when` on a
`[[program]]`, an `[[apply]]` or a flag entry: false drops the piece before substitution, so a
parameter referenced only from dropped pieces needs no binding. **No parameter has a default**
except that an unbound bool is false; every other parameter a surviving piece references must be
bound, and the error names it. A ruleset applied by another passes bindings down whole
(`force = "${force}"`), each kind as its value. A ruleset is applied at most once; two applications with different bindings is
an error (apply it once with the union), the same application reached twice through nested
rulesets is one document. Atom and validation names are unique across the whole composition
(namespace by convention: `unix.no-flag`); region names are shared on purpose, identical
declarations merging; flagsets are private to their file. A ruleset's validation may run only
`${checkers}/<name>` or `test`. Denials name the ruleset and bindings a rule came from.

**Taking a shape back, or replacing it.** Composition is additive below the root; only the root
subtracts, and only from what rulesets contributed:

```toml
[[deny]]                                  # git apply is not for this agent: the rung's shape is gone
argv = ["git", "apply"]                   # every applied rule whose leading words begin with these

[[program]]                               # the pack's push, replaced by the root's own
override     = true                       # without it the overlap is a load error naming this fix
name         = "git"
argv         = ["git", "push", "${REMOTE}", "${BRANCH}"]
...
```

A denied shape fails closed like any unlisted form (`git apply` then "matches no declared
subcommand"). A `[[deny]]` that takes nothing back, or that names a shape the root grants
itself, is an error; so is an `override` that overlaps nothing, or one written in a ruleset.
A ruleset may not deny. Denials are applied before overrides.

**The base ruleset.** `~/.certorail/rulesets/base.toml`, when it exists, is applied to every
root policy, and to the built-in policy of a root with none, exactly as if the root wrote
`[[apply]] ruleset = "base.toml"` with no bindings. **Nobody ships it.** The repository provides
rulesets to apply (`coreutils-ro.toml`), never a `base.toml`; no installer writes one unasked;
creating it is a deliberate first-run act of whoever owns the machine (a setup verb may generate
it on request). `--check`, `--describe`, every rejection and the session hook say when it was
composed in (an accepted run prints nothing: those lines would be tokens in an agent's context
saying nothing new), and `--describe` lists every ruleset composed into the policy. It is just a
ruleset: exec shapes and
`no-write` protections, no filesystem or network grants, no absolute paths, and no parameters
except bools (which are false). Its purpose is the read-only tooling an agent reaches for
everywhere (`ls`, `cat`, `grep`, `find`, the git read rung bound to `where = "."`), each jailed
with `network = false`, `write-fs = false`, `exec.spawn = false`, so no root has to spell them.
The same rules apply as to any pack: a root rule overlapping a base shape needs `override =
true`, `[[deny]]` takes a base shape back, and `base = false` at the top of a root policy drops
the whole layer. `--describe` labels its rules `[from base.toml]`. The shipped
`coreutils-ro.toml` is the intended starting point: `ls`, `tree`, `find`, `cat`,
`head`, `tail`, `stat`, `file`, `grep`, `diff`, `wc`, `du`, `sort`, `uniq`, `cut`, each jailed,
every path-taking flag constrained to the tree, and nothing that follows, writes or runs a
program. `sed` and `awk` are deliberately absent: their scripts can name a file the flag list
never sees, and the GNU `--sandbox` that would close that is not portable. A minimal base is then

```toml
ruleset-version = 1

[[apply]]
ruleset = "coreutils-ro.toml"
where   = "."
```

certorail ships its ruleset packs as directories, one per pack -- the git rungs (with
`git.md`, their program-author note, and their checkers) and the coreutils read rung -- under
`rulesets/` in the certorail source repository. `certorail policy install-pack <pack dir>`
validates one (shape, the checker closure in both directions, pins against the supplied
bytes) and rotates it into the config directory; nothing applies a pack until a policy does.

## `[[network]]`

Rules for the program's own requests (`certora.network.*`), enforced statically at every call
site and again by the broker at runtime on every redirect hop. Deny by default. Exec'd programs'
network use is not governed here; it is folded into their `[[program]]` grant.

| Key | Type | Meaning |
|---|---|---|
| `host` | string, required | exact host, or `*.suffix` (subdomains, not the suffix itself) |
| `schemes` | list, default `["https"]` | among `http`, `https` |
| `ports` | list of ints, default empty | empty means the scheme's default port only |
| `methods` | list, default empty | empty means any method |
| `allow-nonpublic` | bool, default false | permit loopback, RFC1918, link-local and metadata addresses |
| `path` | location or list, server-absolute | the URL's path must be proven within one of them (a literal URL, or `urlsplit(u).path` guards); checked again on every redirect hop, percent-decoded. Absent: any path |
| `requires` | list | atoms the URL value must carry at the call site: `"atom"`, or `{ atom = "…", on-redirect = "recheck" \| "stop" \| "waive" }` |
| `source` | atom name | responses yield this pure atom on extraction |
| `writes` | list of network regions | what a request may change remotely; default every network region, or nothing for a `GET`/`HEAD`-only rule |
| `read-timeout`, `total-timeout` | number (s) | per-destination overrides of the broker caps (600 s silence, 900 s total) |
| `max-response-bytes` | int | per-destination override of the 16 MiB cap |

`on-redirect` says what a redirect hop — a URL the analysis never saw — owes the atom:
`recheck` re-establishes it from the hop URL's text (defined atoms and literal checkers only),
`stop` refuses hops under this rule, `waive` asks nothing of hops. A bare name defaults to
`recheck` when the atom is textual and `stop` otherwise; an explicit `recheck` of a non-textual
atom is an error. The broker follows at most 5 redirects and drops `Authorization`/`Cookie`
when the host changes.

## The checker runtime contract

What a validation's program experiences when a confined program calls `certora.check` /
`certora.check_single`, or when the host discharges a literal:

- **Command.** `argv` with each `${param}` piece replaced by the program's string for that
  parameter, as one token. No shell. `argv[0]` is resolved like `subprocess` does: an absolute
  path, or a name on the host's `PATH`. `~` is not expanded. Checkers belong in
  `~/.certorail/checkers/` and are named `${checkers}/<name>`.
- **Working directory.** The validation's `cwd` argument, resolved under the sandbox root
  (an absolute one as is); the sandbox root itself for a cwd-free validation. The broker has
  already verified it lies within the declared `cwd` location.
- **Environment.** The host's: the invoking user, its environment variables, credentials and
  tools. The checker runs **outside** the jail; that is its purpose (it can consult what the
  program cannot). It is trusted code.
- **Stdin** is `/dev/null`. **Stdout** is discarded. **Stderr** (up to 8 MiB) is returned and,
  on refusal, shown to the program as the failure reason.
- **Verdict.** Exit status `0` establishes the declared atoms; any other status refuses (the
  program's `certora.check` raises). A checker that cannot be spawned refuses.
- **Time.** Killed after 900 s (whole process group). A program that gives up on the check
  hangs up, which also kills the checker.
- **Literal checkers** run additionally at analysis time, under `--root`, on every constant
  that needs the atom: a parameter-slot checker in the root, a cwd-slot checker in
  `root/<text>` (which must exist). Results are cached per (atom, text) within one analysis.
  Keep them fast and free of side effects.

## What kills an environmental fact

A program author needs to know when a checked fact is still live. The rule (EFFECTS.md): a
fact established by `certora.check` dies when its variable is reassigned, and additionally at
every call whose write set meets the atom's `reads`. What a call writes:

- `certora.exec`, `certora.network.*`, `certora.check`: the rule's declared write set, as
  above; an undeclared rule writes everything.
- a file write by the program (`write_text`, `open(p, "w")`, `mkdir`, …): every filesystem
  region, today.
- a call the analysis can place as the interpreter's own code over values it can see are
  ordinary data (`s.strip()`, `sorted(xs)`, `json.loads(text)`, `p.read_text()`, `len`, `print`
  with plain arguments): nothing. Handing such a call a program-defined function, a generator,
  an instance or a hook keyword makes it an unknown call.
- a call to one of the program's own module-level functions: what its body writes, computed.
- anything else that may run program code (a class instantiated, a method on an instance, a
  lambda or a parameter called, a property read): everything.

So `check` immediately before the use is still the safe idiom, but ordinary text handling
between the two no longer matters, and a rule with declared `writes` can sit between a check and
a use that reads other state. `--describe` lists, per environmental atom, exactly which grants
kill it.

## Program-side vocabulary (for writing probes)

Full rules in `SUBSET_PROMPT.md` (next to this file). The parts a policy author needs:

- `certora.exec(program, *args, cwd=<proven path>, HOLE=value, …, stream=False)`: literal program name,
  string arguments, no splats, `cwd` mandatory; keyword arguments bind a template's holes by
  name (required for keyword-only holes and for a value the positional rule cannot place). Returns a `CompletedProcess` whose `.stdout_lines()` / `.stdout_string()` (and stderr
  twins) raise `certora.CalledProcessError` on a non-zero exit.
- `certora.check(name, key=var, …, cwd=var)`: bare statement; establishes on the variables
  passed; `cwd=` present iff the validation declares one.
- `branch = certora.check_single(name, value)`: expression form for one-parameter validations;
  the atoms ride the result.
- `certora.network.get/head/delete/post/put/patch(url, headers=…, body=…, timeout=…)`: a
  literal URL, or a variable guarded by `urllib.parse.urlsplit(u).scheme == "https"` and
  `urllib.parse.urlsplit(u).netloc == "host"`.
- Contracts: `typing.Annotated[pathlib.Path, certora.within("repos"), certora.validated("org-checkout")]`;
  a source atom is spelled `certora.source("gh-api")` (naming it with `validated` is a contract
  error, and vice versa); the built-ins as bare markers (`certora.not_option`).

## Command line

```
certorail [--root DIR] [--policy FILE] [--check] [--no-jail] PROGRAM [-- ARG ...]
certorail -c SOURCE [--root DIR] [--policy FILE] [--check] [--no-jail] [-- ARG ...]
certorail-run [--check] (-c SOURCE | FILE) [-- ARG ...]
certorail --describe [--root DIR] [--policy FILE]
certorail init [--yes] [--root DIR]
certorail policy install FILE | install-pack DIR | edit [--root DIR | --policy FILE] | list [--root DIR] | verify | pin DIR
certorail policy apply RULESET [KEY=VALUE ...] [--root DIR | --policy FILE]
certorail session-hook
certorail view [status | stop [KEY]]
```

`init`, `policy`, `session-hook` and `view` are reserved first words (a program literally named
`policy` is spelled `./policy`). `certorail policy …` is the installer: it validates before it
places, refuses conflicts instead of overwriting, and is the one path that keeps `verify`
meaningful.

`certorail init` creates the ambient policy for `--root` as a short deterministic interview,
and writes nothing else. A directory already governed by a policy gets "already set up". If a
base ruleset is installed, `init` summarises what it applies from the rulesets' own
`description` keys and asks whether this root inherits it; no writes `base = false`. Then it
asks whether programs get full read, write and list access under the root; no leads to one
question per kind, answered as locations in the micro-syntax and checked as typed. Then whether
to allow all programs the policy does not name (`default-allow`, default no). It ends by
listing the installed rulesets the base does not apply, each with its description, its
parameters, and the `apply` command that brings it in. Installing rulesets is the installer's
job (`certorail policy install-pack DIR`); applying one is `certorail policy apply RULESET`,
which appends an `[[apply]]` to the policy governing `--root` with the `KEY=VALUE` bindings
given (VALUE in TOML: `true`, `[]`, `{ one-of = ["origin"] }`; a plain string otherwise, so
`where=.` works), asks for each parameter the load reports unbound, with the parameter's own
description, when a terminal is there, and lands the result only if the whole policy loads. It
refuses a ruleset the policy already applies and one the base already applies to every root.
`certorail policy list` describes every installed ruleset with its parameters and who applies
it; with `--root DIR`, the policy governing that directory is among the appliers.
`--yes` takes every default without a terminal. `certorail policy edit` opens the policy
governing `--root` (or `--policy FILE`) in `$VISUAL` / `$EDITOR` on a copy; when the editor
exits the copy is loaded against the installed tree, and it replaces the original only if it
loads and still declares the same root. Otherwise the problems are printed and you choose to
edit again or discard, as in `git add -p`.

`certorail-run [--check] (-c SOURCE | FILE) [-- ARG ...]` is the entry point to allow an agent.
Its interface is closed: `--check` is the only option and comes first, the program is inline or a
file, the policy is the ambient one for the working directory, the jail is always on, and
everything after the source or the file is an argument for the program, options included. A
permission rule on its prefix (`Bash(certorail-run *)`) therefore admits a program and its
arguments and nothing else, where a rule on `certorail -c` also admits `--policy`, `--root` and
`--no-jail`.

`--check` analyses and evaluates without running and prints every sink with its proven
location. `certora.reveal_fact(x)` in the program -- a bare name, nothing else -- makes the
report begin with what the analysis knew about `x` at that point (its location, the text shape
it matches, the atoms it carries, or that nothing is known); it establishes nothing, kills
nothing, and does nothing at runtime. A run prints the reveals on stderr before starting. `--policy` takes a `.toml` or `.json` document; without it the nearest ambient policy
for the root applies, else the built-in default (read, write and list anywhere within the root;
no programs, no network). `--describe` prints the policy's interface for the program author,
rendered from the loaded policy: filesystem grants, regions, every program form as a signature
with its holes, flags and effects, validations, atoms with what they depend on and what kills
them, sources, network rules. Put it in the agent's context with a Claude Code hook in the
project's `.claude/settings.json`:

```json
{"hooks": {"SessionStart": [{"matcher": "startup|resume|clear|compact",
  "hooks": [{"type": "command", "command": "certorail session-hook"}]}]}}
```

`certorail session-hook` prints a short how-to-run preamble plus the describe output, and
nothing at all where no ambient policy governs -- safe to register globally. The certorail
Claude Code plugin ships exactly this hook.

Exit status: the program's own when it ran; 1 when rejected; 2 when it does not parse.

Ambient discovery: the config directory is `$CERTORAIL_CONFIG_DIR`, else
`$XDG_CONFIG_HOME/certorail`, else `~/.certorail`. Under its `policy/` subdirectory, a
directory named by the root with `/` turned into `-` (`/srv/work/repo` →
`policy/-srv-work-repo/`, `/` → `policy/-/`) holds `*.toml` files that each carry
`root = "/abs/path"`. The root's ancestors are probed nearest first; only the file whose `root`
equals the probed prefix applies; two such files is an error. Only TOML is discovered
ambiently. The `checkers/` subdirectory beside `policy/` is where validations' programs live,
and `rulesets/` where shared vocabularies do, so the config directory is the single place to
audit.

## No Python policy API

A policy is a TOML or JSON document, nothing else: `--policy` refuses any other suffix, and only
TOML is discovered ambiently. The constructors in `certorail/policy.py` are the object model the
loader builds, not a second language.
