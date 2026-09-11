# certorail policy reference

The policy is a TOML document (JSON with the same shape is accepted too). The schema is strict
and fails closed: unknown keys, undeclared atoms or regions, malformed locations and mistyped
values are errors, and every error in the document is reported, not just the first.

```toml
policy-version = 1
root = "/srv/work/repo"            # ambient policies only: the sandbox root this file governs

[filesystem]
read  = ["**"]
write = ["repos/**"]
list  = ["repos/**"]

[regions]                          # the state checks depend on and commands change
git.config = { footprint = ".git/config", about = "remotes, hooks: everything git reads from config" }
git.refs   = { footprint = [".git/refs", ".git/packed-refs"], about = "local and remote-tracking refs" }
git.remote = { network = true, about = "the remote repository" }

[atoms]
org-checkout = { reads = ["git.config"] }  # environmental: dies when git.config may have changed
not-force    = { pure = true }             # pure, established by a checker
no-flag      = { matches = '[^-].*' }      # defined: the regex is its meaning (pure)

[[validation]]
name        = "not-force-check"
params      = ["value"]
argv        = ["test", "${value}", "!=", "--force"]
effect-free = true
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
(one of the names), or `<regex>` (a full match of one name; raw regex, may contain `/`).

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

## `[filesystem]`

`read`, `write`, `list`: lists of locations; absent means nothing of that kind is permitted.
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
| `footprint` | location or list | the region's medium is the **filesystem**: where its state lives, spelled relative to the cwd of a validation that establishes an atom reading it (`.git/config`), or absolute. A footprint means that path *and every descendant*: write `.git/refs`, never `.git/refs/**` |
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
| `effect-free` | bool, default false | the checker changes nothing: it writes no region, so its run kills no environmental atoms. Equivalent to `network = false, write = false` |
| `network`, `write` | bool, default true | the media the checker reaches (below) |
| `writes` | list of regions | what the checker's run writes, within its media (below) |

A validation is a **literal checker** when it is effect-free, establishes a pure atom, and has
exactly one input slot (one param, or no params plus `cwd`). The host then runs it at analysis
time on statically-known text, so constants carry the atom without any `certora.check` in the
program (cached per atom and text; for the `cwd` slot the directory `root/<text>` must exist).

## Media and `writes`

The evaluator a validation spawns, the tool a `[[program]]` grant runs and a `[[network]]`
request are all effects; what each one may change is its **write set**, and it is declared in
two layers, both trusted like the rest of the policy:

- **Media** (`[[program]]`, `[[validation]]`): `network = false` says the tool never reaches the
  network, `write = false` that it never writes the filesystem. Each removes every region of
  that medium from the write set with no region named. `effect-free = true` is both: the empty
  write set. Local git work is `network = false`; a query tool (`gh pr view`) is `write = false`.
- **`writes = [regions]`** (`[[program]]`, `[[validation]]`, `[[network]]`): the regions the
  effect may change, within the media. A region outside the declared media is a load error
  (`git add` cannot write `git.remote` under `network = false`). Undeclared means *every* region
  of the media, so a bare grant with neither key kills every environmental atom. A medium name
  stands for the whole medium: `writes = ["network"]`.

Only a rule whose arguments cannot smuggle an option or a subcommand past the shape may declare
`writes`: no open flag vocabulary (`any = true` on a flags hole), and no `any` hole except where
the leading-dash guard already exempts it (a flag's value, a hole after a literal `--`). Media
need no such condition.

A `[[network]]` rule is network medium by construction. Its default write set is every network
region; a rule whose methods are only `GET` and `HEAD` defaults to writing nothing. The
program's own file writes are filesystem medium; today they write every filesystem region (the
footprint-based derivation is not yet in). `--describe` renders the result per rule
(`effects: writes git.refs (no network)`) and per environmental atom the computed
`dies on:` list, which is what the program author reads.

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
| `requires` | list of atoms | the cwd must carry these, live, at the exec |
| `source` | atom name | the rule's output yields this pure atom on extraction (Sources, below) |
| `effect-free`, `network`, `write`, `writes` | | the write set (Media and `writes`, above) |
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
| `flags` | `${X...}` | a list/tuple display | `flagset = "name"` referencing a `[[flagset]]`, or inline `bare = [...]` plus `"-x" = { constraint }` keys |

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

```toml
[[flagset]]
name = "find-ro"
bare = ["-print"]
"-mindepth" = { matches = '\d+' }
"-newer"    = { location = "repos/**" }

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
**only if it is the last piece**. A variadic hole that is not last, and every hole after it, is
**keyword-only**: nothing else could mark where it ends. An unbound variadic hole is empty; an
unbound token hole is a violation. Interior literal words (`--`, `-f`) are emitted by the host
and never spelled by the program. The three shapes, from the templates they call:

```toml
argv = ["git", "push", "origin", "${BRANCH}"]           # one token hole
argv = ["find", "${WHERE}", "${FLAGS...}"]              # a token, then a trailing variadic
argv = ["tar", "${FLAGS...}", "${ARCHIVE}", "${FILES...}"]  # a variadic not last: everything keyword-only
```

```python
certora.exec("git", "push", "origin", branch, cwd=repo)
certora.exec("find", where, "-mindepth", "1", "-name", pattern, cwd=root)   # the tail is the flags display
certora.exec("tar", FLAGS=["-c", "-z"], ARCHIVE=out, FILES=files, cwd=root)
```

A flags display is read left to right: an element in flag position must be a string literal
naming a flag of the vocabulary (a computed flag is a violation, an unlisted one a denial); a
valued flag consumes the next element as its value. `--describe` prints `bind by keyword: …` on
every template whose holes are keyword-only.

**The leading-dash guard.** A value in a token or each hole must carry the built-in atom
`not-option`, "the text does not begin with `-`". Structure supplies it for a located value
whose first component is a literal name (`repos/…`) or an absolute path, and for text whose
known regex begins with a literal that is not `-`; a checker supplies it for text the analysis
cannot see the head of, by listing `not-option` in `establishes` beside the atom it checks
(every text checker should). A value known only to lie somewhere under `**`, or unguarded,
unchecked text, is denied with the fix in the message. Flag *values* are exempt (the flag
consumed the slot), and so is every hole after a literal `--` in the template, for tools that
honour it (`argv = ["grep", "--", "${PATTERN}", "${FILES...}"]`). `not-option` may not be
declared in `[atoms]`.

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
`[[flagset]]`, `[[program]]`, `[[validation]]`, `[[source]]`, `[[apply]]`. No `[filesystem]`,
no `[[network]]`, no `root`; no absolute locations, in footprints included. The root policy
applies it:

```toml
[[apply]]
ruleset = "unix.toml"
where   = ["repos", "/srv/data"]      # a directory parameter is set-valued
org     = "org-checkout"              # an atom parameter names an atom the root declares
```

`[params] where = { kind = "directory" }` binds one directory or a list (plain paths, no `**`);
the ruleset writes `${where}` for the directory and `${where}/**` for its subtree, and every
location slot so written becomes a one-of list over the bound directories. `kind = "atom"`
parameters are substituted whole into atom lists (`requires`, a hole's `atoms`,
`establishes`). A ruleset is applied at most once; two applications with different bindings is
an error (apply it once with the union), the same application reached twice through nested
rulesets is one document. Atom and validation names are unique across the whole composition
(namespace by convention: `unix.no-flag`); region names are shared on purpose, identical
declarations merging; flagsets are private to their file. A ruleset's validation may run only
`${checkers}/<name>` or `test`. Denials name the ruleset and bindings a rule came from.

The `rulesets/` directory of the certorail repository holds the git pack (`git.md` describes
it); read its status note before relying on it, since parts of its syntax are ahead of the loader.

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

Full rules in `examples/SUBSET_PROMPT.md`. The parts a policy author needs:

- `certora.exec(program, *args, cwd=<proven path>, HOLE=value, …)`: literal program name,
  string arguments, no splats, `cwd` mandatory; keyword arguments bind a template's keyword-only
  holes. Returns a `CompletedProcess` whose `.stdout_lines()` / `.stdout_string()` (and stderr
  twins) raise `certora.CalledProcessError` on a non-zero exit.
- `certora.check(name, key=var, …, cwd=var)`: bare statement; establishes on the variables
  passed; `cwd=` present iff the validation declares one.
- `branch = certora.check_single(name, value)`: expression form for one-parameter validations;
  the atoms ride the result.
- `certora.network.get/head/delete/post/put/patch(url, headers=…, body=…, timeout=…)`: a
  literal URL, or a variable guarded by `urllib.parse.urlsplit(u).scheme == "https"` and
  `urllib.parse.urlsplit(u).netloc == "host"`.
- Contracts: `typing.Annotated[pathlib.Path, certora.within("repos"), certora.validated("org-checkout")]`.

## Command line

```
certorail [--root DIR] [--policy FILE] [--check] [--no-jail] PROGRAM [-- ARG ...]
certorail -c SOURCE [--root DIR] [--policy FILE] [--check] [--no-jail] [-- ARG ...]
certorail --describe [--root DIR] [--policy FILE]
```

`--check` analyses and evaluates without running and prints every sink with its proven
location. `--policy` takes a `.toml` or `.json` document; without it the nearest ambient policy
for the root applies, else the built-in default (read, write and list anywhere within the root;
no programs, no network). `--describe` prints the policy's interface for the program author,
rendered from the loaded policy: filesystem grants, regions, every program form as a signature
with its holes, flags and effects, validations, atoms with what they depend on and what kills
them, sources, network rules. Put it in the agent's context with a Claude Code hook in the
project's `.claude/settings.json`:

```json
{"hooks": {"SessionStart": [{"matcher": "startup|resume|clear|compact",
  "hooks": [{"type": "command", "command": "certorail --describe"}]}]}}
```

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
