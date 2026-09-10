# certorail policy reference

The policy is a TOML document (JSON with the same shape is accepted too). The schema is strict
and fails closed: unknown keys, undeclared atoms, malformed locations and mistyped values are
errors, and every error in the document is reported, not just the first.

```toml
policy-version = 1                 # required, exactly 1
root = "/srv/work/repo"            # ambient policies only: the sandbox root this file governs

[filesystem]
read  = ["**"]
write = ["repos/**"]
list  = ["repos/**"]

[atoms]
org-checkout = {}                          # environmental
not-force    = { pure = true }             # pure, established by a checker
no-flag      = { matches = '[^-].*' }      # defined: the regex is its meaning (pure)

[[validation]]
name        = "not-force-check"
params      = ["value"]
argv        = ["test", "${value}", "!=", "--force"]
effect-free = true
establishes = { value = ["not-force"] }

[[program]]
name           = "git"
subcommand     = "push origin"
cwd            = "repos/**"
requires       = ["org-checkout"]
argument-atoms = ["not-force"]

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
| `reports/**/<\w+\.json>` | a `.json`-named entry anywhere at or below `reports` (the leaf after `**` is exactly one component) |
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
| write | `open` with a writing mode, `write_text`, `write_bytes`, `mkdir`, `touch`, `chmod`, `replace` (the path *and* its target) |
| list | `os.listdir`, `os.walk`, `os.path.exists/isfile/isdir`, `iterdir`, `glob`, `rglob`, `exists`, `is_file`, `is_dir` |

Everything else on the filesystem (`unlink`, `rename`, `shutil`, archives, …) is unavailable to
programs regardless of policy.

## `[atoms]`

Every fact name used anywhere is declared here, once. A name maps to a table:

| Form | Meaning |
|---|---|
| `name = {}` | environmental: true of the world, dies at every potentially effectful call |
| `name = { pure = true }` | pure: a property of the value's text; survives calls, dies with the value |
| `name = { matches = 'regex' }` | defined: the regex *is* the property; pure by construction (`pure = false` here is an error). Any value whose text is known to match carries it with no check; a program guard `re.fullmatch(r"<same regex text>", v)` establishes it on a dynamic value |

## `[[validation]]`

| Key | Type | Meaning |
|---|---|---|
| `name` | string, required, unique | what programs name in `certora.check(name, …)` |
| `params` | list of strings | the keyword parameters programs pass; unique; `cwd` is not allowed as a name |
| `argv` | list of strings, required | the checker command; the first piece is a literal program: `${checkers}/<name>` (the executable `<name>` in the config directory's `checkers/`, resolved at load, which must exist), an absolute path, or a name on `PATH`; a piece that is exactly `${param}` is replaced by that argument; `${…}` inside a larger piece is an error |
| `cwd` | location or list | where the check may run (any of them); programs must pass a proven `cwd=` within one. **Omit** for a check that does not care where it runs: programs then omit `cwd=` and the check cannot establish on `cwd` |
| `effect-free` | bool, default false | the checker mutates nothing: its run kills no environmental atoms |
| `establishes` | table: param name or `cwd` → list of atom names | what success establishes on which argument |

A validation is a **literal checker** when it is effect-free, establishes a pure atom, and has
exactly one input slot (one param, or no params plus `cwd`). The host then runs it at analysis
time on statically-known text, so constants carry the atom without any `certora.check` in the
program (cached per atom and text; for the `cwd` slot the directory `root/<text>` must exist).

## `[[program]]`

Two forms. The **flat** form governs a program (or one subcommand of it) by rules over its
arguments as a whole; the **templated** form (`argv` + `holes`) states the shape of the command
line. A program's rules, of either form, must be prefix-free in their leading literal words, so
an exec selects exactly one and an unlisted form fails closed. `cwd` is a location *slot* on
both: one location or a list meaning any-of.

| Key | Type | Meaning |
|---|---|---|
| `name` | string, required | the executable, as programs spell it in `certora.exec(name, …)` |
| `cwd` | location or list, required | the exec's `cwd=` must be proven within one of them |
| `requires` | list of atoms | the cwd must carry these, live, at the exec |
| `argv` | list of words | templated form: literal words, `${X}` (one token), `${X...}` (a splice); the first is the program |
| `holes` | table | templated form: one table per hole named in `argv` (below) |

Flat-form keys (not allowed together with `argv`):

| Key | Type | Meaning |
|---|---|---|
| `subcommand` | string | leading literal words this rule governs (`"push origin"`) |
| `argument-atoms` | list of atoms | every argument after the subcommand must carry these |
| `argument-locations` | list of locations | every argument that is a proven path must lie within one |
| `unknown-arguments` | bool, default **false** | may arguments include values the analysis cannot vouch for? |

**Holes** (`holes.X = { ... }`, or `holes.X.key = ...` dotted). `kind` is `token` (default,
`${X}`), `each` (`${X...}`, every element checked; optional `min`) or `flags` (`${X...}`, a flag
vocabulary: `flagset = "name"` referencing a `[[flagset]]`, or inline `bare = [...]` plus
`"-x" = { constraint }` keys). A token hole, an each hole and a valued flag carry a
**constraint**: `location` (one or a list: a proven path within one of them), `matches`
(a regex the text is known to fullmatch), `one-of` (a list of strings), `atoms` (validation
facts the value must carry), `literal = true` (statically known text: the program *named* the
value, it did not read it from a file, argv or an API), `any = true` (anything). Shape
(`location`/`matches`/`one-of`), provenance (`literal`) and facts (`atoms`) combine freely
except that `location` excludes `matches`/`one-of` and `any` stands alone; an empty constraint
is an error. `{ matches = 'dev-\w+', literal = true }` is the intent gate for a destructive
command: only a database the program itself named, of the dev shape.

**`[[flagset]]`**: `name`, `bare = [...]` (flags taking no value), and `"-x" = { constraint }`
for each valued flag. `{}` is not a bare flag.

**Binding.** A template binds like a Python call: the leading literal words select it,
positionals fill holes in order, a trailing splice takes the rest, a splice that is not last and
every hole after it are keyword-only. Interior literal words (`--`, `-f`) are emitted by the host,
never spelled. A token or each value must be shown not to begin with `-` unless a literal `--`
precedes its hole. The broker re-binds the concrete call and composes the argv itself.

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
| `subcommand` | string | leading literal words this rule governs (`"push origin"`). Once any rule for a program names a subcommand, that program **fails closed**: an exec matching no declared subcommand (unlisted, or not literal) is denied. Subcommands of one program must be prefix-free and cannot mix with a bare rule |
Vouched-for means exactly-known text or a proven path; an f-string, a `.strip()` result or a
runtime-checked value is *not*, even when it carries atoms. Prefer a template
over `unknown-arguments = true` whenever the program takes flags or paths: a template grants
exactly the flags and positions listed and nothing else.

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
`~/.certorail/rulesets/<name>.toml`: `ruleset-version = 1`, `[params]`, `[atoms]`,
`[[flagset]]`, `[[program]]`, `[[validation]]`, `[[apply]]`. No `[filesystem]`, no
`[[network]]`, no `root`; no absolute locations. The root policy applies it:

```toml
[[apply]]
ruleset = "unix.toml"
where   = ["repos", "/srv/data"]      # a directory parameter is set-valued
org     = "org-checkout"              # an atom parameter names an atom the root declares
```

`[params] where = { kind = "directory" }` binds one directory or a list (plain paths, no `**`);
the ruleset writes `${where}` for the directory and `${where}/**` for its subtree, and every
location slot so written becomes a one-of list over the bound directories. `kind = "atom"`
parameters are substituted whole into atom lists (`requires`, `argument-atoms`, `atoms`,
`establishes`). A ruleset is applied at most once; two applications with different bindings is
an error (apply it once with the union), the same application reached twice through nested
rulesets is one document. Atom and validation names are unique across the whole composition
(namespace by convention: `unix.no-flag`); flagsets are private to their file. A ruleset's
validation may run only `${checkers}/<name>` or `test`. Denials name the ruleset and bindings a
rule came from.

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
  `~/.certorail/checkers/` and are named by absolute path.
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

## Program-side vocabulary (for writing probes)

Full rules in `examples/SUBSET_PROMPT.md`. The parts a policy author needs:

- `certora.exec(program, *args, cwd=<proven path>)`: literal program name, string arguments,
  no splats, `cwd` mandatory. Returns a `CompletedProcess` whose `.stdout_lines()` /
  `.stdout_string()` (and stderr twins) raise `certora.CalledProcessError` on a non-zero exit.
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
location. `--policy` takes a `.toml` or `.json` document. `--describe` prints the policy's interface for the program author, rendered from the
loaded policy: filesystem grants, every program form as a signature with its holes and flags,
validations, atoms, network rules. Put it in the agent's context with a Claude Code hook in the
project's `.claude/settings.json`:

```json
{"hooks": {"SessionStart": [{"matcher": "startup|resume|clear|compact",
  "hooks": [{"type": "command", "command": "certorail --describe"}]}]}}
``` `--policy` takes `.toml`, `.json`, or a Python file defining `POLICY`. Without it the
nearest ambient policy for the root applies, else the built-in default (read, write and list
anywhere within the root; no programs, no network). Exit status: the program's own when it ran;
1 when rejected; 2 when it does not parse.

Ambient discovery: the config directory is `$CERTORAIL_CONFIG_DIR`, else
`$XDG_CONFIG_HOME/certorail`, else `~/.certorail`. Under its `policy/` subdirectory, a
directory named by the root with `/` turned into `-` (`/srv/work/repo` →
`policy/-srv-work-repo/`, `/` → `policy/-/`) holds `*.toml` files that each carry
`root = "/abs/path"`. The root's ancestors are probed nearest first; only the file whose `root`
equals the probed prefix applies; two such files is an error. Only TOML is discovered
ambiently. The `checkers/` subdirectory beside `policy/` is where validations' programs live,
so the config directory is the single place to audit.

## No Python policy API

A policy is a TOML or JSON document, nothing else: `--policy` refuses any other suffix, and only
TOML is discovered ambiently. The constructors in `certorail/policy.py` are the object model the
loader builds, not a second language.
