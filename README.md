# certorail

Static confinement for LLM-authored Python.

A program written in a restricted subset of Python is analysed, checked against a security
policy, and — only if every filesystem and subprocess operation is *proven* to stay where the
policy allows — run in an isolated interpreter. Anything unprovable is rejected before it runs.

```
$ certorail program.py --root sandbox/ -- arg1 arg2
```

## Why

Agents run code nobody reviewed, and the usual mitigations each give something up. Per-command
approval prompts habituate the user into hitting yes. Containers are coarse: the code needs the
repo and the network to do its job, so the wall has doors. And in-process Python sandboxes have a
long history of escapes — enough that folklore says the problem is unsolvable.

The folklore is about a different threat model: untrusted code sharing a live object graph with
its host, where `__class__`-walking, frames, and `gc` are always one expression away. certorail
deletes those premises. Programs are written in a source subset with no reflection, no dunders,
and no computed attribute access; they are analysed statically; and they run in a separate
interpreter with no ambient authority. The load-bearing consequence is the **value invariant**: no
filesystem, socket, or exec primitive can ever exist as a *value* in a confined program. Sinks are
call-only and syntactically enumerable, so the audit obligation is finite — and where the surface
is broad (`os`, `typing`, imports, decorators, class bases), the subset allowlists rather than
denylists.

## How it works

`certorail program.py` (the `certorail.host` entry point) is a four-step pipeline:

1. **Analyse** (`safepy.py`, `walker.py`, `enforcement.py`, `summaries.py`): the lexical subset
   rules, then a dataflow over an abstract domain of paths and strings — each variable carries
   facts about where it can point — with every policy-facing verdict about a call (is it a site,
   what does it write, what does it yield, does a value establish what is demanded) in
   `enforcement.py`, and what a call to one of the program's own functions does in
   `summaries.py`. Any violation, or any sink whose location is not proven, rejects the program.
2. **Policy** (`policy.py`): every proven filesystem site (read / write / list, with its
   location) and every `certora.exec` site (program, cwd, arguments) is evaluated against the
   policy. Any denial rejects the program.
3. **Rewrite** (`rewrite.py`): `@certora.checked` is prepended to contracted module-level
   functions — the runtime guard for the plain-type half of their annotations. The marker half
   needs no runtime counterpart: relies are discharged at call sites and guarantees at returns,
   statically. Nothing else changes.
4. **Run** (`host.py`): the rewritten source in a fresh `python -I -P` subprocess with the
   sandbox root as its working directory, `certora` bound to `certorail.markers`, and `sys.argv`
   set to the program's arguments.

Exit status: the program's own when it ran; 1 when rejected; 2 when it does not parse.

## Usage

```
uv tool install .
certorail program.py [--root DIR] [--policy POLICY] [--check] [-- ARG ...]
certorail -c SOURCE  [--root DIR] [--policy POLICY] [--check] [-- ARG ...]
certorail --describe [--root DIR] [--policy POLICY]
```

`--check` analyses and evaluates without running. `--root` defaults to the current directory.
`-c` takes the program inline, for agents that generate and run in one step. `--describe` prints
what the policy for the root permits, rendered from the loaded policy for the program author;
a Claude Code `SessionStart` hook running it puts the policy into the agent's context.

Command *templates* let a rule state the shape of a permitted command line — literal words,
typed holes, a flag vocabulary — so `find`, `grep` and friends can be granted without granting
`-exec` or `-r /etc`; *rulesets* bundle such templates for reuse, applied to a policy with a
location. Both are specified in [`TEMPLATES.md`](TEMPLATES.md). A rule may also be a *source*:
values extracted unmodified from its result (`certora.extract` and friends) carry a provenance
fact a hole can demand, so a program acts only on what a trusted query returned; that is
[`PROVENANCE.md`](PROVENANCE.md).

The policy is **trusted**. It is normally a TOML document ([`examples/policy.toml`](examples/policy.toml);
the schema is [`certorail/schema.py`](certorail/schema.py), the loader [`certorail/policyfile.py`](certorail/policyfile.py)), passed with
`--policy` or discovered ambiently under `~/.certorail/policy/` for the sandbox root, with the
checker programs its validations run kept beside it under `~/.certorail/checkers/`. The
[`certorail-policy`](.claude/skills/certorail-policy/SKILL.md) skill walks a Claude Code session
through deriving one from what your scripts need to do, including the checker programs its
runtime validations run. Locations are spelled the same way in the policy and in the program's
annotations, so "the policy permits reads within `data`" and "this function relies on a path
within `data`" mean the same thing:

```toml
policy-version = 1

[filesystem]
read  = ["data/**", "repos/**"]
write = ["repos/**"]
list  = ["repos/**"]

[[program]]
name = "git"
cwd  = "repos/**"

[[program]]
name = "gh"
cwd  = "."
```

There is no Python policy API; a policy is data. Without `--policy` or an ambient policy, the
built-in default applies: read, write and list anywhere within the root, and no subprocesses.

## The subset

The full rules — what is banned, what proves a location, what a guard establishes — are in
[`examples/SUBSET_PROMPT.md`](examples/SUBSET_PROMPT.md), written as the prompt you hand to a
model that is generating confined programs. The short version:

- **Imports**: `import x` only (no `from`, no `as`), standard library only, against a
  forbidden-module list; `os` and `typing` are allowlisted member-by-member. A module name may
  never be a value.
- **No reflection**: `getattr`/`setattr`/`vars`/`eval`/`exec`/… are banned; no dunder identifiers
  anywhere (defining `__init__` is the one exception); callees are names or attribute chains;
  imported and builtin names are never rebound.
- **Filesystem operations are sinks**: `open`, `os.listdir`, `pathlib` reads and writes, … are
  accepted only where the path's location is proven — built from literals and located joins, or
  established by a guard (`assert ".." not in s and "/" not in s`) the analysis recognises.
- **Contracts**: `typing.Annotated` markers on module-level functions state what a parameter
  *relies* on and what a return value *guarantees* (`certora.within("data")`,
  `certora.no_slash`, …). Relies are discharged at call sites, guarantees at returns.
- **Subprocesses**: only `certora.exec(program, *args, cwd=<located>)` — literal program name,
  mandatory proven cwd, no shell, output captured.

[`examples/repo_audit.py`](examples/repo_audit.py) is a non-trivial program in the subset: it
pages a GitHub GraphQL search via `gh`, clones selected repos into a confined `repos/` directory,
and inspects the clones — with exactly one runtime assertion needed to make untrusted API data a
proven-safe path component.

## What this is not

- **Not a DoS guard.** Infinite loops, memory bombs, and decompression bombs are out of scope for
  a static checker; bound them with OS limits on the child process.
- **Not an in-process sandbox.** The analysis is sound only for programs it accepts, running
  under the host's isolation; the isolated interpreter and the OS are the trusted base.
- **Not finished.** This is v0.1.x; the checker's surface is under active adversarial review —
  [`ESCAPE_ENUMERATION.md`](ESCAPE_ENUMERATION.md) is the running catalogue of candidate bypasses
  (many pre-dating current checks) kept as a source of test cases.

## License

GPL-3.0-only. © Certora Ltd.
