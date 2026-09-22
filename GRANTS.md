# Writing grants

A certorail policy is a list of grants, and everything not granted is denied. Each grant is trust
you extend: a program that uses it acts with your authority, and certorail proves only that the
program stays within what you granted. This guide introduces the kinds of grant and the knobs that
decide how much a granted program can do. The exact keys and their types are in the policy
reference that ships with the `certorail-policy` skill; `certorail describe` shows what a policy
adds up to, in the form the agent sees.

## The root and the filesystem

A policy governs one directory, its **root**, and every directory below it that has no policy of
its own. Locations are spelled relative to the root: `src/**` is `src` and everything below it,
`repos/*` is any single directory under `repos`, `docs/**/<.*\.md>` is any Markdown file under
`docs`, and a leading `/` names a path on the machine rather than in the root.

The filesystem section says where programs may read and write:

```toml
[filesystem]
read     = "**"
write    = ["out/**", "reports/**"]
no-write = ".git/**"
```

Every certorail program's file operation has to be *proven* to fall within one of these. Listing a
directory, or asking whether a path exists, is a read of it. `no-write` is a
protection that beats any write grant: a write that could land under `.git` is denied even
though `**` would have allowed it. Start with reads open and writes narrow; a program that
needs to write somewhere new is asking you for a grant, and that is the review moment.

## Programs

Programs are the reason certorail exists: an agent that can run `git`, `grep` or `pytest` can
get real work done, and each of those can also do harm. A program grant names a program and the
**shapes** of command line it may be run with. The simplest shape is a fixed set of words:

```toml
[[program]]
name       = "git"
subcommand = "status"
cwd        = "repos/*"
```

`cwd` says where the tool may run; the program's `cwd=` argument must be proven to lie within
it. A shape with variable parts is a template with typed **holes**:

```toml
[[program]]
name = "grep"
argv = ["grep", "${FLAGS...}", "--", "${PATTERN}", "${FILES...}"]
cwd  = "."
holes.FLAGS.kind = "flags"
holes.FLAGS.bare = ["-n", "-r", "-i"]
holes.FLAGS."-m" = { matches = '[0-9]+' }
holes.PATTERN    = { any = true }
holes.FILES      = { kind = "each", location = "src/**" }
```

Every hole says what may fill it: a path within a location, text matching a regex, one of some
literals, a value carrying a fact (below), a literal the program itself spells, or `any`. A flags
hole lists the only flags that exist; anything else is rejected. The `--` in the template is a
literal word the host inserts, so whatever follows it is data to the tool even if it starts with a
dash. What is not in a shape does not exist: granting `git status` says nothing about `git push`.

## How much a granted program can do

By default a granted tool runs as you would run it, with the network, the whole filesystem and the
ability to start further processes. Three **media** keys turn those off, per rule, and they are
enforced by an OS jail around the tool rather than declared:

```toml
[[program]]
name       = "git"
subcommand = "status"
cwd        = "repos/*"
network    = false
write-fs   = false
exec.spawn = false
```

Under `write-fs = false` the tool sees a read-only filesystem and a private scratch directory;
under `network = false` it has no network at all; under `exec.spawn = false` it cannot start a
process of its own. A flag that would need one of these fails inside the tool rather than being
quietly permitted. Use them on every tool whose job is to read: the whole coreutils pack that ships
with certorail carries all three.

The tool's **view** of the filesystem is the other knob. By default (`exec.view = "host"`) a tool
sees the host's filesystem and is trusted as granted. With `exec.view = "policy"` it sees only what
the filesystem section grants: the read locations read-only, the write locations writable if the
rule allows writes, the protections read-only on top, plus the system toolchain, its own working
directory and a scratch directory. Nothing else exists for it. `exec.mount-read` and
`exec.mount-write` add locations a particular tool needs beyond the section, a credentials file for
instance, without widening what programs may touch. `exec.env` limits the environment the tool
inherits to the variables you name.

## Gates: validations and atoms

Some commands are fine only in some states: push only from an organisation checkout, force-push
only to an unprotected branch. A **validation** is a small program you write that inspects the
state and exits zero or non-zero; success establishes a named fact, an **atom**, on the value or
directory it checked:

```toml
[atoms]
on-main = {}

[[validation]]
name        = "on-main"
argv        = ["grep", "-qx", "ref: refs/heads/main", ".git/HEAD"]
cwd         = "repos/*"
establishes = { cwd = ["on-main"] }
writes      = []
network     = false

[[program]]
name       = "git"
subcommand = "push origin main"
cwd        = "repos/*"
requires   = ["on-main"]
```

The program calls the validation, and the analysis lets the gated command through only where the
fact is still live. A fact about the world dies at any operation that may have changed the world,
so the agent checks right before it acts. An atom defined by a regex (`not-force = { matches = '[^-].*' }`)
needs no checker: a literal that matches carries it. Validations run with your
authority and are trusted as written; keep them small and install them through `certorail policy
install`.

For batches, a check followed by several commands, the policy can say what each command changes
and what each fact depends on, as named regions of state, so that a `git commit` does not kill a
fact about the remote. That refinement is in the reference under regions; a policy that says
nothing about them is simply stricter.

## Network

A network grant names a host and what may be done to it:

```toml
[[network]]
host    = "api.github.com"
methods = ["GET"]
path    = "/repos/**"
```

The program's URL must be proven to have that scheme, host and path shape before the request is
made, and the host follows redirects only within what is granted. `requires` demands an atom of
the URL, the way a program rule demands one of its directory. `GET` and `HEAD` are treated as
changing nothing; anything else counts as an effect.

## Rulesets and the base

Shapes for a tool are the same in every project, so they come as **rulesets**: parameterised
documents installed once and applied per policy with bindings:

```toml
[[apply]]
ruleset = "git.toml"
where   = "repos"
```

`certorail policy list` shows what is installed and what each ruleset's parameters mean;
`certorail policy apply` writes the table above for you. The **base ruleset**, `rulesets/base.toml`
in your config directory, applies to every root that does not opt out with `base = false`;
`certorail init` offers to create it with the read-only coreutils, so agents have `ls`, `grep`
and `cat` everywhere, jailed. A root policy can take a shape back from an applied ruleset with
`[[deny]] argv = ["git", "push"]`, or replace one of its rules with `override = true`.

## The escape hatch

`default-allow = true` lets a program that no rule names run with any arguments, unjailed, as you.
Programs that rules do name keep their shapes. It is the right setting for a scratch directory and
the wrong one anywhere you care about what runs; everything else in this guide is how to avoid
needing it.

## A way to work

Start from what the task needs, not from what the tool can do. Grant reads widely and writes
narrowly, name every program with the shapes it actually needs, and put the three media keys on
every tool that only reads. Run `certorail describe` and read the result as the agent will; run
`certorail check` on a probe program for each grant, and on one that oversteps it, before you
install. When the agent is denied it should tell you what it needs and why; that request is a
policy edit for you to make, not for it.
