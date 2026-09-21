# The git pack

Status: **loads** (2026-09-15). The common git surface, written in the parameter, `when`,
flag-`requires`, `[[deny]]`/`override` and `no-write` syntax, all of which the loader has;
`tests/test_rulesets.py::TestGitPack` installs the pack into a scratch config directory and
loads `examples/git-policy.toml` against it, and every rung with every parameter on. Two things
the load surfaced: the vocabulary's `[regions]`/`[atoms]` keys had to be quoted (`"git.head"`,
since a bare `git.head` is TOML for a nested table), and `remote` has no default, so a root
applying the umbrella binds it even when it overrides `push`. The checkers in `checkers/` are
not executable in the tree; installing them is what sets the bit. The section "What the loader
must grow" records what the attempt found and what each finding became.

## Files

| file | what it grants | media |
|---|---|---|
| `git-vocabulary.toml` | nothing: `git.*` regions, atoms, seven validations | |
| `git-read.toml` | log, show, diff, status, rev-parse, remote -v, config --get/--list, ls-files, ls-tree, blame, grep, describe, cat-file, check-ignore | no network; status and diff write `git.index` |
| `git-local.toml` | add, commit, branch, switch, stash, tag, merge, cherry-pick, mv, apply | no network |
| `git-rewrite.toml` | checkout (both meanings), restore, reset, rebase, rm, clean | no network |
| `git-remote.toml` | push, fetch, pull, ls-remote | network |
| `git-create.toml` | clone, init | network (clone) |
| `git.toml` | the umbrella: read + local always, the rest by parameter | |
| `checkers/git-ref-name`, `-rev`, `-not-default-branch`, `-remote-url`, `-config-key` | text checkers: literal checkers, run by the host on constants | |
| `checkers/git-clean`, `checkers/git-head-not-default` | repository checkers, run in the repository | |

Rungs are the composition axis: prefix-freedom puts each subcommand in exactly one file, so a
root chooses rungs, not subcommands. Every rung applies the vocabulary with the same binding and
the diamond dedupes to one copy.

## Parameters

| name | kind | owner | meaning |
|---|---|---|---|
| `where` | directory (set) | all | the directory holding repositories, or a repository. Command cwd is `${where}/**`: git runs from any subdirectory; `where = "."` makes the root itself the repository |
| `remote` | constraint | remote | what REMOTE may be; default `{ one-of = ["origin"] }` |
| `branch` | constraint | remote | what BRANCH may be; **required**. `{ atoms = ["git.ref-name"] }` is "any well-formed branch" |
| `push-gate` | atom (list) | remote | atoms the repository must carry to push; `[]` is no gate |
| `force`, `force-gate` | bool, atom (list) | remote | `--force`/`--force-with-lease`, and what BRANCH must carry for them |
| `delete` | bool | remote | `push --delete`, gated on `force-gate` too |
| `rebase-pull` | bool | remote | `pull --rebase` |
| `rewrite` | bool | umbrella, local | apply the rewrite rung; unlock `--amend`, `branch -D/-M/-f/-C`, `tag -f` |
| `skip-hooks` | bool | local, rewrite, remote | `--no-verify` |
| `clone`, `clone-from` | bool, constraint | umbrella, create | apply the create rung; what may be cloned |

Bools default to false and false is always the tighter policy. `git.not-default-branch` is a
pure atom the pack ships for `force-gate`; `git.clean` and `git.head-not-default` are
environmental atoms with checkers, for `push-gate` or a root's own rules.

## What a program spells

The hole names are the same across every rung: `FLAGS` (a list of flag literals and their
values), `REVS` (revisions), `ARGS` (names), `PATHS` (paths, after `--`), `REMOTE`, `BRANCH`,
`URL`, `DIR`, `OP` (the stash operation), `KEY`.

```python
certora.exec("git", "status", "--short", cwd=repo)                         # flags last: positional
certora.exec("git", "commit", "-m", "notice", cwd=repo)
certora.exec("git", "push", "origin", branch, "-u", cwd=repo)
certora.exec("git", "stash", "push", "-m", "wip", cwd=repo)
certora.exec("git", "log", FLAGS=["--oneline", "-n", "20"], REVS=["main..HEAD"], cwd=repo)
certora.exec("git", "diff", FLAGS=["--stat"], PATHS=[pathlib.Path("src")], cwd=repo)
certora.exec("git", "add", PATHS=[pathlib.Path("src") / name], cwd=repo)     # relative to the repository
certora.exec("git", "switch", FLAGS=["-c"], ARGS=[name], cwd=repo)
```

A closed `FLAGS` hole that is not last now ends at the first positional that provably is not a
flag (finding 7, landed), so `diff`, `add` and `switch` bind positionally when the operand is a
path or a literal: `certora.exec("git", "add", pathlib.Path("src") / name, cwd=repo)`. An
operand that is unknown text (a name from `sys.argv`) right after the flags is rejected, not
guessed: spell those by keyword. `log`'s `REVS...` is an `each` hole before `PATHS...`, and an
each hole cannot end on its own, so `log` stays keyword-only.

**Path operands are text git resolves against its cwd, the repository.** The hole asks only
that the value be a proven relative location (`location = "**"`): a well-formed relative
spelling with no `..` and no leading `/`, which is a valid pathspec anywhere. Spell them
relative to the repository, `pathlib.Path("src") / name`, not `repo / "src" / name`; the latter
is a proven location too and is not denied, but git will look for `repos/x/src/...` inside
`repos/x` and match nothing. Whether the spelled file exists is a runtime fact of the working
tree that only git can decide, and it reports when it cannot.

**Revisions, names, URLs and keys are checked text.** Each pure atom (`git.ref-name`, `git.rev`,
`git.remote-url`, `git.config-key`, `git.not-default-branch`) is established by a small Python
checker rather than defined by a regex: a literal in the program is discharged by the host at
analysis time with no ceremony, and a dynamic value goes through
`name = certora.check_single("git.ref-name", name)`. Spawning a Python process per name is
nothing next to a command that reaches a remote, and five assertions with a reason on stderr are
what a reviewer can read; a lookahead regex is not.

## What the root must do

- **Grant no writes under any `.git`.** Repository config and hooks are how a tree makes git
  execute programs: `core.hooksPath`, `core.fsmonitor`, `diff.external`, `filter.*.clean`,
  `credential.helper`, `core.sshCommand`. The pack keeps every git command that writes config
  or hooks out of the vocabulary; the root's `[filesystem]` grant must keep the program out too.
  `examples/git-policy.toml` spells it: `repos/*/<(?!\.git\Z).+>/**`. Nested repositories,
  worktrees (a `.git` *file*) and submodules put a `.git` deeper than that spelling excludes;
  if the tree has them, the grant must be tighter. A ruleset cannot state this obligation
  today (below).
- Install the seven scripts under `checkers/` in the checkers directory, executable, or the
  vocabulary fails to load.
- Bind `branch`, and `clone-from` if `clone = true`. Everything else has a safe default.

## What the attempt found

Things a sketch would not have surfaced; each is either a needed extension or a decision worth
a second look.

**Extensions the pack needs to load** (beyond the parameter kinds, `when`, `value = false`,
flag-level `requires`, `[[deny]]` and `override` already contemplated; item 1 is kept as a
record of a wrong turn):

1. **Withdrawn: a cwd-relative path constraint.** The first draft gave every pathspec hole
   `location = "${where}/**"` plus a `relative-to = "cwd"` modifier, on the theory that the
   operand must be shown to lie under the exec's cwd. Three versions of that were considered
   (a broker-side `relpath` rewrite, a relational "derived from the cwd variable" fact, an
   anchor flip with a `relative_to` transfer function) and all rested on one category error: a
   location fact is a claim about **text**, and where that text meets the filesystem the sandbox
   containment applies. "This spelling, joined to the cwd, names a file in the repository" is a
   property of the working tree at run time, which no static checker can discharge and git
   already decides. The hole therefore says `location = "**"`: a proven relative spelling, which
   is a valid pathspec in any cwd. The dash guard denies a value with an unknown first component
   unless a spelled `--` precedes it, which is where every path operand in the pack sits and
   where git wants them. No extension.
2. **Rule-level `requires` in table form**, `{ cwd = [...], HOLE = [...] }`. This turned out to
   be load-bearing, not cosmetic: it is how the pack conjoins its own atom with the root's
   constraint on the same hole. `holes.BRANCH = "${branch}"` is whatever the root bound;
   `requires = { BRANCH = ["git.ref-name"] }` is the pack insisting a branch is not a refspec.
   Without it a root regex that admits `feature:main` pushes to main. The "pack cannot constrain
   the binding" limitation noted earlier is closed for atoms by this alone.
3. **Parameters referenced only from dropped pieces need no binding.** `force-gate` is used
   only inside flags gated by `force`; `clone-from` only in an apply gated by `clone`. So `when`
   is resolved before bindings are checked. Otherwise every bool drags its companions into
   every `[[apply]]`.
4. **Bindings pass through nested applies for every kind**: `branch = "${branch}"`,
   `force = "${force}"`, `push-gate = "${push-gate}"`, as `where` does today.
5. **`holes = [...]` on a `[[flagset]]`: the mixin contract.** A flag's `requires` gates an
   atom on another hole's value (`--force` requires `force-gate` of `BRANCH`), and the first
   draft had the flagset name `BRANCH` with no declaration that such a hole exists: a reusable
   vocabulary reaching into a template it never saw. The flagset instead declares the holes it
   requires by name; a flag's `requires` may name only `cwd` or one of them (error at the
   flagset otherwise), and a template referencing the flagset must bind a token or each hole of
   each name (error naming both parties). `holes` says nothing about the hole's constraint: the
   template says what the value is, the flagset asks for an atom on it. Inline vocabularies need
   no declaration. Flagsets stay private and inlined; this is a reference, not a definition.
6. **`not-option` as a built-in pure atom, and the dash guard as its saturation rule.** The
   guard today reads structure: a value fills a token or each hole with no spelled `--` before
   it only if its regex has a fixed head not starting with `-`, or its location's first
   component is named or absolute. A checker-established atom has no structure to read, so
   every `REVS`/`ARGS` value proven by `git-ref-name` would be denied before `--`, and most of
   the pack's holes sit there. Flip it: `not-option` is an atom certorail declares (no file
   does), a checker lists it in `establishes` (every text checker in the vocabulary does), and
   the structural test becomes the rule by which literals, fixed-head regexes and named
   locations *saturate* it, exactly as a `matches` atom saturates onto text known to match.
   The guard is then one line: a token or each hole not preceded by `--` requires
   `not-option`; a flag's value does not. Denials name the atom, `--describe` renders it, and
   the deferred program-side guard (`not s.startswith("-")` establishing it) is a later transfer
   function, not a new mechanism. This is TEMPLATES.md's deferred "`not-option` atom" item,
   arrived at from the other side.

**Binder ergonomics** (the pack loads without these; the fast path needs them):

7. **A flags hole ends at the first positional that cannot be in flag position.** *Landed.* The
   dash guard already makes this decidable: a positional that is known text not starting with
   `-`, or a located value, cannot be a flag, so a closed `FLAGS` hole takes the flag-shaped head
   and the next hole begins at the first `not-option` positional. A positional that could be
   either is a rejection naming the fix (bind by keyword), never a guess. `diff`, `add`, `switch`
   bind positionally. *Rejected*: the **spelled separator** (`--` after a variadic hole as a word
   the program passes) that would let `REVS... -- PATHS...` bind positionally. A variable value
   before the `--` is not proven to differ from `--`, so the parse is ambiguous (and with it,
   which value a `requires` on the later hole is demanded of); proving it would mean facts about
   template spelling. Keywords are unambiguous and cheap. `log` stays keyword-only.

**A ruleset-side obligation on the root** -- *landed, with a change of semantics*:

8. `[filesystem] no-write = ["${where}/**/.git"]` in a ruleset (`git-vocabulary.toml` carries
   it). As proposed it was a load-time check on the root's write grants; as built it is a
   **protection**: a program write whose path may lie at or below the location is denied at
   analysis time whatever `write` grants, by the same at-or-below alignment EFFECTS.md uses for
   footprints. The load-time reading was unsatisfiable: a root granting `repos/*/**` always
   *can* name `.git`, and the regex exclusion the example wrote (`<(?!\.git\Z).+>`) is opaque to
   the conservative component match. So the pack imposes the exclusion rather than asking for
   it, and the root grants `repos/*/**` plainly. The cost is precision: a `*` component may be
   `.git`, so a dynamic component under a protected tree needs a regex that cannot spell it
   (`<\w+>`, `<[^.].*>`; the regex-versus-name test is exact over the name's case spellings).
   A concrete protection is also lowered into srt's `denyWrite`.

`[[deny]]` and `override` landed too (root only; a denial takes back every applied shape under
its words, an override replaces the overlapping applied shape, and each errors when it finds
nothing). `git-policy.toml` loads, pack and all.

**Decisions the pack made that deserve a look:**

- `checkout` is in the rewrite rung, both meanings. `git checkout X` restores the file X when X is
  not a ref, discarding changes; that cannot be told apart statically, so the local rung offers
  `switch` and `restore` lives with the destructive commands. Agents habitually type `checkout
  -b`; `--describe` tells them `switch -c`.
- `stash` is one shape with a spelled operation (`push|pop|apply|list|show`); `drop` and
  `clear` are absent, as is `stash@{n}` addressing. `branch` and `tag` are each one shape that
  lists and creates, because listing and creating share leading words.
- `push` requires an explicit remote and branch. Bare `git push`, `--all`, `--mirror`, `--prune`
  and refspecs are absent because each names a destination the policy never saw. `--tags` is
  allowed.
- `fetch` and `pull` take remote *names* only. Fetching from a URL is not spellable (the
  `git-ref-name` checker refuses `:` and empty components, so no URL passes); the set of remotes
  is repository config, which the `.git` exclusion protects.
- `status` and `diff` declare `writes = ["git.index"]` rather than `write-fs = false`: they
  refresh the stat cache, and `write-fs = false` is enforced, so the refresh would fail. The
  checkers run `--no-optional-locks` so a check is honestly effect-free (`writes = []`).
- `commit` takes `-m` as a flag rather than as a structural word (`git commit -m ${MESSAGE}`
  would need the dash guard to exempt a hole after a literal flag word, one more extension). A
  commit without `-m` opens an editor and fails on the broker's `/dev/null` stdin.
- Global options (`-c key=value`, `-C`, `--git-dir`) precede the subcommand and are unspellable
  in a template whose leading words select it. Good: `-c core.hooksPath=` is the sharpest tool
  in the box. But it also means the pack cannot *emit* `-c core.hooksPath=/dev/null` as a
  defence; that would be a child-environment matter (JAILS.md).
- `git.rev` admits text that is also a path. In every command that takes `REVS` this is either
  harmless (the read rung) or already in the rewrite rung; `switch` rejects a path itself.
