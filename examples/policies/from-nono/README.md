# nono profiles, ported to certorail policies

[nono](https://nono.sh) confines a live process: it reads a JSON profile, turns it into
Landlock or Seatbelt rules plus a proxy and a set of exec shims, and then runs whatever binary
you point it at. certorail confines a program: it reads a TOML policy, proves that every
filesystem, subprocess and network operation the program can reach is permitted by it, and only
then runs the program in an isolated interpreter.

The two overlap enough to be worth comparing and differ enough that a port is not a translation.
This directory holds five ports, each a policy, a program it accepts, a program it rejects, and
a header comment saying which parts of the nono fragment survived, which turned into a proof,
and which have no spelling here at all.

## The ports

| Files | nono fragment | The interesting part |
|---|---|---|
| `paths.toml`, `paths_ok.py`, `paths_denied.py` | `groups.include` with `when` predicates, and the `filesystem` block beside it | Path grants carry over; groups, `extends`, `when` and `$HOME` do not |
| `delegation.toml`, `delegation_ok.py`, `delegation_denied.py` | the `git` → `ssh` chained-tool grant with an `invocation_policy` | Subcommands carry over; delegation has no counterpart at all |
| `argv_gate.toml`, `argv_gate_ok.py`, `argv_gate_denied.py` | the `gh` argv gate, and the `kubectl` approval gate | One atom replaces the enumerated flag spellings, and catches the one they miss; approval has no counterpart |
| `endpoints.toml`, `endpoints_ok.py`, `endpoints_denied.py`, `checks/issues-endpoint` | `endpoint_policy` with a method-and-path allow list | Method and host carry over; the path becomes a property of the URL value |
| `protection.toml`, `protection_ok.py`, `protection_denied.py`, `protection_deleted.py` | `unlink_protection`, `deny_credentials`, `dangerous_commands` | All three are already the default; none of the three is expressible as a rule |

## Running them

Every pair is checked, not just read. From the repository root:

```
certorail examples/policies/from-nono/paths_ok.py \
    --check --policy examples/policies/from-nono/paths.toml \
    --root examples/policies/from-nono/sandbox
```

and the same for the other four `_ok.py` programs, which exit 0 and print one line per sink.
The `_denied.py` programs take the same commands, exit 1, and print one line per denial, as does
`protection_deleted.py` — which prints a violation instead, because it is rejected by the subset
rather than by the policy.

`tests/test_examples_from_nono.py` runs all eleven and asserts the denial text, so a policy that
stops behaving as its header claims fails the suite:

```
python3 -m unittest discover -s tests -t .
```

`sandbox/` is a tree for the programs to talk about. `--check` never touches the filesystem, so
it is only needed for a real run — drop `--check` and add `--no-jail`, and `paths_ok.py` and
`protection_ok.py` run end to end. The other three additionally want `git`, `gh`, network access,
and the checker in `checks/` installed at the absolute path `endpoints.toml` names.

## nono says / certorail says / neither says

**Filesystem scoping.** nono says: `allow` (read and write), `read`, `write`, `deny`,
`bypass_protection`, over glob patterns with `$HOME`, `$WORKDIR` and the XDG variables expanded,
per platform, and a directory that matches grants everything under it. certorail says: `read`,
`write` and `list`, three kinds not two, over locations that are relative to the sandbox root or
absolute, with no variables and no platform conditional — and every access site must be *placed*
inside one of them by the analysis, so a path the program computes out of data it read is not
denied, it is unprovable, which rejects the program. Neither says: anything about a path that
exists only at runtime. nono grants an ancestor and inherits the descendants; certorail proves
the descendant or gives up.

**Argv matching.** nono says: `exact`, `prefix` and `contains` over the argv it observes, and its
own documentation is candid that there is no normalisation — not `--flag=value` versus
`--flag value`, not short versus long aliases, not flag order. Its examples work around it by
enumerating: `api graphql`, `api -X POST graphql`, `api --method POST graphql` as three rules;
`namespace`, `namespaces`, `ns` as three more. certorail says: the program name and every
subcommand word must be a string literal, so there is no argv it has not already read, and a
rule constrains arguments by *property* — `argument-atoms` names atoms every argument must carry,
discharged from each argument's known text. `argv_gate.toml` states one such property and it
catches `-X POST`, `-XPOST`, `--method=post` and `POST` together, including the spelling that
slips past all three of nono's rules. The property is coarser than a parser: it rejects any token
containing those letters, "postgres" included. Neither says: anything about what the command will
do with the arguments. Both are looking at text.

**Network and L7 constraints.** nono says: `allow_domain` and `deny_domain` with a hostname
wildcard grammar, and, where a rule carries `endpoints`/`endpoint_rules`/`endpoint_policy`, TLS
interception and per-request method-and-path matching with `deny`, `approve`, `allow`, `default`
and a `reason` on each. certorail says: host, scheme, port and method per `[[network]]` rule,
evaluated at every call site before the program runs and again by the broker on every redirect
hop; the path has no field, and is constrained only by `requires`, naming an atom the URL value
must carry — which a literal URL discharges from its own text. A URL whose scheme and netloc are
not proven is refused outright. Neither says: anything about a query string, a header, or a body.
And neither reaches an exec'd child's traffic: nono's child gets its own sandbox, certorail's
child runs outside the jail entirely.

**Credentials.** nono says a great deal: keyring and 1Password and file and env `credential_key`
URIs, phantom tokens the sandbox sees in place of real ones, header/query/basic injection modes
performed by the proxy on egress, `capture_credential` intercepts, OAuth routes, and socket
brokering that lets `ssh` reach a hardware-backed agent without the key entering the sandbox.
certorail says nothing at all: there is no credential concept in the policy language. What it has
instead is smaller and blunter. A confined program cannot read `os.environ` — `environ` is not on
the allowed `os` surface — so ambient secrets do not reach it, and it cannot read a credential
file unless the policy grants that exact location. Neither says: what an exec'd child may do with
a credential. certorail's broker spawns children outside the jail with the invoking user's whole
environment, and its validation checkers run the same way, so anything certorail runs gets
everything the user has. nono is much stronger here, and this is the largest single gap.

**Composition.** nono says: `extends` up to ten deep, `--extends` on the command line, per-field
merge rules (scalars override, arrays append and deduplicate, maps merge, `network_profile`
three-state, `open_urls` replace-if-present), `platform_overrides` applied after inheritance, and
packs whose profiles extend other packs' profiles by qualified name. certorail says: nothing. A
policy is one document. There is no `extends`, no include, no merge; `--policy` takes one file,
and ambient discovery picks exactly one file — nearest ancestor wins, and two files claiming one
prefix is an error rather than a merge. Neither says: how to remove something a base granted.
nono documents that gap for filesystem paths and `deny_domain`; certorail has no base to remove
from.

**Delegation.** nono says: `can_use` names the children a command may spawn, `from` gives each
caller its own child sandbox, `"session": "deny"` denies the same binary to the session, and a
shell wrapper is not part of the authority chain because the shim-prefixed `PATH` catches it
anyway. certorail says: nothing. A `[[program]]` grant is coarse and terminal — the broker spawns
the child outside the jail with the invoking user's authority, and nothing it does afterwards is
analysed. Granting `git` grants whatever git chooses to run. Neither says: anything about a
grandchild's behaviour once it has started. nono is stronger, decisively; `delegation.toml` says
so in its header rather than pretending otherwise.

**Removal.** nono says: `groups.exclude`, `filesystem.deny`, `deny_domain`, `deny.access`,
`deny.unlink`, `deny.commands`, `bypass_protection` to punch back through a deny group — and
refuses to start on Linux when a `deny` overlaps an `allow`, because Landlock has no deny
primitive to express the carve-out. certorail says: nothing, and needs less. `Policy.allow` is the
only constructor; there is no deny list, no negative rule, no key that removes an earlier grant,
and rules for one program are read disjunctively so listing more can only widen. Default-deny
makes most deny lists unnecessary: `deny_credentials` is the absence of a grant, and
`dangerous_commands` is the empty program list. The one thing genuinely missing is the carve-out —
excluding one name from inside a granted tree. The nearest approximation is a negative lookahead
inside a single location component, which `protection.toml` uses and its header flags as a regex
trick rather than a feature: nothing backstops it, and a wider grant beside it silently reopens
what it excluded. Neither says: how to remove an *operation*. certorail forbids deletion in the
subset, where no policy can grant it back; nono's `unlink_protection` is a group, so a profile can
exclude it.

**The enforcement model.** nono says: the profile becomes kernel rules before the process starts,
and the kernel stops the operation. That works on any binary — a Rust agent, a shell script, a
compiled tool nobody has the source for — and it stops the operation that actually happens rather
than the one that was predicted. What it costs is the granularity: an ancestor grant covers its
descendants, an argv matcher sees text, a deny group is best-effort where an allowed interpreter
can make the syscall directly, and a denial arrives mid-run, after side effects have already
landed. certorail says: the program is analysed before it runs, and only a program whose every
operation is *proven* permitted runs at all. Rejection is total and happens before the first
line executes, so there is no partial-failure state to clean up, and the audit obligation is
finite because sinks are call-only and syntactically enumerable. What it costs is the scope: it
governs Python written in one restricted subset and nothing else. It cannot confine a binary, and
the binaries it does permit run entirely outside its reach. Neither says: anything useful about a
program that is neither analysable nor started under the tool.

## Not expressible today

These have no syntax in certorail. Nothing below is a feature you can write; each is a gap, with
a sketch of what closing it would take.

**Composition (`extends`).** The top-level key set is closed and `from_data` builds one `Policy`
from one document, so there is no include, no inherit and no merge — and no partial policy to
share between projects. Closing it means picking a merge law and defending it. Union of grants is
the only law consistent with `Policy.allow` being the sole constructor, since there is no removal
to express an override with; that makes a base a floor a child cannot lower, which is exactly the
property nono documents as a wart. The other half is atom identity: two documents declaring the
same atom name with different `matches` regexes, or one pure and one environmental, would have to
be an error rather than a silent winner — `Policy.allow` already rejects the second case within
one document.

**Platform conditionals.** No `when`, no `platform_overrides`, no environment reference of any
kind in the policy content. A `.py` policy could branch on `sys.platform`, but that is Python
rather than the language, and such a policy is deliberately never discovered ambiently. Closing
it means either a `when` field on every entry, or ambient discovery choosing among per-platform
documents — which is the smaller change, since discovery already selects one file by root.

**Delegation and per-child policy.** No caller in the model, no `can_use`, no child sandbox.
This is not a syntax gap: the broker spawns children outside the jail on purpose, and giving them
policy would mean confining processes rather than programs — a different tool with a different
enforcement mechanism underneath. Saying so is more useful than a keyword that would not mean
anything.

**Approval.** No `approve` decision, no backend, no human in the loop. Analysis produces one
verdict before the program starts; there is no moment at which a person could be asked, because
by design nothing has happened yet. A runtime approval would have to live in the broker, beside
the existing runtime re-checks, and it would then apply to exec and network calls only — not to
the filesystem sites, which are settled statically and never reach the broker as questions.

**Reasons.** A `Denial` carries a site and a reason string that the evaluator renders; the policy
cannot attach its own words to a rule, and the rule that came closest is not reported at all.
Every nono rule in this directory's quoted fragments carries a `reason`, and those reasons are
what a person actually reads. Closing it means a field on the rule dataclasses and a back-pointer
from `Denial` to the candidate rule.

**Path patterns for URLs, and carve-outs for paths.** A `[[network]]` rule has no path field, so a
path constraint has to be smuggled into an atom's regex over the whole URL; and a location has no
exclusion, so removing one name from a granted tree has to be smuggled into a negative lookahead
in one component. Both work, both are the wrong shape, and both are flagged where they are used.
