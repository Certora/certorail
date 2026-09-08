# revision-exists

A dependency pin may be moved only to a revision a checker confirms exists on the upstream
default branch. The pin is a literal, so certorail runs the checker *while checking the
program* — an arbitrary string, or a branch name, or a plausible-looking commit id that is not
upstream, is refused before anything is checked out.

`revision-exists` is declared **pure**, and that declaration is a claim: that upstream history
is append-only, so once a revision exists it goes on existing and the fact travels with the
string. Purity is what makes analysis-time discharge legitimate. If your upstream can be
force-pushed, that claim is false — drop `pure`, and the fact then has to be established at
runtime by a `certora.check` immediately before the checkout, the way `budget-gate` does it.
The example takes the append-only reading, and says so in the policy.

## Run it

```
certorail examples/policies/revision-exists/pin_dependency.py --check \
  --policy examples/policies/revision-exists/policy.toml \
  --root   examples/policies/revision-exists
```

## The probes

| Probe | Denial |
|---|---|
| `unknown_revision.py` | `argument 3 is not validated by: revision-exists` |
| `moving_ref.py` | `argument 3 is not validated by: revision-exists` |
| `revision_from_argv.py` | `argument 3 is of unknown provenance (neither statically known text nor a proven path)` |

## The checker

`checkers/revision-exists.sh` has two modes, and the offline one is the default.

**Fixture mode** consults `fixtures/upstream-revisions.txt`, one full revision per line. No
network, no git, deterministic — this is what the tests use.

```
$ sh checkers/revision-exists.sh 0123456789abcdef0123456789abcdef01234567 && echo upstream
upstream
$ sh checkers/revision-exists.sh ffffffffffffffffffffffffffffffffffffffff
'ffffffffffffffffffffffffffffffffffffffff' is not on the upstream default branch
$ sh checkers/revision-exists.sh main
'main' is not a full hexadecimal commit id
```

**Mirror mode** takes `EXAMPLE_UPSTREAM_MIRROR` pointing at a local clone of the upstream
project, kept fresh out of band, and asks git whether the revision is an ancestor of that
clone's `origin/HEAD`. It never fetches: a literal checker runs during analysis, possibly more
than once, so it must not touch the network and must not mutate anything. Keeping the mirror
current is the deployment's job, not the checker's. In this mode a revision git has never heard
of comes back as git's own exit code rather than the checker's `1`; anything non-zero refuses.

## What a syscall-level sandbox cannot express

A syscall filter can decide whether `git` may run. It cannot decide whether a string names
something that exists on a machine somewhere else.
