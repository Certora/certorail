# Example policies

Five self-contained examples of what certorail's value logic can express: facts about values
and about the world, established by checker programs and demanded at the call site. Each
directory holds a policy, its checkers, one conforming program, and probes that overstep — one
per way of getting it wrong.

Each example directory is its own sandbox root. `--root` is what the checkers' relative paths
and the runtime sandbox are resolved against, so pass it in every invocation. Omitting it is
not uniformly an error, which is the awkward part: `pinned-image`, `publishable-text` and
`revision-exists` run a literal checker during analysis, so without a root that checker runs in
the wrong directory, finds no fixture and refuses, and the program is rejected. `budget-gate`
and `cloud-account-guard` establish their atoms at runtime, so nothing runs during `--check`
and they are accepted -- against a root that is not theirs, which only shows up when the
program is actually run.

```
certorail examples/policies/<name>/<program>.py --check \
  --policy examples/policies/<name>/policy.toml \
  --root   examples/policies/<name>
```

All five, conforming programs only:

```
for d in examples/policies/*/; do
    certorail "$d"*.py --check --policy "$d/policy.toml" --root "$d"
done
```

Everything runs offline, though the two checkers that would otherwise ask the world default
differently. `revision-exists.sh` consults a fixture file unless `EXAMPLE_UPSTREAM_MIRROR`
points it at a local clone. `cloud-account.sh` is the other way round: it calls the provider
CLI unless `EXAMPLE_CLOUD_ACCOUNT` supplies the answer, which is the stub the tests set.

| Example | What it demonstrates that a syscall-level sandbox cannot express |
|---|---|
| [`cloud-account-guard`](cloud-account-guard/) | That the credentials in effect belong to the account the caller named. A kernel filter sees `execve("cloudctl", ["deploy", ..., "production"])`; it cannot relate that argument to who the ambient credentials say you are. |
| [`pinned-image`](pinned-image/) | That an image reference is pinned to content rather than to a moving name. A tag and a digest are the same kind of `execve` argument; the difference is a property of the string, settled before anything starts. |
| [`budget-gate`](budget-gate/) | That a fact about the world was established recently enough. A sandbox has no notion of a fact going stale between two calls it has already allowed. |
| [`revision-exists`](revision-exists/) | That a string names something that exists on another machine. The answer comes from a process that asks, at analysis time, and it gates the call. |
| [`publishable-text`](publishable-text/) | That the bytes about to leave were scanned — whether they leave as an argument or as a file. Allowing or denying `write()` and `execve()` says nothing about what has been run over their contents. |

## What these examples are not

A `[[program]]` grant is coarse and terminal. certorail decides whether the child may be
spawned and with what arguments; the child then runs outside the jail with the invoking user's
authority, and nothing it does is analysed. These policies constrain what is *started*.

The programs are written to be checked (`--check`). Four of them shell out to `cloudctl`,
`docker`, `submit-job` or `post-note`, none of which exist, so a run without `--check` stops
at the first exec. `revision-exists` is the exception: it drives `git`, which does exist, and
`deps/widget` is a placeholder directory rather than a repository, so git walks up out of it
and acts on whichever checkout the examples happen to sit in. Run that one with `--check`.

The checkers are the trusted half of the policy, and certorail runs the literal ones during
`--check` — analysis is not side-effect free. Keep them fast, deterministic, and free of
writes. Nothing a checker reads on the way to its verdict may fall inside the program's
write grant, and that means the fixtures as much as the scripts: `denylist.txt`,
`approved-images.txt`, `accounts/*.account`, `fixtures/upstream-revisions.txt` and
`state/budget` decide every verdict here. A program that could append to the approved
list, or blank the denylist, would satisfy every atom.

Placeholders throughout: account ids, an `example.com` registry, synthetic digests and
revisions, and a denylist of three obviously fake terms. Substitute your own.
