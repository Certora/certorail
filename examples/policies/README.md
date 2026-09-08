# Example policies

Five self-contained examples of what certorail's value logic can express: facts about values
and about the world, established by checker programs and demanded at the call site. Each
directory holds a policy, its checkers, one conforming program, and probes that overstep — one
per way of getting it wrong.

Each example directory is its own sandbox root. That is what lets a checker find its fixtures
with a plain relative path, and it is why `--root` is not optional here: without it the literal
checkers run in the wrong directory and refuse, which reads as a denial on the atom they were
meant to discharge.

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

Everything runs offline. Where a checker would otherwise ask a cloud provider or a git remote,
it has a documented fixture or stub mode, and that mode is the default.

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

The programs are written to be checked (`--check`). Running them for real would need
`cloudctl`, `docker`, `submit-job` and `post-note` to exist, which is not the point.

The checkers are the trusted half of the policy, and certorail runs the literal ones during
`--check` — analysis is not side-effect free. Keep them fast, deterministic, and free of
writes. Nothing under `checkers/` should be writable by the confined program.

Placeholders throughout: account ids, an `example.com` registry, synthetic digests and
revisions, and a denylist of three obviously fake terms. Substitute your own.
