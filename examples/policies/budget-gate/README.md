# budget-gate

An expensive submission is permitted only while the caller is under budget. `under-budget` is
an **environmental** atom established on the *directory* the submission is made from —
`requires` on a `[[program]]` rule is about the exec's cwd, not its arguments — and it dies at
every possibly-effectful call. The previous submission is such a call, and so is the loop
boundary, so the gate has to be re-established for each job. That is not a limitation being
worked around; it is the only reading of "under budget" that is still true when the money is
spent.

The job specs are passed as proven paths confined to `jobs/**` by `argument-locations`, and
`unknown-arguments = false` refuses anything the analysis cannot vouch for.

## Run it

```
certorail examples/policies/budget-gate/submit_jobs.py --check \
  --policy examples/policies/budget-gate/policy.toml \
  --root   examples/policies/budget-gate
```

## The probes

| Probe | Denial |
|---|---|
| `no_gate.py` | `cwd is not validated by: under-budget` |
| `gate_hoisted.py` | `cwd is not validated by: under-budget` |
| `gate_at_wrong_cwd.py` | `check 'budget-gate' may not run at jobs (permitted: .)`, and then the exec's own denial |

`gate_hoisted.py` is the one to read. The gate is real and it is genuinely called before the
first submission; it is only that one answer is being made to cover a whole batch.

## The checker

`checkers/budget-gate.sh` reads `state/budget`, one line of `spent cap`, so the example works
offline and deterministically. A real deployment replaces that read with a call to whatever
holds the truth: a billing API, a metering service, an accounting database.

```
$ sh checkers/budget-gate.sh && echo under budget      # state/budget is "40 100"
under budget
```

At the cap it refuses with exit 1 and `spend 100 has reached the cap 100`; a fixture it cannot
parse, or a working directory with no fixture in it, is exit 2 and a different message, so a
missing budget never reads as a budget with room in it.

## What a syscall-level sandbox cannot express

A sandbox can allow or deny each submission. It has no notion of a fact going stale between two
calls it has already allowed.
