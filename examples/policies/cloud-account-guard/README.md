# cloud-account-guard

A cloud CLI may be invoked only when the credentials in effect resolve to the account this
sandbox has recorded for the environment the caller named. `credentials-verified` is an
**environmental** atom: the checker asks the provider who it is, and the answer is true of a
moment rather than of a string. The atom rides the environment name itself, so one validation
covers any number of environments — and because it dies at every possibly-effectful call, the
answer that authorizes the deploy is the most recent one, with nothing that could have changed
the world in between. Calls the analysis proves effect-free may sit there; `print` and
`os.path.join` do not invalidate it. A profile
named `staging` that resolves to the production account fails the check, loudly, with the two
account ids in the message.

Note the shape of the `[[program]]` rule. `argument-atoms` is demanded of *every* argument
after the subcommand words, so the manifest is pinned inside `subcommand` rather than passed
as an argument. And `unknown-arguments = true` is deliberate: the environment name comes from
`sys.argv`, so it is not statically known text, and the atom rather than the spelling is what
makes it safe.

## Run it

```
certorail examples/policies/cloud-account-guard/deploy.py --check \
  --policy examples/policies/cloud-account-guard/policy.toml \
  --root   examples/policies/cloud-account-guard

certorail examples/policies/cloud-account-guard/probes/no_check.py --check \
  --policy examples/policies/cloud-account-guard/policy.toml \
  --root   examples/policies/cloud-account-guard
```

## The probes

| Probe | Denial |
|---|---|
| `no_check.py` | `argument 4 is not validated by: credentials-verified` |
| `stale_check.py` | `argument 4 is not validated by: credentials-verified` |
| `undeclared_subcommand.py` | `arguments match no declared subcommand of 'cloudctl' (subcommands fail closed)` |

## The checker

`checkers/cloud-account.sh` runs at runtime only, with the sandbox root as its working
directory. Set `EXAMPLE_CLOUD_ACCOUNT` to the account id the credentials should resolve to and
it uses that instead of shelling out — this is the stub the tests use, and it is how the
example stays runnable with no cloud account. **Delete that branch when you adapt the
checker.** It is an unconditional override of a credential check: anything that can set one
variable in the broker's environment answers the question. Left unset, it calls
`cloudctl account show --format id`; replace that one line with your provider's "who am I"
command. Each way of failing exits differently (`1` mismatch, `3` unknown environment, `4` no
CLI, `5` no credentials) and says so on stderr, which is what reaches the confined program as
`CheckFailed`.

```
$ EXAMPLE_CLOUD_ACCOUNT=000000000002 sh checkers/cloud-account.sh staging
credentials resolve to account 000000000002, not the 'staging' account 000000000001
```

The environment name arrives from the confined program and becomes a path component, so the
checker rejects anything that is not `[a-z0-9_-]` before building the path. A checker
validates everything it is handed, including the arguments it is only going to look things
up with.

`accounts/*.account` hold placeholder ids. Substitute your own.

## What a syscall-level sandbox cannot express

A seccomp or Landlock rule sees `execve("cloudctl", ["deploy", ..., "production"])` and can
allow or deny it. It has no way to relate that argument to what the ambient credentials say
about who you are — and no way to insist the relation was established recently.
