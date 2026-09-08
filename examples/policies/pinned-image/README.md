# pinned-image

A container may be run only from an image pinned by digest, and only from a digest this
repository has approved. Two atoms, settled two different ways and both during analysis.
`pinned-by-digest` is **defined** by a regex — the regex is the atom's meaning, so a literal
image reference satisfies it with no process run at all. `approved-image` is **pure** but not a
shape: membership in `approved-images.txt` is not something a regex can say, so a *literal
checker* answers it, and certorail runs that checker while it is checking the program.

This policy grants no filesystem access whatsoever; the program's only sink is the exec. Note
also that a `[[program]]` grant is coarse and terminal — certorail decides whether `docker` may
be spawned and with what arguments, and then the child runs outside the jail with the invoking
user's authority. Pinning the image is a statement about what is *started*, not a confinement
of what it then does.

The regex here is a deliberate simplification, not a specification of the OCI reference
grammar: it admits lowercase registry paths without a port. Widen it for your registry.

## Run it

```
certorail examples/policies/pinned-image/run_report.py --check \
  --policy examples/policies/pinned-image/policy.toml \
  --root   examples/policies/pinned-image
```

## The probes

| Probe | Denial |
|---|---|
| `moving_tag.py` | `argument 3 is not validated by: approved-image, pinned-by-digest` |
| `unapproved_digest.py` | `argument 3 is not validated by: approved-image` |
| `computed_image.py` | `argument 3 is of unknown provenance (neither statically known text nor a proven path)` |

The middle one is the interesting denial: the digest satisfies the regex, so only the
list-membership atom is missing, and the message says exactly that.

## Forgetting `--root`

`--root` defaults to the current directory, so the literal checker still runs -- in the wrong
place, where there is no `approved-images.txt`. It exits non-zero, `approved-image` is never
discharged, and the conforming program is rejected:

```
$ certorail examples/policies/pinned-image/run_report.py --check \
    --policy examples/policies/pinned-image/policy.toml
examples/policies/pinned-image/run_report.py: rejected
examples/policies/pinned-image/run_report.py:9:14: denied: exec('docker'): argument 3 is not validated by: approved-image
```

## What a syscall-level sandbox cannot express

A syscall filter sees one `execve` argument either way. A tag and a digest differ only as
strings, and that difference is settled before anything starts.
