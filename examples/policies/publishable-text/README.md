# publishable-text

Text may reach a public destination only after a scan against a denylist of terms that must not
leak. There are two routes out and the policy closes both, with two atoms of different kinds,
because they are not the same claim.

`text-scanned` is **pure**: it is about one exact string, so it survives every call after the
scan and dies only when the string is rebuilt. A literal that passes the scan carries it for
free — certorail runs the scanner during analysis, so `probes/literal_leak.py` is rejected
before it starts.

`file-scanned` is **environmental**: it is about the bytes in a file at one moment. Anything
effectful may have rewritten them since, so it dies at every possibly-effectful call, and the
scan has to come after the last write and immediately before the publish. That is what
`probes/rewrite_after_scan.py` gets wrong.

The file route is the point of the example. A scan that inspects command arguments sees nothing
at all in `probes/write_then_publish.py`: the text is written to a file and the file is handed
over by name, and every string in that `execve` is innocuous.

The published path is confined twice over, and it takes both. `argument-locations` holds the
arguments the analysis tracked as located paths inside `outbox/**`, but a hard-coded string is
known text rather than a path, so that test skips it — and `scan-file` scans whatever path it
is handed, including one outside the root. The `outbox-path` atom closes that: a regex is a
claim about the text, so a literal has to satisfy it too, and a program asking to publish
`../../etc/passwd` is refused with `argument 2 is not validated by: outbox-path`.

## The denylist is a placeholder

`denylist.txt` holds three obviously fake terms. **It is not a starting point.** A real
deployment supplies its own list, and the list is as trusted as the policy — treat it that way.
Terms only: one per line, no comments, no blank lines. The checkers refuse a blank line rather
than pass on everything, because `grep -f` reads a blank line as a pattern that matches
anything.

## Run it

```
certorail examples/policies/publishable-text/publish_note.py --check \
  --policy examples/policies/publishable-text/policy.toml \
  --root   examples/policies/publishable-text
```

## The probes

| Probe | Denial |
|---|---|
| `unscanned_text.py` | `argument 2 is not validated by: text-scanned` |
| `literal_leak.py` | `argument 2 is not validated by: text-scanned` |
| `write_then_publish.py` | `argument 2 is not validated by: file-scanned` |
| `rewrite_after_scan.py` | `argument 2 is not validated by: file-scanned` |

`literal_leak.py` shows the scanner running during analysis. The same call with clean text is
accepted, and neither version ever ran:

```
$ certorail -c 'import pathlib
certora.exec("post-note", "publish-text", "XXX-DO-NOT-SHIP-XXX: internal build", cwd=pathlib.Path("."))' \
    --check --policy examples/policies/publishable-text/policy.toml \
    --root examples/policies/publishable-text
<command>: rejected
<command>:2:1: denied: exec('post-note'): argument 2 is not validated by: text-scanned
```

## The checkers

`checkers/scan-text.sh` takes the text as an argument; `checkers/scan-file.sh` takes a path and
reads it. Both are case-insensitive, and both validations declare `cwd = "."`, so both run at
the sandbox root. That declaration is load-bearing on the text scanner too: a validation that
declares no `cwd` lets the confined program choose the directory the checker runs in, and
`denylist.txt` is resolved relative to that directory — so the program would be picking the
list it is scanned against.

```
$ sh checkers/scan-text.sh "we ship project-bluebottle soon"
the text contains a term from denylist.txt
$ sh checkers/scan-file.sh outbox/nope.md
no such file: .../outbox/nope.md
```

Neither scanner passes on a failure to look. `grep` exits 0 for a match, 1 for no match and 2
for an error, and both scripts read the status rather than branching on truthiness, so an
unreadable target file or an unreadable denylist is exit 2 and never a pass.

## What a syscall-level sandbox cannot express

A syscall filter can allow or deny `write()` and `execve()`. It cannot require that a
particular predicate has been run over the bytes that flow through them.
