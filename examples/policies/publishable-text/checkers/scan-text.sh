#!/bin/sh
# Exit 0 iff the text in $1 contains none of the terms in denylist.txt (case-insensitive).
#
# certorail runs this as a *literal checker* during analysis when the text is statically
# known, and through the broker at runtime otherwise. Either way: fast, deterministic, no
# side effects.
set -u
[ "$#" -eq 1 ] || { echo "usage: scan-text.sh TEXT" >&2; exit 2; }
[ -f denylist.txt ] || { echo "no denylist at $PWD/denylist.txt" >&2; exit 2; }
# grep -f treats a blank line as a pattern that matches everything, which would make the
# scan pass on anything. Refuse rather than pass.
grep -q -e '^[[:space:]]*$' denylist.txt && {
    echo "denylist.txt contains a blank line" >&2
    exit 2
}
printf '%s' "$1" | grep -q -i -F -f denylist.txt && {
    echo "the text contains a term from denylist.txt" >&2
    exit 1
}
exit 0
