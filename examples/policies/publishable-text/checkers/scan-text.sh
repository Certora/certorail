#!/bin/sh
# Exit 0 iff the text in $1 contains none of the terms in denylist.txt (case-insensitive).
#
# certorail runs this as a *literal checker* during analysis when the text is statically
# known, and through the broker at runtime otherwise. Either way: fast, deterministic, no
# side effects.
#
# grep's exit status has three meanings -- 0 matched, 1 did not match, anything else went
# wrong -- so every call reads the status rather than branching on truthiness. `cmd && ...`
# would fold "went wrong" in with "did not match" and pass the text.
set -u
[ "$#" -eq 1 ] || { echo "usage: scan-text.sh TEXT" >&2; exit 2; }
[ -f denylist.txt ] && [ -r denylist.txt ] || {
    echo "no readable denylist at $PWD/denylist.txt" >&2
    exit 2
}

# grep -f treats a blank line as a pattern that matches everything, which would make the
# scan pass on anything. Refuse rather than pass.
grep -q -e '^[[:space:]]*$' denylist.txt
case $? in
    0) echo "denylist.txt contains a blank line" >&2; exit 2 ;;
    1) ;;
    *) echo "could not read denylist.txt" >&2; exit 2 ;;
esac

printf '%s' "$1" | grep -q -i -F -f denylist.txt
case $? in
    0) echo "the text contains a term from denylist.txt" >&2; exit 1 ;;
    1) exit 0 ;;
    *) echo "the scan of the text failed to run" >&2; exit 2 ;;
esac
