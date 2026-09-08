#!/bin/sh
# Exit 0 iff the file at $1 contains none of the terms in denylist.txt (case-insensitive).
#
# certorail runs this through the broker at runtime, with the sandbox root as its working
# directory, so $1 is interpreted exactly as the confined program spelled it.
#
# grep's exit status has three meanings -- 0 matched, 1 did not match, anything else went
# wrong -- so every call reads the status rather than branching on truthiness. A file that
# cannot be read is the third case, and it must not read as a clean file.
set -u
[ "$#" -eq 1 ] || { echo "usage: scan-file.sh PATH" >&2; exit 2; }
[ -f denylist.txt ] && [ -r denylist.txt ] || {
    echo "no readable denylist at $PWD/denylist.txt" >&2
    exit 2
}

grep -q -e '^[[:space:]]*$' denylist.txt
case $? in
    0) echo "denylist.txt contains a blank line" >&2; exit 2 ;;
    1) ;;
    *) echo "could not read denylist.txt" >&2; exit 2 ;;
esac

[ -f "$1" ] || { echo "no such file: $PWD/$1" >&2; exit 2; }
[ -r "$1" ] || { echo "cannot read $PWD/$1" >&2; exit 2; }

grep -q -i -F -f denylist.txt -- "$1"
case $? in
    0) echo "$1 contains a term from denylist.txt" >&2; exit 1 ;;
    1) exit 0 ;;
    *) echo "the scan of $1 failed to run" >&2; exit 2 ;;
esac
