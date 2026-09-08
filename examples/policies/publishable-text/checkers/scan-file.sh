#!/bin/sh
# Exit 0 iff the file at $1 contains none of the terms in denylist.txt (case-insensitive).
#
# certorail runs this through the broker at runtime, with the sandbox root as its working
# directory, so $1 is interpreted exactly as the confined program spelled it.
set -u
[ "$#" -eq 1 ] || { echo "usage: scan-file.sh PATH" >&2; exit 2; }
[ -f denylist.txt ] || { echo "no denylist at $PWD/denylist.txt" >&2; exit 2; }
grep -q -e '^[[:space:]]*$' denylist.txt && {
    echo "denylist.txt contains a blank line" >&2
    exit 2
}
[ -f "$1" ] || { echo "no such file: $PWD/$1" >&2; exit 2; }
grep -q -i -F -f denylist.txt -- "$1" && {
    echo "$1 contains a term from denylist.txt" >&2
    exit 1
}
exit 0
