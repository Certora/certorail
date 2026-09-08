#!/bin/sh
# Exit 0 iff $1 names a commit that exists on the upstream project's default branch.
#
# certorail runs this as a *literal checker*: during analysis, once per distinct revision
# string, with the sandbox root as its working directory. So it must be fast, deterministic
# and free of side effects -- in particular it never fetches.
#
# Two modes:
#   fixture (the default, and what the tests use) -- consult fixtures/upstream-revisions.txt,
#     one full revision per line. Offline, deterministic, no network, no git.
#   mirror -- set EXAMPLE_UPSTREAM_MIRROR to a local clone of the upstream project that is
#     kept fresh out of band, and the checker asks git whether the revision is an ancestor
#     of that clone's origin/HEAD.
set -u
[ "$#" -eq 1 ] || { echo "usage: revision-exists.sh REVISION" >&2; exit 2; }
revision="$1"

# A pin is a full commit id. A branch or tag name is a moving target, so it is not one.
case "$revision" in
    "" | *[!0-9a-f]*) echo "'$revision' is not a full hexadecimal commit id" >&2; exit 1 ;;
esac
[ "${#revision}" -eq 40 ] || { echo "'$revision' is not 40 hex digits" >&2; exit 1; }

if [ -n "${EXAMPLE_UPSTREAM_MIRROR-}" ]; then
    command -v git >/dev/null 2>&1 || { echo "git is not on PATH" >&2; exit 2; }
    [ -d "$EXAMPLE_UPSTREAM_MIRROR" ] || {
        echo "EXAMPLE_UPSTREAM_MIRROR=$EXAMPLE_UPSTREAM_MIRROR is not a directory" >&2
        exit 2
    }
    git -C "$EXAMPLE_UPSTREAM_MIRROR" merge-base --is-ancestor "$revision" origin/HEAD 2>/dev/null
    exit $?
fi

fixture="fixtures/upstream-revisions.txt"
[ -f "$fixture" ] || {
    echo "no fixture at $PWD/$fixture and EXAMPLE_UPSTREAM_MIRROR is unset" >&2
    exit 2
}
grep -q -x -F -- "$revision" "$fixture" || {
    echo "'$revision' is not on the upstream default branch" >&2
    exit 1
}
