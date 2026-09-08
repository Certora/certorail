#!/bin/sh
# Exit 0 iff the credentials currently in effect resolve to the account this sandbox has
# recorded for the environment named in $1.
#
# certorail runs this at RUNTIME, through the broker, with the sandbox root as its working
# directory and the host's own environment and credentials. It is never run during analysis:
# the atom it establishes is environmental, so there is nothing about a literal to discharge.
#
# Two modes:
#   stub  -- EXAMPLE_CLOUD_ACCOUNT is set: its value is taken as the account the credentials
#            resolve to. This is what the offline tests use. DELETE THAT BRANCH when you
#            adapt this checker: it lets anything that can set one variable in the broker's
#            environment answer the question for you.
#   live  -- otherwise: ask the provider CLI who it is. Substitute your own provider's
#            "who am I" command for the `cloudctl account show` line below.
#
# Every failure is loud and distinct, so an absent CLI never reads as an absent account.
set -u
[ "$#" -eq 1 ] || { echo "usage: cloud-account.sh ENVIRONMENT" >&2; exit 2; }
environment="$1"

# The name comes from the confined program, and it is about to become a path component.
# A checker validates everything it is handed; without this, a name containing `..` reads a
# file outside accounts/ while a different string is what goes on to the provider.
# The characters are spelled out rather than given as `a-z0-9`: a range in a case pattern
# is collation-dependent, and matches uppercase under a UTF-8 locale.
case "$environment" in
    "" | *[!abcdefghijklmnopqrstuvwxyz0123456789_-]*)
        echo "not an environment name: '$environment' (expected [a-z0-9_-])" >&2
        exit 2
        ;;
esac

expected_file="accounts/$environment.account"
if [ ! -f "$expected_file" ]; then
    echo "no account recorded for environment '$environment' ($PWD/$expected_file)" >&2
    exit 3
fi
expected=$(cat "$expected_file")
[ -n "$expected" ] || { echo "$expected_file is empty" >&2; exit 3; }

if [ -n "${EXAMPLE_CLOUD_ACCOUNT-}" ]; then
    # Test stub. Delete this branch when adapting the checker -- see the header.
    actual="$EXAMPLE_CLOUD_ACCOUNT"
else
    command -v cloudctl >/dev/null 2>&1 || {
        echo "cloudctl is not on PATH: cannot tell which account these credentials are for" >&2
        exit 4
    }
    actual=$(cloudctl account show --format id 2>/dev/null) || {
        echo "cloudctl could not resolve the current credentials (expired? unset?)" >&2
        exit 5
    }
fi

[ -n "$actual" ] || { echo "the provider reported no account id" >&2; exit 5; }
[ "$actual" = "$expected" ] || {
    echo "credentials resolve to account $actual, not the '$environment' account $expected" >&2
    exit 1
}
