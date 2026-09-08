#!/bin/sh
# Exit 0 iff the image reference in $1 is listed, verbatim, in approved-images.txt.
#
# certorail runs this as a *literal checker*: during analysis, once per distinct argument
# text, with the sandbox root as the working directory. It must be fast, deterministic and
# free of side effects.
set -u
[ "$#" -eq 1 ] || { echo "usage: approved-image.sh IMAGE" >&2; exit 2; }
[ -f approved-images.txt ] || { echo "no approved-images.txt in $PWD" >&2; exit 2; }
grep -q -x -F -- "$1" approved-images.txt
