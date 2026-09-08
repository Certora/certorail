#!/bin/sh
# Exit 0 while this sandbox is still under its spend cap.
#
# certorail runs this at RUNTIME, through the broker, with the sandbox root as its working
# directory. The atom it establishes is environmental, so it is never run during analysis.
#
# The example reads a fixture so the whole thing works offline and deterministically. A real
# deployment replaces the two lines below with a call to whatever holds the truth: a billing
# API, a metering service, an accounting database.
set -u
budget_file="state/budget"
[ -f "$budget_file" ] || { echo "no budget fixture at $PWD/$budget_file" >&2; exit 2; }
read -r spent cap < "$budget_file" || { echo "$budget_file is empty" >&2; exit 2; }
case "$spent" in "" | *[!0-9]*) echo "spend '$spent' is not a number" >&2; exit 2 ;; esac
case "$cap"   in "" | *[!0-9]*) echo "cap '$cap' is not a number" >&2; exit 2 ;; esac
[ "$spent" -lt "$cap" ] || { echo "spend $spent has reached the cap $cap" >&2; exit 1; }
