#!/bin/bash

set -o nounset -o pipefail -o errexit

usage() {
    cat <<EOF >&2
Helper script to run tests with strace enabled and filter the trace output to
only include the seccomp enableb zone processes.

usage:
  $0 gather cargo test [OPTIONS] [TESTNAME] [-- <args>...]
  $0 traces
EOF
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

ACTION=$1
shift 1

TRACE_OUTPUT=$(pwd)/.trace

if [ "$ACTION" = "gather" ]; then
    strace -o "$TRACE_OUTPUT" -f "$@"
elif [ "$ACTION" = "traces" ]; then
    for p in "$(grep 'prctl(PR_SET_SECCOMP' "$TRACE_OUTPUT" | cut -f1 -d' ')"; do
        grep "^$p" "$TRACE_OUTPUT"
    done
else
    usage
fi
