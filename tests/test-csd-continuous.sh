#!/usr/bin/env bash
set -euo pipefail
root=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
# Unit contracts use real Git and env subprocesses without requiring elevation.
command -v git >/dev/null
node --test "$root/tests/csd-continuous.test.mjs"
