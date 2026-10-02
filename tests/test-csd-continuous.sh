#!/usr/bin/env bash
set -euo pipefail
root=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
# Process-boundary/provenance regressions require real Linux sudo and Git.
command -v git >/dev/null
command -v sudo >/dev/null
sudo -n -u nobody -- /usr/bin/env -i PATH=/usr/bin:/bin /bin/true
node --test "$root/tests/csd-continuous.test.mjs"
