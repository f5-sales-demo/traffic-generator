#!/usr/bin/env bash
# Explicit catalog discovery; dry-run never sources configuration or writes files.
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")/.." && pwd)/scripts/traffic_catalog.py" "$@"
