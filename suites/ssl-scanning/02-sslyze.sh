#!/bin/bash
# SSL/TLS analysis with sslyze
# Tools: sslyze
# Targets: Comprehensive TLS/SSL configuration audit
# Estimated duration: 1-2 minutes
set -euo pipefail

TARGET="${1:?Usage: 02-sslyze.sh <TARGET_FQDN>}"

if [[ "${TARGET_PROTOCOL:-http}" == "http" ]]; then
  echo "[FAIL]: sslyze requires HTTPS target (TARGET_PROTOCOL=http)"
  exit 1
fi

echo "[*] sslyze against ${TARGET}"
echo ""

sslyze "$TARGET" ||
  echo "WARN: sslyze exited with non-zero status"

echo ""
echo "[*] sslyze complete"
