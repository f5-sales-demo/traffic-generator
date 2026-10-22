#!/bin/bash
# SSL/TLS testing with testssl.sh
# Tools: testssl.sh
# Targets: Full TLS assessment (ciphers, protocols, vulnerabilities)
# Estimated duration: 2-4 minutes
set -euo pipefail

TARGET="${1:?Usage: 03-testssl.sh <TARGET_FQDN>}"

if [[ "${TARGET_PROTOCOL:-http}" == "http" ]]; then
  echo "[FAIL]: testssl requires HTTPS target (TARGET_PROTOCOL=http)"
  exit 1
fi

echo "[*] testssl.sh against ${TARGET}"
echo ""

testssl --quiet --color 0 "$TARGET" ||
  echo "WARN: testssl exited with non-zero status"

echo ""
echo "[*] testssl.sh complete"
