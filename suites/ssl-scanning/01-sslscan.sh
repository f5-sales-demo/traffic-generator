#!/bin/bash
# SSL/TLS scan with sslscan
# Tools: sslscan
# Targets: TLS configuration analysis
# Estimated duration: 30-60 seconds
set -euo pipefail

TARGET="${1:?Usage: 01-sslscan.sh <TARGET_FQDN>}"

if [[ "${TARGET_PROTOCOL:-http}" == "http" ]]; then
  echo "[FAIL]: sslscan requires HTTPS target (TARGET_PROTOCOL=http)"
  exit 1
fi

echo "[*] sslscan against ${TARGET}"
echo ""

sslscan "$TARGET" ||
  echo "WARN: sslscan exited with non-zero status"

echo ""
echo "[*] sslscan complete"
