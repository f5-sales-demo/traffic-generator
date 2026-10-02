#!/bin/bash
# Nikto web server vulnerability scanner
# Tools: nikto
# Targets: Full web server scan
# Estimated duration: 2-3 minutes (120s max)
set -euo pipefail

TARGET="${1:?Usage: 05-nikto-scan.sh <TARGET_FQDN>}"

echo "[*] Nikto scan against ${TARGET}"
echo ""

nikto -h "${TARGET_PROTOCOL:-http}://${TARGET}" -maxtime "${TGEN_SCANNER_SECONDS:-120}s" ||
  echo "WARN: nikto exited with non-zero status"

echo ""
echo "[*] Nikto scan complete"
