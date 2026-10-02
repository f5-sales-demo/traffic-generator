#!/bin/bash
# Nmap service detection scan
# Tools: nmap
# Targets: Top 1000 ports with service/version detection
# Estimated duration: 3-5 minutes
set -euo pipefail

TARGET="${1:?Usage: 01-nmap-service-scan.sh <TARGET_FQDN>}"

echo "[*] Nmap service scan against ${TARGET}"
echo ""

nmap -sV -sC --max-rate "${TGEN_CONNECTION_RATE:-20}" -p 80,443 "$TARGET" ||
  echo "WARN: nmap exited with non-zero status"

echo ""
echo "[*] Nmap service scan complete"
