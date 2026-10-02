#!/bin/bash
# Nmap service detection scan
# Tools: nmap
# Targets: Top 1000 ports with service/version detection
# Estimated duration: 3-5 minutes
set -euo pipefail

TARGET="${1:?Usage: 01-nmap-service-scan.sh <TARGET_FQDN>}"

echo "[*] Nmap service scan against ${TARGET}"
echo ""

PORT_ARGS=(--top-ports 1000)
if [[ -n "${TGEN_CONNECTION_RATE:-}" ]]; then PORT_ARGS=(-p "80,443" --max-rate "$TGEN_CONNECTION_RATE"); fi
nmap -sV -sC -T4 "${PORT_ARGS[@]}" "$TARGET" ||
  echo "WARN: nmap exited with non-zero status"

echo ""
echo "[*] Nmap service scan complete"
