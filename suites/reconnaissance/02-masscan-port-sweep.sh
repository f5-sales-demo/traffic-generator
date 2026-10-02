#!/bin/bash
# Masscan fast port sweep
# Tools: masscan, dig/host
# Targets: All 65535 ports on the resolved IP address
# Estimated duration: 1-3 minutes
set -euo pipefail

TARGET="${1:?Usage: 02-masscan-port-sweep.sh <TARGET_FQDN>}"

echo "[*] Masscan port sweep for ${TARGET}"
echo ""

# Resolve TARGET_FQDN to IP address
echo "[+] Resolving ${TARGET} to IP..."
TARGET_IP=$(dig +short "$TARGET" | head -1)
if [[ -z "$TARGET_IP" ]]; then
  echo "ERROR: Could not resolve ${TARGET} to an IP address"
  exit 1
fi
echo "    Resolved to: ${TARGET_IP}"
echo ""

echo "[+] Running masscan against ${TARGET_IP} (all ports)..."
masscan "$TARGET_IP" -p"${TGEN_CONNECTION_PORTS:-0-65535}" --rate="${TGEN_CONNECTION_RATE:-1000}" ||
  echo "WARN: masscan exited with non-zero status"

echo ""
echo "[*] Masscan port sweep complete"
