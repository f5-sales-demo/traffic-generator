#!/bin/bash
# Directory brute-force with Gobuster
# Tools: gobuster
# Targets: Common web content paths
# Estimated duration: 2-4 minutes
set -euo pipefail

TARGET="${1:?Usage: 03-gobuster-dir.sh <TARGET_FQDN>}"

echo "[*] Gobuster directory scan against ${TARGET}"
echo ""

WORDLIST="/opt/seclists/Discovery/Web-Content/common.txt"
if [[ ! -f "$WORDLIST" ]]; then
  echo "WARN: Wordlist not found at ${WORDLIST}, trying alternate locations..."
  for alt in /usr/share/seclists/Discovery/Web-Content/common.txt \
    /usr/share/wordlists/dirb/common.txt; do
    if [[ -f "$alt" ]]; then
      WORDLIST="$alt"
      break
    fi
  done
fi

echo "[+] Using wordlist: ${WORDLIST}"
echo ""

gobuster dir -u "${TARGET_PROTOCOL:-http}://${TARGET}" \
  -w "$WORDLIST" \
  -t 20 \
  -k \
  --no-error ||
  echo "WARN: gobuster exited with non-zero status"

echo ""
echo "[*] Gobuster directory scan complete"
