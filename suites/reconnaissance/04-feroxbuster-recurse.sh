#!/bin/bash
# Recursive content discovery with Feroxbuster
# Tools: feroxbuster
# Targets: Raft medium directories, 2 levels deep
# Estimated duration: 3-5 minutes
set -uo pipefail

TARGET="${1:?Usage: 04-feroxbuster-recurse.sh <TARGET_FQDN>}"

echo "[*] Feroxbuster recursive scan against ${TARGET}"
echo ""

WORDLIST="/opt/seclists/Discovery/Web-Content/raft-medium-directories.txt"
if [[ ! -f "$WORDLIST" ]]; then
  echo "WARN: Wordlist not found at ${WORDLIST}, trying alternate locations..."
  for alt in /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    /opt/seclists/Discovery/Web-Content/common.txt \
    /usr/share/wordlists/dirb/common.txt; do
    if [[ -f "$alt" ]]; then
      WORDLIST="$alt"
      break
    fi
  done
fi

if [[ -n "${TGEN_DISCOVERY_WORDLIST:-}" ]]; then
  WORDLIST="$TGEN_DISCOVERY_WORDLIST"
fi

echo "[+] Using wordlist: ${WORDLIST}"
echo ""

feroxbuster -u "${TARGET_PROTOCOL:-http}://${TARGET}" \
  -w "$WORDLIST" \
  -d 2 \
  -t 10 \
  -k \
  --no-state \
  --time-limit 300s ||
  echo "WARN: feroxbuster exited with non-zero status"

echo ""
echo "[*] Feroxbuster recursive scan complete"
