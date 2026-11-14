#!/bin/bash
# Subdomain enumeration with Subfinder
# Tools: subfinder
# Targets: Root domain extracted from TARGET_FQDN
# Estimated duration: 1-2 minutes
set -euo pipefail

TARGET="${1:?Usage: 05-subfinder-enum.sh <TARGET_FQDN>}"

echo "[*] Subfinder subdomain enumeration for ${TARGET}"
echo ""

# Extract root domain (last two parts of the FQDN)
ROOT_DOMAIN=$(echo "$TARGET" | awk -F. '{if (NF>=2) print $(NF-1)"."$NF; else print $0}')
echo "[+] Root domain: ${ROOT_DOMAIN}"
echo ""

echo "[+] Running subfinder..."
subfinder -d "$ROOT_DOMAIN" -silent -rl 5 -timeout 15 -max-time 1

echo ""
echo "[*] Subfinder enumeration complete"
