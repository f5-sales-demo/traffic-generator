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

if [[ -n "${TGEN_AUTHORIZED_DOMAINS:-}" ]]; then
  echo "[CATALOG] Bounded authorized-name discovery equivalent; passive external providers excluded"
  while IFS= read -r domain; do
    getent ahostsv4 "$domain"
    curl -sk --max-time 10 -o /dev/null -w "${domain} HTTP %{http_code}\n" "https://${domain}/health"
  done < <(python3 -c 'import json,os; print("\n".join(json.loads(os.environ["TGEN_AUTHORIZED_DOMAINS"])))')
  exit 0
fi

echo "[+] Running subfinder..."
subfinder -d "$ROOT_DOMAIN" -silent ||
  echo "WARN: subfinder exited with non-zero status"

echo ""
echo "[*] Subfinder enumeration complete"
