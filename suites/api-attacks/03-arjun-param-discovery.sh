#!/bin/bash
# Hidden parameter discovery with Arjun
# Tools: arjun
# Targets: Multiple origin application paths
# Estimated duration: 3-5 minutes
set -euo pipefail

TARGET="${1:?Usage: 03-arjun-param-discovery.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] Arjun parameter discovery against ${TARGET}"
echo ""

ENDPOINTS=(
  "${BASE}/juice-shop/"
  "${BASE}/juice-shop/rest/products/search"
  "${BASE}/juice-shop/api/Users/"
  "${BASE}/dvwa/"
  "${BASE}/dvwa/vulnerabilities/sqli/"
  "${BASE}/vampi/users/v1"
  "${BASE}/vampi/users/v1/login"
)

for endpoint in "${ENDPOINTS[@]}"; do
  echo "[+] Scanning: ${endpoint}"
  if [[ -n "${TGEN_PARAMETER_WORDLIST:-}" ]]; then
    arjun -u "$endpoint" -t 2 -w "$TGEN_PARAMETER_WORDLIST" --disable-redirects
  else
    arjun -u "$endpoint" -t 10 --stable
  fi ||
    echo "WARN: arjun returned non-zero for ${endpoint}"
  echo ""
done

echo "[*] Arjun parameter discovery complete"
