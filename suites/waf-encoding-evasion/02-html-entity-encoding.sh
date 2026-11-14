#!/bin/bash
# HTML entity encoding evasion: decimal, hex, named, zero-padded
# Tests WAF ability to decode HTML entities in URL parameters and POST bodies
# Estimated duration: 1-2 minutes
set -euo pipefail

TARGET="${1:?Usage: 02-html-entity-encoding.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] HTML Entity Encoding Evasion against ${TARGET}"
echo ""

PAYLOADS=(
  # Decimal entities for <script>alert(1)</script>
  "decimal-xss|&#60;script&#62;alert(1)&#60;/script&#62;"
  # Hex entities
  "hex-xss|&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;"
  # Named entities
  "named-xss|&lt;script&gt;alert(1)&lt;/script&gt;"
  # Zero-padded decimal (&#0060; = <)
  "zeropad-xss|&#0060;script&#0062;alert(1)&#0060;/script&#0062;"
  # Long zero-padded
  "longpad-xss|&#00060;script&#00062;alert(1)&#00060;/script&#00062;"
  # Decimal entity for single quote (SQLi)
  "decimal-sqli|&#39; OR 1=1--"
  # Hex entity for single quote
  "hex-sqli|&#x27; OR 1=1--"
  # Template injection with decimal entities (user's example: {{7*7}})
  "template-inject|&#123;&#123;7*7&#125;&#125;"
  # Mixed decimal + hex
  "mixed-entities|&#60;img src&#x3d;x onerror&#x3d;alert&#40;1&#41;&#62;"
  # Without semicolons (some parsers accept this)
  "nosemicolon|&#60script&#62alert(1)&#60/script&#62"
)

ENDPOINTS=(
  "/?q="
  "/httpbin/get?q="
  "/juice-shop/rest/products/search?q="
)

for entry in "${PAYLOADS[@]}"; do
  name="${entry%%|*}"
  payload="${entry#*|}"
  encoded=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "${payload}")

  echo "[+] ${name}: ${payload}"
  for ep in "${ENDPOINTS[@]}"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
      "${BASE}${ep}${encoded}" --max-time 10) || code="ERR"
    printf "    GET  %-35s -> HTTP %s\n" "${ep}" "${code}"
  done

  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "${BASE}/" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "input=${encoded}" --max-time 10) || code="ERR"
  printf "    POST %-35s -> HTTP %s\n" "/" "${code}"
  echo ""
done

echo "[*] HTML entity encoding evasion complete"
