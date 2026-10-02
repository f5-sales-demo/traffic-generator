#!/bin/bash
# MITRE ATT&CK: Discovery (TA0007)
# Techniques: T1046 Network Service Discovery, T1087 Account Discovery,
#             T1082 System Info Discovery, T1083 File/Dir Discovery
# Tools: nmap, curl, ffuf, arjun
set -uo pipefail

TARGET="${1:?Usage: 05-discovery.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] MITRE ATT&CK TA0007: Discovery against ${TARGET}"
echo ""

echo "=== T1046: Network Service Scanning ==="
if [[ -n "${TGEN_INHERITED_BOUNDARY:-}" ]]; then
  curl -skI --max-time 15 "$BASE/" | head -10
else
  nmap -sV --max-rate "${TGEN_CONNECTION_RATE:-20}" -p 80,443 -Pn "$TARGET" 2>/dev/null | grep -E "open|filtered" | head -10
fi
echo ""

echo "=== T1087.004: Account Discovery — Cloud/Web Accounts ==="
echo "  Juice Shop user enumeration:"
curl -sf "${BASE}/juice-shop/api/Users" --max-time 10 2>/dev/null | jq '[.data[]? | {id, email, role}]' 2>/dev/null | head -30
echo ""
echo "  VAmPI user enumeration:"
curl -sf "${BASE}/vampi/users/v1" --max-time 10 2>/dev/null | jq '.' 2>/dev/null | head -20
echo ""

echo "=== T1082: System Information Discovery ==="
echo "  Server headers:"
curl -sf -I "${BASE}" --max-time 5 2>/dev/null | grep -iE "(server|x-powered|via|x-frame|x-content|strict|content-security)" | head -10
echo ""
echo "  Juice Shop version/config:"
curl -sf "${BASE}/juice-shop/api/Challenges" --max-time 10 2>/dev/null | jq '{totalChallenges: (.data | length), solved: [.data[] | select(.solved==true)] | length}' 2>/dev/null
echo ""
echo "  Prometheus metrics exposure:"
code=$(curl -sf -o /dev/null -w "%{http_code}" "${BASE}/juice-shop/metrics" --max-time 10 2>/dev/null) || code="ERR"
[[ "$code" == "200" ]] && echo "  [VULN] /metrics exposed (HTTP 200)" || echo "  [SAFE] /metrics not exposed (HTTP $code)"
echo ""

echo "=== T1083: File and Directory Discovery ==="
echo "  Sensitive path probing:"
PATHS=(
  "/juice-shop/ftp/" "/juice-shop/encryptionkeys/" "/juice-shop/robots.txt"
  "/juice-shop/api-docs/" "/juice-shop/.well-known/security.txt"
  "/vampi/openapi.json" "/vampi/console"
  "/dvwa/config/" "/dvwa/docs/" "/dvwa/phpinfo.php"
  "/httpbin/spec.json"
)
for p in "${PATHS[@]}"; do
  code=$(curl -sf -o /dev/null -w "%{http_code}" "${BASE}${p}" --max-time 5 2>/dev/null) || code="ERR"
  tag="[INFO]"
  [[ "$code" == "200" ]] && tag="[VULN]"
  printf "  %s %-50s HTTP %s\n" "$tag" "$p" "$code"
done
echo ""

echo "=== T1518: Software Discovery ==="
echo "  Application identification:"
for app in "/" "/juice-shop/" "/dvwa/" "/vampi/" "/httpbin/" "/whoami/" "/csd-demo/"; do
  size=$(curl -sf "${BASE}${app}" --max-time 5 2>/dev/null | wc -c)
  printf "  %-20s %6d bytes\n" "$app" "$size"
done
echo ""

echo "[*] TA0007 Discovery complete"
