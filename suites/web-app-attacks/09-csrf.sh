#!/bin/bash
# Cross-Site Request Forgery (CSRF) protection tests
# Tools: curl
# Targets: DVWA CSRF endpoint, VAmPI password change, Juice Shop profile
# Estimated duration: 1-2 minutes
set -uo pipefail

TARGET="${1:?Usage: 09-csrf.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] CSRF protection test suite against ${TARGET}"
echo ""

# --- Helper ---
csrf_test() {
  local label="$1"
  shift
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$@" --max-time 10) || code="ERR"
  echo "    ${label} -> HTTP ${code}"
}

# --- 1. DVWA CSRF — password change without token ---
echo "[+] DVWA: Password change via GET without CSRF token"
csrf_test "GET password_new=hacked (no token)" \
  "${BASE}/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change"

echo ""

# --- 2. DVWA CSRF — POST without CSRF token ---
echo "[+] DVWA: POST password change without CSRF token"
csrf_test "POST password change (no token)" \
  -X POST "${BASE}/dvwa/vulnerabilities/csrf/" \
  -d "password_new=hacked&password_conf=hacked&Change=Change"

echo ""

# --- 3. DVWA CSRF — forged Origin header ---
echo "[+] DVWA: POST with forged Origin header"
csrf_test "POST forged Origin: http://evil.example" \
  -X POST "${BASE}/dvwa/vulnerabilities/csrf/" \
  -H "Origin: http://evil.example" \
  -d "password_new=hacked&password_conf=hacked&Change=Change"

echo ""

# --- 4. DVWA CSRF — forged Referer header ---
echo "[+] DVWA: POST with forged Referer header"
csrf_test "POST forged Referer" \
  -X POST "${BASE}/dvwa/vulnerabilities/csrf/" \
  -H "Referer: http://evil.example/csrf-attack.html" \
  -d "password_new=hacked&password_conf=hacked&Change=Change"

echo ""

# --- 5. VAmPI — password change without auth ---
echo "[+] VAmPI: PUT password change without auth token"
csrf_test "vampi PUT password (no auth)" \
  -X PUT "${BASE}/vampi/users/v1/admin/password" \
  -H "Content-Type: application/json" \
  -d '{"password":"hacked123"}'

echo ""

# --- 6. VAmPI — password change with forged Origin ---
echo "[+] VAmPI: PUT password change with forged Origin"
csrf_test "vampi PUT password (forged Origin)" \
  -X PUT "${BASE}/vampi/users/v1/admin/password" \
  -H "Content-Type: application/json" \
  -H "Origin: http://evil.example" \
  -H "Authorization: Bearer fake-token-csrf-test" \
  -d '{"password":"hacked123"}'

echo ""

# --- 7. Juice Shop — profile update without auth ---
echo "[+] Juice Shop: GET-based profile endpoint without auth"
csrf_test "juice-shop GET /rest/user/whoami (no auth)" \
  "${BASE}/juice-shop/rest/user/whoami"

echo ""

# --- 8. Juice Shop — profile update with forged Origin ---
echo "[+] Juice Shop: POST profile update with forged Origin"
csrf_test "juice-shop POST /api/Users (forged Origin)" \
  -X POST "${BASE}/juice-shop/api/Users" \
  -H "Content-Type: application/json" \
  -H "Origin: http://evil.example" \
  -d '{"email":"csrf@example.com","password":"Test1234","passwordRepeat":"Test1234"}'

echo ""

# --- 9. Juice Shop — state change via GET ---
echo "[+] Juice Shop: GET-based state change attempt"
csrf_test "juice-shop GET /rest/basket/1 (no auth)" \
  "${BASE}/juice-shop/rest/basket/1"

echo ""

# --- 10. Cross-origin POST with no Content-Type (simple request) ---
echo "[+] Cross-origin simple POST (no Content-Type header)"
csrf_test "dvwa simple POST (no Content-Type)" \
  -X POST "${BASE}/dvwa/vulnerabilities/csrf/" \
  -H "Origin: http://evil.example" \
  --data-raw "password_new=hacked&password_conf=hacked&Change=Change"

echo ""
echo "[*] CSRF protection test suite complete (10 test cases)"
