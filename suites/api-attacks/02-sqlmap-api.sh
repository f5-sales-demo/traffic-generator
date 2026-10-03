#!/bin/bash
# SQLMap API-mode scan against VAmPI
# Tools: sqlmap
# Targets: VAmPI user endpoints via F5 XC LB
# Estimated duration: 3-5 minutes
set -euo pipefail

TARGET="${1:?Usage: 02-sqlmap-api.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}/vampi"

echo "[*] SQLMap API scan against VAmPI at ${TARGET}"
echo ""

# --- Login to get token ---
echo "[+] Obtaining auth token..."
LOGIN_RESP=$(curl -sk -X POST "${BASE}/users/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"attacker123"}' \
  --max-time 30) || true

TOKEN=$(echo "$LOGIN_RESP" | jq -r '.auth_token // empty' 2>/dev/null || true)
if [[ -z "$TOKEN" && -n "${TGEN_FIXTURES:-}" ]]; then
  TOKEN=$(python3 "$(dirname "$0")/../../scripts/fixture_token.py" vampi_token)
  echo "[FIXTURE] Using a real seeded VAmPI token after blocked authentication"
fi
if [[ -z "$TOKEN" ]]; then
  echo "WARN: Could not get token, running sqlmap without auth"
  AUTH_FLAG=""
else
  echo "    Token acquired: ${TOKEN:0:20}..."
  AUTH_FLAG="--headers=Authorization: Bearer ${TOKEN}"
fi

echo ""

# --- SQLMap against user lookup ---
echo "[+] SQLMap against user lookup endpoint..."
sqlmap --batch --level=1 --risk=1 \
  -u "${BASE}/users/v1/admin" \
  ${AUTH_FLAG:+"$AUTH_FLAG"} \
  --timeout=30 --retries=1 --threads=3 \
  --output-dir="${TGEN_RESULTS_DIR:-/tmp}/sqlmap-vampi-users" ||
  echo "WARN: sqlmap user lookup scan returned non-zero"

echo ""

# --- SQLMap against login endpoint ---
echo "[+] SQLMap against login endpoint (POST)..."
sqlmap --batch --level=1 --risk=1 \
  -u "${BASE}/users/v1/login" \
  --data='{"username":"*","password":"test"}' \
  --method=POST \
  -H "Content-Type: application/json" \
  --timeout=30 --retries=1 --threads=3 \
  --output-dir="${TGEN_RESULTS_DIR:-/tmp}/sqlmap-vampi-login" ||
  echo "WARN: sqlmap login scan returned non-zero"

echo ""

# --- SQLMap against register endpoint ---
echo "[+] SQLMap against register endpoint (POST)..."
sqlmap --batch --level=1 --risk=1 \
  -u "${BASE}/users/v1/register" \
  --data='{"username":"*","password":"test123","email":"test@test.com"}' \
  --method=POST \
  -H "Content-Type: application/json" \
  --timeout=30 --retries=1 --threads=3 \
  --output-dir="${TGEN_RESULTS_DIR:-/tmp}/sqlmap-vampi-register" ||
  echo "WARN: sqlmap register scan returned non-zero"

echo ""
echo "[*] SQLMap API scan complete"
