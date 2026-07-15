#!/bin/bash
# OpenAPI schema-violation traffic — drives requests that break the published API
# contract (wrong content-type, malformed JSON body, wrong param types, missing
# required fields) so an F5 XC LB with api_specification validation (validation_disabled
# off) / validation_custom_list raises schema-enforcement security events.
# Tools: curl
# Targets: api.<domain> spec endpoints (crAPI / VAmPI / juice-shop REST)
# Estimated duration: <1 minute
# Marker: User-Agent "sp5-api-verify" (behavioral-verify harness correlates by this).
set -euo pipefail

TARGET="${1:?Usage: 01-schema-violation.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-https}://${TARGET}"
UA="sp5-api-verify"
CURL=(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' -A "$UA" -H "X-SP5-Verify: schema-violation")

echo "[*] Schema-violation traffic against ${BASE}"

# 1) Malformed JSON body on a JSON endpoint.
echo -n "  POST /vampi/users/v1/register (malformed JSON) -> "
"${CURL[@]}" -X POST -H 'Content-Type: application/json' \
  --data '{"username": "sp5", "password":' "${BASE}/vampi/users/v1/register" || true
echo ""

# 2) Wrong content-type (text/plain where JSON is required).
echo -n "  POST /crapi/identity/api/auth/login (wrong content-type) -> "
"${CURL[@]}" -X POST -H 'Content-Type: text/plain' \
  --data 'not-json' "${BASE}/crapi/identity/api/auth/login" || true
echo ""

# 3) Wrong param type — string where the spec expects an integer id.
echo -n "  GET /vampi/books/v1/not-an-integer (type violation) -> "
"${CURL[@]}" "${BASE}/vampi/books/v1/not-an-integer" || true
echo ""

# 4) Missing required field.
echo -n "  POST /crapi/identity/api/auth/signup (missing required) -> "
"${CURL[@]}" -X POST -H 'Content-Type: application/json' \
  --data '{}' "${BASE}/crapi/identity/api/auth/signup" || true
echo ""

# 5) Oversized/unexpected query parameters (property-count violation).
echo -n "  GET /vampi/users/v1?a=1&b=2&c=3&d=4&e=5 (unexpected params) -> "
"${CURL[@]}" "${BASE}/vampi/users/v1?a=1&b=2&c=3&d=4&e=5" || true
echo ""

echo "[*] Schema-violation traffic complete"
