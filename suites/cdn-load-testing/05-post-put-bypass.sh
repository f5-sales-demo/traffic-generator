#!/bin/bash
# CDN Scenario 5: POST/PUT/DELETE/PATCH cache bypass verification
# Tools: curl
# Targets: httpbin, vampi, juice-shop — non-GET methods should never cache
# Estimated duration: 1 minute
set -uo pipefail
. "$(dirname "$0")/_lib.sh"

echo "[*] CDN POST/PUT/DELETE/PATCH Bypass Test"
echo "[*] Target: $BASE"
echo "[*] Verify: non-GET methods pass through to origin without caching"
echo ""

check_method_bypass() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local url="${BASE}${path}"
  local label="${method} ${path}"

  local curl_args=(-s -D - -o /dev/null --max-time 10 -X "$method")
  curl_args+=(-H "X-Forwarded-For: $(rand_ip)")
  curl_args+=(-H "Content-Type: application/json")

  if [ -n "$data" ]; then
    curl_args+=(-d "$data")
  fi

  local headers
  headers=$(curl "${curl_args[@]}" "$url" 2>/dev/null)
  local http_code
  http_code=$(echo "$headers" | head -1 | awk '{print $2}')
  local cache_status
  cache_status=$(echo "$headers" | grep -i "X-Cache-Status" | awk '{print $2}' | tr -d '\r')
  cache_status="${cache_status:-NONE}"

  echo "    ${label} → HTTP ${http_code:-???}, X-Cache-Status: ${cache_status}"

  if [[ ! "$http_code" =~ ^[1-5][0-9][0-9]$ ]]; then
    fail "No HTTP response for ${label}"
  elif [ "$cache_status" = "HIT" ]; then
    fail "${label} — returned HIT (non-GET should not be cached)"
  else
    pass "${label} — not cached ($cache_status)"
  fi
}

# httpbin echo endpoints
echo "[+] httpbin method testing"
check_method_bypass "POST" "/httpbin/post" '{"test":true,"method":"POST","ts":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}'
check_method_bypass "PUT" "/httpbin/put" '{"test":true,"method":"PUT","ts":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}'
check_method_bypass "DELETE" "/httpbin/delete" '{"test":true,"method":"DELETE"}'
check_method_bypass "PATCH" "/httpbin/patch" '{"test":true,"method":"PATCH"}'
echo ""

# VAmPI API endpoints
echo "[+] VAmPI API testing"
check_method_bypass "POST" "/vampi/users/v1/register" '{"username":"cdn-test-'"$RANDOM"'","password":"testpass123","email":"cdn'"$RANDOM"'@test.com"}'
check_method_bypass "POST" "/vampi/users/v1/login" '{"username":"admin","password":"pass1"}'
echo ""

# Juice Shop endpoints
echo "[+] Juice Shop testing"
check_method_bypass "POST" "/juice-shop/rest/user/login" '{"email":"admin@juice-sh.op","password":"admin123"}'
check_method_bypass "POST" "/juice-shop/api/Feedbacks/" '{"comment":"CDN test","rating":5}'
echo ""

# Verify GET still caches after POST testing
echo "[+] Verify GET still caches (not poisoned by POST tests)"
curl -sf -o /dev/null --max-time 5 "${BASE}/httpbin/get" 2>/dev/null
sleep 0.3
GET_STATUS=$(check_cache_status "${BASE}/httpbin/get")
if [ "$GET_STATUS" = "NONE" ] || [ "$GET_STATUS" = "BYPASS" ]; then
  pass "GET /httpbin/get retains declared dynamic-bypass behavior ($GET_STATUS)"
else
  fail "GET /httpbin/get cache may be poisoned ($GET_STATUS)"
fi

summary
