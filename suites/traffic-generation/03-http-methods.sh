#!/bin/bash
# HTTP method fuzzing
# Tools: curl
# Targets: Various endpoints with unusual HTTP methods
# Estimated duration: 1-2 minutes
set -euo pipefail

TARGET="${1:?Usage: 03-http-methods.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] HTTP method fuzzing against ${TARGET}"
echo ""

METHODS=(
  GET
  POST
  PUT
  DELETE
  PATCH
  OPTIONS
  HEAD
  TRACE
  CONNECT
  PROPFIND
  PROPPATCH
  MKCOL
  COPY
  MOVE
  LOCK
  UNLOCK
  SEARCH
  PURGE
  DEBUG
)

ENDPOINTS=(
  "/"
  "/juice-shop/"
  "/juice-shop/rest/products/search?q=test"
  "/dvwa/"
  "/dvwa/login.php"
  "/vampi/"
  "/vampi/users/v1"
  "/admin"
  "/.env"
  "/.git/config"
)

for endpoint in "${ENDPOINTS[@]}"; do
  echo "[+] Endpoint: ${endpoint}"
  for method in "${METHODS[@]}"; do
    request_method="$method"
    headers=()
    if [[ "$method" == "CONNECT" && -n "${TGEN_INHERITED_BOUNDARY:-}" ]]; then
      request_method=GET
      headers=(-H 'X-TGen-Raw-Method: CONNECT')
    fi
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
      "${headers[@]}" -X "$request_method" \
      "${BASE}${endpoint}" \
      --max-time 10) || code="ERR"
    echo "    ${method} -> HTTP ${code}"
  done
  echo ""
done

echo "[*] HTTP method fuzzing complete"
