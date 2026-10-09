#!/bin/bash
# API endpoint and HTTP method fuzzing
# Tools: ffuf
# Targets: API paths and HTTP methods via F5 XC LB
# Estimated duration: 2-4 minutes
set -euo pipefail

TARGET="${1:?Usage: 04-ffuf-api-fuzz.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] API fuzzing suite against ${TARGET}"
echo ""

# --- Endpoint fuzzing with common API wordlist ---
echo "[+] Fuzzing API endpoints with ffuf..."

# Create a temporary wordlist of common API paths
WORDLIST=$(mktemp /tmp/ffuf-api-wordlist.XXXXXX)
cat >"$WORDLIST" <<'EOF'
api
api/v1
api/v2
api/v3
rest
graphql
swagger
swagger.json
openapi.json
docs
admin
users
login
register
health
healthz
status
metrics
debug
console
config
env
info
version
actuator
actuator/health
.env
.git
.git/config
robots.txt
sitemap.xml
EOF

for prefix in "" "/vampi" "/juice-shop" "/dvwa"; do
  echo ""
  echo "[+] Fuzzing ${BASE}${prefix}/FUZZ ..."
  ffuf -u "${BASE}${prefix}/FUZZ" \
    -w "$WORDLIST" \
    -t 20 \
    -timeout 30 \
    -mc all \
    -fc 404 \
    -s ||
    echo "WARN: ffuf returned non-zero for prefix '${prefix}'"
done

rm -f "$WORDLIST"

echo ""

# --- HTTP method fuzzing ---
echo "[+] Fuzzing HTTP methods..."

METHODS_FILE=$(mktemp /tmp/ffuf-methods.XXXXXX)
cat >"$METHODS_FILE" <<'EOF'
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
MOVE
COPY
LOCK
UNLOCK
MKCOL
EOF

FUZZ_ENDPOINTS=(
  "${BASE}/vampi/users/v1"
  "${BASE}/juice-shop/rest/products/search"
  "${BASE}/dvwa/"
)

if [[ -n "${TGEN_INHERITED_BOUNDARY:-}" ]]; then
  sed -i '/^CONNECT$/d' "$METHODS_FILE"
fi
for endpoint in "${FUZZ_ENDPOINTS[@]}"; do
  if [[ -n "${TGEN_INHERITED_BOUNDARY:-}" ]]; then
    echo "[+] Paced raw CONNECT method probe: $endpoint"
    curl -s --max-time 30 -o /dev/null -w 'CONNECT -> HTTP %{http_code}\n' \
      -H 'X-TGen-Raw-Method: CONNECT' "$endpoint"
  fi
  echo ""
  echo "[+] Method fuzzing: ${endpoint}"
  ffuf -u "$endpoint" \
    -w "$METHODS_FILE" \
    -X FUZZ \
    -t 10 \
    -timeout 30 \
    -mc all \
    -s ||
    echo "WARN: ffuf method fuzz returned non-zero"
done

rm -f "$METHODS_FILE"

echo ""
echo "[*] API fuzzing suite complete"
