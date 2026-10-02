#!/bin/bash
# hey quick benchmark — simple Go-based load generator with summary stats
# Tools: hey
# Fast per-endpoint benchmark with latency histogram
# Estimated duration: 2 minutes
set -uo pipefail

TARGET="${1:?Usage: 12-hey-quick-bench.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

if ! command -v hey &>/dev/null; then
  echo "FAIL: hey not installed"
  exit 1
fi

REQUESTS="${TGEN_REQUESTS:-1000}"
CONCURRENCY="${TGEN_CONCURRENCY:-100}"

ENDPOINTS=(
  "/health"
  "/juice-shop/"
  "/juice-shop/rest/products/search?q=test"
  "/dvwa/login.php"
  "/vampi/users/v1"
  "/httpbin/get"
  "/whoami/"
  "/csd-demo/"
  "/csd-demo/health"
)

echo "[*] hey quick benchmark against ${TARGET}"
echo "    Requests per endpoint: ${REQUESTS}"
echo "    Concurrency: ${CONCURRENCY}"
echo ""

for endpoint in "${ENDPOINTS[@]}"; do
  url="${BASE}${endpoint}"
  echo "=== ${endpoint} ==="

  output=$(hey -n "$REQUESTS" -c "$CONCURRENCY" -t 30 "$url" 2>&1)

  rps=$(echo "$output" | grep 'Requests/sec' | awk '{print $2}')
  avg=$(echo "$output" | grep 'Average' | head -1 | awk '{print $2}')
  fastest=$(echo "$output" | grep 'Fastest' | awk '{print $2}')
  slowest=$(echo "$output" | grep 'Slowest' | awk '{print $2}')
  ok=$(echo "$output" | grep '\[200\]' | awk '{print $2}')
  total=$(echo "$output" | grep 'Requests/sec' | awk '{print $2}')

  status_dist=$(echo "$output" | grep -A20 'Status code distribution' | grep '\[' | tr '\n' ' ')
  errors=$(echo "$output" | grep -A5 'Error distribution' | grep -v 'Error distribution' | head -3 | tr '\n' ' ')

  printf "  Req/s: %s | Avg: %s | Fastest: %s | Slowest: %s\n" \
    "${rps:-N/A}" "${avg:-N/A}" "${fastest:-N/A}" "${slowest:-N/A}"
  printf "  Status: %s\n" "${status_dist:-N/A}"
  if [[ -n "$errors" ]] && [[ "$errors" != *"N/A"* ]]; then
    printf "  Errors: %s\n" "$errors"
  fi
  echo ""
done

echo "[*] hey quick benchmark complete"
