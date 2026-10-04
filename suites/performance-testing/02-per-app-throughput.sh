#!/bin/bash
# Per-application throughput benchmark
# Tools: hey
# Measures: throughput (req/s), latency percentiles, error rate for each app independently
# Estimated duration: 3-5 minutes
set -uo pipefail

# Native dependencies are mandatory; no alternate request engine is accepted.
command -v hey >/dev/null || {
  echo "[FAIL] Required native hey missing" >&2
  exit 1
}

TARGET="${1:?Usage: 02-per-app-throughput.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

CONCURRENCY="${TGEN_CONCURRENCY:-50}"
REQUESTS="${TGEN_REQUESTS:-200}"

declare -A APP_ENDPOINTS
APP_ENDPOINTS=(
  ["health"]="/health"
  ["landing"]="/"
  ["juice-shop"]="/juice-shop/"
  ["juice-shop-api"]="/juice-shop/rest/products/search?q="
  ["dvwa"]="/dvwa/login.php"
  ["vampi"]="/vampi/users/v1"
  ["vampi-api"]="/vampi/"
  ["httpbin"]="/httpbin/get"
  ["whoami"]="/whoami/"
  ["csd-demo"]="/csd-demo/"
  ["csd-demo-health"]="/csd-demo/health"
)

echo "[*] Per-application throughput benchmark against ${TARGET}"
echo "    Concurrency: ${CONCURRENCY}"
echo "    Requests per app: ${REQUESTS}"
echo ""

USE_HEY=true

echo ""

printf "%-20s %6s %6s %6s %8s %8s %8s %8s\n" \
  "Application" "Total" "OK" "Fail" "Avg(s)" "P95(s)" "P99(s)" "Req/s"
echo "-------------------- ------ ------ ------ -------- -------- -------- --------"

for app in health landing juice-shop juice-shop-api dvwa vampi vampi-api httpbin whoami csd-demo csd-demo-health; do
  endpoint="${APP_ENDPOINTS[$app]}"
  url="${BASE}${endpoint}"

  result=$(hey -n "${REQUESTS}" -c "${CONCURRENCY}" -t 30 "${url}" 2>&1)

  rps=$(echo "$result" | grep "Requests/sec" | awk '{print $2}')
  avg=$(echo "$result" | grep "Average" | head -1 | awk '{print $2}')

  # Extract percentiles from hey's latency distribution
  p95=$(echo "$result" | grep "95%" | head -1 | awk '{print $2}')
  p99=$(echo "$result" | grep "99%" | head -1 | awk '{print $2}')

  # Extract status code counts
  total="${REQUESTS}"
  status_200=$(echo "$result" | grep '^\s*\[200\]' | awk '{print $2}' || echo 0)
  status_301=$(echo "$result" | grep '^\s*\[301\]' | awk '{print $2}' || echo 0)
  status_302=$(echo "$result" | grep '^\s*\[302\]' | awk '{print $2}' || echo 0)
  [[ -z "$status_200" ]] && status_200=0
  [[ -z "$status_301" ]] && status_301=0
  [[ -z "$status_302" ]] && status_302=0
  ok=$((status_200 + status_301 + status_302))
  fail=$((total - ok))
  flag=""
  if [[ "$fail" -gt 0 ]]; then flag=" **"; fi

  printf "%-20s %6d %6d %6d %8s %8s %8s %8s%s\n" \
    "$app" "$total" "$ok" "$fail" "${avg:-N/A}" "${p95:-N/A}" "${p99:-N/A}" "${rps:-N/A}" "$flag"
done

echo ""
echo "** = has failures (investigate bottleneck)"
echo "[*] Per-application throughput benchmark complete"
