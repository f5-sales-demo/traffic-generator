#!/bin/bash
# Per-application throughput benchmark
# Tools: hey (primary), curl+xargs (fallback)
# Measures: throughput (req/s), latency percentiles, error rate for each app independently
# Estimated duration: 3-5 minutes
set -uo pipefail

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

USE_HEY=false
if command -v hey &>/dev/null; then
  USE_HEY=true
  echo "[+] Using hey (goroutine-based engine)"
else
  echo "[+] hey not found — falling back to curl+xargs"
fi
echo ""

printf "%-20s %6s %6s %6s %8s %8s %8s %8s\n" \
  "Application" "Total" "OK" "Fail" "Avg(s)" "P95(s)" "P99(s)" "Req/s"
echo "-------------------- ------ ------ ------ -------- -------- -------- --------"

for app in health landing juice-shop juice-shop-api dvwa vampi vampi-api httpbin whoami csd-demo csd-demo-health; do
  endpoint="${APP_ENDPOINTS[$app]}"
  url="${BASE}${endpoint}"

  if [[ "$USE_HEY" == "true" ]]; then
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

  else
    start_time=$(date +%s%N)

    results=$(seq "$REQUESTS" | xargs -P"$CONCURRENCY" -I{} \
      curl -sf -o /dev/null -w "%{http_code} %{time_total}\n" \
      --max-time 10 --connect-timeout 5 "$url" 2>/dev/null)

    end_time=$(date +%s%N)
    wall_ms=$(((end_time - start_time) / 1000000))

    total=$(echo "$results" | grep -c . || echo 0)
    ok=$(echo "$results" | grep -c '^[23]0[0-9] ' || true)
    fail=$((total - ok))

    avg=$(echo "$results" | awk '{sum+=$2; n++} END {if(n>0) printf "%.3f", sum/n; else print "0"}')
    p95=$(echo "$results" | awk '{print $2}' | sort -n | awk -v p=95 'BEGIN{c=0} {a[c++]=$1} END{idx=int(c*p/100); if(idx>=c)idx=c-1; printf "%.3f", a[idx]}')
    p99=$(echo "$results" | awk '{print $2}' | sort -n | awk -v p=99 'BEGIN{c=0} {a[c++]=$1} END{idx=int(c*p/100); if(idx>=c)idx=c-1; printf "%.3f", a[idx]}')
    rps=$(awk "BEGIN {if($wall_ms>0) printf \"%.1f\", $total / ($wall_ms / 1000.0); else print \"N/A\"}")
  fi

  flag=""
  if [[ "$fail" -gt 0 ]]; then flag=" **"; fi

  printf "%-20s %6d %6d %6d %8s %8s %8s %8s%s\n" \
    "$app" "$total" "$ok" "$fail" "${avg:-N/A}" "${p95:-N/A}" "${p99:-N/A}" "${rps:-N/A}" "$flag"
done

echo ""
echo "** = has failures (investigate bottleneck)"
echo "[*] Per-application throughput benchmark complete"
