#!/bin/bash
# Latency distribution heatmap — measures response time distribution per endpoint
# Tools: curl
# Produces histogram buckets for latency analysis
# Estimated duration: 1-2 minutes
set -uo pipefail

TARGET="${1:?Usage: 06-latency-heatmap.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

REQUESTS="${TGEN_REQUESTS:-50}"

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

echo "[*] Latency distribution analysis against ${TARGET}"
echo "    Requests per endpoint: ${REQUESTS}"
echo ""
printf "%-30s %8s %8s %8s %8s %8s %8s %5s\n" \
  "Endpoint" "Min" "P50" "P90" "P95" "P99" "Max" "Err"
echo "------------------------------ -------- -------- -------- -------- -------- -------- -----"

for endpoint in "${ENDPOINTS[@]}"; do
  url="${BASE}${endpoint}"

  times=""
  errs=0
  for _ in $(seq "$REQUESTS"); do
    t=$(curl -sf -o /dev/null -w "%{time_total}" --max-time 10 --connect-timeout 5 "$url" 2>/dev/null) || {
      errs=$((errs + 1))
      continue
    }
    times="${times}${t}\n"
  done

  if [[ -z "$times" ]]; then
    printf "%-30s %8s %8s %8s %8s %8s %8s %5d\n" "$endpoint" "N/A" "N/A" "N/A" "N/A" "N/A" "N/A" "$errs"
    continue
  fi

  sorted=$(printf "%b" "$times" | sort -n)
  count=$(printf "%b" "$times" | grep -c . || echo 0)

  min_val=$(echo "$sorted" | head -1)
  max_val=$(echo "$sorted" | tail -1)
  p50=$(echo "$sorted" | awk -v p=50 'BEGIN{c=0}{a[c++]=$1}END{idx=int(c*p/100);if(idx>=c)idx=c-1;printf "%.4f",a[idx]}')
  p90=$(echo "$sorted" | awk -v p=90 'BEGIN{c=0}{a[c++]=$1}END{idx=int(c*p/100);if(idx>=c)idx=c-1;printf "%.4f",a[idx]}')
  p95=$(echo "$sorted" | awk -v p=95 'BEGIN{c=0}{a[c++]=$1}END{idx=int(c*p/100);if(idx>=c)idx=c-1;printf "%.4f",a[idx]}')
  p99=$(echo "$sorted" | awk -v p=99 'BEGIN{c=0}{a[c++]=$1}END{idx=int(c*p/100);if(idx>=c)idx=c-1;printf "%.4f",a[idx]}')

  flag=""
  if ((errs > 0)); then flag="**"; fi
  if [[ $(awk "BEGIN {print ($p99 > 2.0)}" 2>/dev/null) == "1" ]]; then
    flag="${flag} SLOW"
  fi

  printf "%-30s %8s %8s %8s %8s %8s %8s %5d %s\n" \
    "$endpoint" "$min_val" "$p50" "$p90" "$p95" "$p99" "$max_val" "$errs" "$flag"
done

echo ""
echo "** = has errors | SLOW = P99 > 2s"
echo "[*] Latency distribution analysis complete"
