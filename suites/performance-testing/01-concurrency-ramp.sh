#!/bin/bash
# Concurrency ramp test — progressively increase concurrent connections
# Tools: hey (primary), curl+xargs (fallback)
# Measures: success rate, response time, and failure threshold at each concurrency level
# Estimated duration: 3-5 minutes
set -uo pipefail

# Native dependencies are mandatory; no alternate request engine is accepted.
command -v hey >/dev/null || { echo "[FAIL] Required native hey missing" >&2; exit 1; }

TARGET="${1:?Usage: 01-concurrency-ramp.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

ENDPOINTS=(
  "/health"
  "/juice-shop/"
  "/vampi/users/v1"
  "/httpbin/get"
  "/whoami/"
  "/csd-demo/health"
)

CONCURRENCY_LEVELS=(1 10 "${TGEN_CONCURRENCY:-20}")
REQUESTS_PER_LEVEL="${TGEN_REQUESTS:-100}"

echo "[*] Concurrency ramp test against ${TARGET}"
echo "    Endpoints: ${#ENDPOINTS[@]}"
echo "    Levels: ${CONCURRENCY_LEVELS[*]}"
echo "    Requests per level: ${REQUESTS_PER_LEVEL}"
echo ""

USE_HEY=false
if command -v hey &>/dev/null; then
  USE_HEY=true
  echo "[+] Using hey (goroutine-based engine)"
else
  echo "[+] hey not found — falling back to curl+xargs"
fi
echo ""

for concurrency in "${CONCURRENCY_LEVELS[@]}"; do
  echo "=== Concurrency: ${concurrency} ==="

  endpoint="${ENDPOINTS[$((RANDOM % ${#ENDPOINTS[@]}))]}"
  url="${BASE}${endpoint}"

  if [[ "$USE_HEY" == "true" ]]; then
    result=$(hey -n "${REQUESTS_PER_LEVEL}" -c "${concurrency}" -t 30 "${url}" 2>&1)

    rps=$(echo "$result" | grep "Requests/sec" | awk '{print $2}')
    avg=$(echo "$result" | grep "Average" | head -1 | awk '{print $2}')
    p99=$(echo "$result" | grep "99%" | head -1 | awk '{print $2}')
    fastest=$(echo "$result" | grep "Fastest" | awk '{print $2}')
    slowest=$(echo "$result" | grep "Slowest" | awk '{print $2}')

    # Extract status code counts from hey output
    total="${REQUESTS_PER_LEVEL}"
    status_200=$(echo "$result" | grep '^\s*\[200\]' | awk '{print $2}' || echo 0)
    [[ -z "$status_200" ]] && status_200=0
    success="${status_200}"
    failed=$((total - success))
    success_pct=$((success * 100 / (total > 0 ? total : 1)))

    printf "  Endpoint:    %s\n" "$endpoint"
    printf "  Success:     %d/%d (%d%%)\n" "$success" "$total" "$success_pct"
    printf "  Failed:      %d\n" "$failed"
    printf "  Throughput:  %s req/s\n" "${rps:-N/A}"
    printf "  Latency:     avg=%ss p99=%ss fastest=%ss slowest=%ss\n" \
      "${avg:-N/A}" "${p99:-N/A}" "${fastest:-N/A}" "${slowest:-N/A}"

  else
    start_time=$(date +%s%N)

    results=$(seq "$REQUESTS_PER_LEVEL" | xargs -P"$concurrency" -I{} \
      curl -sf -o /dev/null -w "%{http_code} %{time_total}\n" \
      --max-time 10 --connect-timeout 5 "$url" 2>/dev/null)

    end_time=$(date +%s%N)
    wall_ms=$(((end_time - start_time) / 1000000))

    total=$(echo "$results" | wc -l)
    success=$(echo "$results" | grep -c '^200 ' || true)
    failed=$((total - success))
    success_pct=$((success * 100 / total))

    avg=$(echo "$results" | awk '{sum+=$2; n++} END {if(n>0) printf "%.3f", sum/n; else print "N/A"}')
    p99=$(echo "$results" | awk '{print $2}' | sort -n | awk -v p=99 'BEGIN{c=0} {a[c++]=$1} END{idx=int(c*p/100); if(idx>=c)idx=c-1; printf "%.3f", a[idx]}')
    min_time=$(echo "$results" | awk '{print $2}' | sort -n | head -1)
    max_time=$(echo "$results" | awk '{print $2}' | sort -n | tail -1)
    rps=$(awk "BEGIN {printf \"%.1f\", $total / ($wall_ms / 1000.0)}")

    printf "  Endpoint:    %s\n" "$endpoint"
    printf "  Success:     %d/%d (%d%%)\n" "$success" "$total" "$success_pct"
    printf "  Failed:      %d\n" "$failed"
    printf "  Wall time:   %d ms\n" "$wall_ms"
    printf "  Throughput:  %s req/s\n" "$rps"
    printf "  Latency:     min=%ss avg=%ss p99=%ss max=%ss\n" "$min_time" "$avg" "$p99" "$max_time"
  fi

  if [[ "$success_pct" -lt 95 ]]; then
    echo "  ** BOTTLENECK: <95% success at concurrency ${concurrency} **"
  fi
  echo ""

  if [[ "$success_pct" -lt 50 ]]; then
    echo "  STOPPING: Success rate dropped below 50% — origin saturated at concurrency ${concurrency}"
    break
  fi
done

echo "[*] Concurrency ramp test complete"
