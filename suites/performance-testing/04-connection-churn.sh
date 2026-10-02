#!/bin/bash
# Connection churn test — measures new TCP connection overhead
# Tools: curl
# Tests the impact of the nginx upstream keepalive pools by forcing new connections
# Estimated duration: 1-2 minutes
set -uo pipefail

TARGET="${1:?Usage: 04-connection-churn.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

REQUESTS="${TGEN_REQUESTS:-100}"

echo "[*] Connection churn test against ${TARGET}"
echo ""

echo "=== Test 1: Keepalive (reuse connections) ==="
start_ns=$(date +%s%N)
results_ka=""
for i in $(seq "$REQUESTS"); do
  t=$(curl -sf -o /dev/null -w "%{time_total}" --max-time 10 "$BASE/health" 2>/dev/null) || t="ERR"
  results_ka="${results_ka}${t}\n"
done
end_ns=$(date +%s%N)
wall_ka=$(((end_ns - start_ns) / 1000000))

avg_ka=$(printf "%b" "$results_ka" | grep -v ERR | awk '{sum+=$1; n++} END {if(n>0) printf "%.4f", sum/n; else print "N/A"}')
errs_ka=$(printf "%b" "$results_ka" | grep -c ERR || true)
rps_ka=$(awk "BEGIN {printf \"%.1f\", $REQUESTS / ($wall_ka / 1000.0)}")
printf "  Requests:  %d\n  Errors:    %d\n  Avg time:  %ss\n  Wall time: %dms\n  Rate:      %s req/s\n" \
  "$REQUESTS" "$errs_ka" "$avg_ka" "$wall_ka" "$rps_ka"

echo ""
echo "=== Test 2: No keepalive (fresh connection each request) ==="
start_ns=$(date +%s%N)
results_nk=""
for i in $(seq "$REQUESTS"); do
  t=$(curl -sf -o /dev/null -w "%{time_total}" --max-time 10 \
    -H "Connection: close" "$BASE/health" 2>/dev/null) || t="ERR"
  results_nk="${results_nk}${t}\n"
done
end_ns=$(date +%s%N)
wall_nk=$(((end_ns - start_ns) / 1000000))

avg_nk=$(printf "%b" "$results_nk" | grep -v ERR | awk '{sum+=$1; n++} END {if(n>0) printf "%.4f", sum/n; else print "N/A"}')
errs_nk=$(printf "%b" "$results_nk" | grep -c ERR || true)
rps_nk=$(awk "BEGIN {printf \"%.1f\", $REQUESTS / ($wall_nk / 1000.0)}")
printf "  Requests:  %d\n  Errors:    %d\n  Avg time:  %ss\n  Wall time: %dms\n  Rate:      %s req/s\n" \
  "$REQUESTS" "$errs_nk" "$avg_nk" "$wall_nk" "$rps_nk"

echo ""
echo "=== Comparison ==="
printf "  Keepalive avg:    %ss (%s req/s)\n" "$avg_ka" "$rps_ka"
printf "  No-keepalive avg: %ss (%s req/s)\n" "$avg_nk" "$rps_nk"

if [[ "$avg_ka" != "N/A" ]] && [[ "$avg_nk" != "N/A" ]]; then
  speedup=$(awk "BEGIN {if($avg_nk>0) printf \"%.1f\", ($avg_nk - $avg_ka) / $avg_nk * 100; else print \"N/A\"}")
  echo "  Keepalive improvement: ${speedup}%"
fi

echo ""
echo "[*] Connection churn test complete"
