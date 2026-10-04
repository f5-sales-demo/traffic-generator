#!/bin/bash
# CDN Scenario 7: Sustained load with cache expiry monitoring
# Tools: wrk, curl
# Targets: All endpoints — 30-min sustained load monitoring cache status transitions
# Estimated duration: 30+ minutes
set -uo pipefail

# Native dependencies are mandatory; no alternate request engine is accepted.
command -v wrk >/dev/null || {
  echo "[FAIL] Required native wrk missing" >&2
  exit 1
}
command -v hey >/dev/null || {
  echo "[FAIL] Required native hey missing" >&2
  exit 1
}
. "$(dirname "$0")/_lib.sh"

DURATION="${TGEN_DURATION:-${2:-1800}}"
THREADS=4
CONNS="${TGEN_CONCURRENCY:-200}"
LUA_SCRIPT="$(dirname "$0")/_baseline.lua"
SAMPLE_INTERVAL=30
SAMPLES_PER_CHECK=10

echo "[*] CDN Sustained Cache Expiry Monitor"
echo "[*] Target: $BASE"
echo "[*] Duration: $((DURATION / 60)) minutes at ${THREADS}t/${CONNS}c"
echo "[*] Sampling: $SAMPLES_PER_CHECK requests every ${SAMPLE_INTERVAL}s"
echo ""

MONITOR_ENDPOINTS=(
  "/juice-shop/"
  "/httpbin/get"
  "/whoami/"
  "/health"
  "/dvwa/login.php"
  "/vampi/users/v1"
  "/csd-demo/health"
)

# Start wrk in background
echo "[+] Starting sustained wrk load..."
WRK_LOG="/tmp/cdn-sustained-wrk-$$.log"
[[ -f "$LUA_SCRIPT" ]] || {
  echo "[FAIL] Required native wrk Lua phase missing" >&2
  exit 1
}
wrk -t"$THREADS" -c"$CONNS" -d"${DURATION}s" --timeout 10s \
  -s "$LUA_SCRIPT" "${BASE}/" >"$WRK_LOG" 2>&1 &
WRK_PID=$!
echo "    wrk PID: $WRK_PID"echo ""

# Monitoring header
printf " %6s" "Time"
for ep in "${MONITOR_ENDPOINTS[@]}"; do
  SHORT=$(echo "$ep" | sed 's|^/||;s|/$||' | cut -c1-12)
  printf " %13s" "$SHORT"
done
printf " %6s %6s %6s %6s\n" "HIT" "MISS" "STALE" "OTHER"
printf " %6s" "------"
for ep in "${MONITOR_ENDPOINTS[@]}"; do
  printf " %13s" "-------------"
done
printf " %6s %6s %6s %6s\n" "------" "------" "------" "------"

START=$(date +%s)
PREV_RPS=0
DIPS=0
CACHE_POLICY_FAILURES=0

while true; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))

  if [ "$ELAPSED" -ge "$DURATION" ]; then
    break
  fi

  # Kill check — if wrk died, stop monitoring
  if ! kill -0 "$WRK_PID" 2>/dev/null; then
    echo ""
    echo "[WARN] Load generator exited early at ${ELAPSED}s"
    break
  fi

  TOTAL_HIT=0
  TOTAL_MISS=0
  TOTAL_STALE=0
  TOTAL_OTHER=0

  printf " %5ss" "$ELAPSED"

  for ep in "${MONITOR_ENDPOINTS[@]}"; do
    HIT=0
    MISS=0
    STALE=0
    OTHER=0
    for s in $(seq 1 "$SAMPLES_PER_CHECK"); do
      STATUS=$(check_cache_status "${BASE}${ep}")
      case "$STATUS" in
      HIT)
        HIT=$((HIT + 1))
        CACHE_POLICY_FAILURES=$((CACHE_POLICY_FAILURES + 1))
        ;;
      MISS) MISS=$((MISS + 1)) ;;
      STALE | UPDATING | EXPIRED)
        STALE=$((STALE + 1))
        CACHE_POLICY_FAILURES=$((CACHE_POLICY_FAILURES + 1))
        ;;
      NONE | BYPASS) OTHER=$((OTHER + 1)) ;;
      *)
        OTHER=$((OTHER + 1))
        CACHE_POLICY_FAILURES=$((CACHE_POLICY_FAILURES + 1))
        ;;
      esac
    done
    TOTAL_HIT=$((TOTAL_HIT + HIT))
    TOTAL_MISS=$((TOTAL_MISS + MISS))
    TOTAL_STALE=$((TOTAL_STALE + STALE))
    TOTAL_OTHER=$((TOTAL_OTHER + OTHER))

    # Compact display: H/M/S
    printf " %4dH/%1dM/%1dS" "$HIT" "$MISS" "$STALE"
  done

  printf " %6d %6d %6d %6d\n" "$TOTAL_HIT" "$TOTAL_MISS" "$TOTAL_STALE" "$TOTAL_OTHER"

  # Detect throughput dips (compare cache hit rate between windows)
  HIT_RATE=$((TOTAL_HIT * 100 / (TOTAL_HIT + TOTAL_MISS + TOTAL_STALE + TOTAL_OTHER + 1)))
  if [ "$ELAPSED" -gt 60 ] && [ "$HIT_RATE" -lt 50 ]; then
    DIPS=$((DIPS + 1))
    echo "    *** THROUGHPUT DIP at ${ELAPSED}s: HIT rate ${HIT_RATE}% ***"
  fi

  sleep "$SAMPLE_INTERVAL"
done

echo ""

# Wait for wrk to finish and collect results
wait "$WRK_PID" 2>/dev/null
echo "[+] wrk results:"
grep -E "Requests/sec|Latency|Transfer|Socket" "$WRK_LOG" 2>/dev/null | sed 's/^/    /'
rm -f "$WRK_LOG"

echo ""
echo "[*] Sustained test summary:"
echo "    Duration: $((DURATION / 60)) minutes"
echo "    Throughput dips detected: $DIPS"

if [ "$DIPS" -eq 0 ]; then
  pass "No throughput dips during cache refresh cycles"
else
  fail "$DIPS throughput dips detected during sustained load"
fi

if ((CACHE_POLICY_FAILURES > 0)); then
  fail "Unexpected cached dynamic responses: $CACHE_POLICY_FAILURES"
fi
summary
