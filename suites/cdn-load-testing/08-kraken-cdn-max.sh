#!/bin/bash
# CDN Scenario 8: Maximum sustained CDN bombardment (KRAKEN MODE)
# Tools: wrk, hey, vegeta, ab, curl
# Targets: All endpoints with full header diversity, path randomization, session isolation
# Estimated duration: 10 minutes
set -uo pipefail
. "$(dirname "$0")/_lib.sh"

DURATION="${TGEN_DURATION:-${2:-600}}"
RESULTS_DIR="${TGEN_RESULTS_DIR:-/tmp/cdn-kraken-$$}"
mkdir -p "$RESULTS_DIR"

echo "================================================================"
echo "  KRAKEN CDN MAX — FULL INTENSITY BOMBARDMENT"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Target: $BASE"
echo "  Duration: $((DURATION / 60)) minutes"
echo "  Mode: ALL layers simultaneous"
echo "================================================================"
echo ""

RUN_DEADLINE=$(($(date +%s) + DURATION))
CPU_PRE=$(awk '{printf "%.2f", $1}' /proc/loadavg)
RAM_PRE=$(free -m | awk '/Mem:/{print $3}')
echo "Pre-storm: CPU=$CPU_PRE RAM=${RAM_PRE}MB"
echo ""

LUA_BASELINE="$(dirname "$0")/_baseline.lua"
LUA_MULTI="$(dirname "$0")/_multi-client.lua"
WRK_THREADS="${TGEN_THREADS:-4}"
WRK_CONNECTIONS="${TGEN_CONCURRENCY:-500}"
[ "$WRK_THREADS" -gt "$WRK_CONNECTIONS" ] && WRK_THREADS="$WRK_CONNECTIONS"

# ================================================================
# LAYER 1: wrk with deep path randomization (7 instances)
# ================================================================
echo "=== LAYER 1: wrk SUSTAINED LOAD (deep path randomization) ==="
WRK_PIDS=""
if command -v wrk >/dev/null 2>&1; then
  for ep in "/juice-shop/" "/dvwa/login.php" "/vampi/users/v1" "/httpbin/get" "/csd-demo/health" "/whoami/" "/health"; do
    wrk -t"$WRK_THREADS" -c"$WRK_CONNECTIONS" -d"${DURATION}s" --timeout 60s \
      -H "X-Forwarded-For: $(rand_ip)" \
      -H "Accept-Encoding: $(rand_encoding)" \
      -H "User-Agent: $(rand_ua)" \
      "${BASE}${ep}" >"$RESULTS_DIR/wrk-$(echo "$ep" | tr '/' '_').log" 2>&1 &
    WRK_PIDS="$WRK_PIDS $!"
    echo "[+] wrk: $ep (PID $!, 4t/500c)"
  done
  # Combined Lua-randomized instance
  if [ -f "$LUA_BASELINE" ]; then
    wrk -t"$WRK_THREADS" -c"$WRK_CONNECTIONS" -d"${DURATION}s" --timeout 60s -s "$LUA_BASELINE" "${BASE}/" >"$RESULTS_DIR/wrk-lua-baseline.log" 2>&1 &
    WRK_PIDS="$WRK_PIDS $!"
    echo "[+] wrk Lua-randomized: all paths (PID $!, 4t/500c)"
  fi
  # Multi-client Lua instance
  if [ -f "$LUA_MULTI" ]; then
    wrk -t"$WRK_THREADS" -c"$WRK_CONNECTIONS" -d"${DURATION}s" --timeout 60s -s "$LUA_MULTI" "${BASE}/" >"$RESULTS_DIR/wrk-lua-multi.log" 2>&1 &
    WRK_PIDS="$WRK_PIDS $!"
    echo "[+] wrk Lua-multi-client: vendor headers (PID $!, 4t/500c)"
  fi
fi
echo ""

# ================================================================
# LAYER 2: hey with diverse client simulation
# ================================================================
echo "=== LAYER 2: hey SUSTAINED (diverse clients) ==="
HEY_PIDS=""
if command -v hey >/dev/null 2>&1; then
  hey -z "${DURATION}s" -c "${TGEN_CONCURRENCY:-200}" -H "X-Forwarded-For: $(rand_ip)" -H "Accept-Encoding: $(rand_encoding)" "${BASE}/juice-shop/" >"$RESULTS_DIR/hey-juice-shop.log" 2>&1 &
  HEY_PIDS="$HEY_PIDS $!"
  echo "[+] hey: /juice-shop/ (PID $!, 200c)"
  hey -z "${DURATION}s" -c "${TGEN_CONCURRENCY:-200}" -H "X-Forwarded-For: $(rand_ip)" -H "Accept-Encoding: $(rand_encoding)" "${BASE}/juice-shop/rest/products/search?q=apple" >"$RESULTS_DIR/hey-juice-api.log" 2>&1 &
  HEY_PIDS="$HEY_PIDS $!"
  echo "[+] hey: /juice-shop/rest/products/search (PID $!, 200c)"
  hey -z "${DURATION}s" -c "${TGEN_CONCURRENCY:-200}" -H "X-Forwarded-For: $(rand_ip)" -H "Accept-Encoding: $(rand_encoding)" "${BASE}/httpbin/get" >"$RESULTS_DIR/hey-httpbin.log" 2>&1 &
  HEY_PIDS="$HEY_PIDS $!"
  echo "[+] hey: /httpbin/get (PID $!, 200c)"
  hey -z "${DURATION}s" -c "${TGEN_CONCURRENCY:-200}" -H "X-Forwarded-For: $(rand_ip)" -H "Accept-Encoding: $(rand_encoding)" "${BASE}/vampi/users/v1" >"$RESULTS_DIR/hey-vampi.log" 2>&1 &
  HEY_PIDS="$HEY_PIDS $!"
  echo "[+] hey: /vampi/users/v1 (PID $!, 200c)"
fi
echo ""

# ================================================================
# LAYER 3: vegeta constant-rate with per-request headers
# ================================================================
echo "=== LAYER 3: vegeta CONSTANT-RATE (500 rps per stream) ==="
VEG_PIDS=""
if command -v vegeta >/dev/null 2>&1; then
  for ep in "/juice-shop/" "/httpbin/get" "/dvwa/login.php" "/whoami/" "/health"; do
    (
      echo "GET ${BASE}${ep}"
      echo "X-Forwarded-For: $(rand_ip)"
      echo "True-Client-IP: $(rand_ip)"
      echo "Accept-Encoding: $(rand_encoding)"
      echo "Cookie: session=vegeta-${RANDOM}"
    ) >"$RESULTS_DIR/vegeta-targets-$(echo "$ep" | tr '/' '_').txt"
    vegeta attack -workers=1 -max-workers=2 -rate="${TGEN_ATTACK_RATE:-500}/s" -duration="${DURATION}s" -timeout=60s \
      -targets="$RESULTS_DIR/vegeta-targets-$(echo "$ep" | tr '/' '_').txt" 2>/dev/null |
      vegeta encode >"$RESULTS_DIR/vegeta-$(echo "$ep" | tr '/' '_').bin" &
    VEG_PIDS="$VEG_PIDS $!"
    echo "[+] vegeta: $ep (PID $!, 500rps)"
  done
fi
echo ""

# ================================================================
# LAYER 4: ab keepalive baseline
# ================================================================
echo "=== LAYER 4: ab KEEPALIVE BASELINE ==="
AB_PIDS=""
# Exercise ApacheBench against the owned HTTP companion while other engines use HTTPS.
AB_BASE="$BASE"
[[ -n "${TGEN_INHERITED_BOUNDARY:-}" ]] && AB_BASE="http://${TARGET}"
if command -v ab >/dev/null 2>&1; then
  ab -n 999999 -c "${TGEN_CONCURRENCY:-300}" -k -t "$DURATION" -s 60 -H "X-Forwarded-For: $(rand_ip)" "${AB_BASE}/juice-shop/" >"$RESULTS_DIR/ab-juice-shop.log" 2>&1 &
  AB_PIDS="$AB_PIDS $!"
  echo "[+] ab: /juice-shop/ (PID $!, 300c keepalive)"
  ab -n 999999 -c "${TGEN_CONCURRENCY:-300}" -k -t "$DURATION" -s 60 -H "X-Forwarded-For: $(rand_ip)" "${AB_BASE}/httpbin/get" >"$RESULTS_DIR/ab-httpbin.log" 2>&1 &
  AB_PIDS="$AB_PIDS $!"
  echo "[+] ab: /httpbin/get (PID $!, 300c keepalive)"
fi
echo ""

# ================================================================
# LAYER 5: Thundering herd bursts every 60 seconds
# ================================================================
echo "=== LAYER 5: THUNDERING HERD BURSTS (every 60s) ==="
(
  BURST_NUM=0
  while [ "$(date +%s)" -lt "$RUN_DEADLINE" ]; do
    sleep 60
    [ "$(date +%s)" -ge "$RUN_DEADLINE" ] && break
    BURST_NUM=$((BURST_NUM + 1))
    STAMP="burst-${BURST_NUM}-$(date +%s%N)"
    if command -v hey >/dev/null 2>&1; then
      hey -n "${TGEN_REQUESTS:-2000}" -c "${TGEN_CONCURRENCY:-500}" -t 60 "${BASE}/httpbin/get?${STAMP}" >"$RESULTS_DIR/hey-${STAMP}.log" 2>&1
    fi
  done
) &
BURST_PID=$!
echo "[+] Thundering herd burst generator (PID $BURST_PID, every 60s)"
echo ""

# ================================================================
# LAYER 6: POST/PUT mixed traffic (10% of requests)
# ================================================================
echo "=== LAYER 6: POST/PUT MIXED TRAFFIC ==="
(
  while [ "$(date +%s)" -lt "$RUN_DEADLINE" ]; do
    curl -sf -o /dev/null --max-time 30 -X POST \
      -H "Content-Type: application/json" \
      -H "X-Forwarded-For: $(rand_ip)" \
      -d '{"test":true,"ts":"'"$(date +%s)"'"}' \
      "${BASE}/httpbin/post" 2>/dev/null
    curl -sf -o /dev/null --max-time 30 -X PUT \
      -H "Content-Type: application/json" \
      -H "X-Forwarded-For: $(rand_ip)" \
      -d '{"test":true}' \
      "${BASE}/httpbin/put" 2>/dev/null
    sleep 0.5
  done
) &
POST_PID=$!
echo "[+] POST/PUT generator (PID $POST_PID)"
echo ""

# ================================================================
# MONITORING
# ================================================================
echo "=== MONITORING ==="
echo ""
printf " %5s %8s %8s %8s %6s %6s %6s %6s\n" "Time" "CPU" "RAM-MB" "ESTAB" "HIT" "MISS" "STALE" "OTHER"
printf " %5s %8s %8s %8s %6s %6s %6s %6s\n" "-----" "--------" "--------" "--------" "------" "------" "------" "------"

START=$(date +%s)
while true; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))

  if [ "$ELAPSED" -ge "$DURATION" ]; then
    break
  fi

  CPU=$(awk '{printf "%.2f", $1}' /proc/loadavg)
  RAM=$(free -m | awk '/Mem:/{print $3}')
  ESTAB=$(ss -tan state established | wc -l)

  # Sample cache status
  HIT=0
  MISS=0
  STALE=0
  OTHER=0
  for ep in "/juice-shop/" "/httpbin/get" "/whoami/" "/health" "/dvwa/login.php"; do
    S=$(check_cache_status "${BASE}${ep}")
    case "$S" in
    HIT) HIT=$((HIT + 1)) ;;
    MISS) MISS=$((MISS + 1)) ;;
    STALE | UPDATING | EXPIRED) STALE=$((STALE + 1)) ;;
    *) OTHER=$((OTHER + 1)) ;;
    esac
  done

  printf " %4ss %8s %8s %8s %6d %6d %6d %6d\n" "$ELAPSED" "$CPU" "$RAM" "$ESTAB" "$HIT" "$MISS" "$STALE" "$OTHER"
  sleep 15
done

echo ""
echo "================================================================"
echo "  KRAKEN CDN MAX RESULTS — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"
echo ""

# Drain every bounded worker so shutdown does not cancel an in-flight request.
WORKER_FAILED=0
for pid in $WRK_PIDS $HEY_PIDS $VEG_PIDS $AB_PIDS; do
  wait "$pid" || WORKER_FAILED=1
done
for pid in "$BURST_PID" "$POST_PID"; do
  wait "$pid" || WORKER_FAILED=1
done
if [[ "$WORKER_FAILED" -ne 0 ]]; then
  echo "[FAIL] Native load worker failed"
  exit 1
fi

# Collect results
echo "=== wrk RESULTS ==="
for f in "$RESULTS_DIR"/wrk-*.log; do
  [ -f "$f" ] || continue
  EP=$(basename "$f" .log | sed 's/wrk-//')
  RPS=$(grep "Requests/sec" "$f" 2>/dev/null | awk '{print $2}')
  LAT=$(grep "Latency" "$f" 2>/dev/null | awk '{print $2}')
  printf "  %-25s %10s req/s  Lat: %s\n" "$EP" "${RPS:-N/A}" "${LAT:-N/A}"
done
echo ""

echo "=== hey RESULTS ==="
for f in "$RESULTS_DIR"/hey-*.log; do
  [ -f "$f" ] || continue
  EP=$(basename "$f" .log | sed 's/hey-//')
  RPS=$(grep "Requests/sec" "$f" 2>/dev/null | awk '{printf "%.0f", $2}')
  printf "  %-25s %10s req/s\n" "$EP" "${RPS:-N/A}"
done
echo ""

echo "=== vegeta RESULTS ==="
for f in "$RESULTS_DIR"/vegeta-*.bin; do
  [ -f "$f" ] || continue
  EP=$(basename "$f" .bin | sed 's/vegeta-//')
  REPORT=$(cat "$f" 2>/dev/null | vegeta report 2>/dev/null)
  RPS=$(echo "$REPORT" | grep "Requests" | awk '{print $3}')
  SUCCESS=$(echo "$REPORT" | grep "Success" | awk '{print $3}')
  printf "  %-25s %10s req/s  Success: %s\n" "$EP" "${RPS:-N/A}" "${SUCCESS:-N/A}"
done
echo ""

echo "=== ab RESULTS ==="
for f in "$RESULTS_DIR"/ab-*.log; do
  [ -f "$f" ] || continue
  EP=$(basename "$f" .log | sed 's/ab-//')
  RPS=$(grep "Requests per second" "$f" 2>/dev/null | awk '{print $4}')
  printf "  %-25s %10s req/s\n" "$EP" "${RPS:-N/A}"
done
echo ""

echo "=== GENERATOR FINAL STATE ==="
cat /proc/loadavg
free -m | grep Mem
ss -s | grep estab
echo "TIME_WAIT: $(ss -tan state time-wait | wc -l)"

if [[ -z "${TGEN_RESULTS_DIR:-}" ]]; then
  rm -rf "$RESULTS_DIR"
fi

echo ""
echo "================================================================"
echo "  KRAKEN CDN MAX COMPLETE"
echo "================================================================"
