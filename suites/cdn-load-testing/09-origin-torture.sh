#!/bin/bash
# Origin Server Torture Test — all apps, all exploits, sustained load, capture stats
# Tools: wrk, hey, vegeta, curl, all exploit suites
# Targets: Origin server directly — DVGA, RESTaurant, crAPI, Juice Shop, DVWA, VAmPI, httpbin
# Estimated duration: 10 minutes
set -uo pipefail

TARGET="${1:-${TARGET_FQDN:?TARGET_FQDN required}}"
PROTOCOL="${TARGET_PROTOCOL:-http}"
BASE="${PROTOCOL}://${TARGET}"
CRAPI_PORT="${CRAPI_PORT:-8888}"
CRAPI_BASE="${CRAPI_BASE_URL:-${PROTOCOL}://${TARGET}:${CRAPI_PORT}}"
DURATION="${TGEN_DURATION:-${2:-600}}"
NCPU=$(nproc)

RESULTS_DIR="${TGEN_RESULTS_DIR:-/tmp/origin-torture-$$}"
mkdir -p "$RESULTS_DIR"
SUITE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "================================================================"
echo "  ORIGIN TORTURE TEST — FULL STACK DESTRUCTION"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  Origin:   $BASE"
echo "  crAPI:    $CRAPI_BASE"
echo "  Duration: $((DURATION / 60)) minutes"
echo "  vCPU:     $NCPU"
echo "  Mode:     ALL exploit suites + sustained load generators"
echo "================================================================"
echo ""

# Host tuning is excluded from paced, supervised execution.
if [[ -z "${TGEN_INHERITED_BOUNDARY:-}" ]]; then
  # Kernel tuning
  SOMAXCONN=$((NCPU * 8192))
  [ "$SOMAXCONN" -gt 131072 ] && SOMAXCONN=131072
  sudo sysctl -w net.core.somaxconn=$SOMAXCONN >/dev/null 2>&1
  sudo sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1
  sudo sysctl -w net.ipv4.tcp_fin_timeout=5 >/dev/null 2>&1
  sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535" >/dev/null 2>&1
  sudo sysctl -w fs.file-max=$((NCPU * 262144)) >/dev/null 2>&1
  ulimit -n 524288 2>/dev/null || ulimit -n 65535 2>/dev/null || true

fi

CPU_PRE=$(awk '{printf "%.2f", $1}' /proc/loadavg)
RAM_PRE=$(free -m | awk '/Mem:/{print $3}')
echo "Pre-storm: CPU=$CPU_PRE RAM=${RAM_PRE}MB"
echo ""

# ================================================================
# LAYER 1: Sustained wrk load against ALL app endpoints (keepalive)
# ================================================================
echo "=== LAYER 1: SUSTAINED WRK LOAD (all apps, keepalive) ==="
WRK_T=$((NCPU / 2))
[ "$WRK_T" -lt 2 ] && WRK_T=2
WRK_C="${TGEN_CONCURRENCY:-256}"

ORIGIN_ENDPOINTS=(
  "/juice-shop/"
  "/juice-shop/rest/products/search?q=apple"
  "/dvwa/login.php"
  "/vampi/users/v1"
  "/httpbin/get"
  "/httpbin/headers"
  "/csd-demo/health"
  "/whoami/"
  "/health"
  "/dvga/"
  "/restaurant/docs"
  "/restaurant/menu"
)

for ep in "${ORIGIN_ENDPOINTS[@]}"; do
  wrk -t"$WRK_T" -c"$WRK_C" -d"${DURATION}s" --timeout 10s \
    -H "Connection: keep-alive" \
    -H "X-Forwarded-For: 198.51.100.$((RANDOM % 256))" \
    "${BASE}${ep}" >"$RESULTS_DIR/wrk-$(echo "$ep" | tr '/' '_' | tr '?' '_').log" 2>&1 &
  echo "[+] wrk: $ep (PID $!, ${WRK_T}t/${WRK_C}c)"
done

# crAPI endpoints on port 8888
CRAPI_ENDPOINTS=(
  "/"
  "/identity/api/v2/user/dashboard"
  "/workshop/api/shop/products"
  "/community/api/v2/community/posts"
)
for ep in "${CRAPI_ENDPOINTS[@]}"; do
  wrk -t"$WRK_T" -c"$WRK_C" -d"${DURATION}s" --timeout 10s \
    -H "Connection: keep-alive" \
    "${CRAPI_BASE}${ep}" >"$RESULTS_DIR/wrk-crapi-$(echo "$ep" | tr '/' '_').log" 2>&1 &
  echo "[+] wrk crAPI: $ep (PID $!, ${WRK_T}t/${WRK_C}c)"
done
echo ""

# ================================================================
# LAYER 2: hey sustained against key API endpoints
# ================================================================
echo "=== LAYER 2: HEY SUSTAINED (API throughput) ==="
HEY_C="${TGEN_CONCURRENCY:-200}"

hey -z "${DURATION}s" -c "$HEY_C" -H "Connection: keep-alive" "${BASE}/juice-shop/rest/products/search?q=test" >"$RESULTS_DIR/hey-juice-api.log" 2>&1 &
echo "[+] hey: /juice-shop/rest/products/search (PID $!, ${HEY_C}c)"
hey -z "${DURATION}s" -c "$HEY_C" -H "Connection: keep-alive" "${BASE}/vampi/users/v1" >"$RESULTS_DIR/hey-vampi.log" 2>&1 &
echo "[+] hey: /vampi/users/v1 (PID $!, ${HEY_C}c)"
hey -z "${DURATION}s" -c "$HEY_C" -H "Connection: keep-alive" "${BASE}/httpbin/get" >"$RESULTS_DIR/hey-httpbin.log" 2>&1 &
echo "[+] hey: /httpbin/get (PID $!, ${HEY_C}c)"
hey -z "${DURATION}s" -c "$HEY_C" -H "Connection: keep-alive" "${BASE}/restaurant/menu" >"$RESULTS_DIR/hey-restaurant.log" 2>&1 &
echo "[+] hey: /restaurant/menu (PID $!, ${HEY_C}c)"
echo ""

# ================================================================
# LAYER 3: GraphQL torture via wrk Lua (persistent connections)
# ================================================================
echo "=== LAYER 3: GRAPHQL TORTURE (wrk Lua, keepalive) ==="
GQL_LUA="$(dirname "$0")/_graphql-torture.lua"
if [ -f "$GQL_LUA" ]; then
  wrk -t"$WRK_T" -c"${TGEN_CONCURRENCY:-128}" -d"${DURATION}s" --timeout 30s \
    -s "$GQL_LUA" "${BASE}/" >"$RESULTS_DIR/wrk-gql-torture.log" 2>&1 &
  GQL_PID=$!
  echo "[+] wrk GraphQL torture: batch DoS + recursion + SQLi + XSS (PID $GQL_PID, ${WRK_T}t/128c keepalive)"
else
  echo "[WARN] GraphQL Lua script not found"
  GQL_PID=""
fi
echo ""

# ================================================================
# LAYER 4: RESTaurant attack patterns via wrk Lua (persistent connections)
# ================================================================
echo "=== LAYER 4: RESTAURANT ATTACKS (wrk Lua, keepalive) ==="
REST_LUA="$(dirname "$0")/_restaurant-torture.lua"
if [ -f "$REST_LUA" ]; then
  wrk -t"$WRK_T" -c"${TGEN_CONCURRENCY:-128}" -d"${DURATION}s" --timeout 10s \
    -s "$REST_LUA" "${BASE}/" >"$RESULTS_DIR/wrk-restaurant-torture.log" 2>&1 &
  REST_PID=$!
  echo "[+] wrk Restaurant torture: BOLA + BOPLA + SSRF + injection (PID $REST_PID, ${WRK_T}t/128c keepalive)"
else
  echo "[WARN] Restaurant Lua script not found"
  REST_PID=""
fi
echo ""

# ================================================================
# LAYER 5: crAPI challenge patterns via wrk Lua (persistent connections)
# ================================================================
echo "=== LAYER 5: CRAPI CHALLENGES (wrk Lua, keepalive) ==="
CRAPI_LUA="$(dirname "$0")/_crapi-torture.lua"
if [ -f "$CRAPI_LUA" ]; then
  wrk -t"$WRK_T" -c"${TGEN_CONCURRENCY:-128}" -d"${DURATION}s" --timeout 10s \
    -s "$CRAPI_LUA" "${CRAPI_BASE}/" >"$RESULTS_DIR/wrk-crapi-torture.log" 2>&1 &
  CRAPI_PID=$!
  echo "[+] wrk crAPI torture: BOLA + NoSQL + OTP + orders (PID $CRAPI_PID, ${WRK_T}t/128c keepalive)"
else
  echo "[WARN] crAPI Lua script not found"
  CRAPI_PID=""
fi
echo ""

# ================================================================
# LAYER 6: All existing exploit suites in parallel
# ================================================================
echo "=== LAYER 6: ALL EXPLOIT SUITES ==="
SUITE_PIDS=""
for suite in dvga-exploits restaurant-exploits crapi-exploits web-app-attacks api-attacks juice-shop-exploits dvwa-exploits mitre-attack; do
  if [ -d "$SUITE_DIR/$suite" ]; then
    (
      if [[ -n "${TGEN_INHERITED_BOUNDARY:-}" ]]; then
        TGEN_RESULTS_DIR="$RESULTS_DIR/nested-$suite" bash "$SUITE_DIR/runner.sh" "$suite"
      else
        bash "$SUITE_DIR/runner.sh" "$suite"
      fi
    ) >"$RESULTS_DIR/suite-${suite}.log" 2>&1 &
    PID=$!
    SUITE_PIDS="$SUITE_PIDS $PID"
    echo "[+] $suite (PID $PID)"
  fi
done
echo ""

# ================================================================
# MONITORING
# ================================================================
echo "=== MONITORING ==="
echo ""
printf " %5s %8s %8s %8s %8s %8s %8s\n" "Time" "CPU" "RAM-MB" "ESTAB" "TW" "Suites" "OrigHP"
printf " %5s %8s %8s %8s %8s %8s %8s\n" "-----" "--------" "--------" "--------" "--------" "--------" "--------"

START=$(date +%s)
STATS_LOG="$RESULTS_DIR/stats.csv"
echo "elapsed,cpu,ram_mb,estab,tw,origin_http,origin_latency_ms" >"$STATS_LOG"

while true; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))
  [ "$ELAPSED" -ge "$DURATION" ] && break

  CPU=$(awk '{printf "%.2f", $1}' /proc/loadavg)
  RAM=$(free -m | awk '/Mem:/{print $3}')
  ESTAB=$(ss -tan state established | wc -l)
  TW=$(ss -tan state time-wait | wc -l)

  ACTIVE_SUITES=0
  for pid in $SUITE_PIDS; do
    kill -0 "$pid" 2>/dev/null && ACTIVE_SUITES=$((ACTIVE_SUITES + 1))
  done

  # Origin health probe
  ORIGIN_START=$(date +%s%N)
  ORIGIN_HTTP=$(curl -sf -o /dev/null -w '%{http_code}' --max-time 5 "${BASE}/health" 2>/dev/null || echo "000")
  ORIGIN_END=$(date +%s%N)
  ORIGIN_MS=$(((ORIGIN_END - ORIGIN_START) / 1000000))

  printf " %4ss %8s %8s %8s %8s %8s %4s/%sms\n" "$ELAPSED" "$CPU" "$RAM" "$ESTAB" "$TW" "$ACTIVE_SUITES" "$ORIGIN_HTTP" "$ORIGIN_MS"
  echo "$ELAPSED,$CPU,$RAM,$ESTAB,$TW,$ORIGIN_HTTP,$ORIGIN_MS" >>"$STATS_LOG"

  sleep 15
done

echo ""

# Kill background loops
[ -n "${GQL_PID:-}" ] && kill "$GQL_PID" 2>/dev/null
[ -n "${REST_PID:-}" ] && kill "$REST_PID" 2>/dev/null
[ -n "${CRAPI_PID:-}" ] && kill "$CRAPI_PID" 2>/dev/null
for pid in $SUITE_PIDS; do kill "$pid" 2>/dev/null; done
sleep 3

# ================================================================
# RESULTS
# ================================================================
echo "================================================================"
echo "  ORIGIN TORTURE TEST RESULTS — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"
echo ""

echo "=== WRK THROUGHPUT (per endpoint) ==="
printf "  %-40s %10s %10s\n" "Endpoint" "Req/s" "Avg Lat"
printf "  %-40s %10s %10s\n" "----------------------------------------" "----------" "----------"
TOTAL_WRK=0
for f in "$RESULTS_DIR"/wrk-*.log; do
  [ -f "$f" ] || continue
  EP=$(basename "$f" .log | sed 's/^wrk-//')
  RPS=$(grep "Requests/sec" "$f" 2>/dev/null | awk '{printf "%.0f", $2}')
  LAT=$(grep "Latency" "$f" 2>/dev/null | awk '{print $2}')
  printf "  %-40s %10s %10s\n" "$EP" "${RPS:-0}" "${LAT:-N/A}"
  TOTAL_WRK=$((TOTAL_WRK + ${RPS:-0}))
done
echo "  ----------------------------------------"
printf "  %-40s %10s\n" "TOTAL WRK" "$TOTAL_WRK req/s"
echo ""

echo "=== HEY THROUGHPUT ==="
TOTAL_HEY=0
for f in "$RESULTS_DIR"/hey-*.log; do
  [ -f "$f" ] || continue
  EP=$(basename "$f" .log | sed 's/^hey-//')
  RPS=$(grep "Requests/sec" "$f" 2>/dev/null | awk '{printf "%.0f", $2}')
  printf "  %-30s %10s req/s\n" "$EP" "${RPS:-0}"
  TOTAL_HEY=$((TOTAL_HEY + ${RPS:-0}))
done
printf "  %-30s %10s req/s\n" "TOTAL HEY" "$TOTAL_HEY"
echo ""

echo "=== ATTACK LAYER RESULTS (wrk Lua keepalive) ==="
for f in "$RESULTS_DIR"/wrk-*-torture.log; do
  [ -f "$f" ] || continue
  LAYER=$(basename "$f" .log | sed 's/wrk-//' | sed 's/-torture//')
  RPS=$(grep "Requests/sec" "$f" 2>/dev/null | awk '{printf "%.0f", $2}')
  LAT=$(grep "Latency" "$f" 2>/dev/null | awk '{print $2}')
  ERR=$(grep "Socket errors" "$f" 2>/dev/null | sed 's/.*Socket errors: //' || echo "none")
  printf "  %-20s %10s req/s  Lat: %s  Errors: %s\n" "$LAYER" "${RPS:-0}" "${LAT:-N/A}" "${ERR:-none}"
done
echo ""

echo "=== EXPLOIT SUITE RESULTS ==="
for suite in dvga-exploits restaurant-exploits crapi-exploits web-app-attacks api-attacks juice-shop-exploits dvwa-exploits mitre-attack; do
  LOG="$RESULTS_DIR/suite-${suite}.log"
  if [ -f "$LOG" ]; then
    P=$(grep -c '\[PASS\]' "$LOG" 2>/dev/null || echo 0)
    F=$(grep -c '\[FAIL\]' "$LOG" 2>/dev/null || echo 0)
    V=$(grep -c '\[VULN\]' "$LOG" 2>/dev/null || echo 0)
    printf "  %-28s P:%-4s F:%-4s V:%-4s\n" "$suite" "$P" "$F" "$V"
  fi
done
echo ""

echo "=== ORIGIN HEALTH TIMELINE ==="
echo "  Samples: $(wc -l <"$STATS_LOG") intervals"
ORIGIN_DOWNS=$(grep -c ",000," "$STATS_LOG" 2>/dev/null || echo 0)
ORIGIN_SLOW=$(awk -F, '$7>5000' "$STATS_LOG" 2>/dev/null | wc -l)
MAX_LAT=$(awk -F, 'NR>1{if($7>m)m=$7}END{print m+0}' "$STATS_LOG")
AVG_LAT=$(awk -F, 'NR>1{s+=$7;n++}END{printf "%.0f",s/(n+1)}' "$STATS_LOG")
echo "  Origin unreachable: $ORIGIN_DOWNS times"
echo "  Origin >5s latency: $ORIGIN_SLOW times"
echo "  Max health latency: ${MAX_LAT}ms"
echo "  Avg health latency: ${AVG_LAT}ms"
echo ""

echo "=== GENERATOR FINAL STATE ==="
cat /proc/loadavg
free -m | grep Mem
echo "ESTAB: $(ss -tan state established | wc -l)"
echo "TIME_WAIT: $(ss -tan state time-wait | wc -l)"
echo "Ports: $(ss -tan | awk -v l=1024 -v h=65535 '{split($4,a,":"); p=a[length(a)]; if(p>=l && p<=h) c++} END{print c+0}') / 64511"
echo ""

echo "=== STATS CSV ==="
echo "  Saved to: $STATS_LOG"
echo "  $(wc -l <"$STATS_LOG") data points"
cat "$STATS_LOG" | head -5
echo "  ..."
cat "$STATS_LOG" | tail -3
echo ""

echo "================================================================"
echo "  ORIGIN TORTURE TEST COMPLETE"
echo "  Duration: $((DURATION / 60)) minutes"
echo "  Combined wrk: $TOTAL_WRK req/s"
echo "  Combined hey: $TOTAL_HEY req/s"
echo "================================================================"

# Don't rm results dir — user may want the logs
echo ""
echo "Full logs: $RESULTS_DIR/"
