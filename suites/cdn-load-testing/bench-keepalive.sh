#!/bin/bash
# VM Keepalive Benchmark — measures CDN caching throughput, not TCP stack overhead
# All tools configured for persistent connection reuse
# Usage: bench-keepalive.sh <TARGET_FQDN> [duration_seconds]
set -uo pipefail

# Native dependencies are mandatory; no alternate request engine is accepted.
command -v wrk >/dev/null || { echo "[FAIL] Required native wrk missing" >&2; exit 1; }
command -v hey >/dev/null || { echo "[FAIL] Required native hey missing" >&2; exit 1; }
command -v vegeta >/dev/null || { echo "[FAIL] Required native vegeta missing" >&2; exit 1; }
command -v ab >/dev/null || { echo "[FAIL] Required native ab missing" >&2; exit 1; }

TARGET="${1:?Usage: bench-keepalive.sh <TARGET_FQDN> [duration]}"
PROTOCOL="${TARGET_PROTOCOL:-http}"
BASE="${PROTOCOL}://${TARGET}"
DURATION="${2:-120}"

NCPU=$(nproc)
TOTAL_RAM_MB=$(free -m | awk '/Mem:/{print $2}')
VM_SIZE=$(curl -sf -H Metadata:true "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01" 2>/dev/null || echo "unknown")
LUA_SCRIPT="$(dirname "$0")/_keepalive.lua"

echo "================================================================"
echo "  VM KEEPALIVE BENCHMARK — CDN CACHING THROUGHPUT"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  VM Size:    $VM_SIZE"
echo "  vCPU:       $NCPU"
echo "  RAM:        ${TOTAL_RAM_MB} MB"
echo "  Target:     $BASE"
echo "  Duration:   ${DURATION}s per test phase"
echo "  Mode:       ALL connections persistent (keepalive)"
echo "================================================================"
echo ""

# ================================================================
# PHASE 0: Kernel tuning (same as before)
# ================================================================
echo "=== PHASE 0: KERNEL + OS TUNING ==="

SOMAXCONN=$((NCPU * 8192))
[ "$SOMAXCONN" -gt 131072 ] && SOMAXCONN=131072
NETDEV_BACKLOG=$((NCPU * 8192))
[ "$NETDEV_BACKLOG" -gt 131072 ] && NETDEV_BACKLOG=131072
FILE_MAX=$((NCPU * 262144))
TW_BUCKETS=$((NCPU * 250000))
NET_MEM_MAX=$(((TOTAL_RAM_MB / 4) * 1024 * 1024))
[ "$NET_MEM_MAX" -gt 67108864 ] && NET_MEM_MAX=67108864

sudo sysctl -w net.core.somaxconn=$SOMAXCONN >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=$SOMAXCONN >/dev/null 2>&1
sudo sysctl -w net.core.netdev_max_backlog=$NETDEV_BACKLOG >/dev/null 2>&1
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535" >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_fin_timeout=5 >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_max_tw_buckets=$TW_BUCKETS >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_keepalive_time=30 >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_keepalive_intvl=5 >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_keepalive_probes=3 >/dev/null 2>&1
sudo sysctl -w net.core.rmem_max=$NET_MEM_MAX >/dev/null 2>&1
sudo sysctl -w net.core.wmem_max=$NET_MEM_MAX >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 $NET_MEM_MAX" >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 $NET_MEM_MAX" >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_no_metrics_save=1 >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_window_scaling=1 >/dev/null 2>&1
sudo sysctl -w fs.file-max=$FILE_MAX >/dev/null 2>&1

ulimit -n 524288 2>/dev/null || ulimit -n 65535 2>/dev/null || true

# RPS/RFS
NIC=$(ip -o link show | awk -F': ' '/state UP/ && !/lo/{print $2; exit}')
RPS_STATUS="N/A"
if [ -n "$NIC" ]; then
  RPS_MASK=$(printf '%x' $(((1 << NCPU) - 1)))
  RFS_ENTRIES=$((32768 * NCPU))
  echo "$RFS_ENTRIES" | sudo tee /proc/sys/net/core/rps_sock_flow_entries >/dev/null 2>&1
  for rxq in /sys/class/net/"$NIC"/queues/rx-*/rps_cpus; do
    echo "$RPS_MASK" | sudo tee "$rxq" >/dev/null 2>&1
  done
  RPS_STATUS="mask=$RPS_MASK on $NIC"
fi

# Ring buffers
RING_STATUS="N/A"
if [ -n "$NIC" ] && command -v ethtool >/dev/null 2>&1; then
  RX_MAX=$(ethtool -g "$NIC" 2>/dev/null | awk '/Pre-set.*:/,/^$/{if(/RX:/){print $2; exit}}')
  TX_MAX=$(ethtool -g "$NIC" 2>/dev/null | awk '/Pre-set.*:/,/^$/{if(/TX:/){print $2; exit}}')
  if [ -n "$RX_MAX" ] && [ -n "$TX_MAX" ]; then
    sudo ethtool -G "$NIC" rx "$RX_MAX" tx "$TX_MAX" 2>/dev/null
    RING_STATUS="rx=$RX_MAX tx=$TX_MAX"
  fi
fi

# THP
echo "always" | sudo tee /sys/kernel/mm/transparent_hugepage/enabled >/dev/null 2>&1

echo "  sysctl:     somaxconn=$SOMAXCONN tw_buckets=$TW_BUCKETS file-max=$FILE_MAX"
echo "  RPS/RFS:    $RPS_STATUS"
echo "  ring buf:   $RING_STATUS"
echo "  THP:        always"
echo ""

# ================================================================
# KEEPALIVE STRATEGY
# ================================================================
# Key insight from CDN team: without keepalive, 65-72% of CDN CPU
# goes to kernel TCP setup/teardown. With keepalive, NGINX gets 55%
# of CPU for serving requests — roughly doubling useful throughput.
#
# Design principles:
# 1. FEWER connections, MORE requests per connection
# 2. Every tool explicitly configured for connection reuse
# 3. No curl loops (new conn per invocation)
# 4. No thundering herd in throughput tests (separate concern)
# 5. Connection count capped at what the CDN can handle without churn
#
# Target: ~2000-4000 persistent connections total (not 28K)
# Each connection should serve hundreds of requests over its lifetime

# Scale connections conservatively — goal is saturating CDN cache serving,
# not CDN TCP stack
WRK_THREADS=$NCPU
# Fewer connections per endpoint, but they stay alive the full duration
WRK_CONNS_PER_EP=$((NCPU * 16))
[ "$WRK_CONNS_PER_EP" -gt 512 ] && WRK_CONNS_PER_EP=512
HEY_CONNS=$((NCPU * 12))
[ "$HEY_CONNS" -gt 400 ] && HEY_CONNS=400
VEGETA_RATE=$((NCPU * 200))
AB_CONNS=$((NCPU * 16))
[ "$AB_CONNS" -gt 400 ] && AB_CONNS=400

TOTAL_WRK_CONNS=$((WRK_CONNS_PER_EP * 7))
TOTAL_CONNS=$((TOTAL_WRK_CONNS + HEY_CONNS * 4 + AB_CONNS * 2))

echo "=== KEEPALIVE TEST PARAMETERS (scaled to $NCPU vCPU) ==="
echo "  wrk:        ${WRK_THREADS}t / ${WRK_CONNS_PER_EP}c per endpoint (7 ep = $TOTAL_WRK_CONNS persistent)"
echo "  hey:        ${HEY_CONNS}c per endpoint (4 ep = $((HEY_CONNS * 4)) persistent)"
echo "  vegeta:     ${VEGETA_RATE} rps per stream (connection pooled)"
echo "  ab:         ${AB_CONNS}c per endpoint with -k (2 ep = $((AB_CONNS * 2)) persistent)"
echo "  TOTAL:      ~$TOTAL_CONNS persistent connections (vs 28K before)"
echo ""
echo "  Key difference: connections stay alive for FULL duration."
echo "  CDN serves hundreds of req per connection instead of 1."
echo ""

# Wait for clean TCP state
sleep 3

CPU_PRE=$(awk '{printf "%.2f", $1}' /proc/loadavg)
RAM_PRE=$(free -m | awk '/Mem:/{print $3}')
echo "Pre-test baseline: CPU=$CPU_PRE RAM=${RAM_PRE}MB"
echo ""

RESULTS="/tmp/bench-ka-$$"
mkdir -p "$RESULTS"

# ================================================================
# TEST 1: wrk keepalive — static paths (pure CDN cache throughput)
# ================================================================
echo "=== TEST 1: wrk KEEPALIVE STATIC (CDN cache throughput ceiling) ==="
echo "  wrk uses HTTP/1.1 with persistent connections by default."
echo "  Each of $WRK_CONNS_PER_EP connections serves requests for full ${DURATION}s."
echo ""

ENDPOINTS=("/juice-shop/" "/httpbin/get" "/whoami/" "/health" "/dvwa/login.php" "/vampi/users/v1" "/csd-demo/health")

for ep in "${ENDPOINTS[@]}"; do
  wrk -t"$WRK_THREADS" -c"$WRK_CONNS_PER_EP" -d"${DURATION}s" --timeout 10s \
    -H "Connection: keep-alive" \
    -H "X-Forwarded-For: 198.51.100.$((RANDOM % 256))" \
    -H "Accept-Encoding: gzip" \
    "${BASE}${ep}" >"$RESULTS/t1-wrk-$(echo "$ep" | tr '/' '_').log" 2>&1 &
done
wait

T1_TOTAL_RPS=0
T1_TOTAL_XFER=0
printf "  %-25s %12s %12s %12s %12s\n" "Endpoint" "Req/s" "Avg Lat" "Transfer/s" "Errors"
printf "  %-25s %12s %12s %12s %12s\n" "-------------------------" "------------" "------------" "------------" "------------"
for ep in "${ENDPOINTS[@]}"; do
  F="$RESULTS/t1-wrk-$(echo "$ep" | tr '/' '_').log"
  RPS=$(grep "Requests/sec" "$F" 2>/dev/null | awk '{printf "%.0f", $2}')
  LAT=$(grep "Latency" "$F" 2>/dev/null | awk '{print $2}')
  XFER=$(grep "Transfer/sec" "$F" 2>/dev/null | awk '{print $2}')
  SOCK_ERR=$(grep "Socket errors" "$F" 2>/dev/null | sed 's/.*Socket errors: //' || echo "none")
  printf "  %-25s %12s %12s %12s %12s\n" "$ep" "${RPS:-0}" "${LAT:-N/A}" "${XFER:-N/A}" "${SOCK_ERR:-none}"
  T1_TOTAL_RPS=$((T1_TOTAL_RPS + ${RPS:-0}))
done
echo "  -------------------------"
printf "  %-25s %12s\n" "TOTAL" "$T1_TOTAL_RPS req/s"
echo ""

CPU_T1=$(awk '{printf "%.2f", $1}' /proc/loadavg)
RAM_T1=$(free -m | awk '/Mem:/{print $3}')
TW_T1=$(ss -tan state time-wait | wc -l)
echo "  Post-T1: CPU=$CPU_T1 RAM=${RAM_T1}MB TIME_WAIT=$TW_T1"
echo "  (Low TIME_WAIT = connections being REUSED, not torn down)"
echo ""
sleep 5

# ================================================================
# TEST 2: wrk Lua keepalive — randomized paths (realistic CDN traffic)
# ================================================================
echo "=== TEST 2: wrk LUA KEEPALIVE RANDOMIZED (realistic CDN traffic) ==="
echo "  Same persistent connections, but paths/headers randomized per request."
echo ""

LUA_CONNS=$((WRK_CONNS_PER_EP * 4))
[ "$LUA_CONNS" -gt 2000 ] && LUA_CONNS=2000

if [ -f "$LUA_SCRIPT" ]; then
  wrk -t"$WRK_THREADS" -c"$LUA_CONNS" -d"${DURATION}s" --timeout 10s \
    -s "$LUA_SCRIPT" "${BASE}/" >"$RESULTS/t2-wrk-lua.log" 2>&1
  T2_RPS=$(grep "Requests/sec" "$RESULTS/t2-wrk-lua.log" 2>/dev/null | awk '{printf "%.0f", $2}')
  T2_LAT=$(grep "Latency" "$RESULTS/t2-wrk-lua.log" 2>/dev/null | awk '{print $2}')
  T2_XFER=$(grep "Transfer/sec" "$RESULTS/t2-wrk-lua.log" 2>/dev/null | awk '{print $2}')
  T2_ERR=$(grep "Socket errors" "$RESULTS/t2-wrk-lua.log" 2>/dev/null | sed 's/.*Socket errors: //' || echo "none")
  echo "  Threads/Conns: ${WRK_THREADS}t / ${LUA_CONNS}c (persistent)"
  echo "  Req/s:         ${T2_RPS:-0}"
  echo "  Avg Latency:   ${T2_LAT:-N/A}"
  echo "  Transfer/s:    ${T2_XFER:-N/A}"
  echo "  Socket errors: ${T2_ERR:-none}"
else
  echo "  [SKIP] Lua script not found"
  T2_RPS=0
fi

TW_T2=$(ss -tan state time-wait | wc -l)
echo "  TIME_WAIT after Lua test: $TW_T2"
echo ""
sleep 5

# ================================================================
# TEST 3: hey keepalive (goroutine throughput)
# ================================================================
echo "=== TEST 3: hey KEEPALIVE (goroutine throughput) ==="
echo "  hey uses keepalive by default. ${HEY_CONNS}c persistent per endpoint."
echo ""

for ep in "/juice-shop/" "/httpbin/get" "/whoami/" "/vampi/users/v1"; do
  hey -z "${DURATION}s" -c "$HEY_CONNS" -t 10 \
    -H "Connection: keep-alive" \
    -H "X-Forwarded-For: 203.0.113.$((RANDOM % 256))" \
    -H "Accept-Encoding: gzip" \
    "${BASE}${ep}" >"$RESULTS/t3-hey-$(echo "$ep" | tr '/' '_').log" 2>&1 &
done
wait

T3_TOTAL_RPS=0
printf "  %-25s %12s %12s %12s\n" "Endpoint" "Req/s" "Avg Latency" "Errors"
printf "  %-25s %12s %12s %12s\n" "-------------------------" "------------" "------------" "------------"
for ep in "/juice-shop/" "/httpbin/get" "/whoami/" "/vampi/users/v1"; do
  F="$RESULTS/t3-hey-$(echo "$ep" | tr '/' '_').log"
  RPS=$(grep "Requests/sec" "$F" 2>/dev/null | awk '{printf "%.0f", $2}')
  LAT=$(grep "Average" "$F" 2>/dev/null | head -1 | awk '{print $2}')
  ERRS=$(grep -c "error" "$F" 2>/dev/null || echo "0")
  printf "  %-25s %12s %12s %12s\n" "$ep" "${RPS:-0}" "${LAT:-N/A}s" "${ERRS:-0}"
  T3_TOTAL_RPS=$((T3_TOTAL_RPS + ${RPS:-0}))
done
echo "  -------------------------"
printf "  %-25s %12s\n" "TOTAL" "$T3_TOTAL_RPS req/s"
echo ""
sleep 5

# ================================================================
# TEST 4: vegeta keepalive — constant-rate stepping
# ================================================================
echo "=== TEST 4: vegeta KEEPALIVE CONSTANT-RATE ==="
echo "  vegeta reuses connections by default (-keepalive=true)."
echo ""

for rate_mult in 1 2 4 8; do
  RATE=$((VEGETA_RATE * rate_mult))
  echo "GET ${BASE}/httpbin/get
X-Forwarded-For: 192.0.2.$((RANDOM % 256))
Accept-Encoding: gzip
Connection: keep-alive" >"$RESULTS/t4-vegeta-targets.txt"

  vegeta attack -rate="${RATE}/s" -duration=30s -timeout=10s -keepalive \
    -targets="$RESULTS/t4-vegeta-targets.txt" 2>/dev/null |
    vegeta report >"$RESULTS/t4-vegeta-${RATE}rps.log" 2>&1
  SUCCESS=$(grep "Success" "$RESULTS/t4-vegeta-${RATE}rps.log" 2>/dev/null | head -1 | awk '{print $3}')
  ACTUAL=$(grep "Throughput" "$RESULTS/t4-vegeta-${RATE}rps.log" 2>/dev/null | awk '{printf "%.0f", $2}')
  P99=$(grep "99th" "$RESULTS/t4-vegeta-${RATE}rps.log" 2>/dev/null | awk '{print $2}')
  BYTES=$(grep "Bytes In" "$RESULTS/t4-vegeta-${RATE}rps.log" 2>/dev/null | head -1)
  printf "  Target: %6d rps → Actual: %6s rps | Success: %s | p99: %s\n" "$RATE" "${ACTUAL:-0}" "${SUCCESS:-N/A}" "${P99:-N/A}"
done
echo ""
sleep 5

# ================================================================
# TEST 5: Combined keepalive kraken (all tools, all persistent)
# ================================================================
KRAKEN_DUR=$((DURATION / 2))
echo "=== TEST 5: COMBINED KEEPALIVE KRAKEN (${KRAKEN_DUR}s, all persistent) ==="
echo "  NO curl loops. NO thundering herd. ONLY persistent-connection tools."
echo "  Target: ~$TOTAL_CONNS persistent connections, max req per connection."
echo ""

ALL_PIDS=""

# wrk per endpoint (persistent)
for ep in "${ENDPOINTS[@]}"; do
  wrk -t"$WRK_THREADS" -c"$WRK_CONNS_PER_EP" -d"${KRAKEN_DUR}s" --timeout 10s \
    -H "Connection: keep-alive" \
    -H "X-Forwarded-For: 192.0.2.$((RANDOM % 256))" \
    -H "Accept-Encoding: gzip" \
    "${BASE}${ep}" >"$RESULTS/t5-wrk-$(echo "$ep" | tr '/' '_').log" 2>&1 &
  ALL_PIDS="$ALL_PIDS $!"
done

# wrk Lua (persistent, randomized paths reuse same connections)
if [ -f "$LUA_SCRIPT" ]; then
  wrk -t"$WRK_THREADS" -c"$LUA_CONNS" -d"${KRAKEN_DUR}s" --timeout 10s \
    -s "$LUA_SCRIPT" "${BASE}/" >"$RESULTS/t5-wrk-lua.log" 2>&1 &
  ALL_PIDS="$ALL_PIDS $!"
fi

# hey per endpoint (persistent)
for ep in "/juice-shop/" "/httpbin/get" "/whoami/" "/vampi/users/v1"; do
  hey -z "${KRAKEN_DUR}s" -c "$HEY_CONNS" -t 10 \
    -H "Connection: keep-alive" \
    -H "X-Forwarded-For: 198.51.100.$((RANDOM % 256))" \
    -H "Accept-Encoding: gzip" \
    "${BASE}${ep}" >"$RESULTS/t5-hey-$(echo "$ep" | tr '/' '_').log" 2>&1 &
  ALL_PIDS="$ALL_PIDS $!"
done

# vegeta constant-rate (persistent, connection-pooled)
for ep in "/juice-shop/" "/httpbin/get" "/dvwa/login.php"; do
  echo "GET ${BASE}${ep}
X-Forwarded-For: 203.0.113.$((RANDOM % 256))
Accept-Encoding: gzip
Connection: keep-alive" >"$RESULTS/t5-vegeta-targets-$(echo "$ep" | tr '/' '_').txt"

  vegeta attack -rate="${VEGETA_RATE}/s" -duration="${KRAKEN_DUR}s" -timeout=10s -keepalive \
    -targets="$RESULTS/t5-vegeta-targets-$(echo "$ep" | tr '/' '_').txt" 2>/dev/null |
    vegeta encode >"$RESULTS/t5-vegeta-$(echo "$ep" | tr '/' '_').bin" &
  ALL_PIDS="$ALL_PIDS $!"
done

# ab keepalive
ab -n 999999 -c "$AB_CONNS" -k -t "$KRAKEN_DUR" -s 10 \
  -H "X-Forwarded-For: 192.0.2.$((RANDOM % 256))" \
  -H "Accept-Encoding: gzip" \
  "${BASE}/juice-shop/" >"$RESULTS/t5-ab-juice.log" 2>&1 &
ALL_PIDS="$ALL_PIDS $!"
ab -n 999999 -c "$AB_CONNS" -k -t "$KRAKEN_DUR" -s 10 \
  -H "X-Forwarded-For: 198.51.100.$((RANDOM % 256))" \
  -H "Accept-Encoding: gzip" \
  "${BASE}/httpbin/get" >"$RESULTS/t5-ab-httpbin.log" 2>&1 &
ALL_PIDS="$ALL_PIDS $!"

# Monitor
printf " %5s %8s %8s %8s %8s\n" "Time" "CPU" "RAM-MB" "ESTAB" "TW"
printf " %5s %8s %8s %8s %8s\n" "-----" "--------" "--------" "--------" "--------"
START=$(date +%s)
while true; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))
  [ "$ELAPSED" -ge "$KRAKEN_DUR" ] && break
  CPU=$(awk '{printf "%.2f", $1}' /proc/loadavg)
  RAM=$(free -m | awk '/Mem:/{print $3}')
  ESTAB=$(ss -tan state established | wc -l)
  TW=$(ss -tan state time-wait | wc -l)
  printf " %4ss %8s %8s %8s %8s\n" "$ELAPSED" "$CPU" "$RAM" "$ESTAB" "$TW"
  sleep 15
done

# shellcheck disable=SC2086
wait $ALL_PIDS 2>/dev/null
echo ""

# Aggregate kraken
T5_WRK_RPS=0
for f in "$RESULTS"/t5-wrk-*.log; do
  [ -f "$f" ] || continue
  RPS=$(grep "Requests/sec" "$f" 2>/dev/null | awk '{printf "%.0f", $2}')
  T5_WRK_RPS=$((T5_WRK_RPS + ${RPS:-0}))
done

T5_HEY_RPS=0
for f in "$RESULTS"/t5-hey-*.log; do
  [ -f "$f" ] || continue
  RPS=$(grep "Requests/sec" "$f" 2>/dev/null | awk '{printf "%.0f", $2}')
  T5_HEY_RPS=$((T5_HEY_RPS + ${RPS:-0}))
done

T5_AB_RPS=0
for f in "$RESULTS"/t5-ab-*.log; do
  [ -f "$f" ] || continue
  RPS=$(grep "Requests per second" "$f" 2>/dev/null | awk '{printf "%.0f", $4}')
  T5_AB_RPS=$((T5_AB_RPS + ${RPS:-0}))
done

T5_VEGETA_RPS=0
for f in "$RESULTS"/t5-vegeta-*.bin; do
  [ -f "$f" ] || continue
  RPS=$(vegeta report <"$f" 2>/dev/null | grep "Throughput" | awk '{printf "%.0f", $2}')
  T5_VEGETA_RPS=$((T5_VEGETA_RPS + ${RPS:-0}))
done

T5_COMBINED=$((T5_WRK_RPS + T5_HEY_RPS + T5_AB_RPS + T5_VEGETA_RPS))

echo "  Kraken wrk:      $T5_WRK_RPS req/s"
echo "  Kraken hey:      $T5_HEY_RPS req/s"
echo "  Kraken ab:       $T5_AB_RPS req/s"
echo "  Kraken vegeta:   $T5_VEGETA_RPS req/s"
echo "  Kraken combined: $T5_COMBINED req/s"
echo ""
echo "  Post-kraken TIME_WAIT: $(ss -tan state time-wait | wc -l)"
echo "  (Lower = better connection reuse)"

# ================================================================
# FINAL SUMMARY
# ================================================================
echo ""
echo "================================================================"
echo "  KEEPALIVE BENCHMARK SUMMARY — $VM_SIZE"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"
echo ""
CPU_MODEL=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | sed 's/model name\s*:\s*//')
echo "  Hardware:          $NCPU vCPU, ${TOTAL_RAM_MB} MB RAM"
echo "  CPU:               $CPU_MODEL"
echo "  VM Size:           $VM_SIZE"
echo "  Connection mode:   ALL KEEPALIVE (persistent)"
echo "  Total connections: ~$TOTAL_CONNS persistent"
echo "  Test duration:     ${DURATION}s per phase, ${KRAKEN_DUR}s kraken"
echo ""
echo "  T1 wrk static:     $T1_TOTAL_RPS req/s (7 ep × ${WRK_CONNS_PER_EP}c persistent)"
echo "  T2 wrk Lua rand:   ${T2_RPS:-0} req/s (${LUA_CONNS}c persistent)"
echo "  T3 hey goroutine:  $T3_TOTAL_RPS req/s (4 ep × ${HEY_CONNS}c persistent)"
echo "  T4 vegeta max:     see rate-stepping above"
echo "  T5 kraken combined: $T5_COMBINED req/s"
echo ""
echo "  Peak CPU load:     $(awk '{printf "%.2f", $1}' /proc/loadavg)"
echo "  Peak RAM:          $(free -m | awk '/Mem:/{print $3}') MB / $TOTAL_RAM_MB MB"
echo "  Final TIME_WAIT:   $(ss -tan state time-wait | wc -l)"
echo "  Final ESTAB:       $(ss -tan state established | wc -l)"
echo "  Port usage:        $(ss -tan | awk -v l=1024 -v h=65535 '{split($4,a,":"); p=a[length(a)]; if(p>=l && p<=h) c++} END{print c+0}') / 64511"
echo ""
echo "================================================================"

rm -rf "$RESULTS"
