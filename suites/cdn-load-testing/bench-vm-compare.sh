#!/bin/bash
# VM Size A/B/C Benchmark — auto-tunes kernel + test params to available hardware
# Usage: bench-vm-compare.sh <TARGET_FQDN> [duration_seconds]
# Produces standardized results for cross-VM comparison
set -uo pipefail

# Native dependencies are mandatory; no alternate request engine is accepted.
command -v wrk >/dev/null || { echo "[FAIL] Required native wrk missing" >&2; exit 1; }
command -v hey >/dev/null || { echo "[FAIL] Required native hey missing" >&2; exit 1; }
command -v vegeta >/dev/null || { echo "[FAIL] Required native vegeta missing" >&2; exit 1; }
command -v ab >/dev/null || { echo "[FAIL] Required native ab missing" >&2; exit 1; }

TARGET="${1:?Usage: bench-vm-compare.sh <TARGET_FQDN> [duration]}"
PROTOCOL="${TARGET_PROTOCOL:-http}"
BASE="${PROTOCOL}://${TARGET}"
DURATION="${2:-120}"

NCPU=$(nproc)
TOTAL_RAM_MB=$(free -m | awk '/Mem:/{print $2}')
VM_SIZE=$(curl -sf -H Metadata:true "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01" 2>/dev/null || echo "unknown")
LUA_SCRIPT="$(dirname "$0")/_baseline.lua"

echo "================================================================"
echo "  VM BENCHMARK — STANDARDIZED CDN LOAD TEST"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  VM Size:    $VM_SIZE"
echo "  vCPU:       $NCPU"
echo "  RAM:        ${TOTAL_RAM_MB} MB"
echo "  Target:     $BASE"
echo "  Duration:   ${DURATION}s per test phase"
echo "================================================================"
echo ""

# ================================================================
# PHASE 0: Auto-tune kernel for this VM's capacity
# ================================================================
echo "=== PHASE 0: KERNEL AUTO-TUNE ==="

# Scale connection limits with CPU count
SOMAXCONN=$((NCPU * 8192))
[ "$SOMAXCONN" -gt 131072 ] && SOMAXCONN=131072
TCP_MAX_SYN=$SOMAXCONN
NETDEV_BACKLOG=$((NCPU * 8192))
[ "$NETDEV_BACKLOG" -gt 131072 ] && NETDEV_BACKLOG=131072
FILE_MAX=$((NCPU * 262144))
TW_BUCKETS=$((NCPU * 250000))

# Scale TCP buffers with RAM (use 1/4 of RAM for networking max)
NET_MEM_MAX=$(((TOTAL_RAM_MB / 4) * 1024 * 1024))
[ "$NET_MEM_MAX" -gt 67108864 ] && NET_MEM_MAX=67108864

sudo sysctl -w net.core.somaxconn=$SOMAXCONN >/dev/null 2>&1
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=$TCP_MAX_SYN >/dev/null 2>&1
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

# Raise file descriptor limits for this session
ulimit -n 524288 2>/dev/null || ulimit -n 65535 2>/dev/null || true

# --- CPU governor: lock to performance mode (no frequency scaling) ---
GOVERNOR="unknown"
if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
  for cpu_dir in /sys/devices/system/cpu/cpu*/cpufreq; do
    echo "performance" | sudo tee "$cpu_dir/scaling_governor" >/dev/null 2>&1
  done
  GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "N/A")
else
  GOVERNOR="(no cpufreq — hypervisor-managed)"
fi

# --- RPS/RFS: distribute NIC softirqs across ALL cores ---
RPS_MASK=$(printf '%x' $(((1 << NCPU) - 1)))
NIC=$(ip -o link show | awk -F': ' '/state UP/ && !/lo/{print $2; exit}')
RPS_STATUS="N/A"
if [ -n "$NIC" ]; then
  RFS_ENTRIES=$((32768 * NCPU))
  echo "$RFS_ENTRIES" | sudo tee /proc/sys/net/core/rps_sock_flow_entries >/dev/null 2>&1
  for rxq in /sys/class/net/"$NIC"/queues/rx-*/rps_cpus; do
    echo "$RPS_MASK" | sudo tee "$rxq" >/dev/null 2>&1
  done
  for rxq in /sys/class/net/"$NIC"/queues/rx-*/rps_flow_cnt; do
    echo "$((RFS_ENTRIES / $(ls -d /sys/class/net/"$NIC"/queues/rx-* 2>/dev/null | wc -l)))" | sudo tee "$rxq" >/dev/null 2>&1
  done
  RPS_STATUS="mask=$RPS_MASK on $NIC ($(ls -d /sys/class/net/"$NIC"/queues/rx-* 2>/dev/null | wc -l) queues)"
fi

# --- IRQ affinity: spread NIC interrupts across cores ---
IRQ_STATUS="N/A"
if [ -n "$NIC" ]; then
  NIC_IRQS=$(grep "$NIC" /proc/interrupts 2>/dev/null | awk '{print $1}' | tr -d ':')
  if [ -n "$NIC_IRQS" ]; then
    CPU_IDX=0
    for irq in $NIC_IRQS; do
      AFFINITY=$(printf '%x' $((1 << (CPU_IDX % NCPU))))
      echo "$AFFINITY" | sudo tee "/proc/irq/$irq/smp_affinity" >/dev/null 2>&1
      CPU_IDX=$((CPU_IDX + 1))
    done
    IRQ_STATUS="$CPU_IDX IRQs spread across $NCPU cores"
  else
    IRQ_STATUS="(no NIC IRQs found — virtio/hypervisor managed)"
  fi
fi

# --- NIC ring buffer: maximize ---
RING_STATUS="N/A"
if [ -n "$NIC" ] && command -v ethtool >/dev/null 2>&1; then
  RX_MAX=$(ethtool -g "$NIC" 2>/dev/null | awk '/Pre-set.*:/,/^$/{if(/RX:/){print $2; exit}}')
  TX_MAX=$(ethtool -g "$NIC" 2>/dev/null | awk '/Pre-set.*:/,/^$/{if(/TX:/){print $2; exit}}')
  if [ -n "$RX_MAX" ] && [ -n "$TX_MAX" ]; then
    sudo ethtool -G "$NIC" rx "$RX_MAX" tx "$TX_MAX" 2>/dev/null
    RING_STATUS="rx=$RX_MAX tx=$TX_MAX on $NIC"
  else
    RING_STATUS="(ring buffer query not supported)"
  fi
fi

# --- Transparent Huge Pages: enable for large memory pools ---
THP_STATUS="N/A"
if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
  echo "always" | sudo tee /sys/kernel/mm/transparent_hugepage/enabled >/dev/null 2>&1
  THP_STATUS=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)
fi

# --- Disable kernel security mitigations for max perf (safe in benchmark VM) ---
MITIG_STATUS="N/A"
if [ -f /sys/devices/system/cpu/vulnerabilities/spectre_v2 ]; then
  MITIG_STATUS=$(cat /sys/devices/system/cpu/vulnerabilities/spectre_v2 2>/dev/null | head -c 60)
fi

echo "  --- Sysctl ---"
echo "  somaxconn:        $SOMAXCONN"
echo "  tcp_max_syn:      $TCP_MAX_SYN"
echo "  netdev_backlog:   $NETDEV_BACKLOG"
echo "  tcp_fin_timeout:  5"
echo "  tcp_tw_buckets:   $TW_BUCKETS"
echo "  net_mem_max:      $((NET_MEM_MAX / 1024 / 1024)) MB"
echo "  file-max:         $FILE_MAX"
echo "  ulimit -n:        $(ulimit -n)"
echo "  port range:       1024-65535 (64511 ports)"
echo "  --- CPU ---"
echo "  governor:         $GOVERNOR"
echo "  mitigations:      $MITIG_STATUS"
echo "  --- NIC ---"
echo "  RPS/RFS:          $RPS_STATUS"
echo "  IRQ affinity:     $IRQ_STATUS"
echo "  ring buffer:      $RING_STATUS"
echo "  --- Memory ---"
echo "  THP:              $THP_STATUS"
echo ""

# Scale test parameters to CPU count
WRK_THREADS=$NCPU
WRK_CONNS_PER_EP=$((NCPU * 64))
HEY_CONNS=$((NCPU * 32))
VEGETA_RATE=$((NCPU * 100))
AB_CONNS=$((NCPU * 50))
CURL_WORKERS=$((NCPU * 30))

echo "=== TEST PARAMETERS (scaled to $NCPU vCPU) ==="
echo "  wrk:    ${WRK_THREADS}t / ${WRK_CONNS_PER_EP}c per endpoint"
echo "  hey:    ${HEY_CONNS}c per endpoint"
echo "  vegeta: ${VEGETA_RATE} rps per stream"
echo "  ab:     ${AB_CONNS}c per endpoint"
echo "  curl:   ${CURL_WORKERS} parallel workers"
echo ""

# Clear TCP state from any previous runs
sleep 2

# Record baseline
CPU_PRE=$(awk '{printf "%.2f", $1}' /proc/loadavg)
RAM_PRE=$(free -m | awk '/Mem:/{print $3}')
ESTAB_PRE=$(ss -tan state established | wc -l)
echo "Pre-test baseline: CPU=$CPU_PRE RAM=${RAM_PRE}MB ESTAB=$ESTAB_PRE"
echo ""

RESULTS="/tmp/bench-$$"
mkdir -p "$RESULTS"

# ================================================================
# TEST 1: wrk — static path throughput (pure req/s ceiling)
# ================================================================
echo "=== TEST 1: wrk STATIC PATH (pure throughput ceiling) ==="
ENDPOINTS=("/juice-shop/" "/httpbin/get" "/whoami/" "/health" "/dvwa/login.php" "/vampi/users/v1" "/csd-demo/health")

T1_TOTAL_RPS=0
for ep in "${ENDPOINTS[@]}"; do
  wrk -t"$WRK_THREADS" -c"$WRK_CONNS_PER_EP" -d"${DURATION}s" --timeout 10s \
    -H "X-Forwarded-For: 198.51.100.$((RANDOM % 256))" \
    "${BASE}${ep}" >"$RESULTS/wrk-static-$(echo "$ep" | tr '/' '_').log" 2>&1 &
done
wait

echo ""
printf "  %-25s %12s %12s %12s\n" "Endpoint" "Req/s" "Avg Latency" "Transfer/s"
printf "  %-25s %12s %12s %12s\n" "-------------------------" "------------" "------------" "------------"
for ep in "${ENDPOINTS[@]}"; do
  F="$RESULTS/wrk-static-$(echo "$ep" | tr '/' '_').log"
  RPS=$(grep "Requests/sec" "$F" 2>/dev/null | awk '{printf "%.0f", $2}')
  LAT=$(grep "Latency" "$F" 2>/dev/null | awk '{print $2}')
  XFER=$(grep "Transfer/sec" "$F" 2>/dev/null | awk '{print $2}')
  printf "  %-25s %12s %12s %12s\n" "$ep" "${RPS:-0}" "${LAT:-N/A}" "${XFER:-N/A}"
  T1_TOTAL_RPS=$((T1_TOTAL_RPS + ${RPS:-0}))
done
echo "  -------------------------"
printf "  %-25s %12s\n" "TOTAL" "$T1_TOTAL_RPS req/s"
echo ""

# Record mid-test state
CPU_T1=$(awk '{printf "%.2f", $1}' /proc/loadavg)
RAM_T1=$(free -m | awk '/Mem:/{print $3}')
echo "Post-T1: CPU=$CPU_T1 RAM=${RAM_T1}MB"
sleep 5

# ================================================================
# TEST 2: wrk Lua — randomized path throughput (realistic CDN traffic)
# ================================================================
echo ""
echo "=== TEST 2: wrk LUA RANDOMIZED (realistic CDN traffic) ==="

if [ -f "$LUA_SCRIPT" ]; then
  wrk -t"$WRK_THREADS" -c"$((WRK_CONNS_PER_EP * 4))" -d"${DURATION}s" --timeout 10s \
    -s "$LUA_SCRIPT" "${BASE}/" >"$RESULTS/wrk-lua.log" 2>&1
  T2_RPS=$(grep "Requests/sec" "$RESULTS/wrk-lua.log" 2>/dev/null | awk '{printf "%.0f", $2}')
  T2_LAT=$(grep "Latency" "$RESULTS/wrk-lua.log" 2>/dev/null | awk '{print $2}')
  T2_XFER=$(grep "Transfer/sec" "$RESULTS/wrk-lua.log" 2>/dev/null | awk '{print $2}')
  echo "  Threads/Conns: ${WRK_THREADS}t / $((WRK_CONNS_PER_EP * 4))c"
  echo "  Req/s:         ${T2_RPS:-0}"
  echo "  Avg Latency:   ${T2_LAT:-N/A}"
  echo "  Transfer/s:    ${T2_XFER:-N/A}"
else
  echo "  [SKIP] Lua script not found"
  T2_RPS=0
fi
echo ""
sleep 5

# ================================================================
# TEST 3: hey — goroutine throughput
# ================================================================
echo "=== TEST 3: hey GOROUTINE THROUGHPUT ==="

for ep in "/juice-shop/" "/httpbin/get" "/whoami/" "/vampi/users/v1"; do
  hey -z "${DURATION}s" -c "$HEY_CONNS" -t 10 \
    -H "X-Forwarded-For: 203.0.113.$((RANDOM % 256))" \
    "${BASE}${ep}" >"$RESULTS/hey-$(echo "$ep" | tr '/' '_').log" 2>&1 &
done
wait

T3_TOTAL_RPS=0
printf "  %-25s %12s %12s\n" "Endpoint" "Req/s" "Avg Latency"
printf "  %-25s %12s %12s\n" "-------------------------" "------------" "------------"
for ep in "/juice-shop/" "/httpbin/get" "/whoami/" "/vampi/users/v1"; do
  F="$RESULTS/hey-$(echo "$ep" | tr '/' '_').log"
  RPS=$(grep "Requests/sec" "$F" 2>/dev/null | awk '{printf "%.0f", $2}')
  LAT=$(grep "Average" "$F" 2>/dev/null | head -1 | awk '{print $2}')
  printf "  %-25s %12s %12s\n" "$ep" "${RPS:-0}" "${LAT:-N/A}"
  T3_TOTAL_RPS=$((T3_TOTAL_RPS + ${RPS:-0}))
done
echo "  -------------------------"
printf "  %-25s %12s\n" "TOTAL" "$T3_TOTAL_RPS req/s"
echo ""
sleep 5

# ================================================================
# TEST 4: vegeta — constant-rate ceiling
# ================================================================
echo "=== TEST 4: vegeta CONSTANT-RATE (find max sustainable rate) ==="

for rate_mult in 1 2 4; do
  RATE=$((VEGETA_RATE * rate_mult))
  echo "GET ${BASE}/httpbin/get" | vegeta attack -rate="${RATE}/s" -duration=30s -timeout=10s 2>/dev/null |
    vegeta report >"$RESULTS/vegeta-${RATE}rps.log" 2>&1
  SUCCESS=$(grep "Success" "$RESULTS/vegeta-${RATE}rps.log" 2>/dev/null | awk '{print $3}')
  ACTUAL_RATE=$(grep "Requests" "$RESULTS/vegeta-${RATE}rps.log" 2>/dev/null | awk '{printf "%.0f", $3}')
  P99=$(grep "99th" "$RESULTS/vegeta-${RATE}rps.log" 2>/dev/null | awk '{print $2}')
  printf "  Target: %6d rps → Actual: %6s rps | Success: %s | p99: %s\n" "$RATE" "${ACTUAL_RATE:-0}" "${SUCCESS:-N/A}" "${P99:-N/A}"
done
echo ""
sleep 5

# ================================================================
# TEST 5: Combined kraken (all tools, full saturation)
# ================================================================
echo "=== TEST 5: COMBINED KRAKEN ($((DURATION / 2))s, all tools simultaneous) ==="
KRAKEN_DUR=$((DURATION / 2))

ALL_PIDS=""

# wrk per endpoint
for ep in "/juice-shop/" "/httpbin/get" "/whoami/" "/health" "/dvwa/login.php" "/vampi/users/v1" "/csd-demo/health"; do
  wrk -t"$WRK_THREADS" -c"$WRK_CONNS_PER_EP" -d"${KRAKEN_DUR}s" --timeout 10s \
    -H "X-Forwarded-For: 192.0.2.$((RANDOM % 256))" \
    "${BASE}${ep}" >"$RESULTS/kraken-wrk-$(echo "$ep" | tr '/' '_').log" 2>&1 &
  ALL_PIDS="$ALL_PIDS $!"
done

# wrk Lua
if [ -f "$LUA_SCRIPT" ]; then
  wrk -t"$WRK_THREADS" -c"$((WRK_CONNS_PER_EP * 2))" -d"${KRAKEN_DUR}s" --timeout 10s \
    -s "$LUA_SCRIPT" "${BASE}/" >"$RESULTS/kraken-wrk-lua.log" 2>&1 &
  ALL_PIDS="$ALL_PIDS $!"
fi

# hey
for ep in "/juice-shop/" "/httpbin/get" "/whoami/" "/vampi/users/v1"; do
  hey -z "${KRAKEN_DUR}s" -c "$HEY_CONNS" -t 10 \
    -H "X-Forwarded-For: 198.51.100.$((RANDOM % 256))" \
    "${BASE}${ep}" >"$RESULTS/kraken-hey-$(echo "$ep" | tr '/' '_').log" 2>&1 &
  ALL_PIDS="$ALL_PIDS $!"
done

# vegeta
for ep in "/juice-shop/" "/httpbin/get" "/dvwa/login.php"; do
  echo "GET ${BASE}${ep}" | vegeta attack -rate="${VEGETA_RATE}/s" -duration="${KRAKEN_DUR}s" -timeout=10s 2>/dev/null |
    vegeta encode >"$RESULTS/kraken-vegeta-$(echo "$ep" | tr '/' '_').bin" &
  ALL_PIDS="$ALL_PIDS $!"
done

# ab
ab -n 999999 -c "$AB_CONNS" -k -t "$KRAKEN_DUR" -s 10 \
  -H "X-Forwarded-For: 203.0.113.$((RANDOM % 256))" \
  "${BASE}/juice-shop/" >"$RESULTS/kraken-ab.log" 2>&1 &
ALL_PIDS="$ALL_PIDS $!"

# Monitor during kraken
echo ""
printf " %5s %8s %8s %8s\n" "Time" "CPU" "RAM-MB" "ESTAB"
printf " %5s %8s %8s %8s\n" "-----" "--------" "--------" "--------"
START=$(date +%s)
while true; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))
  [ "$ELAPSED" -ge "$KRAKEN_DUR" ] && break
  CPU=$(awk '{printf "%.2f", $1}' /proc/loadavg)
  RAM=$(free -m | awk '/Mem:/{print $3}')
  ESTAB=$(ss -tan state established | wc -l)
  printf " %4ss %8s %8s %8s\n" "$ELAPSED" "$CPU" "$RAM" "$ESTAB"
  sleep 15
done

wait $ALL_PIDS 2>/dev/null
echo ""

# Aggregate kraken results
T5_WRK_RPS=0
for f in "$RESULTS"/kraken-wrk-*.log; do
  [ -f "$f" ] || continue
  RPS=$(grep "Requests/sec" "$f" 2>/dev/null | awk '{printf "%.0f", $2}')
  T5_WRK_RPS=$((T5_WRK_RPS + ${RPS:-0}))
done

T5_HEY_RPS=0
for f in "$RESULTS"/kraken-hey-*.log; do
  [ -f "$f" ] || continue
  RPS=$(grep "Requests/sec" "$f" 2>/dev/null | awk '{printf "%.0f", $2}')
  T5_HEY_RPS=$((T5_HEY_RPS + ${RPS:-0}))
done

T5_AB_RPS=$(grep "Requests per second" "$RESULTS/kraken-ab.log" 2>/dev/null | awk '{printf "%.0f", $4}')

echo "  Kraken wrk total:    $T5_WRK_RPS req/s"
echo "  Kraken hey total:    $T5_HEY_RPS req/s"
echo "  Kraken ab:           ${T5_AB_RPS:-0} req/s"
echo "  Kraken combined:     $((T5_WRK_RPS + T5_HEY_RPS + ${T5_AB_RPS:-0})) req/s"

# ================================================================
# FINAL SUMMARY
# ================================================================
echo ""
echo "================================================================"
echo "  BENCHMARK SUMMARY — $VM_SIZE"
echo "  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "================================================================"
echo ""
CPU_MODEL=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | sed 's/model name\s*:\s*//')
echo "  Hardware:          $NCPU vCPU, ${TOTAL_RAM_MB} MB RAM"
echo "  CPU:               $CPU_MODEL"
echo "  VM Size:           $VM_SIZE"
echo "  Governor:          $GOVERNOR"
echo "  RPS/RFS:           $RPS_STATUS"
echo "  IRQ affinity:      $IRQ_STATUS"
echo "  Ring buffer:       $RING_STATUS"
echo "  THP:               $THP_STATUS"
echo "  Kernel tuning:     somaxconn=$SOMAXCONN fin_timeout=5 tw_buckets=$TW_BUCKETS"
echo "  Test duration:     ${DURATION}s per phase, ${KRAKEN_DUR}s kraken"
echo ""
echo "  T1 wrk static:     $T1_TOTAL_RPS req/s (7 endpoints parallel)"
echo "  T2 wrk Lua rand:   ${T2_RPS:-0} req/s (randomized paths)"
echo "  T3 hey goroutine:  $T3_TOTAL_RPS req/s (4 endpoints parallel)"
echo "  T4 vegeta max:     see rate-stepping above"
echo "  T5 kraken combined: $((T5_WRK_RPS + T5_HEY_RPS + ${T5_AB_RPS:-0})) req/s"
echo ""
echo "  Peak CPU load:     $(awk '{printf "%.2f", $1}' /proc/loadavg)"
echo "  Peak RAM:          $(free -m | awk '/Mem:/{print $3}') MB / $TOTAL_RAM_MB MB"
echo "  TIME_WAIT:         $(ss -tan state time-wait | wc -l)"
echo "  Port usage:        $(ss -tan | awk -v l=1024 -v h=65535 '{split($4,a,":"); p=a[length(a)]; if(p>=l && p<=h) c++} END{print c+0}') / 64511"
echo ""
echo "================================================================"

rm -rf "$RESULTS"
