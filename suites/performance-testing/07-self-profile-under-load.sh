#!/bin/bash
# Self-profiling under load — measures THIS machine's resource consumption
# while generating traffic, identifying CPU/RAM/disk/network bottlenecks
# Tools: curl, iostat, ss, free, /proc
# Run this ON the traffic generator VM via SSH
# Estimated duration: 2 minutes
set -uo pipefail

TARGET="${1:?Usage: 07-self-profile-under-load.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

CONCURRENCY="${TGEN_CONCURRENCY:-100}"
DURATION="${TGEN_DURATION:-60}"
SAMPLE_INTERVAL=5

echo "[*] Self-profile under load against ${TARGET}"
echo "    Concurrency: ${CONCURRENCY}"
echo "    Duration: ${DURATION}s"
echo "    Sample interval: ${SAMPLE_INTERVAL}s"
echo ""

echo "=== PRE-LOAD BASELINE ==="
echo "CPU: $(uptime | awk -F'load average:' '{print $2}')"
free -m | awk '/^Mem:/ {printf "RAM: %dMB used / %dMB total (%.0f%%)\n", $3, $2, $3/$2*100}'
TW_BEFORE=$(ss -tan state time-wait 2>/dev/null | wc -l)
ESTAB_BEFORE=$(ss -tan state established 2>/dev/null | wc -l)
FD_BEFORE=$(cat /proc/sys/fs/file-nr 2>/dev/null | awk '{print $1}' || echo 0)
echo "TCP established: ${ESTAB_BEFORE} | TIME_WAIT: ${TW_BEFORE} | Open FDs: ${FD_BEFORE}"
echo ""

ENDPOINTS=(
  "/health"
  "/juice-shop/"
  "/juice-shop/rest/products/search?q=test"
  "/vampi/users/v1"
  "/httpbin/get"
  "/whoami/"
  "/csd-demo/health"
  "/dvwa/login.php"
)

echo "=== GENERATING LOAD (${DURATION}s at ${CONCURRENCY} concurrent) ==="
echo ""
printf "%6s %6s %8s %8s %6s %6s %6s %8s\n" \
  "Time" "Req/s" "CPU-load" "RAM-used" "ESTAB" "T-WAIT" "FDs" "Errors"
echo "------ ------ -------- -------- ------ ------ ------ --------"

TOTAL_OK=0
TOTAL_ERR=0
elapsed=0

while [[ $elapsed -lt $DURATION ]]; do
  batch=$((CONCURRENCY * 2))

  err_before=$TOTAL_ERR

  for _ in $(seq "$batch"); do
    echo "${BASE}${ENDPOINTS[$((RANDOM % ${#ENDPOINTS[@]}))]}"
  done | xargs -P"$CONCURRENCY" -I{} \
    curl -sf -o /dev/null -w "%{http_code}\n" --max-time 10 --connect-timeout 5 {} \
    2>/dev/null >/tmp/self-profile-$$.txt || true

  ok=$(grep -c '^[23]0[0-9]$' /tmp/self-profile-$$.txt 2>/dev/null || echo 0)
  total=$(wc -l </tmp/self-profile-$$.txt 2>/dev/null || echo 0)
  err=$((total - ok))
  TOTAL_OK=$((TOTAL_OK + ok))
  TOTAL_ERR=$((TOTAL_ERR + err))

  cpu_load=$(uptime | awk -F'load average:' '{print $2}' | awk -F, '{gsub(/^ /,"",$1); print $1}')
  ram_used=$(free -m | awk '/^Mem:/ {print $3}')
  ram_total=$(free -m | awk '/^Mem:/ {print $2}')
  estab=$(ss -tan state established 2>/dev/null | wc -l)
  tw=$(ss -tan state time-wait 2>/dev/null | wc -l)
  fds=$(cat /proc/sys/fs/file-nr 2>/dev/null | awk '{print $1}' || echo 0)
  rps=$(awk "BEGIN {printf \"%.0f\", $total / $SAMPLE_INTERVAL}")

  flag=""
  if [[ "$err" -gt $((total / 10)) ]]; then flag=" !!ERR"; fi
  if [[ "$tw" -gt 10000 ]]; then flag="${flag} !!TW"; fi
  if [[ "$ram_used" -gt $((ram_total * 90 / 100)) ]]; then flag="${flag} !!RAM"; fi

  printf "%5ds %6s %8s %6dMB %6d %6d %6s %8d%s\n" \
    "$elapsed" "$rps" "$cpu_load" "$ram_used" "$estab" "$tw" "$fds" "$err" "$flag"

  sleep "$SAMPLE_INTERVAL"
  elapsed=$((elapsed + SAMPLE_INTERVAL))
done

rm -f /tmp/self-profile-$$.txt

echo ""
echo "=== POST-LOAD STATE ==="
echo "CPU: $(uptime | awk -F'load average:' '{print $2}')"
free -m | awk '/^Mem:/ {printf "RAM: %dMB used / %dMB total (%.0f%%)\n", $3, $2, $3/$2*100}'
TW_AFTER=$(ss -tan state time-wait 2>/dev/null | wc -l)
ESTAB_AFTER=$(ss -tan state established 2>/dev/null | wc -l)
FD_AFTER=$(cat /proc/sys/fs/file-nr 2>/dev/null | awk '{print $1}' || echo 0)
echo "TCP established: ${ESTAB_AFTER} | TIME_WAIT: ${TW_AFTER} | Open FDs: ${FD_AFTER}"
echo ""

echo "=== BOTTLENECK ANALYSIS ==="

if [[ "$TW_AFTER" -gt 10000 ]]; then
  echo "** TIME_WAIT EXHAUSTION: ${TW_AFTER} sockets in TIME_WAIT **"
  echo "   Fix: sysctl net.ipv4.tcp_tw_reuse=1 net.ipv4.tcp_fin_timeout=10"
fi

RANGE=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || echo "32768 60999")
LOW=$(echo "$RANGE" | awk '{print $1}')
HIGH=$(echo "$RANGE" | awk '{print $2}')
PORT_TOTAL=$((HIGH - LOW))
PORT_USED=$(ss -tan | awk -v low="$LOW" -v high="$HIGH" '{split($4,a,":"); p=a[length(a)]; if(p>=low && p<=high) count++} END {print count+0}')
PORT_PCT=$((PORT_USED * 100 / PORT_TOTAL))
if [[ "$PORT_PCT" -gt 80 ]]; then
  echo "** EPHEMERAL PORT EXHAUSTION: ${PORT_USED}/${PORT_TOTAL} (${PORT_PCT}%) **"
  echo "   Fix: sysctl net.ipv4.ip_local_port_range='1024 65535'"
fi

FD_LIMIT=$(ulimit -n)
if [[ "$FD_AFTER" -gt $((FD_LIMIT * 80 / 100)) ]]; then
  echo "** FILE DESCRIPTOR LIMIT: ${FD_AFTER}/${FD_LIMIT} ($((FD_AFTER * 100 / FD_LIMIT))%) **"
  echo "   Fix: increase LimitNOFILE in systemd or /etc/security/limits.conf"
fi

if [[ "$TOTAL_ERR" -eq 0 ]]; then
  echo "NO BOTTLENECKS DETECTED — all ${TOTAL_OK} requests succeeded"
else
  echo ""
  echo "Summary: ${TOTAL_OK} OK, ${TOTAL_ERR} errors ($((TOTAL_ERR * 100 / (TOTAL_OK + TOTAL_ERR)))% error rate)"
fi

echo ""
echo "[*] Self-profile under load complete"
