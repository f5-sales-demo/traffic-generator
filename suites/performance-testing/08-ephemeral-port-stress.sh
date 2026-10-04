#!/bin/bash
# Ephemeral port exhaustion test — drives TCP connection churn to find port ceiling
# Tools: hey (primary, with -disable-keepalive), curl+xargs (fallback), ss, sysctl
# Identifies whether ip_local_port_range and tcp_tw_reuse are properly tuned
# Estimated duration: 1-2 minutes
set -uo pipefail

# Native dependencies are mandatory; no alternate request engine is accepted.
command -v hey >/dev/null || { echo "[FAIL] Required native hey missing" >&2; exit 1; }

TARGET="${1:?Usage: 08-ephemeral-port-stress.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] Ephemeral port stress test against ${TARGET}"
echo ""

RANGE=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null || echo "32768 60999")
LOW=$(echo "$RANGE" | awk '{print $1}')
HIGH=$(echo "$RANGE" | awk '{print $2}')
TOTAL=$((HIGH - LOW))
TW_REUSE=$(sysctl -n net.ipv4.tcp_tw_reuse 2>/dev/null || echo "unknown")
FIN_TIMEOUT=$(sysctl -n net.ipv4.tcp_fin_timeout 2>/dev/null || echo "unknown")

echo "  Port range:    ${LOW}-${HIGH} (${TOTAL} ports)"
echo "  tcp_tw_reuse:  ${TW_REUSE}"
echo "  tcp_fin_timeout: ${FIN_TIMEOUT}s"
echo ""

USE_HEY=false
if command -v hey &>/dev/null; then
  USE_HEY=true
  echo "[+] Using hey -disable-keepalive (forces new TCP connections per request)"
else
  echo "[+] hey not found — falling back to curl+xargs"
fi
echo ""

BATCHES=(20 50 "${TGEN_REQUESTS:-100}")

for batch in "${BATCHES[@]}"; do
  echo "=== Batch: ${batch} rapid connections (Connection: close) ==="

  tw_before=$(ss -tan state time-wait 2>/dev/null | wc -l)
  port_before=$(ss -tan | awk -v low="$LOW" -v high="$HIGH" '{split($4,a,":"); p=a[length(a)]; if(p>=low && p<=high) count++} END {print count+0}')

  start_ns=$(date +%s%N)

  if [[ "$USE_HEY" == "true" ]]; then
    # hey -disable-keepalive forces Connection: close, creating one TCP connection per request
    hey_output=$(hey -n "${batch}" -c 50 -t 5 -disable-keepalive "${BASE}/health" 2>&1)

    ok=$(echo "$hey_output" | grep '^\s*\[200\]' | awk '{print $2}' || echo 0)
    [[ -z "$ok" ]] && ok=0
    err=$((batch - ok))

  else
    results=$(seq "$batch" | xargs -P50 -I{} \
      curl -sf -o /dev/null -w "%{http_code}\n" \
      --max-time 5 --connect-timeout 3 \
      -H "Connection: close" "$BASE/health" 2>/dev/null)

    ok=$(echo "$results" | grep -c '^200$' || true)
    err=$((batch - ok))
  fi

  end_ns=$(date +%s%N)
  wall_ms=$(((end_ns - start_ns) / 1000000))

  tw_after=$(ss -tan state time-wait 2>/dev/null | wc -l)
  port_after=$(ss -tan | awk -v low="$LOW" -v high="$HIGH" '{split($4,a,":"); p=a[length(a)]; if(p>=low && p<=high) count++} END {print count+0}')
  tw_delta=$((tw_after - tw_before))
  port_pct=$((port_after * 100 / TOTAL))

  printf "  OK: %d | Err: %d | Wall: %dms | TW delta: +%d (total: %d) | Ports: %d/%d (%d%%)\n" \
    "$ok" "$err" "$wall_ms" "$tw_delta" "$tw_after" "$port_after" "$TOTAL" "$port_pct"

  if [[ "$port_pct" -gt 80 ]]; then
    echo "  ** PORT EXHAUSTION WARNING: ${port_pct}% of ephemeral ports in use **"
  fi
  if [[ "$tw_after" -gt $((TOTAL / 2)) ]]; then
    echo "  ** TIME_WAIT SATURATION: ${tw_after} sockets (>${TOTAL}/2 port range) **"
  fi
  if [[ "$err" -gt 0 ]]; then
    echo "  ** ${err} FAILURES at batch size ${batch} **"
  fi
  echo ""

  sleep 2
done

echo "[*] Ephemeral port stress test complete"
echo ""
echo "Recommendations:"
echo "  If TIME_WAIT grows unbounded: sysctl net.ipv4.tcp_tw_reuse=1 net.ipv4.tcp_fin_timeout=10"
echo "  If port exhaustion occurs:    sysctl net.ipv4.ip_local_port_range='1024 65535'"
echo "  If FD errors appear:          ulimit -n 524288 and /etc/security/limits.conf"
