#!/bin/bash
# wrk HTTP benchmark — C-based, thread-pool model, capable of 100K+ req/s
# Tools: wrk
# Measures: true throughput ceiling, latency distribution, transfer rate
# Estimated duration: 3 minutes
set -uo pipefail

TARGET="${1:?Usage: 10-wrk-benchmark.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

if ! command -v wrk &>/dev/null; then
  echo "FAIL: wrk not installed. Install with: apt-get install wrk"
  exit 1
fi

DURATION="${TGEN_DURATION:-30}"
THREADS=$(nproc)
CONNECTIONS_LIST=(1 10 "${TGEN_CONCURRENCY:-20}")

ENDPOINTS=(
  "/health"
  "/juice-shop/"
  "/vampi/users/v1"
  "/httpbin/get"
  "/whoami/"
  "/csd-demo/health"
)

echo "[*] wrk HTTP benchmark against ${TARGET}"
echo "    Threads: ${THREADS} (1 per CPU core)"
echo "    Duration per test: ${DURATION}s"
echo ""

for endpoint in "${ENDPOINTS[@]}"; do
  url="${BASE}${endpoint}"
  echo "=== Endpoint: ${endpoint} ==="
  printf "  %-8s %10s %10s %10s %10s %10s\n" "Conns" "Req/s" "Avg" "P99" "Errors" "Transfer"
  echo "  -------- ---------- ---------- ---------- ---------- ----------"

  for conns in "${CONNECTIONS_LIST[@]}"; do
    if [[ $conns -lt $THREADS ]]; then t=$conns; else t=$THREADS; fi

    output=$(wrk -t"$t" -c"$conns" -d"${DURATION}s" --latency "$url" 2>&1)

    rps=$(echo "$output" | grep 'Requests/sec' | awk '{print $2}')
    avg_lat=$(echo "$output" | grep '    Avg' | head -1 | awk '{print $2}')
    p99_lat=$(echo "$output" | grep '99%' | awk '{print $2}')
    errors=$(echo "$output" | grep -E '(Socket errors|Non-2xx)' | head -2 | tr '\n' ' ')
    transfer=$(echo "$output" | grep 'Transfer/sec' | awk '{print $2}')

    err_flag=""
    if [[ -n "$errors" ]] && echo "$errors" | grep -qvE '^$'; then
      err_flag="*"
    fi

    printf "  %-8s %10s %10s %10s %10s %10s%s\n" \
      "$conns" "${rps:-N/A}" "${avg_lat:-N/A}" "${p99_lat:-N/A}" \
      "$(echo "$errors" | awk '{gsub(/Socket errors:/, ""); gsub(/,/, ""); print}' | xargs | head -c30)" \
      "${transfer:-N/A}" "$err_flag"
  done
  echo ""
done

echo "[*] wrk benchmark complete"
echo ""
echo "Interpretation:"
echo "  - Req/s plateau = origin server or network ceiling"
echo "  - P99 spike at high connections = connection queuing"
echo "  - Socket errors = kernel tuning needed (somaxconn, port range)"
echo "  - Transfer/sec = bandwidth utilization"
