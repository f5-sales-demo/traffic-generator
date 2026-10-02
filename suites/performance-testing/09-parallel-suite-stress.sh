#!/bin/bash
# Parallel suite stress test — runs multiple attack suites simultaneously
# Measures resource contention when N suites fight for CPU/RAM/network
# This is the ultimate capacity test for the traffic generator platform
# Estimated duration: 3-5 minutes
set -uo pipefail

TARGET="${1:?Usage: 09-parallel-suite-stress.sh <TARGET_FQDN>}"
export TARGET_FQDN="$TARGET"
export TARGET_PROTOCOL="${TARGET_PROTOCOL:-http}"

SUITES_DIR="$(cd "$(dirname "$0")/.." && pwd)"

PARALLEL_SUITES=(
  "web-app-attacks"
  "api-attacks"

)

echo "[*] Parallel suite stress test against ${TARGET}"
echo "    Suites: ${PARALLEL_SUITES[*]}"
echo "    Running all ${#PARALLEL_SUITES[@]} suites simultaneously"
echo ""

echo "=== PRE-STRESS BASELINE ==="
echo "CPU: $(uptime | awk -F'load average:' '{print $2}')"
free -m | awk '/^Mem:/ {printf "RAM: %dMB / %dMB (%.0f%% used)\n", $3, $2, $3/$2*100}'
echo ""

PIDS=()
LOGS=()
start_ns=$(date +%s%N)

for suite in "${PARALLEL_SUITES[@]}"; do
  log="/tmp/parallel-stress-${suite}-$$.log"
  LOGS+=("$log")
  echo "[+] Launching: ${suite}"
  if [[ -n "${TGEN_INHERITED_BOUNDARY:-}" ]]; then
    TGEN_RESULTS_DIR="$TGEN_RESULTS_DIR/nested-$suite" bash "$SUITES_DIR/runner.sh" "$suite" >"$log" 2>&1 &
  else
    bash "$SUITES_DIR/runner.sh" "$suite" >"$log" 2>&1 &
  fi
  PIDS+=($!)
done

echo ""
echo "=== MONITORING RESOURCE USAGE ==="
printf "%6s %8s %8s %6s %6s\n" "Time" "CPU-load" "RAM-MB" "ESTAB" "T-WAIT"
echo "------ -------- -------- ------ ------"

elapsed=0
while true; do
  alive=0
  for pid in "${PIDS[@]}"; do
    kill -0 "$pid" 2>/dev/null && alive=$((alive + 1))
  done
  [[ $alive -eq 0 ]] && break

  cpu=$(uptime | awk -F'load average:' '{print $2}' | awk -F, '{gsub(/^ /,"",$1); print $1}')
  ram=$(free -m | awk '/^Mem:/ {print $3}')
  estab=$(ss -tan state established 2>/dev/null | wc -l)
  tw=$(ss -tan state time-wait 2>/dev/null | wc -l)

  printf "%5ds %8s %8s %6d %6d\n" "$elapsed" "$cpu" "$ram" "$estab" "$tw"

  sleep 10
  elapsed=$((elapsed + 10))
done

end_ns=$(date +%s%N)
wall_secs=$(((end_ns - start_ns) / 1000000000))

echo ""
echo "=== POST-STRESS STATE ==="
echo "CPU: $(uptime | awk -F'load average:' '{print $2}')"
free -m | awk '/^Mem:/ {printf "RAM: %dMB / %dMB (%.0f%% used)\n", $3, $2, $3/$2*100}'
echo ""

echo "=== SUITE RESULTS ==="
failed=0
for i in "${!PARALLEL_SUITES[@]}"; do
  suite="${PARALLEL_SUITES[$i]}"
  log="${LOGS[$i]}"
  pid="${PIDS[$i]}"
  wait "$pid" 2>/dev/null
  exit_code=$?
  [[ "$exit_code" -eq 0 ]] || failed=1

  summary=$(grep -E '(Passed|Failed|Skipped|Suite Complete)' "$log" 2>/dev/null | tail -2)
  printf "  %-25s exit=%d %s\n" "$suite" "$exit_code" "$summary"
  rm -f "$log"
done

echo ""
echo "  Total wall time: ${wall_secs}s for ${#PARALLEL_SUITES[@]} parallel suites"

echo ""
echo "[*] Parallel suite stress test complete"
exit "$failed"
