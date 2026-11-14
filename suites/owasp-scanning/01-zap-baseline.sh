#!/bin/bash
set -euo pipefail

########################################################################
# 01-zap-baseline.sh — OWASP ZAP Baseline Scan (Passive)
#
# Runs ZAP in daemon mode, spiders the target, performs passive scanning,
# and reports findings. No active attacks are performed.
########################################################################

TARGET="${1:?Usage: $0 <target-host>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

ZAP_PORT=8090
ZAP_API="http://localhost:${ZAP_PORT}"
ZAP_PID=""
REPORT_DIR="${TGEN_RESULTS_DIR:-/tmp}"

APPS=(
  "/"
  "/juice-shop/"
  "/dvwa/"
  "/vampi/"
  "/httpbin/"
  "/csd-demo/"
)

cleanup() {
  if [[ -n "${ZAP_PID}" ]]; then
    echo "[*] Shutting down ZAP (PID ${ZAP_PID})..."
    kill "${ZAP_PID}" 2>/dev/null || true
    wait "${ZAP_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "========================================"
echo " OWASP ZAP Baseline Scan (Passive)"
echo "========================================"
echo "[*] Target: ${BASE}"
echo ""

########################################################################
# Helper function: Run ZAP via daemon + API fallback
########################################################################
run_zap_daemon_mode() {
  echo "[*] Starting ZAP daemon on port ${ZAP_PORT}..."
  JVM_ARGS="-Xmx512m" zap -silent -daemon -port "${ZAP_PORT}" \
    -config api.disablekey=true \
    -config start.checkForUpdates=false \
    -config start.checkAddonUpdates=false \
    -config callhome.tel.enabled=false \
    -config spider.maxDuration=0 \
    -config scanner.maxScanDurationInMins=0 &
  ZAP_PID=$!

  # Wait for ZAP to become ready (up to 90 seconds)
  echo "[*] Waiting for ZAP to start..."
  ZAP_READY=0
  for i in $(seq 1 30); do
    if curl -sf "${ZAP_API}/JSON/core/view/version/" >/dev/null 2>&1; then
      ZAP_READY=1
      break
    fi
    sleep 3
  done

  if [[ "${ZAP_READY}" -eq 0 ]]; then
    echo "[!] ZAP failed to start within 90 seconds. Aborting."
    return 1
  fi

  ZAP_VERSION=$(curl -s "${ZAP_API}/JSON/core/view/version/" 2>/dev/null || echo "unknown")
  echo "[*] ZAP is ready. Version: ${ZAP_VERSION}"

  # Spider each application
  for app in "${APPS[@]}"; do
    APP_URL="${BASE}${app}"
    echo ""
    echo "[*] Spidering: ${APP_URL}"
    SCAN_ID=$(curl -s "${ZAP_API}/JSON/spider/action/scan/?url=${APP_URL}&maxChildren=50&recurse=true" |
      python3 -c "import sys,json; print(json.load(sys.stdin)['scan'])" 2>/dev/null)

    # Wait for spider to finish (max 120s)
    for j in $(seq 1 "${TGEN_ZAP_BASELINE_POLL_COUNT:-40}"); do
      STATUS=$(curl -s "${ZAP_API}/JSON/spider/view/status/?scanId=${SCAN_ID}" |
        python3 -c "import sys,json; print(int(json.load(sys.stdin)['status']))" 2>/dev/null)
      if [[ "${STATUS}" -ge 100 ]]; then
        break
      fi
      echo "    Spider progress: ${STATUS}%"
      sleep 3
    done
    curl -sf "${ZAP_API}/JSON/spider/action/stop/?scanId=${SCAN_ID}" >/dev/null
    if [[ "${STATUS}" -lt 100 ]]; then
      echo "[!] Spider incomplete for ${app}" >&2
      return 1
    fi
    echo "    Spider complete for ${app}"
  done

  # Wait for passive scan to finish
  echo ""
  echo "[*] Waiting for passive scan to complete..."
  for k in $(seq 1 "${TGEN_ZAP_BASELINE_POLL_COUNT:-40}"); do
    RECORDS=$(curl -s "${ZAP_API}/JSON/pscan/view/recordsToScan/" |
      python3 -c "import sys,json; print(int(json.load(sys.stdin)['recordsToScan']))" 2>/dev/null)
    if [[ "${RECORDS}" -eq 0 ]]; then
      break
    fi
    echo "    Records remaining: ${RECORDS}"
    sleep 3
  done
  if [[ "${RECORDS}" -ne 0 ]]; then
    echo "[!] Passive scan incomplete" >&2
    return 1
  fi
  echo "[*] Passive scan complete."

  # Retrieve alerts
  echo ""
  echo "========================================"
  echo " ZAP Baseline Findings"
  echo "========================================"
  ALERTS_JSON=$(curl -s "${ZAP_API}/JSON/core/view/alerts/?start=0&count=500" 2>/dev/null || echo "{}")
  echo "${ALERTS_JSON}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    alerts = data.get('alerts', [])
    by_risk = {}
    for a in alerts:
        risk = a.get('risk', 'Informational')
        by_risk.setdefault(risk, []).append(a)
    for risk in ['High', 'Medium', 'Low', 'Informational']:
        items = by_risk.get(risk, [])
        if items:
            print(f'\n  [{risk}] ({len(items)} findings)')
            seen = set()
            for a in items:
                key = a.get('alert','')
                if key not in seen:
                    seen.add(key)
                    print(f'    - {key}')
                    print(f'      URL: {a.get(\"url\",\"N/A\")}')
    if not alerts:
        print('  No alerts found.')
except Exception as e:
    print(f'  Error parsing alerts: {e}')
" 2>&1 || true

  # Generate HTML report via API
  curl -s "${ZAP_API}/OTHER/core/other/htmlreport/" \
    -o "${REPORT_DIR}/zap-baseline-report.html" 2>/dev/null || true

  echo ""
  echo "[*] Report: ${REPORT_DIR}/zap-baseline-report.html"
  return 0
}

# Continuous mode uses the bounded native daemon path directly.
if [[ -n "${TGEN_INHERITED_BOUNDARY:-}" ]]; then
  run_zap_daemon_mode
  exit $?
fi

########################################################################
# Attempt 1: ZAP quick scan mode
########################################################################
echo "[*] Attempting ZAP quick scan mode..."
if zap -cmd -quickurl "${BASE}" -quickprogress -quickout "${REPORT_DIR}/zap-baseline-report.html" 2>&1; then
  echo "[*] ZAP quick scan completed successfully."
  echo "[*] Report: ${REPORT_DIR}/zap-baseline-report.html"
  exit 0
fi

########################################################################
# Attempt 2: ZAP autorun via stdin YAML
########################################################################
echo ""
echo "[*] Quick scan failed. Attempting ZAP autorun mode..."

# Create autorun YAML file
AUTORUN_YAML="${REPORT_DIR}/zap-autorun.yaml"
cat >"${AUTORUN_YAML}" <<ZAPCFG
env:
  contexts:
  - name: "origin-server"
    urls:
    - "${BASE}"
    - "${BASE}/juice-shop/"
    - "${BASE}/dvwa/"
    - "${BASE}/vampi/"
    - "${BASE}/httpbin/"
    - "${BASE}/csd-demo/"
  parameters:
    failOnError: false
    progressToStdout: true
jobs:
  - type: spider
    parameters:
      maxDuration: 2
      url: "${BASE}"
  - type: passiveScan-wait
    parameters:
      maxDuration: 2
  - type: report
    parameters:
      template: "traditional-html"
      reportDir: "/tmp"
      reportFile: "zap-baseline"
ZAPCFG

if zap -cmd -autorun "${AUTORUN_YAML}" 2>&1; then
  echo "[*] ZAP autorun completed successfully."
  echo "[*] Report: ${REPORT_DIR}/zap-baseline-report.html"
  rm -f "${AUTORUN_YAML}"
  exit 0
fi

rm -f "${AUTORUN_YAML}"

########################################################################
# Attempt 3: Fall back to daemon + API mode
########################################################################
echo ""
echo "[!] ZAP autorun failed, falling back to daemon + API mode..."
run_zap_daemon_mode
