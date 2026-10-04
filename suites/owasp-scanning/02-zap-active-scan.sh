#!/bin/bash
set -euo pipefail

########################################################################
# 02-zap-active-scan.sh — OWASP ZAP Active Scan (Full Attack Mode)
#
# Starts ZAP in daemon mode, spiders each application, runs active
# scanning against all discovered URLs, and reports findings by risk.
########################################################################

TARGET="${1:?Usage: $0 <target-host>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

ZAP_PORT=8091
ZAP_API="http://localhost:${ZAP_PORT}"
ZAP_PID=""
REPORT_DIR="${TGEN_RESULTS_DIR:-/tmp}"

APPS=(
  "/juice-shop/"
  "/dvwa/"
  "/vampi/"
  "/httpbin/"
  "/csd-demo/"
)

cleanup() {
  if [[ -n "${ZAP_PID}" ]]; then
    echo "[*] Shutting down ZAP (PID ${ZAP_PID})..."
    curl -s "${ZAP_API}/JSON/core/action/shutdown/" >/dev/null 2>&1 || true
    sleep 2
    kill "${ZAP_PID}" 2>/dev/null || true
    wait "${ZAP_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "========================================"
echo " OWASP ZAP Active Scan (Full Attack)"
echo "========================================"
echo "[*] Target: ${BASE}"
echo ""

########################################################################
# Start ZAP daemon
########################################################################
echo "[*] Starting ZAP daemon on port ${ZAP_PORT}..."
JVM_ARGS="-Xmx512m" zap -silent -daemon -port "${ZAP_PORT}" \
  -config api.disablekey=true \
  -config start.checkForUpdates=false \
  -config start.checkAddonUpdates=false \
  -config callhome.tel.enabled=false \
  -config spider.maxDuration="${TGEN_ZAP_SPIDER_MINUTES:-3}" \
  -config scanner.maxScanDurationInMins="${TGEN_ZAP_SCAN_MINUTES:-5}" &
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
  exit 1
fi

ZAP_VERSION=$(curl -s "${ZAP_API}/JSON/core/view/version/" 2>/dev/null || echo "unknown")
echo "[*] ZAP is ready. Version: ${ZAP_VERSION}"

########################################################################
# Spider each application
########################################################################
echo ""
echo "[*] Phase 1: Spidering all applications..."
for app in "${APPS[@]}"; do
  APP_URL="${BASE}${app}"
  echo ""
  echo "[*] Spidering: ${APP_URL}"

  SCAN_ID=$(curl -s "${ZAP_API}/JSON/spider/action/scan/?url=${APP_URL}&maxChildren=100&recurse=true" |
    python3 -c "import sys,json; print(json.load(sys.stdin)['scan'])" 2>/dev/null)

  # Wait for spider to finish (max 180s)
  for j in $(seq 1 60); do
    STATUS=$(curl -s "${ZAP_API}/JSON/spider/view/status/?scanId=${SCAN_ID}" |
      python3 -c "import sys,json; print(int(json.load(sys.stdin)['status']))" 2>/dev/null)
    if [[ "${STATUS}" -ge 100 ]]; then
      break
    fi
    if ((j % 5 == 0)); then
      echo "    Spider progress: ${STATUS}%"
    fi
    sleep 3
  done
  if [[ "${STATUS}" -lt 100 ]]; then
    echo "[!] Spider incomplete for ${app}" >&2
    exit 1
  fi
  echo "    Spider complete for ${app}"
done

# Also spider the root
echo ""
echo "[*] Spidering: ${BASE}/"
curl -s "${ZAP_API}/JSON/spider/action/scan/?url=${BASE}/&maxChildren=50&recurse=true" >/dev/null 2>&1 || true
sleep 10

########################################################################
# Wait for passive scan queue to drain
########################################################################
echo ""
echo "[*] Waiting for passive scan queue to drain..."
for k in $(seq 1 30); do
  RECORDS=$(curl -s "${ZAP_API}/JSON/pscan/view/recordsToScan/" |
    python3 -c "import sys,json; print(int(json.load(sys.stdin)['recordsToScan']))" 2>/dev/null)
  if [[ "${RECORDS}" -eq 0 ]]; then
    break
  fi
  echo "    Records remaining: ${RECORDS}"
  sleep 3
done

########################################################################
# Active scan each application
########################################################################
echo ""
if [[ "${RECORDS}" -ne 0 ]]; then
  echo "[!] Passive scan incomplete" >&2
  exit 1
fi
echo "[*] Phase 2: Running active scans..."
ACTIVE_SCAN_IDS=()
SCAN_EVIDENCE="${REPORT_DIR}/scanner-phases.jsonl"
: >"${SCAN_EVIDENCE}"
chmod 600 "${SCAN_EVIDENCE}"

for app in "${APPS[@]}"; do
  APP_URL="${BASE}${app}"
  echo ""
  echo "[*] Active scanning: ${APP_URL}"

  ASCAN_ID=$(curl -s "${ZAP_API}/JSON/ascan/action/scan/?url=${APP_URL}&recurse=true&inScopeOnly=false&scanPolicyName=&method=&postData=" |
    python3 -c "import sys,json; print(json.load(sys.stdin)['scan'])" 2>/dev/null)
  ACTIVE_SCAN_IDS+=("${ASCAN_ID}")
  echo "    Active scan ID: ${ASCAN_ID}"
  python3 -c "import json,sys; print(json.dumps({'phase':'active','path':sys.argv[1],'scan_id':sys.argv[2],'started':True}))" "${app}" "${ASCAN_ID}" >>"${SCAN_EVIDENCE}"
done

# Wait for all active scans to complete
echo ""
echo "[*] Waiting for active scans to complete..."
ALL_DONE=0
for attempt in $(seq 1 120); do
  ALL_DONE=1
  for sid in "${ACTIVE_SCAN_IDS[@]}"; do
    STATUS=$(curl -s "${ZAP_API}/JSON/ascan/view/status/?scanId=${sid}" |
      python3 -c "import sys,json; print(int(json.load(sys.stdin)['status']))" 2>/dev/null)
    if [[ "${STATUS}" -lt 100 ]]; then
      ALL_DONE=0
      break
    fi
  done
  if [[ "${ALL_DONE}" -eq 1 ]]; then
    break
  fi
  if ((attempt % 10 == 0)); then
    echo "    Active scan in progress... (${attempt}0s elapsed)"
  fi
  sleep 10
done

if [[ "${ALL_DONE}" -eq 0 ]]; then
  echo "[!] Active scans did not complete within the timeout. Preserving partial results."
  curl -sf "${ZAP_API}/OTHER/core/other/htmlreport/" -o "${REPORT_DIR}/zap-active-partial.html" || true
  exit 1
fi

for sid in "${ACTIVE_SCAN_IDS[@]}"; do
  curl -sf "${ZAP_API}/JSON/ascan/view/messagesIds/?scanId=${sid}" |
    python3 -c "import json,sys; ids=json.load(sys.stdin)['messagesIds']; assert isinstance(ids,list) and ids and all(str(i).isdigit() for i in ids); print(json.dumps({'phase':'active','scan_id':sys.argv[1],'completed':True,'status':100,'message_ids':[str(i) for i in ids]}))" "${sid}" >>"${SCAN_EVIDENCE}"
done
echo "[*] Active scanning complete."

########################################################################
# Retrieve and report alerts
########################################################################
echo ""
echo "========================================"
echo " ZAP Active Scan Findings"
echo "========================================"

ALERTS_JSON=$(curl -s "${ZAP_API}/JSON/core/view/alerts/?start=0&count=1000" 2>/dev/null || echo "{}")

echo "${ALERTS_JSON}" | python3 -c "
import sys, json

try:
    data = json.load(sys.stdin)
    alerts = data.get('alerts', [])
    by_risk = {}
    for a in alerts:
        risk = a.get('risk', 'Informational')
        by_risk.setdefault(risk, []).append(a)

    total = len(alerts)
    print(f'  Total alerts: {total}')
    print()

    for risk in ['High', 'Medium', 'Low', 'Informational']:
        items = by_risk.get(risk, [])
        if items:
            print(f'  [{risk}] ({len(items)} findings)')
            # Deduplicate by alert name
            seen = {}
            for a in items:
                key = a.get('alert', 'Unknown')
                if key not in seen:
                    seen[key] = {
                        'count': 0,
                        'urls': [],
                        'desc': a.get('description', '')[:120]
                    }
                seen[key]['count'] += 1
                if len(seen[key]['urls']) < 3:
                    seen[key]['urls'].append(a.get('url', 'N/A'))

            for name, info in seen.items():
                print(f'    - {name} (x{info[\"count\"]})')
                for u in info['urls']:
                    print(f'      URL: {u}')
            print()

    if not alerts:
        print('  No alerts found.')
except Exception as e:
    print(f'  Error parsing alerts: {e}')
" 2>&1 || true

# Generate HTML report
curl -s "${ZAP_API}/OTHER/core/other/htmlreport/" \
  -o "${REPORT_DIR}/zap-active-scan-report.html" 2>/dev/null || true

echo ""
echo "[*] Report: ${REPORT_DIR}/zap-active-scan-report.html"
echo "[*] ZAP active scan finished."
