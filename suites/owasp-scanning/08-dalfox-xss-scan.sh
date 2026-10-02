#!/bin/bash
set -uo pipefail

########################################################################
# 08-dalfox-xss-scan.sh — Automated XSS Discovery with DalFox
#
# Runs DalFox against forms and parameters across all applications
# to discover reflected and stored XSS vectors.
########################################################################

TARGET="${1:?Usage: $0 <target-host>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "========================================"
echo " DalFox XSS Scan"
echo "========================================"
echo "[*] Target: ${BASE}"
echo ""

OUTPUT_DIR="${TGEN_RESULTS_DIR:-/tmp/dalfox}"
mkdir -p "${OUTPUT_DIR}"
TOTAL_XSS=0

########################################################################
# Helper: Run dalfox and count results
########################################################################
run_dalfox() {
  local label="$1"
  local url="$2"
  local output_file="$3"
  shift 3
  local extra_args=("$@")

  echo "----------------------------------------"
  echo "[*] ${label}"
  echo "    URL: ${url}"
  echo "----------------------------------------"

  local output
  output=$(dalfox url "${url}" --silence --output "${output_file}" "${extra_args[@]}" 2>&1) || true
  echo "${output}"

  # Count XSS findings from output file
  local count=0
  if [[ -f "${output_file}" ]]; then
    count=$(wc -l <"${output_file}" 2>/dev/null || echo "0")
    count=$((count + 0)) # ensure numeric
    if [[ "${count}" -gt 0 ]]; then
      echo ""
      echo "    XSS vectors found: ${count}"
      echo "    Details:"
      head -20 "${output_file}" | while IFS= read -r line; do
        echo "      ${line}"
      done
      if [[ "${count}" -gt 20 ]]; then
        echo "      ... (${count} total, see ${output_file})"
      fi
    fi
  fi

  TOTAL_XSS=$((TOTAL_XSS + count))
  echo ""
}

########################################################################
# Phase 1: Juice Shop
########################################################################
echo "[*] Phase 1: Juice Shop XSS Scan"
echo "========================================"

run_dalfox "Juice Shop — Product Search" \
  "${BASE}/juice-shop/rest/products/search?q=test" \
  "${OUTPUT_DIR}/dalfox-juice-search.txt"

run_dalfox "Juice Shop — Track Order" \
  "${BASE}/juice-shop/#/track-result?id=test" \
  "${OUTPUT_DIR}/dalfox-juice-track.txt"

########################################################################
# Phase 2: DVWA (requires authentication)
########################################################################
echo "[*] Phase 2: DVWA XSS Scan"
echo "========================================"

# Attempt to get DVWA session cookie
echo "[*] Authenticating to DVWA..."
PHPSESSID=$(curl -s -I "${BASE}/dvwa/login.php" 2>/dev/null |
  grep -ioP 'PHPSESSID=\K[^;]+' || echo "")

if [[ -n "${PHPSESSID}" ]]; then
  # Try login
  curl -s -b "PHPSESSID=${PHPSESSID}" \
    -d "username=admin&password=password&Login=Login" \
    -L "${BASE}/dvwa/login.php" >/dev/null 2>&1 || true
  # Set security to low
  curl -s -b "PHPSESSID=${PHPSESSID};security=low" \
    "${BASE}/dvwa/security.php" >/dev/null 2>&1 || true
  DVWA_COOKIE="PHPSESSID=${PHPSESSID};security=low"
else
  DVWA_COOKIE="security=low"
fi

echo "[*] Using cookie: ${DVWA_COOKIE}"

run_dalfox "DVWA — Reflected XSS" \
  "${BASE}/dvwa/vulnerabilities/xss_r/?name=test" \
  "${OUTPUT_DIR}/dalfox-dvwa-xss-r.txt" \
  --cookie "${DVWA_COOKIE}"

run_dalfox "DVWA — Stored XSS (name param)" \
  "${BASE}/dvwa/vulnerabilities/xss_s/?txtName=test&mtxMessage=test&btnSign=Sign+Guestbook" \
  "${OUTPUT_DIR}/dalfox-dvwa-xss-s.txt" \
  --cookie "${DVWA_COOKIE}"

run_dalfox "DVWA — SQL Injection (testing for XSS)" \
  "${BASE}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  "${OUTPUT_DIR}/dalfox-dvwa-sqli.txt" \
  --cookie "${DVWA_COOKIE}"

run_dalfox "DVWA — DOM XSS" \
  "${BASE}/dvwa/vulnerabilities/xss_d/?default=English" \
  "${OUTPUT_DIR}/dalfox-dvwa-xss-d.txt" \
  --cookie "${DVWA_COOKIE}"

########################################################################
# Phase 3: HTTPBin (reflection testing)
########################################################################
echo "[*] Phase 3: HTTPBin Reflection Testing"
echo "========================================"

run_dalfox "HTTPBin — Headers endpoint" \
  "${BASE}/httpbin/get?test=xss" \
  "${OUTPUT_DIR}/dalfox-httpbin.txt"

########################################################################
# Phase 4: Root and CSD Demo
########################################################################
echo "[*] Phase 4: Additional Endpoints"
echo "========================================"

run_dalfox "CSD Demo — Root" \
  "${BASE}/csd-demo/?q=test" \
  "${OUTPUT_DIR}/dalfox-csd-demo.txt"

########################################################################
# Summary
########################################################################
echo ""
echo "========================================"
echo " DalFox XSS Scan Summary"
echo "========================================"
echo "  Total XSS vectors found: ${TOTAL_XSS}"
echo "  Output directory: ${OUTPUT_DIR}/"
echo ""
echo "  Output files:"
for f in "${OUTPUT_DIR}"/dalfox-*.txt; do
  if [[ -f "${f}" ]]; then
    count=$(wc -l <"${f}" 2>/dev/null || echo "0")
    echo "    ${f} (${count} findings)"
  fi
done
echo ""
echo "[*] DalFox XSS scan finished."
