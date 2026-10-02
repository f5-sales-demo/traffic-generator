#!/bin/bash
set -uo pipefail

########################################################################
# 03-nikto-full.sh — Comprehensive Nikto Scan
#
# Runs Nikto against each application path with extended timeouts,
# plus a root scan with all CGI checks enabled.
########################################################################

TARGET="${1:?Usage: $0 <target-host>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "========================================"
echo " Nikto Full Scan"
echo "========================================"
echo "[*] Target: ${BASE}"
echo ""

TOTAL_FINDINGS=0

run_nikto() {
  local url="$1"
  local label="$2"
  local extra_args="${3:-}"

  echo "----------------------------------------"
  echo "[*] Scanning: ${label}"
  echo "    URL: ${url}"
  echo "----------------------------------------"

  local output
  output=$(nikto -h "${url}" -maxtime "${TGEN_SCANNER_SECONDS:-180}s" ${extra_args} -nointeractive 2>&1) || true
  echo "${output}"

  # Count findings (lines containing "+ " that are not informational headers)
  local count
  count=$(echo "${output}" | grep -c "^+ " 2>/dev/null || echo "0")
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + count))

  echo ""
  echo "    Findings for ${label}: ${count}"
  echo ""
}

# Scan each application
run_nikto "${BASE}/juice-shop/" "Juice Shop"
run_nikto "${BASE}/dvwa/" "DVWA"
run_nikto "${BASE}/vampi/" "VAmPI"
run_nikto "${BASE}/httpbin/" "HTTPBin"
run_nikto "${BASE}/csd-demo/" "CSD Demo"

# Root scan with all CGI checks
echo "----------------------------------------"
echo "[*] Scanning: Root (all CGI checks)"
echo "    URL: ${BASE}/"
echo "----------------------------------------"

OUTPUT=$(nikto -h "${BASE}/" -maxtime "${TGEN_SCANNER_SECONDS:-120}s" -C all -nointeractive 2>&1) || true
echo "${OUTPUT}"
ROOT_COUNT=$(echo "${OUTPUT}" | grep -c "^+ " 2>/dev/null || echo "0")
TOTAL_FINDINGS=$((TOTAL_FINDINGS + ROOT_COUNT))

echo ""
echo "    Findings for Root: ${ROOT_COUNT}"

########################################################################
# Summary
########################################################################
echo ""
echo "========================================"
echo " Nikto Scan Summary"
echo "========================================"
echo "  Total findings across all scans: ${TOTAL_FINDINGS}"
echo ""
echo "[*] Nikto full scan finished."
