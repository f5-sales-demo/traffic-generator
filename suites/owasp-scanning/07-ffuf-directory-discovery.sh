#!/bin/bash
set -uo pipefail

########################################################################
# 07-ffuf-directory-discovery.sh — Comprehensive Directory/File Fuzzing
#
# Runs ffuf against each application with multiple wordlists for
# directory discovery, API endpoint enumeration, and backup file detection.
########################################################################

TARGET="${1:?Usage: $0 <target-host>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "========================================"
echo " FFUF Directory Discovery"
echo "========================================"
echo "[*] Target: ${BASE}"
echo ""

FFUF_COMMON="-mc 200,301,302,401,403 -t 40 -timeout 10 -ac"
SECLISTS="/opt/seclists"
TOTAL_FOUND=0

########################################################################
# Helper: Run ffuf and count results
########################################################################
run_ffuf() {
  local label="$1"
  shift
  echo "----------------------------------------"
  echo "[*] ${label}"
  echo "    Command: ffuf $*"
  echo "----------------------------------------"

  local output
  if [[ -n "${TGEN_DISCOVERY_WORDLIST:-}" ]]; then
    output=$(ffuf "$@" -w "$TGEN_DISCOVERY_WORDLIST" -t 2 2>&1)
  else
    output=$(ffuf "$@" 2>&1)
  fi || true
  echo "${output}"

  # Count result lines (lines with Status: in ffuf output)
  local count
  count=$(echo "${output}" | grep -cE "Status: [0-9]+" 2>/dev/null || echo "0")
  TOTAL_FOUND=$((TOTAL_FOUND + count))

  echo ""
  echo "    Discovered: ${count} endpoints"
  echo ""
}

########################################################################
# Phase 1: Root directory discovery
########################################################################
echo "[*] Phase 1: Root Directory Discovery"
echo "========================================"

if [[ -f "${SECLISTS}/Discovery/Web-Content/common.txt" ]]; then
  run_ffuf "Root — Common directories" \
    -u "${BASE}/FUZZ" \
    -w "${SECLISTS}/Discovery/Web-Content/common.txt" \
    ${FFUF_COMMON}
else
  echo "[!] Wordlist not found: ${SECLISTS}/Discovery/Web-Content/common.txt"
  echo "    Trying alternative locations..."
  COMMON_WL=$(find /usr/share /opt -name "common.txt" -path "*/Web-Content/*" 2>/dev/null | head -1)
  if [[ -n "${COMMON_WL}" ]]; then
    run_ffuf "Root — Common directories" \
      -u "${BASE}/FUZZ" -w "${COMMON_WL}" ${FFUF_COMMON}
  fi
fi

########################################################################
# Phase 2: Juice Shop deep directory scan
########################################################################
echo "[*] Phase 2: Juice Shop Directory Scan"
echo "========================================"

if [[ -f "${SECLISTS}/Discovery/Web-Content/raft-medium-directories.txt" ]]; then
  run_ffuf "Juice Shop — Raft medium directories" \
    -u "${BASE}/juice-shop/FUZZ" \
    -w "${SECLISTS}/Discovery/Web-Content/raft-medium-directories.txt" \
    -mc 200,301,302 -t 50 -timeout 10 -ac
else
  echo "[!] raft-medium-directories.txt not found, using common.txt fallback"
  COMMON_WL="${SECLISTS}/Discovery/Web-Content/common.txt"
  if [[ -f "${COMMON_WL}" ]]; then
    run_ffuf "Juice Shop — Common directories" \
      -u "${BASE}/juice-shop/FUZZ" -w "${COMMON_WL}" ${FFUF_COMMON}
  fi
fi

########################################################################
# Phase 3: DVWA directory scan
########################################################################
echo "[*] Phase 3: DVWA Directory Scan"
echo "========================================"

if [[ -f "${SECLISTS}/Discovery/Web-Content/common.txt" ]]; then
  run_ffuf "DVWA — Common directories" \
    -u "${BASE}/dvwa/FUZZ" \
    -w "${SECLISTS}/Discovery/Web-Content/common.txt" \
    ${FFUF_COMMON}
fi

########################################################################
# Phase 4: VAmPI API endpoint discovery
########################################################################
echo "[*] Phase 4: VAmPI API Endpoint Discovery"
echo "========================================"

if [[ -f "${SECLISTS}/Discovery/Web-Content/api/objects.txt" ]]; then
  run_ffuf "VAmPI — API objects" \
    -u "${BASE}/vampi/FUZZ" \
    -w "${SECLISTS}/Discovery/Web-Content/api/objects.txt" \
    -mc 200,301,302 -t 40 -timeout 10 -ac
else
  echo "[!] API objects wordlist not found."
  # Try alternative API wordlists
  API_WL=$(find /usr/share /opt -name "*.txt" -path "*/api/*" 2>/dev/null | head -1)
  if [[ -n "${API_WL}" ]]; then
    run_ffuf "VAmPI — API endpoints" \
      -u "${BASE}/vampi/FUZZ" -w "${API_WL}" ${FFUF_COMMON}
  fi
fi

########################################################################
# Phase 5: Backup file fuzzing
########################################################################
echo "[*] Phase 5: Backup File Detection"
echo "========================================"

if [[ -f "${SECLISTS}/Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt" ]]; then
  run_ffuf "Root — PHP backdoors/backups" \
    -u "${BASE}/FUZZ" \
    -w "${SECLISTS}/Discovery/Web-Content/CommonBackdoors-PHP.fuzz.txt" \
    ${FFUF_COMMON}
else
  echo "[!] CommonBackdoors-PHP.fuzz.txt not found."
fi

# Also check for common backup extensions
echo "[*] Checking common backup patterns..."
for ext in ".bak" ".old" ".orig" ".save" ".swp" ".tmp" "~"; do
  for path in "index.html${ext}" "index.php${ext}" "web.config${ext}" ".htaccess${ext}" "config.php${ext}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/${path}" 2>/dev/null || echo "000")
    if [[ "${CODE}" != "404" && "${CODE}" != "000" ]]; then
      echo "    [${CODE}] ${BASE}/${path}"
      TOTAL_FOUND=$((TOTAL_FOUND + 1))
    fi
  done
done

########################################################################
# Summary
########################################################################
echo ""
echo "========================================"
echo " FFUF Discovery Summary"
echo "========================================"
echo "  Total endpoints discovered: ${TOTAL_FOUND}"
echo ""
echo "[*] FFUF directory discovery finished."
