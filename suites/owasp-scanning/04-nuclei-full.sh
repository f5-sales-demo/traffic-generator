#!/bin/bash
set -uo pipefail

########################################################################
# 04-nuclei-full.sh — Nuclei Template Scan (All Severities)
#
# Runs Nuclei with comprehensive template categories against all
# application endpoints.
########################################################################

TARGET="${1:?Usage: $0 <target-host>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "========================================"
echo " Nuclei Full Template Scan"
echo "========================================"
echo "[*] Target: ${BASE}"
echo ""

NUCLEI_OPTS="-timeout 10 -rate-limit 100 -stats -silent"

TARGETS=(
  "${BASE}"
  "${BASE}/juice-shop/"
  "${BASE}/dvwa/"
  "${BASE}/vampi/"
)

if [[ -n "${TGEN_NUCLEI_TEMPLATES:-}" ]]; then
  echo "[CATALOG] Bounded native template scope: $TGEN_NUCLEI_TEMPLATES"
  for url in "${TARGETS[@]}"; do
    nuclei -duc -t "$TGEN_NUCLEI_TEMPLATES" -u "$url" -rl 20 -c 2 -bs 1 -timeout 10 -silent
  done
  exit 0
fi

########################################################################
# Phase 1: Full severity scan against all targets
########################################################################
echo "[*] Phase 1: Full severity scan across all targets"
echo "----------------------------------------"

for url in "${TARGETS[@]}"; do
  echo ""
  echo "[*] Scanning: ${url}"
  nuclei -duc -t "${TGEN_NUCLEI_TEMPLATES:-/opt/nuclei-templates/http}" -u "${url}" -severity info,low,medium,high,critical \
    ${NUCLEI_OPTS} 2>&1 || true
done

########################################################################
# Phase 2: Known CVEs
########################################################################
echo ""
echo "[*] Phase 2: Known CVE templates"
echo "----------------------------------------"

for url in "${TARGETS[@]}"; do
  echo ""
  echo "[*] CVE scan: ${url}"
  nuclei -duc -t "${TGEN_NUCLEI_TEMPLATES:-/opt/nuclei-templates/http}" -u "${url}" -tags cve \
    ${NUCLEI_OPTS} 2>&1 || true
done

########################################################################
# Phase 3: OWASP-category templates
########################################################################
echo ""
echo "[*] Phase 3: OWASP category templates"
echo "----------------------------------------"

for url in "${TARGETS[@]}"; do
  echo ""
  echo "[*] OWASP scan: ${url}"
  nuclei -duc -t "${TGEN_NUCLEI_TEMPLATES:-/opt/nuclei-templates/http}" -u "${url}" -tags owasp \
    ${NUCLEI_OPTS} 2>&1 || true
done

########################################################################
# Phase 4: Injection-type templates
########################################################################
echo ""
echo "[*] Phase 4: Injection templates (sqli, xss, ssrf, lfi)"
echo "----------------------------------------"

for url in "${TARGETS[@]}"; do
  echo ""
  echo "[*] Injection scan: ${url}"
  nuclei -duc -t "${TGEN_NUCLEI_TEMPLATES:-/opt/nuclei-templates/http}" -u "${url}" -tags sqli,xss,ssrf,lfi \
    ${NUCLEI_OPTS} 2>&1 || true
done

########################################################################
# Phase 5: Exposure and misconfiguration
########################################################################
echo ""
echo "[*] Phase 5: Exposure and misconfiguration templates"
echo "----------------------------------------"

for url in "${TARGETS[@]}"; do
  echo ""
  echo "[*] Exposure/misconfig scan: ${url}"
  nuclei -duc -t "${TGEN_NUCLEI_TEMPLATES:-/opt/nuclei-templates/http}" -u "${url}" -tags exposure,misconfig \
    ${NUCLEI_OPTS} 2>&1 || true
done

########################################################################
# Summary
########################################################################
echo ""
echo "========================================"
echo " Nuclei Scan Complete"
echo "========================================"
echo "[*] All template categories have been executed."
echo "[*] Review output above for findings by severity."
echo "[*] Nuclei full scan finished."
