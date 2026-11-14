#!/bin/bash
# Nuclei vulnerability scanner
# Tools: nuclei
# Targets: Medium, high, and critical severity templates
# Estimated duration: 3-5 minutes
set -euo pipefail

TARGET="${1:?Usage: 06-nuclei-scan.sh <TARGET_FQDN>}"

echo "[*] Nuclei scan against ${TARGET}"
echo ""

# Record the declared technology phase with the pinned native template before severity filtering.
nuclei -duc -ni -config "${TGEN_NUCLEI_CONFIG:-$(dirname "$0")/../nuclei-config.yaml}" \
  -t /opt/nuclei-templates/http/technologies/tech-detect.yaml \
  -u "${TARGET_PROTOCOL:-http}://${TARGET}" -timeout 10 -rl 20 -silent

nuclei -duc -ni -config "${TGEN_NUCLEI_CONFIG:-$(dirname "$0")/../nuclei-config.yaml}" -t "${TGEN_NUCLEI_TEMPLATES:-/opt/nuclei-templates/http}" -u "${TARGET_PROTOCOL:-http}://${TARGET}" \
  -severity medium,high,critical \
  -timeout 5 \
  -rate-limit 50 \
  -silent ||
  echo "WARN: nuclei exited with non-zero status"

echo ""
echo "[*] Nuclei scan complete"
