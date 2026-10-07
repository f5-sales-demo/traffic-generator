#!/usr/bin/env bash
# Explicit headed HTTPS fixture; not part of unit discovery unless configured.
# Synthetic sensor/collector only: never live CSD acceptance or security bypass.
set -euo pipefail
umask 077
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ "$(uname -s)" == Linux && "$(id -u)" != 0 ]] || {
  printf '%s\n' 'BLOCKED: nonprivileged Linux host required'
  exit 1
}
for binary in node openssl certutil Xvfb timeout; do
  command -v "$binary" >/dev/null || {
    printf 'BLOCKED: missing %s\n' "$binary"
    exit 1
  }
done
CHROME="${CSD_TEST_CHROME_PATH:-/usr/bin/google-chrome}"
[[ -x "$CHROME" ]] || {
  printf '%s\n' 'BLOCKED: existing Chrome executable required'
  exit 1
}
[[ -n "${CSD_TEST_PLAYWRIGHT_MODULE:-}" && -r "$CSD_TEST_PLAYWRIGHT_MODULE" ]] || {
  printf '%s\n' 'BLOCKED: set CSD_TEST_PLAYWRIGHT_MODULE to existing Playwright index.mjs'
  exit 1
}
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/csd-header-fixture.XXXXXXXX")"
XVFB_PID=''
cleanup() {
  local result=$?
  if [[ -n "$XVFB_PID" ]]; then
    kill "$XVFB_PID" 2>/dev/null || true
    wait "$XVFB_PID" 2>/dev/null || true
  fi
  if [[ "$result" == 0 && "${CSD_HEADER_KEEP_FIXTURE:-0}" != 1 ]]; then
    rm -rf -- "$ROOT"
  else
    printf 'Private fixture artifacts: %s (fixture only; no live acceptance)\n' "$ROOT"
  fi
}
trap cleanup EXIT
mkdir -p "$ROOT/.pki/nssdb" "$ROOT/.local/share/pki/nssdb"
# Actual certificate trust in this disposable HOME, not ignoreHTTPS errors or
# SPKI allowlisting. Resolver mappings affect only the owned browser instance.
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -keyout "$ROOT/key.pem" -out "$ROOT/cert.pem" -subj '/CN=Synthetic CSD transport fixture' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'subjectAltName=DNS:client-side-defense.f5-sales-demo.com,DNS:us.gimp.zeronaught.com,DNS:csd.zeronaught.com' \
  >"$ROOT/tls.log" 2>&1
for database in "$ROOT/.pki/nssdb" "$ROOT/.local/share/pki/nssdb"; do
  certutil -N -d "sql:$database" --empty-password >>"$ROOT/tls.log" 2>&1
  certutil -A -d "sql:$database" -n csd-synthetic-fixture -t 'C,,' -i "$ROOT/cert.pem" >>"$ROOT/tls.log" 2>&1
done
Xvfb -displayfd 3 -screen 0 1280x1024x24 -nolisten tcp 3>"$ROOT/display" >"$ROOT/xvfb.log" 2>&1 &
XVFB_PID=$!
for ((attempt = 0; attempt < 100; attempt++)); do
  [[ -s "$ROOT/display" ]] && break
  kill -0 "$XVFB_PID" || {
    printf '%s\n' 'BLOCKED: Xvfb failed; private log retained'
    exit 1
  }
  sleep 0.05
done
[[ -s "$ROOT/display" ]] || {
  printf '%s\n' 'BLOCKED: Xvfb did not become ready'
  exit 1
}
IFS= read -r DISPLAY_NUMBER <"$ROOT/display"
export DISPLAY=":$DISPLAY_NUMBER" CSD_HEADER_FIXTURE_DIR="$ROOT" CSD_TEST_CHROME_PATH="$CHROME"
# No AppArmor/sandbox policy changes, sudo, vendor JS, cloud commands or targets.
if timeout --signal=TERM --kill-after=15s 240s node "$REPO_DIR/tests/csd-header-circulation.integration.mjs" >"$ROOT/browser.log" 2>&1; then
  printf '%s\n' 'PASS: headed trusted HTTPS fixture, three pairs and failure cleanup; NOT CSD acceptance'
else
  printf '%s\n' 'FAILED/BLOCKED: headed fixture gate; diagnostics private in browser.log'
  exit 1
fi
