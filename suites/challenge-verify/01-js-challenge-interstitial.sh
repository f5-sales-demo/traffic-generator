#!/bin/bash
# JS-challenge interstitial check — when an F5 XC LB has an all-traffic JavaScript challenge
# active (challenge_type js_challenge, or policy_based_challenge always_enable_js_challenge),
# every client without a solved challenge cookie receives an interstitial HTML page carrying a
# JavaScript proof-of-work (an XC `function SHA1(...)` routine) instead of the origin response.
# This drives the target and asserts that signature — the behavioral proof for the webapp
# challenge coverage (CH-4). Pairs with webapp scripts/challenge-verify.sh.
# Tools: curl
# Targets: www.<domain> (any path; the challenge is served for all traffic)
# Estimated duration: <1 minute
# Marker: User-Agent "challenge-verify".
set -euo pipefail

TARGET="${1:?Usage: 01-js-challenge-interstitial.sh <TARGET_FQDN>}"
BASE="${TARGET_PROTOCOL:-http}://${TARGET}"
UA="challenge-verify"

echo "[*] JS-challenge interstitial check against ${BASE}/"
body=$(mktemp)
code=$(curl -s --max-time 15 -o "$body" -w '%{http_code}' -A "$UA" "${BASE}/")
bytes=$(wc -c <"$body")
echo "  GET / -> HTTP ${code}, ${bytes} bytes"

if grep -qi 'function SHA1' "$body" && grep -qi 'challenge' "$body"; then
  echo "  [PASS] JS-challenge interstitial served (SHA1 proof-of-work + challenge markers)"
  rm -f "$body"
  exit 0
fi

echo "  [FAIL] no JS-challenge interstitial (got the origin response or an unchallenged page)."
echo "         Ensure an all-traffic JS challenge is active on the LB before running this suite."
rm -f "$body"
exit 1
