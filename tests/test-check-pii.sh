#!/usr/bin/env bash
# Hermetic contract tests for the managed PII scanner. The fixtures are created
# in throwaway Git repositories so the test never depends on this checkout and
# never sends fixture values to an external service.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCANNER="${REPO_ROOT}/scripts/check-pii.sh"
PYTHON_SCANNER="${REPO_ROOT}/scripts/check_pii.py"
SYNTHETIC_USER=realperson

FAIL=0
WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

if [ -x "$PYTHON_SCANNER" ]; then
  echo "[FAIL] Python scanner is executable — invoke it through the shell wrapper"
  FAIL=1
else
  echo "[OK] Python scanner is a non-executable module"
fi

if head -n 1 "$PYTHON_SCANNER" | grep -q '^#!'; then
  echo "[FAIL] Python scanner has a shebang — invoke it through the shell wrapper"
  FAIL=1
else
  echo "[OK] Python scanner has no executable shebang"
fi

new_repo() {
  local dir="${WORK}/$1"
  mkdir -p "$dir"
  git -C "$dir" init -q -b main
  git -C "$dir" config user.email test@example.com
  git -C "$dir" config user.name "PII Scanner Test"
  printf '# Example\n' >"${dir}/README.md"
  git -C "$dir" add -A
  git -C "$dir" commit -qm baseline
  echo "$dir"
}

run_scan() {
  local dir="$1"
  shift
  local rc=0
  (cd "$dir" && bash "$SCANNER" "$@") >"${WORK}/stdout" 2>"${WORK}/stderr" || rc=$?
  printf '%s' "$rc"
}

assert_clean() {
  local label="$1" dir="$2"
  shift 2
  local rc
  rc=$(run_scan "$dir" "$@")
  if [ "$rc" -eq 0 ]; then
    echo "[OK] $label -> clean"
  else
    echo "[FAIL] $label — expected clean (0), got $rc"
    sed 's/^/  /' "${WORK}/stdout" "${WORK}/stderr"
    FAIL=1
  fi
}

assert_violation() {
  local label="$1" dir="$2"
  shift 2
  local rc
  rc=$(run_scan "$dir" "$@")
  if [ "$rc" -eq 1 ]; then
    echo "[OK] $label -> rejected"
  else
    echo "[FAIL] $label — expected finding (1), got $rc"
    sed 's/^/  /' "${WORK}/stdout" "${WORK}/stderr"
    FAIL=1
  fi
}

assert_error() {
  local label="$1" dir="$2"
  shift 2
  local rc
  rc=$(run_scan "$dir" "$@")
  if [ "$rc" -eq 2 ]; then
    echo "[OK] $label -> usage/environment error"
  else
    echo "[FAIL] $label — expected scanner error (2), got $rc"
    sed 's/^/  /' "${WORK}/stdout" "${WORK}/stderr"
    FAIL=1
  fi
}

repo=$(new_repo clean)
assert_clean "synthetic baseline" "$repo" --scope head --mode enforce

repo=$(new_repo reserved-values)
cat >"${repo}/fixture.yaml" <<'EOF'
email: dana@example.com
phone: 800-555-0107
mobile: +1-555-0100
telephone: +1 212-555-0199
full_name: Dana R.
tenant: example-corp
namespace: demo-app
account_id: 123456789012
project_id: example-project
subscription_name: example-plan
customer_id: 0
project: agent
subscription: 000000
client_ip: 192.0.2.10
origin_ip: 198.51.100.20
service_ip: 203.0.113.30
EOF
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm synthetic
assert_clean "reserved synthetic values" "$repo" --scope head --mode enforce

repo=$(new_repo documentation-expressions)
cat >"${repo}/fixture.mdx" <<'EOF'
```bash
curl "https://example.com/api/config/namespaces/xEXAMPLE_NAMESPACEx/resources" \
  | jq '{namespace: .metadata.namespace}'
jq -n '{metadata: {namespace: "xEXAMPLE_NAMESPACEx"}}'
jq -n '{detail: "Namespace: write denied — create it before continuing"}'
```
EOF
git -C "$repo" add fixture.mdx
git -C "$repo" commit -qm expressions
assert_clean "schematic variables and documentation expressions" "$repo" --scope head --mode enforce

repo=$(new_repo documentation-prose-labels)
cat >"${repo}/fixture.mdx" <<'EOF'
<Note>
Every customer: "Use the documented example tenant." Continue with the setup instructions.
</Note>
EOF
git -C "$repo" add fixture.mdx
git -C "$repo" commit -qm prose-labels
assert_clean "identity words used as prose labels" "$repo" --scope head --mode enforce

repo=$(new_repo expression-shaped-literals)
cat >"${repo}/fixture.mdx" <<'EOF'
```yaml
namespace: xcustomer-namespacex
```
```json
{"namespace": ".customer-namespace"}
```
EOF
git -C "$repo" add fixture.mdx
git -C "$repo" commit -qm literals
assert_violation "expression-shaped identity literals remain enforced" "$repo" --scope head --mode enforce

repo=$(new_repo public-ip-contexts)
cat >"${repo}/fixture.txt" <<'EOF'
rfc6598=100.64.0.1/10
mdns=224.0.0.251
browser=Mozilla/5.0 Chrome/136.0.0.0 Safari/537.36
terminal={ TERM_PROGRAM_VERSION: "1.22.103.0" }
EOF
svg_coordinate="4.254."
svg_coordinate+="141.138"
printf '<svg><path d="M0 0 %s Z"/></svg>\n' "$svg_coordinate" >>"${repo}/fixture.txt"
git -C "$repo" add fixture.txt
git -C "$repo" commit -qm contexts
assert_clean "protocol, version, and SVG coordinate syntax is not a public IP" "$repo" --scope head --mode audit

repo=$(new_repo public-ip)
public_ip="8.8."
public_ip+="4.4"
printf 'version=1; origin_ip=%s\n' "$public_ip" >"${repo}/fixture.txt"
git -C "$repo" add fixture.txt
git -C "$repo" commit -qm public-ip
assert_violation "globally routable unicast address" "$repo" --scope head --mode audit

repo=$(new_repo action-reference)
printf 'uses: f5-sales-demo/docs-control@main\nremote: git@github.com:f5-sales-demo/docs-control.git\n' >"${repo}/workflow.yaml"
git -C "$repo" add workflow.yaml
git -C "$repo" commit -qm action
assert_clean "GitHub action references are not emails" "$repo" --scope head --mode enforce

repo=$(new_repo non-contact-at-syntax)
cat >"${repo}/fixture.txt" <<'EOF'
clone=https://x-access-token:${TOKEN}@github.com/example/repository.git
credential=https://user:secret@github.com/example/repository.git
ssh=ssh://git@gitlab.com/example/repository.git
patch=owner/repository@1.2.3.patch
anchor=`@line.chunk.path
EOF
git -C "$repo" add fixture.txt
git -C "$repo" commit -qm syntax
assert_clean "URI, package, and anchor syntax are not contact emails" "$repo" --scope head --mode enforce

repo=$(new_repo email)
printf 'email: person@customer.local\n' >"${repo}/fixture.yaml"
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm email
assert_violation "personal email" "$repo" --scope head --mode enforce

repo=$(new_repo phone)
printf 'phone: +1 212 555 1234\n' >"${repo}/fixture.yaml"
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm phone
assert_violation "non-fictional phone" "$repo" --scope head --mode enforce

repo=$(new_repo person-name)
printf 'full_name: Jane Doe\n' >"${repo}/fixture.yaml"
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm name
assert_violation "literal structured person name" "$repo" --scope head --mode enforce

repo=$(new_repo numeric-person-fields)
printf 'first_name: 101\nlast_name: "202"\n' >"${repo}/fixture.yaml"
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm numeric-name
assert_clean "numeric person fields are not names" "$repo" --scope head --mode enforce

repo=$(new_repo home-path)
printf 'cache=/Users/%s/.cache/tool\n' "$SYNTHETIC_USER" >"${repo}/config.ini"
git -C "$repo" add config.ini
git -C "$repo" commit -qm path
assert_violation "personal home path" "$repo" --scope head --mode enforce

repo=$(new_repo placeholder-paths)
printf 'mac=/Users/you/work ci=/home/runner/work variable=/home/${USERNAME}/work route=/home/%s\n' index >"${repo}/config.ini"
git -C "$repo" add config.ini
git -C "$repo" commit -qm paths
assert_clean "placeholder, CI, and variable home paths" "$repo" --scope head --mode enforce

repo=$(new_repo embedded-home-tokens)
printf 'keys=Shift+page/%s/%s route=service/%s/%s windows=prefixC:\\%s\\%s\n' home end Users list Users record >"${repo}/config.ini"
git -C "$repo" add config.ini
git -C "$repo" commit -qm tokens
assert_clean "embedded home-like tokens are not absolute paths" "$repo" --scope head --mode enforce

repo=$(new_repo tenant)
printf 'tenant: real-customer\n' >"${repo}/fixture.yaml"
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm tenant
assert_violation "literal customer tenant" "$repo" --scope head --mode enforce

repo=$(new_repo suffixed-customer-identifiers)
printf 'project_id: customer-project\nsubscription_name: customer-plan\n' >"${repo}/fixture.yaml"
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm identifiers
assert_violation "suffixed project and subscription identifiers" "$repo" --scope head --mode enforce

repo=$(new_repo code-expressions)
cat >"${repo}/fixture.ts" <<'EOF'
interface Context {
  tenant: string;
  namespace?: string;
  full_name: string;
}
const namespace = namespaceOverride ?? defaults.namespace;
const context = {
  tenant: status.activeTenant,
  namespace: String(input.namespace),
  full_name: user.displayName,
};
const typed: { tenant: string | null } = context;
const fallback = { namespace: status.activeNamespace ?? "default" };
const indexed = { tenant: tenants["active"] };
EOF
cat >"${repo}/fixture.cpp" <<'EOF'
auto namespace = context->namespace;
auto tenant = Context::resolve(input);
EOF
git -C "$repo" add fixture.ts fixture.cpp
git -C "$repo" commit -qm expressions
assert_clean "code types and expressions are not literal identity values" "$repo" --scope head --mode enforce

repo=$(new_repo code-string-literal)
cat >"${repo}/fixture.ts" <<'EOF'
const context = { tenant: "real-customer", full_name: "Jane Doe" };
const raw = { namespace: `real-customer` };
EOF
git -C "$repo" add fixture.ts
git -C "$repo" commit -qm literal
assert_violation "quoted identity literals in code" "$repo" --scope head --mode enforce

repo=$(new_repo code-numeric-literal)
printf 'const context = { account_id: 987654321 };\n' >"${repo}/fixture.ts"
git -C "$repo" add fixture.ts
git -C "$repo" commit -qm numeric
assert_violation "numeric identity literals in code" "$repo" --scope head --mode enforce

repo=$(new_repo embedded-serialized-schema)
printf 'export const schema = "params:\\n  namespace:\\n    required: true\\n";\n' >"${repo}/fixture.ts"
git -C "$repo" add fixture.ts
git -C "$repo" commit -qm schema
assert_clean "escaped serialized key headings are not field values" "$repo" --scope head --mode enforce

repo=$(new_repo schematic-identities)
cat >"${repo}/fixture.yaml" <<'EOF'
tenant: staging
namespace: default
project: demo
account: value
EOF
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm schematic
assert_clean "generic environment and schema identities" "$repo" --scope head --mode enforce

repo=$(new_repo composite-schematic-identities)
cat >"${repo}/fixture.yaml" <<'EOF'
tenant: example-corp|staging
account_name: example-partners|production
namespace: library
EOF
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm composite-schematic
assert_clean "composite and public schema identities" "$repo" --scope head --mode enforce

repo=$(new_repo composite-customer-identifiers)
cat >"${repo}/fixture.yaml" <<'EOF'
tenant: real-customer|staging
account_name: example-corp|real-customer
EOF
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm composite-customer
assert_violation "composite literal customer identifiers" "$repo" --scope head --mode enforce

repo=$(new_repo sensitive-query)
printf 'redirect=/done?email=person%%40customer.local\n' >"${repo}/config.ini"
git -C "$repo" add config.ini
git -C "$repo" commit -qm query
assert_violation "PII in URL query parameter" "$repo" --scope head --mode enforce

repo=$(new_repo legal-attribution)
printf 'Copyright Example Author <author@upstream.local>\n' >"${repo}/LICENSE"
git -C "$repo" add LICENSE
git -C "$repo" commit -qm license
assert_clean "legal attribution" "$repo" --scope head --mode enforce

repo=$(new_repo git-provenance)
git -C "$repo" config user.email contributor@users.noreply.github.com
printf 'change\n' >>"${repo}/README.md"
git -C "$repo" add README.md
git -C "$repo" commit -qm change
assert_clean "Git author provenance is not scanned" "$repo" --scope history --mode enforce

repo=$(new_repo commit-trailer-provenance)
printf 'change\n' >>"${repo}/README.md"
git -C "$repo" add README.md
git -C "$repo" commit -qm $'change\n\nCo-authored-by: Example Contributor <contributor@upstream.local>'
assert_clean "commit attribution trailers are provenance" "$repo" --scope history --mode enforce

repo=$(new_repo staged)
printf 'email: person@customer.local\n' >"${repo}/fixture.yaml"
git -C "$repo" add fixture.yaml
assert_clean "HEAD ignores staged-only content" "$repo" --scope head --mode enforce
assert_violation "staged scope reads the index" "$repo" --scope staged --mode enforce

repo=$(new_repo untracked)
printf 'email: person@customer.local\n' >"${repo}/scratch.yaml"
assert_clean "untracked files are out of scope" "$repo" --scope staged --mode enforce

repo=$(new_repo history)
printf 'email: person@customer.local\n' >"${repo}/removed.yaml"
git -C "$repo" add removed.yaml
git -C "$repo" commit -qm add
git -C "$repo" rm -q removed.yaml
git -C "$repo" commit -qm remove
assert_clean "removed PII is absent from HEAD" "$repo" --scope head --mode enforce
assert_violation "reachable historical blob is scanned" "$repo" --scope history --mode enforce

repo=$(new_repo commit-message)
printf 'change\n' >>"${repo}/README.md"
git -C "$repo" add README.md
git -C "$repo" commit -qm 'Contact person@customer.local'
assert_violation "commit message is scanned without author metadata" "$repo" --scope history --mode enforce

repo=$(new_repo media)
printf '\x89PNG\r\n\x1a\nsynthetic-image' >"${repo}/screen.png"
git -C "$repo" add screen.png
git -C "$repo" commit -qm media
assert_clean "media inventory is advisory in enforce mode" "$repo" --scope head --mode enforce
assert_violation "media requires review in audit mode" "$repo" --scope head --mode audit
grep -q 'media-review' "${WORK}/stdout" || {
  echo "[FAIL] audit media finding did not identify its category"
  FAIL=1
}

repo=$(new_repo binary-metadata)
printf '\x89PNG\r\n\x1a\nAuthor\x00person@customer.local\x00' >"${repo}/screen.png"
git -C "$repo" add screen.png
git -C "$repo" commit -qm metadata
assert_violation "PII-shaped binary metadata" "$repo" --scope head --mode enforce

repo=$(new_repo binary-package-syntax)
printf '\x89PNG\r\n\x1a\nowner/repository@1.2.3.patch\x00' >"${repo}/screen.png"
git -C "$repo" add screen.png
git -C "$repo" commit -qm metadata
assert_clean "email-like binary package syntax is not contact metadata" "$repo" --scope head --mode enforce

repo=$(new_repo binary-compression-token)
printf '\x89PNG\r\n\x1a\nA@b.Co\x00' >"${repo}/screen.png"
git -C "$repo" add screen.png
git -C "$repo" commit -qm metadata
assert_clean "short binary compression token is not contact metadata" "$repo" --scope head --mode enforce

repo=$(new_repo media-compression-email)
printf 'RIFFfixture@bytes.invalidWEBP' >"${repo}/screen.webp"
git -C "$repo" add screen.webp
git -C "$repo" commit -qm media
assert_clean "email-shaped media bytes without a metadata key are ignored" "$repo" --scope head --mode enforce

repo=$(new_repo odd-filename)
printf 'email: person@customer.local\n' >"${repo}/- odd name.yaml"
git -C "$repo" add -- '- odd name.yaml'
git -C "$repo" commit -qm odd
assert_violation "option-like filename containing spaces" "$repo" --scope head --mode enforce

repo=$(new_repo symlink)
ln -s "/Users/${SYNTHETIC_USER}/private" "${repo}/linked"
git -C "$repo" add linked
git -C "$repo" commit -qm symlink
assert_clean "scanner does not dereference symlinks" "$repo" --scope head --mode enforce

repo=$(new_repo json-output)
printf 'email: person@customer.local\n' >"${repo}/fixture.yaml"
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm json
assert_violation "JSON output still reports findings" "$repo" --scope head --mode enforce --format json
python3 -m json.tool "${WORK}/stdout" >/dev/null || {
  echo "[FAIL] --format json did not emit valid JSON"
  FAIL=1
}

repo=$(new_repo no-suppression)
printf 'email: person@customer.local # pii:allow\n' >"${repo}/fixture.yaml"
git -C "$repo" add fixture.yaml
git -C "$repo" commit -qm suppression
assert_violation "inline suppression markers are not an escape hatch" "$repo" --scope head --mode enforce

mkdir -p "${WORK}/not-a-repository"
assert_error "non-repository fails closed" "${WORK}/not-a-repository" --scope head --mode enforce

if [ "$FAIL" -ne 0 ]; then
  echo "check-pii tests FAILED"
  exit 1
fi
echo "check-pii tests passed"
