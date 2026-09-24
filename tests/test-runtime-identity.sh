#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
AWS_ROOT="${REPO_ROOT}/terraform/aws"
CSD_ROOT="${REPO_ROOT}/suites/csd-violations"
FAIL=0

pass() { printf '[OK] %s\n' "$1"; }
fail() {
  printf '[FAIL] %s\n' "$1"
  FAIL=1
}
require_file() {
  if [ -f "$1" ]; then pass "$2"; else fail "$2 (missing ${1#"${REPO_ROOT}/"})"; fi
}
require_pattern() {
  local pattern=$1 path=$2 label=$3
  if grep -Eq -- "$pattern" "$path"; then pass "$label"; else fail "$label"; fi
}
reject_pattern() {
  local pattern=$1 path=$2 label=$3
  if grep -ERIq --exclude='test-runtime-identity.sh' -- "$pattern" "$path"; then fail "$label"; else pass "$label"; fi
}

MAINTAINED_REFERENCE_PATHS=(
  "${REPO_ROOT}/README.md"
  "${REPO_ROOT}/component-manifest.json"
  "${REPO_ROOT}/docs/en"
  "${REPO_ROOT}/scripts"
  "${REPO_ROOT}/suites"
  "${REPO_ROOT}/tests"
  "${REPO_ROOT}/terraform"
)
for obsolete_suite in csd-demo-attacks csd-detection javascript-exploits; do
  if [ -e "${REPO_ROOT}/suites/${obsolete_suite}" ]; then
    fail "obsolete suite directory is absent: suites/${obsolete_suite}"
  else
    pass "obsolete suite directory is absent: suites/${obsolete_suite}"
  fi
done
OBSOLETE_CSD_REFERENCE='csd-demo-attacks|csd-detection|javascript-exploits|01-csd-formjacking|02-csd-supply-chain|03-csd-exfiltration|04-csd-combined-stress'
if grep -ERIq --exclude='test-runtime-identity.sh' --exclude='csd-violations.test.mjs' "${OBSOLETE_CSD_REFERENCE}" "${MAINTAINED_REFERENCE_PATHS[@]}"; then
  fail "maintained English, root, runtime, tests, scripts, and Terraform sources contain no obsolete CSD paths"
else
  pass "maintained English, root, runtime, tests, scripts, and Terraform sources contain no obsolete CSD paths"
fi

reject_pattern '"manifest_version"' "${REPO_ROOT}/component-manifest.json" "component manifest contains only supported schema fields"
require_pattern '"source_address_prefix"[[:space:]]*:[[:space:]]*"\*"' "${REPO_ROOT}/component-manifest.json" "component manifest preserves Azure wildcard SSH truth"
require_pattern 'csd-violations/obfuscated-loader[[:space:]]+SIMULATED' "${REPO_ROOT}/suites/mitre-attack/08-attck-coverage-report.sh" "CSD loader is labeled simulated, not ATT&CK covered"
require_pattern 'csd-violations/form-overlay[[:space:]]+SIMULATED' "${REPO_ROOT}/suites/mitre-attack/08-attck-coverage-report.sh" "CSD overlay is labeled simulated, not ATT&CK covered"
require_pattern 'csd-violations/multi-channel-exfiltration[[:space:]]+SIMULATED' "${REPO_ROOT}/suites/mitre-attack/08-attck-coverage-report.sh" "CSD exfiltration is labeled simulated, not ATT&CK covered"
reject_pattern 'csd-violations/[^[:space:]]+[[:space:]]+COVERED' "${REPO_ROOT}/suites/mitre-attack/08-attck-coverage-report.sh" "CSD scenarios make no ATT&CK COVERED claims"
require_pattern 'not assessed as ATT&CK technique coverage' "${REPO_ROOT}/suites/mitre-attack/08-attck-coverage-report.sh" "coverage report explains CSD evidence limits"

for source in versions.tf variables.tf main.tf cloud-init.tftpl terraform.tfvars.example tests/stack.tftest.hcl; do
  require_file "${AWS_ROOT}/${source}" "AWS source present: ${source}"
done
require_file "${CSD_ROOT}/scenarios.mjs" "canonical CSD scenarios present"
require_file "${CSD_ROOT}/run.mjs" "canonical CSD runner present"

require_pattern 'CSD_AWS_RUNTIME !== .1.' "${CSD_ROOT}/run.mjs" "real browser runner requires explicit AWS runtime gate"
require_pattern 'platform !== .linux.' "${CSD_ROOT}/run.mjs" "real browser runner requires Linux"
require_pattern '/opt/traffic-generator/status.json' "${CSD_ROOT}/run.mjs" "real browser runner requires deployed status identity"
require_pattern '/opt/chrome/chrome' "${CSD_ROOT}/run.mjs" "real browser runner requires deployed Chrome path"
require_pattern '/opt/traffic-generator/node_modules' "${CSD_ROOT}/run.mjs" "real browser runner requires deployed Playwright path"
PROVENANCE_ALLOWLIST='SOURCE_REPOSITORY_URL,SOURCE_COMMIT,AWS_REGION,AMI_ID,INSTANCE_ID,DEPLOYMENT_MANIFEST_VERSION,DEPLOYMENT_MANIFEST_SHA256'
reject_pattern 'preserve-env=SOURCE_REPOSITORY_URL,SOURCE_COMMIT,AWS_REGION,AMI_ID,INSTANCE_ID,DEPLOYMENT_MANIFEST_VERSION,DEPLOYMENT_MANIFEST_SHA256' "${AWS_ROOT}/cloud-init.tftpl" "canonical suite wrapper sources provenance from runtime.env rather than duplicating it"
if [ "$(grep -Fc 'latest/meta-data/instance-id' "${AWS_ROOT}/cloud-init.tftpl")" -eq 2 ] && [ "$(grep -Fc 'export INSTANCE_ID' "${AWS_ROOT}/cloud-init.tftpl")" -eq 2 ]; then
  pass "normal and first-boot paths derive and export instance identity with IMDSv2"
else
  fail "normal and first-boot paths derive and export instance identity with IMDSv2"
fi
require_pattern 'X-aws-ec2-metadata-token-ttl-seconds: 60' "${AWS_ROOT}/cloud-init.tftpl" "IMDSv2 token retrieval is mandatory"
require_pattern 'IMDSv2 returned an invalid instance ID.*exit 69' "${AWS_ROOT}/cloud-init.tftpl" "missing or malformed instance identity fails closed"
if grep -Eq -- '--arg instance_id "\$INSTANCE_ID"' "${AWS_ROOT}/cloud-init.tftpl"; then
  pass "first-boot status stores the exported instance identity"
else
  fail "first-boot status stores the exported instance identity"
fi
require_pattern '/bin/bash /opt/traffic-generator/source/suites/csd-violations/run\.sh' "${AWS_ROOT}/cloud-init.tftpl" "SSM runner delegates to the canonical suite wrapper"
reject_pattern '/opt/node/bin/node /opt/traffic-generator/source/suites/csd-violations/run\.mjs|stdbuf.*tee|aws s3 cp.*scenario_dir' "${AWS_ROOT}/cloud-init.tftpl" "SSM runner does not duplicate browser, logging, checksum, or upload orchestration"
require_pattern 'rc=\$\?' "${AWS_ROOT}/cloud-init.tftpl" "SSM runner captures the canonical wrapper exit"
require_pattern 'exit "\$rc"' "${AWS_ROOT}/cloud-init.tftpl" "SSM runner preserves the canonical wrapper exit"
require_pattern 'csd-log-event .*\|\| true' "${AWS_ROOT}/cloud-init.tftpl" "worker event logging is best-effort"
require_pattern 'headless: false' "${AWS_ROOT}/cloud-init.tftpl" "boot health launches headed Chrome under Xvfb"
require_pattern 'page\.goto\("about:blank"\)' "${AWS_ROOT}/cloud-init.tftpl" "boot health navigates only to local about:blank"
reject_pattern 'AWS headed Chrome captures|--test-name-pattern|CSD_AWS_ALLOW_VERIFYING_STATUS|health_run_root' "${AWS_ROOT}/cloud-init.tftpl" "boot health never executes a CSD scenario integration"
require_pattern '/opt/traffic-generator/runtime/results' "${AWS_ROOT}/cloud-init.tftpl" "cloud-init uses canonical AWS evidence runtime root"
require_pattern 'path: /usr/local/sbin/csd-bootstrap' "${AWS_ROOT}/cloud-init.tftpl" "cloud-init writes one root-owned bootstrap program"
require_pattern '^  - /usr/local/sbin/csd-bootstrap$' "${AWS_ROOT}/cloud-init.tftpl" "cloud-init invokes only the bootstrap program"
require_pattern 'trap fail_bootstrap ERR' "${AWS_ROOT}/cloud-init.tftpl" "bootstrap records the failing stage through an ERR trap"
require_pattern 'write_status failed "\$stage"' "${AWS_ROOT}/cloud-init.tftpl" "bootstrap writes authoritative failed state"
require_pattern 'install -d -m 0755 /run/sshd' "${AWS_ROOT}/cloud-init.tftpl" "bootstrap creates the sshd runtime directory before validation"
require_pattern 'jq -r \.version node_modules/playwright-core/package\.json' "${AWS_ROOT}/cloud-init.tftpl" "bootstrap verifies npm package version without nested JavaScript quoting"
reject_pattern '/opt/traffic-generator/results' "${AWS_ROOT}/cloud-init.tftpl" "cloud-init contains no obsolete AWS evidence root"
require_pattern "type: 'png'" "${CSD_ROOT}/run.mjs" "screenshots explicitly use PNG before atomic rename"
require_pattern 'await rm\(temporaryPath, \{ force: true \}\)' "${CSD_ROOT}/run.mjs" "failed screenshot capture removes partial temporary file"
require_pattern 'source "\$RUNTIME_ENV"' "${CSD_ROOT}/run.sh" "suite wrapper sources deployed runtime environment"
require_pattern 'CALLER_DISPLAY=\$\{DISPLAY-\}' "${CSD_ROOT}/run.sh" "suite wrapper captures the explicit per-run display before runtime.env"
require_pattern 'DISPLAY="\$\{CALLER_DISPLAY:-:100\}"' "${CSD_ROOT}/run.sh" "suite wrapper preserves the per-run display and never falls back to health display :99"
reject_pattern 'DISPLAY="\$\{DISPLAY:-:99\}"' "${CSD_ROOT}/run.sh" "suite wrapper does not collide with persistent health Xvfb"
require_pattern '^      AWS_CLI_BIN=/usr/local/bin/aws$' "${AWS_ROOT}/cloud-init.tftpl" "runtime environment pins the reviewed AWS CLI install path"
require_pattern '^      AWS_CLI_VERSION=\$\{aws_cli_version\}$' "${AWS_ROOT}/cloud-init.tftpl" "runtime environment records the reviewed AWS CLI version"
require_pattern 'preserve-env=INSTANCE_ID,RUN_ID,CSD_SCENARIO,DISPLAY,AWS_CLI_BIN,AWS_CLI_VERSION' "${AWS_ROOT}/cloud-init.tftpl" "unprivileged wrapper preserves the reviewed AWS CLI contract"
require_pattern 'PATH=/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' "${AWS_ROOT}/cloud-init.tftpl" "unprivileged wrapper includes the reviewed install directory in its exact PATH"
require_pattern 'normalize_aws_cli_permissions /opt/aws-cli' "${AWS_ROOT}/cloud-init.tftpl" "bootstrap normalizes AWS CLI permissions after every install or rerun"
require_pattern 'owner=\$\$\{2:-root\} group=\$\$\{3:-tgen\}' "${AWS_ROOT}/cloud-init.tftpl" "AWS CLI permission normalization targets root:tgen in production"
require_pattern 'find -P "\$aws_cli_root" -type d .*chmod 0750' "${AWS_ROOT}/cloud-init.tftpl" "AWS CLI directories remain root-owned and group traversable without world access"
require_pattern 'find -P "\$aws_cli_root" -type f -perm /u=x .*chmod 0750' "${AWS_ROOT}/cloud-init.tftpl" "AWS CLI executable files retain group execution without world access"
require_pattern 'find -P "\$aws_cli_root" -type f ! -perm /u=x .*chmod 0640' "${AWS_ROOT}/cloud-init.tftpl" "AWS CLI regular data files are group-readable without world access"
require_pattern 'test -L /usr/local/bin/aws' "${AWS_ROOT}/cloud-init.tftpl" "bootstrap requires the AWS CLI symlink"
require_pattern 'sudo -u tgen test -x "?\$AWS_CLI_BIN"?' "${AWS_ROOT}/cloud-init.tftpl" "worker health requires tgen to traverse and execute the reviewed AWS CLI binary"
require_pattern 'sudo -u tgen "\$AWS_CLI_BIN" --version 2>&1' "${AWS_ROOT}/cloud-init.tftpl" "worker health checks the reviewed AWS CLI version as tgen including stderr output"
require_pattern '"\$AWS_CLI_BIN" s3api head-object' "${CSD_ROOT}/run.sh" "suite wrapper uses the reviewed AWS CLI for object checks"
require_pattern '"\$AWS_CLI_BIN" s3 cp' "${CSD_ROOT}/run.sh" "suite wrapper uses the reviewed AWS CLI for evidence uploads"
reject_pattern 'command -v aws|(^|[^A-Z_])aws s3(api)? ' "${CSD_ROOT}/run.sh" "suite wrapper never resolves AWS CLI through PATH"
require_pattern 'AbortController' "${CSD_ROOT}/run.mjs" "terminal fetch uses abortable bounded requests"
require_pattern 'clearTimeout\(timer\)' "${CSD_ROOT}/run.mjs" "terminal fetch cleans its timeout"
require_pattern 'waitForSelector' "${CSD_ROOT}/run.mjs" "SPA route preconditions wait before evaluation"
require_pattern '^CHROME_PATH=/opt/chrome/chrome$' "${CSD_ROOT}/run.sh" "suite wrapper pins exact deployed Chrome"
require_pattern "trap 'on_signal TERM 143' TERM" "${CSD_ROOT}/run.sh" "TERM finalizes evidence while preserving signal exit"
require_pattern "trap 'on_signal INT 130' INT" "${CSD_ROOT}/run.sh" "INT finalizes evidence while preserving signal exit"
require_pattern 'for name in upload-manifest\.json SHA256SUMS' "${CSD_ROOT}/run.sh" "final metadata uploads before the authoritative commit"
require_pattern 'upload-commit\.json' "${CSD_ROOT}/run.sh" "separate upload commit is the final authoritative object"
require_pattern '--retry-upload' "${CSD_ROOT}/run.sh" "failed uploads have a browser-free retry mode"
require_pattern 's3api head-object' "${CSD_ROOT}/run.sh" "existing remote keys are verified with head-object"
require_pattern '--metadata "sha256=\$\{expected\}"' "${CSD_ROOT}/run.sh" "every upload records its local SHA-256 in object metadata"
require_pattern 'ascii_downcase.*sha256' "${CSD_ROOT}/run.sh" "remote checksum metadata keys are normalized case-insensitively"
reject_pattern 'list-objects-v2' "${CSD_ROOT}/run.sh" "retry does not infer object identity from prefix listing"
reject_pattern '--sse([[:space:]]|$)|--sse-kms-key-id' "${CSD_ROOT}/run.sh" "uploads rely on enforced bucket default customer KMS encryption"
require_pattern '! -name "\$COMMIT_FILE" ! -name "\$FAILURE_FILE"' "${CSD_ROOT}/run.sh" "commit and local failure marker are excluded from authoritative evidence"

FINALIZATION_FIXTURE=$(mktemp -d)
trap 'rm -rf "$FINALIZATION_FIXTURE"' EXIT
mkdir -p "${FINALIZATION_FIXTURE}/screenshots"
printf 'ordinary log\n' >"${FINALIZATION_FIXTURE}/browser.log"
printf 'png evidence\n' >"${FINALIZATION_FIXTURE}/screenshots/step.png"
cat >"${FINALIZATION_FIXTURE}/receipt.json" <<'JSON'
{"scenarios":[{"finalScreenshot":{"captureStatus":"captured","uploadStatus":"pending"}}]}
JSON
bash "${CSD_ROOT}/run.sh" --finalize-test "$FINALIZATION_FIXTURE" fixture-run login-credential-skimmer
if (
  cd "$FINALIZATION_FIXTURE"
  sha256sum --check SHA256SUMS >/dev/null
  manifest_count=$(jq '.objects | length' upload-manifest.json)
  checksum_count=$(wc -l <SHA256SUMS | tr -d ' ')
  [ "$manifest_count" -eq 4 ]
  [ "$checksum_count" -eq 5 ]
  jq -e '.status == "pending" and ([.objects[].status] | all(. == "pending")) and (.objects | has("runs/fixture-run/login-credential-skimmer/receipt.json")) and has("runs/fixture-run/login-credential-skimmer/run-status.json")' upload-manifest.json >/dev/null
  jq -e '.scenarios[0].finalScreenshot.uploadStatus == "pending"' receipt.json >/dev/null
  jq -e '.status == "committed" and .objectKey == "runs/fixture-run/login-credential-skimmer/upload-commit.json"' upload-commit.json >/dev/null
  ! grep -Eq 'SHA256SUMS|upload-manifest.json|upload-commit|finalization-failed|tmp-' upload-manifest.json
); then
  pass "immutable pending evidence and separate commit receipt are internally consistent"
else
  fail "immutable pending evidence and separate commit receipt are internally consistent"
fi

MOCK_ROOT=$(mktemp -d)
RETRY_FIXTURE="${MOCK_ROOT}/results/fixture-run/login-credential-skimmer"
STAGED_FIXTURE="${MOCK_ROOT}/staged/results/fixture-run/login-credential-skimmer"
STAGED_MISMATCH_FIXTURE="${MOCK_ROOT}/staged-mismatch/results/fixture-run/login-credential-skimmer"
STAGED_DENIED_FIXTURE="${MOCK_ROOT}/staged-denied/results/fixture-run/login-credential-skimmer"
mkdir -p "$(dirname "$RETRY_FIXTURE")" "$(dirname "$STAGED_FIXTURE")" "$(dirname "$STAGED_MISMATCH_FIXTURE")" "$(dirname "$STAGED_DENIED_FIXTURE")"
cp -R "$FINALIZATION_FIXTURE" "$RETRY_FIXTURE"
cp -R "$FINALIZATION_FIXTURE" "$STAGED_FIXTURE"
cp -R "$FINALIZATION_FIXTURE" "$STAGED_MISMATCH_FIXTURE"
cp -R "$FINALIZATION_FIXTURE" "$STAGED_DENIED_FIXTURE"
MOCK_BIN="${MOCK_ROOT}/bin"
MOCK_REMOTE="${MOCK_ROOT}/remote"
MOCK_METADATA="${MOCK_ROOT}/metadata"
MOCK_STATE="${MOCK_ROOT}/state"
mkdir -p "$MOCK_BIN" "$MOCK_REMOTE" "$MOCK_METADATA"
cat >"${MOCK_ROOT}/runtime.env" <<EOF
EVIDENCE_BUCKET=fixture-bucket
AWS_CLI_BIN=${MOCK_BIN}/aws
AWS_CLI_VERSION=2.31.4
EOF
cat >"${MOCK_BIN}/aws" <<'MOCKAWS'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == --version ]]; then printf 'aws-cli/2.31.4 Python/3.13.7 Linux/6.8.0 exe/x86_64.ubuntu.24\n' >&2; exit 0; fi
if [[ "$1" == s3api && "$2" == head-object ]]; then
  key=
  while [[ $# -gt 0 ]]; do [[ "$1" == --key ]] && { key=$2; break; }; shift; done
  if [[ "${DENY_HEAD_KEY:-}" == "$key" ]]; then printf 'AccessDenied\n' >&2; exit 77; fi
  if [[ ! -f "${MOCK_REMOTE}/${key}" ]]; then printf '404 Not Found\n' >&2; exit 44; fi
  metadata_file="${MOCK_METADATA}/${key}"
  [[ -f "$metadata_file" ]] || { printf '{}\n'; exit 0; }
  metadata_key=${MOCK_METADATA_KEY:-sha256}
  printf '{"Metadata":{"%s":"%s"}}\n' "$metadata_key" "$(cat "$metadata_file")"
  exit 0
fi
if [[ "$1" == s3 && "$2" == cp ]]; then
  source_path=$3
  key=${4#s3://fixture-bucket/}
  shift 4
  digest=
  while [[ $# -gt 0 ]]; do [[ "$1" == --metadata ]] && { digest=${2#sha256=}; shift 2; continue; }; shift; done
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || exit 67
  count=0
  [[ -f "$MOCK_STATE" ]] && count=$(cat "$MOCK_STATE")
  count=$((count + 1))
  printf '%d\n' "$count" >"$MOCK_STATE"
  if [[ -n "${FAIL_UPLOAD_AT:-}" && "$count" -eq "$FAIL_UPLOAD_AT" ]]; then exit 55; fi
  mkdir -p "${MOCK_REMOTE}/$(dirname "$key")" "${MOCK_METADATA}/$(dirname "$key")"
  cp "$source_path" "${MOCK_REMOTE}/${key}"
  printf '%s\n' "$digest" >"${MOCK_METADATA}/${key}"
  exit 0
fi
exit 64
MOCKAWS
chmod +x "${MOCK_BIN}/aws"
export MOCK_REMOTE MOCK_METADATA MOCK_STATE
rm -f "$MOCK_STATE"
if PATH="${MOCK_BIN}:$PATH" RUNTIME_ENV="${MOCK_ROOT}/runtime.env" FAIL_UPLOAD_AT=2 bash "${CSD_ROOT}/run.sh" --retry-upload "$RETRY_FIXTURE"; then
  fail "initial upload failure remains nonzero"
elif [ -f "${RETRY_FIXTURE}/.finalization-failed.json" ] && [ ! -f "${MOCK_REMOTE}/runs/fixture-run/login-credential-skimmer/upload-commit.json" ]; then
  pass "initial upload failure remains retryable and uncommitted"
else
  fail "initial upload failure remains retryable and uncommitted"
fi
rm -f "$MOCK_STATE"
if PATH="${MOCK_BIN}:$PATH" RUNTIME_ENV="${MOCK_ROOT}/runtime.env" bash "${CSD_ROOT}/run.sh" --retry-upload "$RETRY_FIXTURE" &&
  [ ! -f "${RETRY_FIXTURE}/.finalization-failed.json" ] &&
  [ -f "${MOCK_REMOTE}/runs/fixture-run/login-credential-skimmer/upload-commit.json" ]; then
  pass "partial upload retry validates remote metadata and commits without rerunning browser"
else
  fail "partial upload retry validates remote metadata and commits without rerunning browser"
fi
upload_count=$(cat "$MOCK_STATE")
if PATH="${MOCK_BIN}:$PATH" RUNTIME_ENV="${MOCK_ROOT}/runtime.env" MOCK_METADATA_KEY=SHA256 bash "${CSD_ROOT}/run.sh" --retry-upload "$RETRY_FIXTURE" &&
  [ "$(cat "$MOCK_STATE")" -eq "$upload_count" ]; then
  pass "already committed retry is idempotent with case-normalized checksum metadata"
else
  fail "already committed retry is idempotent with case-normalized checksum metadata"
fi
rm -rf "$MOCK_REMOTE" "$MOCK_METADATA" && mkdir -p "$MOCK_REMOTE" "$MOCK_METADATA"
rm -f "$MOCK_STATE"
if PATH="${MOCK_BIN}:$PATH" RUNTIME_ENV="${MOCK_ROOT}/runtime.env" FAIL_UPLOAD_AT=7 bash "${CSD_ROOT}/run.sh" --retry-upload "$STAGED_FIXTURE"; then
  fail "final commit upload failure remains nonzero"
elif [ -f "${STAGED_FIXTURE}/.finalization-failed.json" ] && [ ! -f "${MOCK_REMOTE}/runs/fixture-run/login-credential-skimmer/upload-commit.json" ]; then
  pass "final commit failure remains retryable and uncommitted"
else
  fail "final commit failure remains retryable and uncommitted"
fi
mismatch_key=runs/fixture-run/login-credential-skimmer/browser.log
mkdir -p "${MOCK_REMOTE}/$(dirname "$mismatch_key")" "${MOCK_METADATA}/$(dirname "$mismatch_key")"
printf 'different remote bytes\n' >"${MOCK_REMOTE}/${mismatch_key}"
printf '%064d\n' 0 >"${MOCK_METADATA}/${mismatch_key}"
if PATH="${MOCK_BIN}:$PATH" RUNTIME_ENV="${MOCK_ROOT}/runtime.env" bash "${CSD_ROOT}/run.sh" --retry-upload "$STAGED_MISMATCH_FIXTURE"; then
  fail "existing mismatched remote key fails closed"
else
  pass "existing mismatched remote key fails closed"
fi
rm -rf "$MOCK_REMOTE" "$MOCK_METADATA" && mkdir -p "$MOCK_REMOTE" "$MOCK_METADATA"
printf '' >"${STAGED_DENIED_FIXTURE}/zero-byte.log"
bash "${CSD_ROOT}/run.sh" --finalize-test "$STAGED_DENIED_FIXTURE" fixture-run login-credential-skimmer
if PATH="${MOCK_BIN}:$PATH" RUNTIME_ENV="${MOCK_ROOT}/runtime.env" bash "${CSD_ROOT}/run.sh" --retry-upload "$STAGED_DENIED_FIXTURE" &&
  [ -f "${MOCK_REMOTE}/runs/fixture-run/login-credential-skimmer/zero-byte.log" ] &&
  [ "$(cat "${MOCK_METADATA}/runs/fixture-run/login-credential-skimmer/zero-byte.log")" = "$(sha256sum "${STAGED_DENIED_FIXTURE}/zero-byte.log" | cut -d' ' -f1)" ]; then
  pass "zero-byte evidence uploads with exact SHA-256 metadata"
else
  fail "zero-byte evidence uploads with exact SHA-256 metadata"
fi
if PATH="${MOCK_BIN}:$PATH" RUNTIME_ENV="${MOCK_ROOT}/runtime.env" DENY_HEAD_KEY=runs/fixture-run/login-credential-skimmer/receipt.json bash "${CSD_ROOT}/run.sh" --retry-upload "$STAGED_DENIED_FIXTURE"; then
  fail "head-object denial is not treated as a missing key"
else
  pass "head-object denial is not treated as a missing key"
fi
if [ -f "${CSD_ROOT}/scenarios.mjs" ] && [ -f "${CSD_ROOT}/run.mjs" ]; then
  node --input-type=module - "${CSD_ROOT}/scenarios.mjs" "${CSD_ROOT}/run.mjs" <<'NODE' || FAIL=1
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [scenarioPath, runnerPath] = process.argv.slice(2);
const { SCENARIOS } = await import(pathToFileURL(scenarioPath));
const { runSuite } = await import(pathToFileURL(runnerPath));
const expected = [
  'login-credential-skimmer',
  'registration-harvester',
  'payment-overlay-card-skimmer',
  'obfuscated-loader',
  'multi-cdn-injection',
  'tag-manager-hijack',
  'multi-channel-exfiltration',
  'high-volume-domain-exfiltration',
  'form-overlay',
  'keylogger-simulation',
  'maximum-detection',
];
const names = SCENARIOS.map(({ name }) => name);
if (JSON.stringify(names) !== JSON.stringify(expected)) {
  console.error(`[FAIL] exact CSD scenario order/names (got ${JSON.stringify(names)})`);
  process.exit(1);
}

function passingEvidence(step) {
  const evidence = {};
  for (const { field, operator, value } of step?.assertions ?? []) {
    const actual = operator === 'gt' ? value + 1 : operator === 'lt' ? value - 1 : operator === 'oneOf' ? value[0] : value;
    const segments = field.split('.');
    const leaf = segments.pop();
    let target = evidence;
    for (const segment of segments) target = target[segment] ??= {};
    target[leaf] = actual;
  }
  return evidence;
}

let scenarioIndex = 0;
const playwright = {
  chromium: {
    launch: async () => ({
      newContext: async () => {
        const scenario = SCENARIOS[scenarioIndex++];
        const evaluateSteps = scenario.steps.filter(({ op }) => op === 'evaluate');
        let evaluateIndex = 0;
        const page = {
          on: () => {},
          goto: async () => ({ status: () => 200 }),
          waitForSelector: async () => {},
          evaluate: async (callback) => {
            const source = callback.toString();
            if (source.includes('querySelectorAll') && source.includes('data-csd-masked')) return 0;
            if (source.includes('window.__csdSim?.cleanupPage') || source.includes('window.__csdSim.cleanupPage')) return { artifactCount: 0, controlValueCount: 0, sensitiveValueCount: 0, timerCount: 0, listenerAttached: false };
            return passingEvidence(evaluateSteps[evaluateIndex++]);
          },
          screenshot: async ({ path, type }) => {
            if (type !== 'png' || !/\.png\.tmp-[0-9]+$/.test(path)) throw new Error(`invalid atomic PNG capture: ${path} (${type})`);
            await writeFile(path, 'structural screenshot evidence');
          },
        };
        return {
          addInitScript: async () => {},
          newPage: async () => page,
          close: async () => {},
        };
      },
      close: async () => {},
    }),
  },
};

const outputDirectory = await mkdtemp(join(tmpdir(), 'csd-runtime-identity-'));
const { receipt, exitCode } = await runSuite({
  playwright,
  outputDirectory,
  targetUrl: 'https://client-side-defense.f5-sales-demo.com/',
});
const expectedScreenshotCount = SCENARIOS.reduce((total, scenario) => total + scenario.steps.length + 1, 0);
const screenshots = receipt.scenarios.flatMap((scenario) => [
  ...scenario.steps.map(({ screenshot }) => screenshot),
  scenario.finalScreenshot,
]);
if (exitCode !== 0 || screenshots.length !== expectedScreenshotCount) {
  const failed = receipt.scenarios.filter(({ status }) => status !== 'passed').map(({ name, steps }) => ({
    name,
    errors: steps.filter(({ status }) => status !== 'passed').map(({ name: stepName, error, assertions }) => ({ stepName, error, assertions })),
  }));
  console.error(`[FAIL] expected ${expectedScreenshotCount} successful step/final screenshots, got ${screenshots.length}; failures: ${JSON.stringify(failed)}`);
  process.exit(1);
}
if (screenshots.some((screenshot) =>
  screenshot.status !== 'captured' ||
  !/^[a-f0-9]{64}$/.test(screenshot.sha256) ||
  !screenshot.objectKey ||
  screenshot.uploadStatus !== 'pending' ||
  !Number.isInteger(screenshot.maskedInputCount)
)) {
  console.error('[FAIL] screenshot receipt fields are incomplete');
  process.exit(1);
}
const normalizedOutput = outputDirectory.replaceAll('\\', '/');
if (screenshots.some(({ localPath, objectKey }) => {
  const normalizedLocal = localPath.replaceAll('\\', '/');
  const relative = normalizedLocal.slice(`${normalizedOutput}/`.length);
  return !normalizedLocal.startsWith(`${normalizedOutput}/`) || objectKey !== `runs/${receipt.runId}/${relative}` || /\/([^/]+)\/\1\//.test(relative);
})) {
  console.error('[FAIL] local screenshot paths do not map exactly to receipt object keys');
  process.exit(1);
}
console.log('[OK] exact 11 CSD scenario names');
console.log(`[OK] ${expectedScreenshotCount} structural step/final screenshot receipts`);
NODE
fi

if [ -d "${CSD_ROOT}" ]; then
  reject_pattern "(cookie|authorization|bearer|api[_-]?token|localStorage|sessionStorage|requestBody|responseBody)[[:space:]_-]*(value|body|header)?[[:space:]]*[:=]" "${CSD_ROOT}" "CSD source contains no retained auth, storage, or body values"
  reject_pattern 'console\.(log|error|warn)\([^)]*(\.value|\.key|password|card|ssn)' "${CSD_ROOT}" "CSD logs do not emit form, key, or sensitive-shaped values"
fi

if [ -d "${AWS_ROOT}" ]; then
  require_pattern 'resource "aws_network_interface" "worker"' "${AWS_ROOT}/main.tf" "AWS worker uses an explicit primary network interface"
  require_pattern 'resource "aws_eip" "worker"' "${AWS_ROOT}/main.tf" "AWS worker has an explicit Elastic IP"
  require_pattern 'network_interface[[:space:]]*=[[:space:]]*aws_network_interface\.worker\.id' "${AWS_ROOT}/main.tf" "AWS worker Elastic IP attaches directly to the primary ENI"
  reject_pattern 'resource "aws_eip_association"' "${AWS_ROOT}" "AWS worker uses no separate EIP association resource"
  require_pattern 'network_interface_id[[:space:]]*=[[:space:]]*aws_network_interface\.worker\.id' "${AWS_ROOT}/main.tf" "AWS worker launches with the stable EIP network interface"
  require_pattern 'iam_instance_profile[[:space:]]*=[[:space:]]*aws_iam_instance_profile\.worker\.name' "${AWS_ROOT}/main.tf" "AWS worker attaches the exact IAM instance profile"
  require_pattern 'key_name[[:space:]]*=[[:space:]]*aws_key_pair\.operator\.key_name' "${AWS_ROOT}/main.tf" "AWS worker attaches the exact operator key pair"
  reject_pattern 'associate_public_ip_address[[:space:]]*=[[:space:]]*true|map_public_ip_on_launch[[:space:]]*=[[:space:]]*true' "${AWS_ROOT}" "AWS worker receives no automatic public IP"
  require_pattern 'aws_eip\.worker' "${AWS_ROOT}/main.tf" "AWS worker waits for direct EIP attachment"
  require_pattern 'resource "aws_default_security_group" "this"' "${AWS_ROOT}/main.tf" "AWS VPC default security group is managed"
  require_pattern 'ingress[[:space:]]*=[[:space:]]*\[\]' "${AWS_ROOT}/main.tf" "AWS VPC default security group denies ingress"
  require_pattern 'egress[[:space:]]*=[[:space:]]*\[\]' "${AWS_ROOT}/main.tf" "AWS VPC default security group denies egress"
  require_pattern 'resource "aws_flow_log" "vpc"' "${AWS_ROOT}/main.tf" "AWS VPC flow logging is enabled"
  require_pattern 'traffic_type[[:space:]]*=[[:space:]]*"ALL"' "${AWS_ROOT}/main.tf" "AWS VPC flow logging captures accepted and rejected traffic"
  require_pattern 'resource "aws_s3_bucket_notification" "evidence"' "${AWS_ROOT}/main.tf" "AWS evidence bucket notifications are configured"
  require_pattern 'resource "aws_s3_bucket_notification" "access_logs"' "${AWS_ROOT}/main.tf" "AWS access-log sink publishes to EventBridge"
  require_pattern 'resource "aws_s3_bucket_notification" "evidence_replica"' "${AWS_ROOT}/main.tf" "AWS replica bucket publishes to EventBridge"
  require_pattern 'resource "aws_s3_bucket_notification" "replica_access_logs"' "${AWS_ROOT}/main.tf" "AWS replica log sink publishes to EventBridge"
  require_pattern 'eventbridge[[:space:]]*=[[:space:]]*true' "${AWS_ROOT}/main.tf" "AWS S3 events publish to EventBridge"
  require_pattern 'resource "aws_s3_bucket_logging" "evidence"' "${AWS_ROOT}/main.tf" "AWS evidence bucket has server access logging"
  require_pattern 'resource "aws_s3_bucket_logging" "evidence_replica"' "${AWS_ROOT}/main.tf" "AWS replica bucket has server access logging"
  require_pattern 'resource "aws_s3_bucket" "access_logs"' "${AWS_ROOT}/main.tf" "AWS access logs use a dedicated sink bucket"
  require_pattern 'resource "aws_s3_bucket" "replica_access_logs"' "${AWS_ROOT}/main.tf" "AWS replica logs use a dedicated regional sink bucket"
  require_pattern 'resource "aws_kms_key" "evidence_replica"' "${AWS_ROOT}/main.tf" "AWS replica evidence uses a regional KMS key"
  require_pattern 'replica_kms_key_id[[:space:]]*=[[:space:]]*aws_kms_key\.evidence_replica\.arn' "${AWS_ROOT}/main.tf" "AWS replication specifies the replica KMS key"
  require_pattern 'resource "aws_s3_bucket_replication_configuration" "evidence"' "${AWS_ROOT}/main.tf" "AWS evidence bucket has cross-region replication"
  require_pattern 'provider[[:space:]]*=[[:space:]]*aws\.replica' "${AWS_ROOT}/main.tf" "AWS replica resources use the secondary-region provider"
  reject_pattern 'checkov:skip=(CKV2_AWS_11|CKV2_AWS_12|CKV2_AWS_62|CKV2_AWS_19):' "${AWS_ROOT}" "AWS applicable non-sink Checkov controls are not suppressed"
  require_pattern 'checkov:skip=CKV_AWS_18:This bucket is the terminal S3 access-log destination' "${AWS_ROOT}/main.tf" "AWS primary access-log sink has a narrow nonrecursive logging exemption"
  require_pattern 'checkov:skip=CKV_AWS_18:This bucket is the terminal cross-region S3 access-log destination' "${AWS_ROOT}/main.tf" "AWS replica access-log sink has a narrow nonrecursive logging exemption"
  require_pattern 'checkov:skip=CKV_AWS_145:Amazon S3 server access-log destination buckets require SSE-S3 default encryption' "${AWS_ROOT}/main.tf" "AWS terminal log sinks have a documented service-compatibility KMS exemption"
  require_pattern 'checkov:skip=CKV_AWS_144:Access logs are operational telemetry with bounded retention' "${AWS_ROOT}/main.tf" "AWS primary access-log sink has a narrow replication exemption"
  require_pattern 'checkov:skip=CKV_AWS_144:Replica access logs are terminal operational telemetry with bounded retention' "${AWS_ROOT}/main.tf" "AWS replica access-log sink has a narrow replication exemption"
  kms_sink_skip_count=$(grep -Ec 'checkov:skip=CKV_AWS_145:Amazon S3 server access-log destination buckets require SSE-S3 default encryption' "${AWS_ROOT}/main.tf")
  if [ "${kms_sink_skip_count}" -eq 2 ]; then pass "AWS KMS skips are limited to the two terminal log sinks"; else fail "AWS KMS skips are limited to the two terminal log sinks"; fi
  reject_pattern 'checkov:skip=CKV_AWS_145:' "${AWS_ROOT}/variables.tf" "AWS KMS controls are not broadly suppressed outside sink resources"
  require_pattern 'cidr_blocks[[:space:]]*=[[:space:]]*\[var\.operator_ssh_cidr\]' "${AWS_ROOT}/main.tf" "SSH ingress uses only operator_ssh_cidr"
  require_pattern 'from_port[[:space:]]*=[[:space:]]*22' "${AWS_ROOT}/main.tf" "AWS SSH ingress opens TCP port 22"
  require_pattern 'public_key[[:space:]]*=[[:space:]]*local\.operator_public_key' "${AWS_ROOT}/main.tf" "EC2 key pair receives public key material only"
  require_pattern 'operator_ssh_cidr.*?/32|/32.*operator_ssh_cidr' "${AWS_ROOT}/variables.tf" "SSH source validation requires an exact IPv4 /32"
  if grep -Eq 'ingress[[:space:]]*\{[^}]*0\.0\.0\.0/0' "${AWS_ROOT}/main.tf"; then fail "AWS SSH ingress is not broad"; else pass "AWS SSH ingress is not broad"; fi
  if grep -Eiq 'resource "aws_nat_gateway"|resource "aws_subnet" "private"|private-worker|private_subnet|--no-sandbox' "${AWS_ROOT}/main.tf" "${AWS_ROOT}/variables.tf" "${AWS_ROOT}/outputs.tf" "${AWS_ROOT}/cloud-init.tftpl"; then fail "AWS root has no NAT/private worker or Chrome sandbox bypass"; else pass "AWS root has no NAT/private worker or Chrome sandbox bypass"; fi
  require_pattern 'operator_ssh_cidr[[:space:]]*=[[:space:]]*"142\.127\.218\.190/32"' "${AWS_ROOT}/terraform.tfvars.example" "AWS example uses the observed jumpbox /32"
  require_pattern '[Rr]evalidate' "${AWS_ROOT}/terraform.tfvars.example" "AWS example requires jumpbox CIDR revalidation"
  require_pattern 'supported_architectures' "${AWS_ROOT}/main.tf" "AWS worker validates live instance architecture"
  require_pattern 'tmp=/opt/traffic-generator/source\.tmp' "${AWS_ROOT}/cloud-init.tftpl" "source checkout uses same-filesystem staging for atomic installation"
  require_pattern 'for attempt in 1 2 3 4' "${AWS_ROOT}/cloud-init.tftpl" "source fetch has bounded retries"
  require_pattern 'rm -rf "\$dst" "\$tmp"' "${AWS_ROOT}/cloud-init.tftpl" "mismatched source and interrupted staging are rebuilt"
  require_pattern 'valid "\$dst"' "${AWS_ROOT}/cloud-init.tftpl" "existing source is reused only after immutable identity validation"
  require_pattern 'manifest=suites/csd-violations/scenarios\.mjs' "${AWS_ROOT}/cloud-init.tftpl" "bootstrap hashes the canonical scenario manifest"
  require_pattern 'sha256sum "\$1/\$manifest".*= "\$digest"' "${AWS_ROOT}/cloud-init.tftpl" "canonical scenario manifest must match the reviewed deployment digest"
  require_pattern 'mv "\$tmp" "\$dst"' "${AWS_ROOT}/cloud-init.tftpl" "verified source is installed with an atomic rename"
  reject_pattern 'git -C /opt/traffic-generator/source remote add' "${AWS_ROOT}/cloud-init.tftpl" "reruns cannot collide with a remote in the installed checkout"
  require_pattern 'chown -R root:root "\$dst"' "${AWS_ROOT}/cloud-init.tftpl" "deployed source becomes root owned"
  require_pattern 'chmod 0555' "${AWS_ROOT}/cloud-init.tftpl" "deployed source directories are read-only"
  require_pattern 'chmod 0444' "${AWS_ROOT}/cloud-init.tftpl" "deployed source files are read-only"
fi
bootstrap_path_count=$(grep -Ec '^  - path: /usr/local/sbin/csd-bootstrap$' "${AWS_ROOT}/cloud-init.tftpl" || true)
bootstrap_runcmd_count=$(grep -Ec '^  - /usr/local/sbin/csd-bootstrap$' "${AWS_ROOT}/cloud-init.tftpl" || true)
legacy_runcmd_count=$(grep -Ec '^  - - /bin/bash$' "${AWS_ROOT}/cloud-init.tftpl" || true)
if [ "${bootstrap_path_count}" -eq 1 ] &&
  [ "${bootstrap_runcmd_count}" -eq 1 ] &&
  [ "${legacy_runcmd_count}" -eq 0 ]; then
  pass "cloud-init executes one root-owned fail-fast bootstrap script"
else
  fail "cloud-init executes one root-owned fail-fast bootstrap script"
fi
require_pattern 'actions[[:space:]]*=[[:space:]]*\["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"\]' "${AWS_ROOT}/main.tf" "worker runtime key permissions include scoped KMS decrypt"
require_pattern 'sid[[:space:]]*=[[:space:]]*"ReadRunEvidence"' "${AWS_ROOT}/main.tf" "worker has an explicit evidence-read statement"
require_pattern 'actions[[:space:]]*=[[:space:]]*\["s3:GetObject"\]' "${AWS_ROOT}/main.tf" "worker can read evidence objects for exact retry verification"
require_pattern 'resources[[:space:]]*=[[:space:]]*\["\$\{aws_s3_bucket\.evidence\.arn\}/runs/\*"\]' "${AWS_ROOT}/main.tf" "worker evidence object access remains scoped to runs only"

OBSERVATION_DOC="${REPO_ROOT}/docs/en/07-integrate.mdx"
require_pattern 'method: GET' "${OBSERVATION_DOC}" "CSD observation documents GET operations"
require_pattern 'path: /api/shape/csd/namespaces/\{namespace\}/detected_domains' "${OBSERVATION_DOC}" "CSD observation documents detected domains endpoint"
require_pattern 'method: POST' "${OBSERVATION_DOC}" "CSD observation documents scripts POST operation"
require_pattern 'path: /api/shape/csd/namespaces/\{namespace\}/scripts' "${OBSERVATION_DOC}" "CSD observation documents scripts endpoint"
require_pattern 'path: /api/shape/csd/namespaces/\{namespace\}/formFields' "${OBSERVATION_DOC}" "CSD observation documents form fields endpoint"
require_pattern 'upload-commit\.json' "${OBSERVATION_DOC}" "CSD observation requires authoritative upload commit retrieval"
require_pattern '\.status == "committed" and \.objectKey == \$object_key' "${OBSERVATION_DOC}" "CSD observation validates committed status and exact prefix object key"
require_pattern '\.uploadManifest\.sha256' "${OBSERVATION_DOC}" "CSD observation validates upload manifest digest"
require_pattern '\.checksumSet\.sha256' "${OBSERVATION_DOC}" "CSD observation validates checksum-set digest"
require_pattern 'fromdateiso8601' "${OBSERVATION_DOC}" "CSD observation converts receipt timestamps portably"
require_pattern 'start_time:' "${OBSERVATION_DOC}" "CSD observation documents snake_case start_time input"
require_pattern 'end_time:' "${OBSERVATION_DOC}" "CSD observation documents snake_case end_time input"
reject_pattern 'startTime:|endTime:' "${OBSERVATION_DOC}" "CSD observation contains no obsolete camelCase time inputs"
require_pattern 'host comparison allowlist only from that receipt' "${OBSERVATION_DOC}" "CSD exact correlation allowlist is receipt-derived hosts only"
require_pattern 'host allowlist only for `detected_domains` and `scripts`' "${OBSERVATION_DOC}" "CSD exact correlation is limited to host-bearing endpoints"
require_pattern 'aggregate record count and endpoint classification' "${OBSERVATION_DOC}" "CSD form fields use aggregate observation only"
require_pattern 'Do not use this status for `formFields`' "${OBSERVATION_DOC}" "CSD form fields never claim exact NOT_OBSERVED attribution"
require_pattern 'Count and endpoint classification only' "${OBSERVATION_DOC}" "CSD form fields correlation table excludes identifiers"
reject_pattern 'form-field identifiers explicitly recorded as observed|explicit form-field identifier exactly matches|Exact receipt-derived hosts/fields|exact normalized hosts or explicit field identifiers' "${OBSERVATION_DOC}" "CSD observation makes no exact form-field identifier claim"
require_pattern 'aggregate receipt-window observation' "${REPO_ROOT}/docs/en/06-runner.mdx" "runner documents aggregate-only form field observation"
reject_pattern 'explicitly observed field identifiers' "${REPO_ROOT}/docs/en/06-runner.mdx" "runner does not claim receipt field identifiers"
require_pattern 'optional aggregate count' "${AWS_ROOT}/README.md" "AWS README documents aggregate-only form field observation"
reject_pattern 'explicitly observed fields' "${AWS_ROOT}/README.md" "AWS README does not claim receipt field identifiers"
require_pattern 'export AWS_PROFILE=280469140135_Users' "${AWS_ROOT}/README.md" "AWS README exports the required Terraform profile"
require_pattern 'export AWS_REGION=us-east-1' "${AWS_ROOT}/README.md" "AWS README exports the required Terraform region"
require_pattern 'set -euo pipefail' "${REPO_ROOT}/docs/en/08-teardown.mdx" "teardown executable blocks fail closed"
for observation_status in OBSERVED NOT_OBSERVED PENDING ERROR; do
  require_pattern "\`${observation_status}\`" "${OBSERVATION_DOC}" "CSD observation defines ${observation_status}"
done
require_pattern 'Store the correlation table separately' "${OBSERVATION_DOC}" "CSD correlation remains separate from browser evidence"
reject_pattern 'XCSH_API_TOKEN|Authorization:[[:space:]]*Bearer|/api/shape/csd/|detected_domains|formFields' "${AWS_ROOT}/cloud-init.tftpl" "AWS worker contains no tenant credentials or CSD API client"

require_pattern '^terraform/aws/.* -> terraform/aws/' "${REPO_ROOT}/docs/_imports" "AWS docs imports are namespaced"
require_pattern '^terraform/main\.tf$' "${REPO_ROOT}/docs/_imports" "Azure docs imports remain present"
require_pattern 'key[[:space:]]*=[[:space:]]*"f5-sales-demo/traffic-generator-aws\.tfstate"' "${AWS_ROOT}/versions.tf" "AWS state key is independent"
if grep -ERq --exclude-dir=aws 'traffic-generator-aws\.tfstate|hashicorp/aws|aws_instance' "${REPO_ROOT}/terraform"; then
  fail "Azure root does not reference AWS state or resources"
else
  pass "Azure root does not reference AWS state or resources"
fi

if [ "$FAIL" -ne 0 ]; then
  echo "runtime identity tests FAILED"
  exit 1
fi
echo "runtime identity tests passed"
