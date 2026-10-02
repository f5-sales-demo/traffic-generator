#!/usr/bin/env bash
set -uo pipefail

COMMIT_FILE=upload-commit.json
FAILURE_FILE=.finalization-failed.json
umask 077
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
NODE_BIN=/opt/node/bin/node
LOCK_PATH=/run/lock/csd-traffic-generator.lock
RESULTS_ROOT=/opt/traffic-generator/runtime/results
PRIMARY_EXIT=0 SIGNAL="" OUTCOME=ok UPLOAD_EXIT=0 UPLOAD_COMMITTED=false
NODE_PID="" XVFB_PID="" FINALIZING=0
FINALIZATION_DEADLINE=0
# Policy belongs to the dispatcher module; shell consumes its exact bounds.
read_policy() {
  local values
  values=$(
    "$NODE_BIN" --input-type=module - "$SCRIPT_DIR/continuous.mjs" <<'NODE'
import { pathToFileURL } from 'node:url';
const { DEFAULT_POLICY: p } = await import(pathToFileURL(process.argv[2]));
console.log([p.scenarioMs / 1000, p.finalizationMs / 1000, p.cleanupMs / 1000, p.maxRunBytes / 1024, p.maxOutputBytes / 1024].join(' '));
NODE
  ) || return 78
  [[ "$values" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]] || return 78
  read -r SCENARIO_SECONDS FINALIZATION_SECONDS CLEANUP_SECONDS FILE_BLOCKS LOG_BLOCKS <<<"$values"
}

read_runtime_env() {
  local line key value assignment
  local bare_assignment='^([A-Z][A-Z0-9_]*)=([a-zA-Z0-9_./:@+-]*)$'
  local single_assignment="^([A-Z][A-Z0-9_]*)='([a-zA-Z0-9_./:@+-]*)'$"
  local double_assignment='^([A-Z][A-Z0-9_]*)="([a-zA-Z0-9_./:@+-]*)"$'
  local -A seen=()
  [[ -r "$RUNTIME_ENV" && ! -L "$RUNTIME_ENV" ]] || return 78
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    # Accept only literal assignments, including readonly/quoted generated paths.
    # Never evaluate shell syntax or make caller-selected DISPLAY readonly.
    assignment=${line#readonly }
    if [[ "$assignment" =~ $bare_assignment || "$assignment" =~ $single_assignment || "$assignment" =~ $double_assignment ]]; then
      key=${BASH_REMATCH[1]} value=${BASH_REMATCH[2]}
    else
      return 78
    fi
    [[ -z "${seen[$key]:-}" ]] || return 78
    seen[$key]=1
    case "$key" in
    TARGET_URL | EVIDENCE_BUCKET | LOG_GROUP_NAME | NODE_PATH | CHROME_BIN | DISPLAY | SOURCE_REPOSITORY_URL | SOURCE_COMMIT | AWS_REGION | AMI_ID | DEPLOYMENT_MANIFEST_VERSION | DEPLOYMENT_MANIFEST_SHA256 | AWS_CLI_BIN | AWS_CLI_VERSION | CSD_AWS_RUNTIME | CONTINUOUS_ENABLED | CHROME_VERSION | NODE_VERSION | PLAYWRIGHT_VERSION) export "$key=$value" ;;
    *) return 78 ;;
    esac
  done <"$RUNTIME_ENV"
}

validate_scenario() {
  "$NODE_BIN" --input-type=module - "$SCRIPT_DIR/scenarios.mjs" "$CSD_SCENARIO" <<'NODE'
import { pathToFileURL } from 'node:url';
const { SCENARIO_NAMES } = await import(pathToFileURL(process.argv[2]));
process.exit(SCENARIO_NAMES.includes(process.argv[3]) ? 0 : 64);
NODE
}

write_execution_result() {
  local failure=null temporary="${RESULTS_DIR}/execution-result.json.tmp-$$"
  [[ "$OUTCOME" == ok ]] || failure="\"${OUTCOME}\""
  jq -cn --arg scenario "$CSD_SCENARIO" --arg runId "$RUN_ID" --arg outcome "$OUTCOME" \
    --arg signal "$SIGNAL" --argjson browserExit "$PRIMARY_EXIT" --argjson uploadExit "$UPLOAD_EXIT" \
    --argjson uploadCommitted "$UPLOAD_COMMITTED" --argjson failureCategory "$failure" \
    '{schemaVersion:1,scenario:$scenario,runId:$runId,outcome:$outcome,browserExit:$browserExit,uploadExit:$uploadExit,uploadCommitted:$uploadCommitted,failureCategory:$failureCategory,signal:$signal}' >"$temporary" &&
    mv "$temporary" "${RESULTS_DIR}/execution-result.json"
}

classify_exit() {
  case "$1" in
  0) OUTCOME=ok ;;
  65 | 66 | 74) OUTCOME=fatal_integrity ;;
  77) OUTCOME=fatal_auth ;;
  78 | 64 | 69) OUTCOME=fatal_config ;;
  67) OUTCOME=fatal_target ;;
  124 | 137) OUTCOME=timeout ;;
  130 | 143) OUTCOME=interrupted ;;
  *) OUTCOME=upload_transient ;;
  esac
}

bounded_aws() {
  local remaining=$((FINALIZATION_DEADLINE - SECONDS)) error_file rc
  ((remaining > 0)) || return 124
  error_file=$(mktemp) || return 78
  (
    ulimit -f "$LOG_BLOCKS"
    timeout --signal=TERM --kill-after=2 "$remaining" "$AWS_CLI_BIN" "$@" 2>"$error_file"
  )
  rc=$?
  if grep -Eqi 'AccessDenied|InvalidAccessKeyId|ExpiredToken|InvalidToken|SignatureDoesNotMatch|Unauthorized|Unable to locate credentials' "$error_file"; then rc=77; fi
  if grep -Eqi '(^|[^0-9])404([^0-9]|$)|Not Found|NoSuchKey' "$error_file"; then rc=44; fi
  rm -f "$error_file"
  return "$rc"
}

stop_owned_group() {
  local pid=$1 deadline=$((SECONDS + CLEANUP_SECONDS))
  [[ -n "$pid" ]] || return 0
  kill -TERM -- "-$pid" 2>/dev/null || true
  while kill -0 -- "-$pid" 2>/dev/null && ((SECONDS < deadline)); do sleep 0.1; done
  kill -KILL -- "-$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

write_status() {
  local status_path="${SCENARIO_DIR}/run-status.json"
  local status_temp="${status_path}.tmp-$$"
  printf '{"browserExit":%d,"uploadStatus":"pending","signal":"%s","sourceCommit":"%s","manifestDigest":"%s"}\n' \
    "$PRIMARY_EXIT" "$SIGNAL" "$SOURCE_COMMIT" "$DEPLOYMENT_MANIFEST_SHA256" >"$status_temp"
  mv "$status_temp" "$status_path"
}

write_upload_manifest() {
  local manifest_path="${SCENARIO_DIR}/upload-manifest.json"
  local manifest_temp="${manifest_path}.tmp-$$"
  (
    cd "$SCENARIO_DIR" || exit 1
    find . -type f \
      ! -name SHA256SUMS ! -name 'SHA256SUMS.tmp*' \
      ! -name upload-manifest.json ! -name 'upload-manifest.json.tmp*' \
      ! -name "$COMMIT_FILE" ! -name "$FAILURE_FILE" ! -name '*.tmp-*' -print0 |
      sort -z |
      while IFS= read -r -d '' file; do
        relative_path=${file#./}
        sha256=$(sha256sum "$file" | cut -d' ' -f1)
        jq -cn \
          --arg key "runs/${RUN_ID}/${CSD_SCENARIO}/${relative_path}" \
          --arg sha256 "$sha256" \
          '{key:$key,sha256:$sha256,status:"pending"}'
      done | jq -s \
      --arg runId "$RUN_ID" \
      --arg scenario "$CSD_SCENARIO" \
      '{schemaVersion:2,runId:$runId,scenario:$scenario,status:"pending",objects:(map({key:.key,value:{sha256:.sha256,status:.status}})|from_entries)}' \
      >"$manifest_temp"
  )
  mv "$manifest_temp" "$manifest_path"
}

write_checksums() {
  (
    cd "$SCENARIO_DIR" || exit 1
    find . -type f \
      ! -name SHA256SUMS ! -name 'SHA256SUMS.tmp*' \
      ! -name "$COMMIT_FILE" ! -name "$FAILURE_FILE" ! -name '*.tmp-*' \
      -exec sha256sum {} + | sort -k2 >"SHA256SUMS.tmp-$$"
    mv "SHA256SUMS.tmp-$$" SHA256SUMS
  )
}

write_upload_commit() {
  local commit_path="${SCENARIO_DIR}/${COMMIT_FILE}"
  local commit_temp="${commit_path}.tmp-$$"
  local checksum_sha256 manifest_sha256
  checksum_sha256=$(sha256sum "${SCENARIO_DIR}/SHA256SUMS" | cut -d' ' -f1) || return
  manifest_sha256=$(sha256sum "${SCENARIO_DIR}/upload-manifest.json" | cut -d' ' -f1) || return
  jq -cn \
    --arg runId "$RUN_ID" \
    --arg scenario "$CSD_SCENARIO" \
    --arg objectKey "runs/${RUN_ID}/${CSD_SCENARIO}/${COMMIT_FILE}" \
    --arg checksumSha256 "$checksum_sha256" \
    --arg manifestSha256 "$manifest_sha256" \
    --argjson browserExit "$PRIMARY_EXIT" \
    '{schemaVersion:1,runId:$runId,scenario:$scenario,status:"committed",browserExit:$browserExit,objectKey:$objectKey,checksumSet:{key:"SHA256SUMS",sha256:$checksumSha256},uploadManifest:{key:"upload-manifest.json",sha256:$manifestSha256}}' \
    >"$commit_temp"
  mv "$commit_temp" "$commit_path"
}

write_failure_marker() {
  local upload_exit=$1 phase=$2
  local marker_temp="${SCENARIO_DIR}/${FAILURE_FILE}.tmp-$$"
  jq -cn --arg phase "$phase" --argjson uploadExit "$upload_exit" \
    '{finalization:"failed",phase:$phase,uploadExit:$uploadExit,commitUploaded:false,retryCommand:"run.sh --retry-upload <scenario-dir>"}' \
    >"$marker_temp"
  mv "$marker_temp" "${SCENARIO_DIR}/${FAILURE_FILE}"
}

remote_object_sha256() {
  local key=$1 response rc
  if response=$(bounded_aws s3api head-object --bucket "$EVIDENCE_BUCKET" --key "$key" --output json); then
    jq -er '[ (.Metadata // {}) | to_entries[] | select((.key | ascii_downcase) == "sha256") | .value ] | if length == 1 then .[0] else empty end' <<<"$response" || return 66
  else
    rc=$?
    return "$rc"
  fi
}

upload_if_missing() {
  local file=$1 key=$2 expected=$3 actual remote rc
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 66
  actual=$(sha256sum "$file" | cut -d' ' -f1) || return
  [[ "$actual" == "$expected" ]] || return 66
  if remote=$(remote_object_sha256 "$key"); then
    [[ "$(printf '%s' "$remote" | tr '[:upper:]' '[:lower:]')" == "$expected" ]] || {
      echo 'ERROR: remote object checksum metadata mismatch' >&2
      return 74
    }
    return 0
  else
    rc=$?
  fi
  [[ "$rc" -eq 44 ]] || return "$rc"
  bounded_aws s3 cp "$file" "s3://${EVIDENCE_BUCKET}/${key}" \
    --metadata "sha256=${expected}" --only-show-errors >/dev/null
}

upload_manifest_objects() {
  local key relative expected actual prefix="runs/${RUN_ID}/${CSD_SCENARIO}/"
  while IFS=$'\t' read -r key expected; do
    [[ "$key" == "${prefix}"* ]] || return 65
    relative=${key#"$prefix"}
    [[ -n "$relative" && "$relative" != /* && "$relative" != *'..'* ]] || return 65
    [[ -f "${SCENARIO_DIR}/${relative}" ]] || return 66
    actual=$(sha256sum "${SCENARIO_DIR}/${relative}" | cut -d' ' -f1) || return
    [[ "$actual" == "$expected" ]] || return 66
    upload_if_missing "${SCENARIO_DIR}/${relative}" "$key" "$expected" || return $?
  done < <(jq -r '.objects | to_entries[] | [.key,.value.sha256] | @tsv' "${SCENARIO_DIR}/upload-manifest.json")
}

upload_final_metadata() {
  local name key expected
  for name in upload-manifest.json SHA256SUMS; do
    [[ -s "${SCENARIO_DIR}/${name}" ]] || return 66
    key="runs/${RUN_ID}/${CSD_SCENARIO}/${name}"
    expected=$(sha256sum "${SCENARIO_DIR}/${name}" | cut -d' ' -f1) || return
    upload_if_missing "${SCENARIO_DIR}/${name}" "$key" "$expected" || return $?
  done
}

validate_frozen_evidence() {
  local manifest_run manifest_scenario
  [[ -s "${SCENARIO_DIR}/upload-manifest.json" && -s "${SCENARIO_DIR}/SHA256SUMS" ]] || return 66
  [[ -z "$(find -P "$SCENARIO_DIR" -type l -print -quit)" ]] || return 66
  jq -e '.schemaVersion == 2 and .status == "pending" and (.objects | type == "object" and length > 0)' "${SCENARIO_DIR}/upload-manifest.json" >/dev/null || return 66
  manifest_run=$(jq -r '.runId' "${SCENARIO_DIR}/upload-manifest.json") || return
  manifest_scenario=$(jq -r '.scenario' "${SCENARIO_DIR}/upload-manifest.json") || return
  [[ "$manifest_run" == "$RUN_ID" && "$manifest_scenario" == "$CSD_SCENARIO" ]] || return 65
  (cd "$SCENARIO_DIR" && sha256sum --check --strict SHA256SUMS >/dev/null) || return 66
}

commit_upload() {
  local key="runs/${RUN_ID}/${CSD_SCENARIO}/${COMMIT_FILE}" expected
  [[ -f "${SCENARIO_DIR}/${COMMIT_FILE}" ]] || write_upload_commit || return
  expected=$(sha256sum "${SCENARIO_DIR}/${COMMIT_FILE}" | cut -d' ' -f1) || return
  upload_if_missing "${SCENARIO_DIR}/${COMMIT_FILE}" "$key" "$expected"
}

upload_worker() {
  local rc=0
  if [[ "$MODE" == normal ]]; then
    write_status || return 66
    write_upload_manifest || return 66
    write_checksums || return 66
  fi
  validate_frozen_evidence || return $?
  upload_manifest_objects || rc=$?
  if [[ "$rc" -eq 0 ]]; then upload_final_metadata || rc=$?; fi
  if [[ "$rc" -eq 0 ]]; then commit_upload || rc=$?; fi
  return "$rc"
}

finalize() {
  local initial=$? worker rc budget=$FINALIZATION_SECONDS
  if [[ "${CANCELLED:-0}" -eq 1 ]]; then budget=10; fi
  [[ "$FINALIZING" -eq 0 ]] || return
  FINALIZING=1
  trap - EXIT
  # A second signal cancels only this run's finalizer, never a global browser.
  stop_owned_group "$NODE_PID"
  stop_owned_group "$XVFB_PID"
  if [[ "$MODE" == normal && "$PRIMARY_EXIT" -eq 0 && "$initial" -ne 0 ]]; then PRIMARY_EXIT=$initial; fi
  export SCENARIO_DIR RUN_ID CSD_SCENARIO PRIMARY_EXIT SIGNAL SOURCE_COMMIT DEPLOYMENT_MANIFEST_SHA256
  export AWS_CLI_BIN EVIDENCE_BUCKET COMMIT_FILE FAILURE_FILE MODE
  export -f write_status write_upload_manifest write_checksums write_upload_commit remote_object_sha256 bounded_aws upload_if_missing upload_manifest_objects upload_final_metadata validate_frozen_evidence commit_upload upload_worker
  export FINALIZATION_BUDGET=$budget
  export LOG_BLOCKS
  setsid timeout --signal=TERM --kill-after=2 "$budget" bash -c 'FINALIZATION_DEADLINE=$((SECONDS + FINALIZATION_BUDGET)); upload_worker' >/dev/null 2>/dev/null &
  worker=$!
  FINALIZER_PID=$worker
  wait "$worker"
  rc=$?
  if [[ "$rc" -eq 130 || "$rc" -eq 143 ]]; then
    kill -KILL -- "-$worker" 2>/dev/null || true
    wait "$worker" 2>/dev/null || true
  fi
  FINALIZER_PID=""
  UPLOAD_EXIT=$rc
  if [[ "$rc" -eq 0 ]]; then
    UPLOAD_COMMITTED=true
    rm -f "${SCENARIO_DIR}/${FAILURE_FILE}"
    case "$PRIMARY_EXIT" in
    0) OUTCOME=ok ;;
    124 | 137) OUTCOME=timeout ;;
    130 | 143) OUTCOME=interrupted ;;
    64 | 78 | 69) OUTCOME=fatal_config ;;
    *) OUTCOME=scenario_failure ;;
    esac
    rc=$PRIMARY_EXIT
  else
    write_failure_marker "$rc" upload || true
    classify_exit "$rc"
    if [[ "${CANCELLED:-0}" -eq 1 ]]; then
      OUTCOME=interrupted
      rc=$PRIMARY_EXIT
    fi
  fi
  write_execution_result || exit 66
  exit "$rc"
}

on_signal() {
  SIGNAL=$1 PRIMARY_EXIT=$2 OUTCOME=interrupted CANCELLED=1
  if [[ -n "${FINALIZER_PID:-}" ]]; then
    kill -TERM -- "-$FINALIZER_PID" 2>/dev/null || true
    return
  fi
  exit "$2"
}

# Returning the scenario status lets the shell invoke its EXIT finalizer once.
wait_for_scenario() {
  wait "$NODE_PID"
  PRIMARY_EXIT=$?
  return "$PRIMARY_EXIT"
}

# The metadata fixture performs no browser/network work or deployed safety bypass.
if [[ "${1:-}" == --finalize-test ]]; then
  [[ $# -eq 4 ]] || exit 64
  SCENARIO_DIR=$2 RUN_ID=$3 CSD_SCENARIO=$4
  SOURCE_COMMIT=0123456789abcdef0123456789abcdef01234567
  DEPLOYMENT_MANIFEST_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  write_status && write_upload_manifest && write_checksums && validate_frozen_evidence && write_upload_commit
  exit $?
fi

RUNTIME_ENV=${RUNTIME_ENV:-/etc/traffic-generator/runtime.env}
CALLER_DISPLAY=${DISPLAY-}
read_runtime_env || {
  echo 'ERROR: runtime configuration rejected' >&2
  exit 78
}
MODE=normal
if [[ "${1:-}" == --retry-upload ]]; then
  [[ $# -eq 2 ]] || exit 64
  MODE=retry
  SCENARIO_DIR=$2
  [[ "$SCENARIO_DIR" == "$RESULTS_ROOT/"* && "$SCENARIO_DIR" != *'..'* && ! -L "$SCENARIO_DIR" ]] || exit 66
  CSD_SCENARIO=$(basename "$SCENARIO_DIR")
  RESULTS_DIR=$(dirname "$SCENARIO_DIR")
  RUN_ID=$(basename "$RESULTS_DIR")
else
  [[ $# -eq 0 ]] || exit 64
  RUN_ID=${RUN_ID:-csd-$(date -u +%Y%m%dt%H%M%Sz)-$$}
  CSD_SCENARIO=${CSD_SCENARIO:-}
  RESULTS_DIR="${RESULTS_ROOT}/${RUN_ID}"
  SCENARIO_DIR="${RESULTS_DIR}/${CSD_SCENARIO}"
fi
[[ "$RUN_ID" =~ ^[a-z0-9][a-z0-9-]{0,127}$ ]] || exit 64
validate_scenario || exit 64
read_policy || exit 78
[[ "$SCENARIO_DIR" == "${RESULTS_ROOT}/${RUN_ID}/${CSD_SCENARIO}" ]] || exit 66
[[ ! -L "$RESULTS_ROOT" && ! -L "$RESULTS_DIR" && ! -L "$SCENARIO_DIR" ]] || exit 66
[[ "$(realpath -m "$SCENARIO_DIR")" == "$SCENARIO_DIR" ]] || exit 66
[[ -d "$RESULTS_ROOT" ]] || exit 78
for command in flock setsid timeout jq sha256sum; do command -v "$command" >/dev/null || exit 69; done
[[ -e "$LOCK_PATH" && ! -L "$LOCK_PATH" ]] || exit 78
exec 9<>"$LOCK_PATH" || exit 78
if ! flock -n 9; then
  # Never overwrite an active run's result on contention.
  echo '{"schemaVersion":1,"outcome":"busy"}'
  exit 75
fi
preflight_result() {
  local rc=$?
  if [[ "$rc" -ne 0 && -d "$RESULTS_DIR" ]]; then
    classify_exit "$rc"
    PRIMARY_EXIT=null UPLOAD_EXIT=null
    write_execution_result || true
  fi
}
if [[ "$MODE" == normal ]]; then
  [[ ! -e "$RESULTS_DIR" ]] || exit 66
  mkdir "$RESULTS_DIR" || exit 78
fi
trap 'preflight_result' EXIT
[[ -n "${AWS_CLI_BIN:-}" && -n "${AWS_CLI_VERSION:-}" && -n "${EVIDENCE_BUCKET:-}" && -x "$AWS_CLI_BIN" ]] || exit 78
[[ "$(timeout 5 "$AWS_CLI_BIN" --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)" == "$AWS_CLI_VERSION" ]] || exit 78
if [[ "$MODE" == retry ]]; then
  [[ -d "$SCENARIO_DIR" ]] || exit 66
  PRIMARY_EXIT=$(jq -er '.browserExit | select(type == "number" and floor == . and . >= 0 and . <= 255)' "${SCENARIO_DIR}/run-status.json") || exit 66
  SIGNAL=$(jq -er '.signal | select(. == "" or . == "TERM" or . == "INT")' "${SCENARIO_DIR}/run-status.json") || exit 66
  # Preserve the frozen browser signal; only new signals set CANCELLED.
  trap 'finalize' EXIT
  trap 'on_signal TERM 143' TERM
  trap 'on_signal INT 130' INT
  exit 0
fi
TARGET_URL=${TARGET_URL:-}
[[ "$TARGET_URL" == https://client-side-defense.f5-sales-demo.com ]] || exit 67
[[ "${CSD_AWS_RUNTIME:-}" == 1 && "${SOURCE_COMMIT:-}" =~ ^[0-9a-f]{40}$ && "${DEPLOYMENT_MANIFEST_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || exit 78
CHROME_PATH=/opt/chrome/chrome
DISPLAY="${CALLER_DISPLAY:-:100}"
[[ "$DISPLAY" =~ ^:[0-9]+$ && "$DISPLAY" != :99 ]] || exit 78
[[ -x "$CHROME_PATH" ]] || exit 69
command -v Xvfb >/dev/null || exit 69
"$NODE_BIN" -e "require.resolve('/opt/traffic-generator/node_modules/playwright-core/package.json')" >/dev/null 2>&1 || exit 69
mkdir -p "$RESULTS_DIR" || exit 78
mkdir "$SCENARIO_DIR" || exit 66
export TARGET_URL EVIDENCE_BUCKET RESULTS_DIR RUN_ID CSD_SCENARIO DISPLAY CHROME_PATH
export CSD_AWS_OUTPUT_DIR="$RESULTS_DIR" NODE_PATH=/opt/traffic-generator/node_modules
trap 'finalize' EXIT
trap 'on_signal TERM 143' TERM
trap 'on_signal INT 130' INT
ulimit -f "$FILE_BLOCKS" # Finite per-file evidence ceiling from canonical policy.
setsid Xvfb "$DISPLAY" -screen 0 1440x900x24 -nolisten tcp >"${SCENARIO_DIR}/xvfb.log" 2>&1 &
XVFB_PID=$!
sleep 1
kill -0 "$XVFB_PID" 2>/dev/null || {
  PRIMARY_EXIT=70
  exit 70
}
setsid timeout --foreground --signal=TERM --kill-after="$CLEANUP_SECONDS" "$SCENARIO_SECONDS" "$NODE_BIN" "$SCRIPT_DIR/run.mjs" >"${SCENARIO_DIR}/runner.log" 2>&1 &
NODE_PID=$!
wait_for_scenario
