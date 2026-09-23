#!/usr/bin/env bash
set -uo pipefail

COMMIT_FILE=upload-commit.json
FAILURE_FILE=.finalization-failed.json

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
  local key=$1 response error_file rc
  error_file=$(mktemp) || return
  if response=$(aws s3api head-object \
    --bucket "$EVIDENCE_BUCKET" --key "$key" --output json 2>"$error_file"); then
    rm -f "$error_file"
    jq -er '
      [(.Metadata // {}) | to_entries[] | select((.key | ascii_downcase) == "sha256") | .value]
      | if length == 1 then .[0] else empty end
    ' <<<"$response"
    return $?
  else
    rc=$?
  fi
  if grep -Eqi '(^|[^0-9])404([^0-9]|$)|Not Found|NoSuchKey' "$error_file"; then
    rm -f "$error_file"
    return 44
  fi
  cat "$error_file" >&2
  rm -f "$error_file"
  return "$rc"
}

upload_if_missing() {
  local file=$1 key=$2 expected=$3 actual remote rc
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 66
  actual=$(sha256sum "$file" | cut -d' ' -f1) || return
  [[ "$actual" == "$expected" ]] || return 66
  if remote=$(remote_object_sha256 "$key"); then
    [[ "$(printf '%s' "$remote" | tr '[:upper:]' '[:lower:]')" == "$expected" ]] || {
      echo "ERROR: remote object checksum metadata mismatch: ${key}" >&2
      return 74
    }
    return 0
  else
    rc=$?
  fi
  [[ "$rc" -eq 44 ]] || return "$rc"
  aws s3 cp "$file" "s3://${EVIDENCE_BUCKET}/${key}" \
    --metadata "sha256=${expected}" --only-show-errors
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
  manifest_run=$(jq -r '.runId' "${SCENARIO_DIR}/upload-manifest.json") || return
  manifest_scenario=$(jq -r '.scenario' "${SCENARIO_DIR}/upload-manifest.json") || return
  [[ "$manifest_run" == "$RUN_ID" && "$manifest_scenario" == "$CSD_SCENARIO" ]] || return 65
  (cd "$SCENARIO_DIR" && sha256sum --check --strict SHA256SUMS >/dev/null) || return 66
}

commit_upload() {
  local key="runs/${RUN_ID}/${CSD_SCENARIO}/${COMMIT_FILE}" expected
  write_upload_commit || return
  expected=$(sha256sum "${SCENARIO_DIR}/${COMMIT_FILE}" | cut -d' ' -f1) || return
  upload_if_missing "${SCENARIO_DIR}/${COMMIT_FILE}" "$key" "$expected"
}

retry_upload() {
  local requested_dir=$1 upload_exit=0
  SCENARIO_DIR=$(cd "$requested_dir" 2>/dev/null && pwd) || {
    echo "ERROR: retry directory is unavailable: ${requested_dir}" >&2
    return 66
  }
  CSD_SCENARIO=$(basename "$SCENARIO_DIR")
  RUN_ID=$(basename "$(dirname "$SCENARIO_DIR")")
  case "$CSD_SCENARIO" in
  login-credential-skimmer | registration-harvester | payment-overlay-card-skimmer | obfuscated-loader | multi-cdn-injection | tag-manager-hijack | multi-channel-exfiltration | high-volume-domain-exfiltration | form-overlay | keylogger-simulation | maximum-detection) ;;
  *)
    echo 'ERROR: retry scenario is not allowlisted' >&2
    return 64
    ;;
  esac
  [[ "$RUN_ID" =~ ^[a-z0-9][a-z0-9-]{0,127}$ ]] || {
    echo 'ERROR: retry run ID contains unsafe path characters' >&2
    return 64
  }
  PRIMARY_EXIT=$(jq -r '.browserExit' "${SCENARIO_DIR}/run-status.json") || return 66
  SIGNAL=$(jq -r '.signal' "${SCENARIO_DIR}/run-status.json") || return 66
  validate_frozen_evidence || {
    upload_exit=$?
    write_failure_marker "$upload_exit" validation
    return "$upload_exit"
  }
  upload_manifest_objects || upload_exit=$?
  if [[ "$upload_exit" -eq 0 ]]; then upload_final_metadata || upload_exit=$?; fi
  if [[ "$upload_exit" -eq 0 ]]; then commit_upload || upload_exit=$?; fi
  if [[ "$upload_exit" -ne 0 ]]; then
    write_failure_marker "$upload_exit" retry-upload
    return "$upload_exit"
  fi
  rm -f "${SCENARIO_DIR}/${FAILURE_FILE}"
  return "$PRIMARY_EXIT"
}

# shellcheck disable=SC2329 # invoked by EXIT trap
finalize() {
  local trap_exit=$? upload_exit=0 final_exit
  [[ "$FINALIZING" -eq 0 ]] || return
  FINALIZING=1
  trap - EXIT TERM INT
  [[ -n "$PRIMARY_EXIT" ]] || PRIMARY_EXIT=$trap_exit

  if [[ -n "$XVFB_PID" ]] && kill -0 "$XVFB_PID" 2>/dev/null; then
    kill "$XVFB_PID" 2>/dev/null || true
    wait "$XVFB_PID" 2>/dev/null || true
  fi
  [[ -d "$SCENARIO_DIR" ]] || exit 1
  rm -f "${SCENARIO_DIR}/${COMMIT_FILE}" "${SCENARIO_DIR}/${FAILURE_FILE}"

  write_status || upload_exit=$?
  if [[ "$upload_exit" -eq 0 ]]; then write_upload_manifest || upload_exit=$?; fi
  if [[ "$upload_exit" -eq 0 ]]; then write_checksums || upload_exit=$?; fi
  if [[ "$upload_exit" -eq 0 ]]; then validate_frozen_evidence || upload_exit=$?; fi
  if [[ "$upload_exit" -eq 0 ]]; then upload_manifest_objects || upload_exit=$?; fi
  if [[ "$upload_exit" -eq 0 ]]; then upload_final_metadata || upload_exit=$?; fi
  if [[ "$upload_exit" -eq 0 ]]; then commit_upload || upload_exit=$?; fi

  if [[ "$upload_exit" -ne 0 ]]; then
    write_failure_marker "$upload_exit" initial-upload
    exit "$upload_exit"
  fi
  rm -f "${SCENARIO_DIR}/${FAILURE_FILE}"
  final_exit=$PRIMARY_EXIT
  exit "$final_exit"
}

RUNTIME_ENV=${RUNTIME_ENV:-/etc/traffic-generator/runtime.env}
if [[ "${1:-}" == "--retry-upload" ]]; then
  [[ $# -eq 2 ]] || {
    echo 'usage: run.sh --retry-upload SCENARIO_DIR' >&2
    exit 64
  }
  [[ -r "$RUNTIME_ENV" ]] || {
    echo "ERROR: runtime environment is unavailable: $RUNTIME_ENV" >&2
    exit 78
  }
  set -a
  # shellcheck disable=SC1090 # validated runtime environment path
  source "$RUNTIME_ENV"
  set +a
  EVIDENCE_BUCKET="${EVIDENCE_BUCKET:?EVIDENCE_BUCKET is required}"
  for command in aws jq sha256sum; do command -v "$command" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: ${command}" >&2
    exit 69
  }; done
  retry_upload "$2"
  exit $?
fi

if [[ "${1:-}" == "--finalize-test" ]]; then
  [[ $# -eq 4 ]] || {
    echo 'usage: run.sh --finalize-test SCENARIO_DIR RUN_ID SCENARIO' >&2
    exit 64
  }
  SCENARIO_DIR=$2
  RUN_ID=$3
  CSD_SCENARIO=$4
  PRIMARY_EXIT=0
  SIGNAL=""
  SOURCE_COMMIT=0123456789abcdef0123456789abcdef01234567
  DEPLOYMENT_MANIFEST_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  write_status
  write_upload_manifest
  write_checksums
  validate_frozen_evidence
  write_upload_commit
  exit 0
fi

CALLER_DISPLAY=${DISPLAY-}
[[ -r "$RUNTIME_ENV" ]] || {
  echo "ERROR: runtime environment is unavailable: $RUNTIME_ENV" >&2
  exit 78
}
set -a
# shellcheck disable=SC1090 # validated runtime environment path
source "$RUNTIME_ENV"
set +a

EXPECTED_HOST="client-side-defense.f5-sales-demo.com"
TARGET_URL="${TARGET_URL:?TARGET_URL is required}"
EVIDENCE_BUCKET="${EVIDENCE_BUCKET:?EVIDENCE_BUCKET is required}"
SOURCE_REPOSITORY_URL="${SOURCE_REPOSITORY_URL:?SOURCE_REPOSITORY_URL is required}"
SOURCE_COMMIT="${SOURCE_COMMIT:?SOURCE_COMMIT is required}"
AWS_REGION="${AWS_REGION:?AWS_REGION is required}"
AMI_ID="${AMI_ID:?AMI_ID is required}"
DEPLOYMENT_MANIFEST_VERSION="${DEPLOYMENT_MANIFEST_VERSION:?DEPLOYMENT_MANIFEST_VERSION is required}"
DEPLOYMENT_MANIFEST_SHA256="${DEPLOYMENT_MANIFEST_SHA256:?DEPLOYMENT_MANIFEST_SHA256 is required}"
[[ "${CSD_AWS_RUNTIME:-}" == "1" ]] || {
  echo 'ERROR: CSD_AWS_RUNTIME must equal 1' >&2
  exit 78
}
RESULTS_ROOT="${RESULTS_ROOT:-/opt/traffic-generator/runtime/results}"
RUN_ID="${RUN_ID:-csd-$(date -u +%Y%m%dt%H%M%Sz)-$$}"
RESULTS_DIR="${RESULTS_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
CSD_SCENARIO="${CSD_SCENARIO:?CSD_SCENARIO is required}"
SCENARIO_DIR="${RESULTS_DIR}/${CSD_SCENARIO}"
# The deployed health service owns :99. Preserve the run-specific display supplied by
# the SSM launcher, otherwise use the dedicated interactive-run display.
DISPLAY="${CALLER_DISPLAY:-:100}"
CHROME_PATH=/opt/chrome/chrome
XVFB_PID=""
NODE_PID=""
PRIMARY_EXIT=""
SIGNAL=""
FINALIZING=0

# shellcheck disable=SC2329 # invoked by signal traps
on_signal() {
  SIGNAL=$1
  PRIMARY_EXIT=$2
  if [[ -n "$NODE_PID" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
    kill -"$1" "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" 2>/dev/null || true
  fi
  exit "$2"
}

case "$TARGET_URL" in "https://${EXPECTED_HOST}" | "https://${EXPECTED_HOST}/"*) ;; *)
  echo "ERROR: TARGET_URL must use exact HTTPS host ${EXPECTED_HOST}" >&2
  exit 64
  ;;
esac
case "$CSD_SCENARIO" in
login-credential-skimmer | registration-harvester | payment-overlay-card-skimmer | obfuscated-loader | multi-cdn-injection | tag-manager-hijack | multi-channel-exfiltration | high-volume-domain-exfiltration | form-overlay | keylogger-simulation | maximum-detection) ;;
*)
  echo 'ERROR: CSD_SCENARIO is not allowlisted' >&2
  exit 64
  ;;
esac
[[ "$RUN_ID" =~ ^[a-z0-9][a-z0-9-]{0,127}$ ]] || {
  echo 'ERROR: RUN_ID contains unsafe path characters' >&2
  exit 64
}
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'ERROR: SOURCE_COMMIT is invalid' >&2
  exit 78
}
[[ "$DEPLOYMENT_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  echo 'ERROR: DEPLOYMENT_MANIFEST_SHA256 is invalid' >&2
  exit 78
}
[[ -x "$CHROME_PATH" ]] || {
  echo 'ERROR: /opt/chrome/chrome is not executable' >&2
  exit 69
}
for command in node Xvfb aws jq sha256sum; do command -v "$command" >/dev/null 2>&1 || {
  echo "ERROR: required command not found: ${command}" >&2
  exit 69
}; done
node -e "require.resolve('/opt/traffic-generator/node_modules/playwright-core/package.json')" >/dev/null 2>&1 || {
  echo 'ERROR: playwright-core is not installed at /opt/traffic-generator/node_modules' >&2
  exit 69
}

mkdir -p "$RESULTS_DIR"
if ! mkdir "$SCENARIO_DIR"; then
  echo "ERROR: scenario evidence directory already exists: $SCENARIO_DIR" >&2
  exit 73
fi
export TARGET_URL EVIDENCE_BUCKET RESULTS_DIR RUN_ID CSD_SCENARIO DISPLAY CHROME_PATH
export SOURCE_REPOSITORY_URL SOURCE_COMMIT AWS_REGION AMI_ID DEPLOYMENT_MANIFEST_VERSION DEPLOYMENT_MANIFEST_SHA256 CSD_AWS_RUNTIME
export CSD_AWS_OUTPUT_DIR="$RESULTS_DIR"
export NODE_PATH=/opt/traffic-generator/node_modules

trap finalize EXIT
trap 'on_signal TERM 143' TERM
trap 'on_signal INT 130' INT
Xvfb "$DISPLAY" -screen 0 1440x900x24 -nolisten tcp >"${SCENARIO_DIR}/xvfb.log" 2>&1 &
XVFB_PID=$!
sleep 1
kill -0 "$XVFB_PID" 2>/dev/null || {
  echo 'ERROR: Xvfb failed to start' >&2
  exit 70
}
set +e
node "$(dirname "$0")/run.mjs" >"${SCENARIO_DIR}/runner.log" 2>&1 &
NODE_PID=$!
wait "$NODE_PID"
PRIMARY_EXIT=$?
NODE_PID=""
set -e
exit "$PRIMARY_EXIT"
