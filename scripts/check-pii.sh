#!/usr/bin/env bash
# Materialize tracked Git blobs into a private temporary directory, then run the
# content scanner. The Python scanner never starts a process and the shell never
# evaluates repository content as code.
set -euo pipefail

SCOPE="head"
MODE="audit"
FORMAT="text"

usage() {
  cat <<'EOF'
Usage: bash scripts/check-pii.sh [--scope staged|head|history] [--mode audit|enforce] [--format text|json]

Exit 0 = clean, 1 = findings, 2 = the scan could not run.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
  --scope)
    [ "$#" -ge 2 ] || {
      usage >&2
      exit 2
    }
    SCOPE=$2
    shift 2
    ;;
  --mode)
    [ "$#" -ge 2 ] || {
      usage >&2
      exit 2
    }
    MODE=$2
    shift 2
    ;;
  --format)
    [ "$#" -ge 2 ] || {
      usage >&2
      exit 2
    }
    FORMAT=$2
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "PII scan error: unknown argument: $1" >&2
    usage >&2
    exit 2
    ;;
  esac
done

case "$SCOPE" in staged | head | history) ;; *)
  echo "PII scan error: invalid scope: $SCOPE" >&2
  exit 2
  ;;
esac
case "$MODE" in audit | enforce) ;; *)
  echo "PII scan error: invalid mode: $MODE" >&2
  exit 2
  ;;
esac
case "$FORMAT" in text | json) ;; *)
  echo "PII scan error: invalid format: $FORMAT" >&2
  exit 2
  ;;
esac

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "PII scan error: not a Git repository" >&2
  exit 2
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SCANNER="${SCRIPT_DIR}/check_pii.py"
if [ ! -f "$SCANNER" ]; then
  echo "PII scan error: content scanner is missing: $SCANNER" >&2
  exit 2
fi

WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
COUNT=0

add_blob() {
  local path=$1 oid=$2 mode=${3:-100644}
  [ "$mode" != "120000" ] || return 0
  COUNT=$((COUNT + 1))
  printf '%s' "$path" >"${WORK}/${COUNT}.path"
  if ! git cat-file blob "$oid" >"${WORK}/${COUNT}.blob"; then
    echo "PII scan error: cannot read tracked blob $oid" >&2
    exit 2
  fi
}

materialize_staged() {
  local record metadata path mode oid stage
  while IFS= read -r -d '' record; do
    metadata=${record%%$'\t'*}
    path=${record#*$'\t'}
    read -r mode oid stage <<<"$metadata"
    [ "$stage" = "0" ] || continue
    add_blob "$path" "$oid" "$mode"
  done < <(git ls-files -s -z)
}

materialize_head() {
  local record metadata path mode object_type oid
  while IFS= read -r -d '' record; do
    metadata=${record%%$'\t'*}
    path=${record#*$'\t'}
    read -r mode object_type oid <<<"$metadata"
    [ "$object_type" = "blob" ] || continue
    add_blob "$path" "$oid" "$mode"
  done < <(git ls-tree -r -z --full-tree HEAD)
}

materialize_history() {
  local oid object_type commit message object_line type_line path type_oid
  git rev-list --objects --all >"${WORK}/objects"
  cut -d ' ' -f 1 "${WORK}/objects" |
    git cat-file --batch-check='%(objectname) %(objecttype)' >"${WORK}/types"

  while IFS= read -r object_line <&3 && IFS= read -r type_line <&4; do
    oid=${object_line%% *}
    path=${object_line#"$oid"}
    path=${path# }
    read -r type_oid object_type <<<"$type_line"
    if [ "$type_oid" != "$oid" ]; then
      echo "PII scan error: Git returned a mismatched history inventory" >&2
      exit 2
    fi
    [ "$object_type" = "blob" ] || continue
    [ -n "$path" ] || path="<blob:${oid:0:12}>"
    add_blob "$path" "$oid"
  done 3<"${WORK}/objects" 4<"${WORK}/types"

  # -z terminates each record with NUL; the explicit NUL separates the commit
  # object ID from its possibly-multiline message.
  while IFS= read -r -d '' commit && IFS= read -r -d '' message; do
    COUNT=$((COUNT + 1))
    printf '<commit:%s>' "${commit:0:12}" >"${WORK}/${COUNT}.path"
    printf '%s' "$message" >"${WORK}/${COUNT}.blob"
  done < <(git log --all -z --format='%H%x00%B')
}

case "$SCOPE" in
staged) materialize_staged ;;
head) materialize_head ;;
history) materialize_history ;;
esac

python3 "$SCANNER" \
  --input-dir "$WORK" \
  --scope "$SCOPE" \
  --mode "$MODE" \
  --format "$FORMAT"
