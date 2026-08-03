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
  local materialized_count object_count ref target target_type type_count
  if ! git rev-list --objects --all >"${WORK}/objects"; then
    echo "PII scan error: cannot enumerate reachable Git objects" >&2
    exit 2
  fi
  if ! cut -d ' ' -f 1 "${WORK}/objects" |
    git cat-file --batch-check='%(objectname) %(objecttype)' >"${WORK}/types"; then
    echo "PII scan error: cannot inspect reachable Git objects" >&2
    exit 2
  fi
  object_count=$(wc -l <"${WORK}/objects")
  type_count=$(wc -l <"${WORK}/types")
  if [ "$object_count" -ne "$type_count" ]; then
    echo "PII scan error: Git returned a truncated history inventory" >&2
    exit 2
  fi

  : >"${WORK}/commits"
  while IFS= read -r object_line <&3 && IFS= read -r type_line <&4; do
    oid=${object_line%% *}
    read -r type_oid object_type <<<"$type_line"
    if [ "$type_oid" != "$oid" ]; then
      echo "PII scan error: Git returned a mismatched history inventory" >&2
      exit 2
    fi
    if [ "$object_type" = "commit" ]; then
      printf '%s\n' "$oid" >>"${WORK}/commits"
    fi
  done 3<"${WORK}/objects" 4<"${WORK}/types"

  if ! git diff-tree --stdin --root -m -r --raw -z --no-renames \
    --no-commit-id <"${WORK}/commits" >"${WORK}/history-diffs"; then
    echo "PII scan error: cannot enumerate reachable history changes" >&2
    exit 2
  fi

  : >"${WORK}/history-trees"
  if ! git for-each-ref --format='%(refname)' >"${WORK}/refs"; then
    echo "PII scan error: cannot enumerate Git refs" >&2
    exit 2
  fi
  while IFS= read -r ref; do
    if ! target=$(git rev-parse "${ref}^{}"); then
      echo "PII scan error: cannot resolve a reachable ref" >&2
      exit 2
    fi
    if ! target_type=$(git cat-file -t "$target"); then
      echo "PII scan error: cannot inspect a reachable ref" >&2
      exit 2
    fi
    case "$target_type" in
    commit) ;;
    tree)
      if ! git ls-tree -r -z --full-tree "$target" >>"${WORK}/history-trees"; then
        echo "PII scan error: cannot enumerate a reachable tree" >&2
        exit 2
      fi
      ;;
    blob)
      printf '100644 blob %s\t<blob:%s>\0' "$target" "${target:0:12}" \
        >>"${WORK}/history-trees"
      ;;
    *)
      echo "PII scan error: reachable ref has an unsupported object type" >&2
      exit 2
      ;;
    esac
  done <"${WORK}/refs"

  if ! PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'import sys; from pathlib import Path; from check_pii import write_history_associations; write_history_associations(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))' \
    "${WORK}/history-diffs" "${WORK}/history-trees" \
    "${WORK}/history-associations" "${WORK}/history-requests"; then
    echo "PII scan error: cannot validate reachable history associations" >&2
    exit 2
  fi

  if ! git cat-file --batch <"${WORK}/history-requests" \
    >"${WORK}/history-batch"; then
    echo "PII scan error: cannot read reachable history blobs" >&2
    exit 2
  fi
  if ! materialized_count=$(PYTHONPATH="$SCRIPT_DIR" python3 -c \
    'import sys; from pathlib import Path; from check_pii import materialize_history_associations; print(materialize_history_associations(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), int(sys.argv[5])))' \
    "${WORK}/history-associations" "${WORK}/history-requests" \
    "${WORK}/history-batch" "$WORK" "$COUNT"); then
    echo "PII scan error: cannot materialize reachable history blobs" >&2
    exit 2
  fi
  COUNT=$materialized_count

  # -z terminates each record with NUL; the explicit NUL separates the commit
  # object ID from its possibly-multiline message.
  if ! git log --no-walk=unsorted --stdin -z --format='%H%x00%B' \
    <"${WORK}/commits" >"${WORK}/messages"; then
    echo "PII scan error: cannot enumerate reachable commit messages" >&2
    exit 2
  fi
  while IFS= read -r -d '' commit && IFS= read -r -d '' message; do
    COUNT=$((COUNT + 1))
    printf '<commit:%s>' "${commit:0:12}" >"${WORK}/${COUNT}.path"
    printf '%s' "$message" >"${WORK}/${COUNT}.blob"
  done <"${WORK}/messages"
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
