#!/usr/bin/env bash
# Decide whether a pull-request branch represents the repository's next stable major release.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/translation-release-policy.sh --head-ref <branch> --tags-file <path>

Prints a deterministic key/value decision. Translation is eligible only for an
exact release/vN.0.0 branch where N is one greater than the highest stable root
vX.Y.Z tag. Namespaced and prerelease tags are ignored. With no stable tags,
the first eligible release is release/v1.0.0.
EOF
}

head_ref=""
tags_file=""
while [ "$#" -gt 0 ]; do
  case "$1" in
  --head-ref | --tags-file)
    [ "$#" -ge 2 ] || {
      echo "[i18n] $1 requires a value" >&2
      exit 2
    }
    case "$1" in
    --head-ref) head_ref=$2 ;;
    --tags-file) tags_file=$2 ;;
    esac
    shift 2
    ;;
  --help | -h)
    usage
    exit 0
    ;;
  *)
    echo "[i18n] unknown option: $1" >&2
    usage >&2
    exit 2
    ;;
  esac
done

[ -n "$head_ref" ] && [ -n "$tags_file" ] || {
  usage >&2
  exit 2
}
[ -f "$tags_file" ] || {
  echo "[i18n] tags file does not exist: $tags_file" >&2
  exit 2
}

eligible=false
release_version=""
reason="not-major-release-branch"
target_major=""
if [[ "$head_ref" =~ ^release/v([1-9][0-9]*)\.0\.0$ ]]; then
  target_major=${BASH_REMATCH[1]}
  release_version="v${target_major}.0.0"
  highest_major=0
  while IFS= read -r tag || [ -n "$tag" ]; do
    if [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
      major=${BASH_REMATCH[1]}
      if ((major > highest_major)); then
        highest_major=$major
      fi
    fi
  done <"$tags_file"
  expected_major=$((highest_major + 1))
  if ((target_major == expected_major)); then
    eligible=true
    reason="next-major-release"
  elif ((target_major <= highest_major)); then
    reason="major-already-released"
  else
    reason="major-sequence-gap"
  fi
fi

printf 'eligible=%s\n' "$eligible"
printf 'release_version=%s\n' "$release_version"
printf 'reason=%s\n' "$reason"
