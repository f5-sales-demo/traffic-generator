#!/usr/bin/env bash
# Run a long Antigravity phase with live, machine-readable progress heartbeats.
set -euo pipefail

usage() {
  echo "Usage: $0 --phase LABEL -- COMMAND [ARG ...]" >&2
}

phase=""
while [ "$#" -gt 0 ]; do
  case "$1" in
  --phase)
    [ "$#" -ge 2 ] || {
      usage
      exit 2
    }
    phase=$2
    shift 2
    ;;
  --)
    shift
    break
    ;;
  *)
    usage
    exit 2
    ;;
  esac
done

case "$phase" in
'' | *[!A-Za-z0-9._-]*)
  echo "[progress] phase must use only letters, digits, dot, underscore, or hyphen" >&2
  exit 2
  ;;
esac
[ "$#" -gt 0 ] || {
  usage
  exit 2
}

heartbeat_seconds=${AGY_PROGRESS_INTERVAL_SECONDS:-30}
case "$heartbeat_seconds" in
'' | 0 | *[!0-9]*)
  echo "[progress] AGY_PROGRESS_INTERVAL_SECONDS must be a positive integer" >&2
  exit 2
  ;;
esac

started_epoch=$(date +%s)
command_pid=""
heartbeat_pid=""

timestamp() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

elapsed_seconds() {
  local now
  now=$(date +%s)
  printf '%s' "$((now - started_epoch))"
}

emit_progress() {
  local state=$1 elapsed=$2 exit_code=${3:-}
  if [ -n "$exit_code" ]; then
    printf '[PROGRESS] component=antigravity phase=%s state=%s elapsed_seconds=%s heartbeat_seconds=%s timestamp=%s exit_code=%s\n' \
      "$phase" "$state" "$elapsed" "$heartbeat_seconds" "$(timestamp)" "$exit_code" >&2
  else
    printf '[PROGRESS] component=antigravity phase=%s state=%s elapsed_seconds=%s heartbeat_seconds=%s timestamp=%s\n' \
      "$phase" "$state" "$elapsed" "$heartbeat_seconds" "$(timestamp)" >&2
  fi
}

append_summary() {
  local state=$1 elapsed=$2 exit_code=$3 completed_at
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  completed_at=$(timestamp)
  if ! printf -- '- Antigravity `%s`: **%s** after `%ss` (exit code `%s`, completed `%s`).\n' \
    "$phase" "$state" "$elapsed" "$exit_code" "$completed_at" >>"$GITHUB_STEP_SUMMARY"; then
    printf '[PROGRESS] component=antigravity phase=%s state=summary-write-failed elapsed_seconds=%s heartbeat_seconds=%s timestamp=%s\n' \
      "$phase" "$elapsed" "$heartbeat_seconds" "$completed_at" >&2
  fi
}

# shellcheck disable=SC2329 # invoked through the EXIT trap below
cleanup() {
  if [ -n "$heartbeat_pid" ]; then
    kill "$heartbeat_pid" 2>/dev/null || true
    wait "$heartbeat_pid" 2>/dev/null || true
  fi
  if [ -n "$command_pid" ]; then
    kill "$command_pid" 2>/dev/null || true
    wait "$command_pid" 2>/dev/null || true
  fi
}

# shellcheck disable=SC2329 # invoked through the signal traps below
handle_signal() {
  local status=$1 elapsed
  trap - INT TERM HUP
  elapsed=$(elapsed_seconds)
  emit_progress interrupted "$elapsed" "$status"
  append_summary interrupted "$elapsed" "$status"
  exit "$status"
}

trap cleanup EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM
trap 'handle_signal 129' HUP

emit_progress started 0
"$@" &
command_pid=$!
(
  while sleep "$heartbeat_seconds"; do
    kill -0 "$command_pid" 2>/dev/null || exit 0
    emit_progress running "$(elapsed_seconds)"
  done
) &
heartbeat_pid=$!

command_status=0
wait "$command_pid" || command_status=$?
command_pid=""
kill "$heartbeat_pid" 2>/dev/null || true
wait "$heartbeat_pid" 2>/dev/null || true
heartbeat_pid=""

elapsed=$(elapsed_seconds)
if [ "$command_status" -eq 0 ]; then
  emit_progress completed "$elapsed" 0
  append_summary completed "$elapsed" 0
else
  emit_progress failed "$elapsed" "$command_status"
  append_summary failed "$elapsed" "$command_status"
fi
exit "$command_status"
