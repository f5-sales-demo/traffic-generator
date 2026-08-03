#!/usr/bin/env bash
# Hermetic test for scripts/check-repo-hygiene.sh — the guard that rejects
# committed content which only works on the machine that produced it.
# Builds throwaway repositories, so it never inspects the repository it lives in.
# No network.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="${REPO_ROOT}/scripts/check-repo-hygiene.sh"

FAIL=0
WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

new_repo() {
  local dir="${WORK}/$1"
  mkdir -p "$dir"
  git -C "$dir" init -q -b main
  git -C "$dir" config user.email hygiene@test
  git -C "$dir" config user.name "Hygiene Test"
  printf 'ok\n' >"${dir}/README.md"
  git -C "$dir" add -A
  git -C "$dir" commit -qm baseline
  echo "$dir"
}

_run() {
  local rc=0 dir="$1"
  shift
  (cd "$dir" && bash "$SCRIPT" "$@") >/dev/null 2>&1 || rc=$?
  echo "$rc"
}

assert_clean() {
  local label="$1" dir="$2"
  shift 2
  local rc
  rc=$(_run "$dir" "$@")
  if [ "$rc" -eq 0 ]; then echo "[OK] $label -> clean"; else
    echo "[FAIL] $label — expected clean (0), got $rc"
    FAIL=1
  fi
}

assert_violation() {
  local label="$1" dir="$2"
  shift 2
  local rc
  rc=$(_run "$dir" "$@")
  if [ "$rc" -eq 1 ]; then echo "[OK] $label -> rejected"; else
    echo "[FAIL] $label — expected rejection (1), got $rc"
    FAIL=1
  fi
}

# --- a clean repository passes -------------------------------------------------
repo=$(new_repo clean)
assert_clean "baseline repository" "$repo"

# --- the defect this check exists for: an absolute symlink named node_modules ---
repo=$(new_repo abs-symlink)
ln -s /some/other/checkout/node_modules "${repo}/node_modules"
git -C "$repo" add -A --force
assert_violation "tracked symlink with an absolute target" "$repo"

# --- relative in-repo symlinks are legitimate and must not be flagged ----------
# Note the target is resolved relative to the LINK's directory: `../docs/shared.md`
# from a link at the repository root would resolve above the root, which is why the
# root-level link below has no leading `../`.
repo=$(new_repo rel-symlink)
mkdir -p "${repo}/docs"
printf 'shared\n' >"${repo}/docs/shared.md"
ln -s docs/shared.md "${repo}/link.md"
git -C "$repo" add -A
assert_clean "relative symlink inside the repository" "$repo"

repo=$(new_repo rel-symlink-updir)
mkdir -p "${repo}/docs"
printf 'shared\n' >"${repo}/shared.md"
ln -s ../shared.md "${repo}/docs/link.md"
git -C "$repo" add -A
assert_clean "relative symlink using ../ that stays inside the repository" "$repo"

# --- hardcoded home directories ------------------------------------------------
# acct1234 is synthetic but intentionally not a portable placeholder: these fixtures must exercise
# rejection of a concrete account segment on every supported platform.
repo=$(new_repo home-macos)
printf 'cache=/Users/acct1234/.cache/thing\n' >"${repo}/config.ini"
git -C "$repo" add -A
assert_violation "hardcoded /Users/<name>/ path" "$repo" --include-paths

repo=$(new_repo home-linux)
printf 'export DATA=/home/acct1234/data\n' >"${repo}/env.sh"
git -C "$repo" add -A
assert_violation "hardcoded /home/<name>/ path" "$repo" --include-paths

repo=$(new_repo home-windows)
printf 'path=C:\\Users\\acct1234\\AppData\n' >"${repo}/win.ini"
git -C "$repo" add -A
assert_violation "hardcoded C:\\Users\\<name>\\ path" "$repo" --include-paths

# --- placeholders are portable documentation, not violations -------------------
repo=$(new_repo placeholder)
printf 'Put the token in /Users/you/.config/token and /home/username/.netrc\n' >"${repo}/README.md"
git -C "$repo" add -A
assert_clean "placeholder home paths in documentation" "$repo" --include-paths

# --- CI home directories are not machine-specific ------------------------------
repo=$(new_repo ci-home)
printf 'workspace: /home/runner/work/repo/repo\n' >"${repo}/ci.yml"
git -C "$repo" add -A
assert_clean "CI runner home directory" "$repo" --include-paths

# --- the explicit escape hatch -------------------------------------------------
repo=$(new_repo allow-marker)
printf 'example=/Users/acct1234/thing  # repo-hygiene:allow\n' >"${repo}/notes.md"
git -C "$repo" add -A
assert_clean "line carrying repo-hygiene:allow" "$repo" --include-paths

# --- untracked files are out of scope: the check gates what is committed -------
repo=$(new_repo untracked)
printf 'cache=/Users/acct1234/.cache\n' >"${repo}/scratch.txt"
assert_clean "untracked file with a home path" "$repo" --include-paths

# --- binary files must not produce noise ---------------------------------------
repo=$(new_repo binary)
printf '\x00\x01/Users/acct1234/x\x00' >"${repo}/blob.bin"
git -C "$repo" add -A
assert_clean "binary file is skipped" "$repo" --include-paths

# --- an exact home directory, with no trailing slash ---------------------------
repo=$(new_repo home-exact)
printf 'HOME=/home/acct1234\n' >"${repo}/env.sh"
git -C "$repo" add -A
assert_violation "hardcoded /home/<name> with no trailing slash" "$repo" --include-paths

repo=$(new_repo home-exact-macos)
printf 'root=/Users/acct1234\n' >"${repo}/conf.ini"
git -C "$repo" add -A
assert_violation "hardcoded /Users/<name> with no trailing slash" "$repo" --include-paths

# --- an allowed path must not launder a real one on the same line --------------
repo=$(new_repo mixed-ci)
printf 'PATH=/home/runner/bin:/home/acct1234/bin\n' >"${repo}/paths.sh"
git -C "$repo" add -A
assert_violation "real home alongside a CI home on one line" "$repo" --include-paths

repo=$(new_repo mixed-placeholder)
printf 'see /Users/you/notes and /Users/acct1234/notes\n' >"${repo}/README.md"
git -C "$repo" add -A
assert_violation "real home alongside a placeholder on one line" "$repo" --include-paths

# --- a pathname containing spaces must not evade the symlink guard -------------
repo=$(new_repo spaced-symlink)
ln -s /some/other/checkout/x "${repo}/bad  link"
git -C "$repo" add -A --force
assert_violation "absolute symlink whose name contains repeated spaces" "$repo"

# --- an option-like filename must not be handed to grep as an option -----------
repo=$(new_repo dash-filename)
printf 'cache=/Users/acct1234/.cache\n' >"${repo}/real.ini"
printf 'placeholder\n' >"${repo}/-q"
git -C "$repo" add -A
assert_violation "home path still found when a file is named -q" "$repo" --include-paths

# --- backslash-escaped Windows paths, as they appear inside JSON ----------------
repo=$(new_repo json-windows)
printf '{"path": "C:\\\\Users\\\\acct1234\\\\data"}\n' >"${repo}/settings.json"
git -C "$repo" add -A
assert_violation "JSON-escaped C:\\\\Users\\\\<name> path" "$repo" --include-paths

# --- a relative symlink that escapes the repository ----------------------------
repo=$(new_repo escaping-symlink)
ln -s ../../home/acct1234/project "${repo}/outside"
git -C "$repo" add -A --force
assert_violation "relative symlink whose target escapes the repository" "$repo"

# --- a dangling symlink must not silently disable the content scan -------------
repo=$(new_repo dangling-symlink)
printf 'cache=/Users/acct1234/.cache\n' >"${repo}/real.ini"
ln -s ./nowhere-at-all "${repo}/dangling"
git -C "$repo" add -A --force
assert_violation "home path still found alongside a dangling symlink" "$repo" --include-paths

# --- Windows profiles outside C: ------------------------------------------------
repo=$(new_repo windows-other-drive)
printf 'path=D:\\Users\\acct1234\\data\n' >"${repo}/d.ini"
git -C "$repo" add -A
assert_violation "hardcoded D:\\Users\\<name> path" "$repo" --include-paths

# --- the home-directory scan is opt-in ------------------------------------------
repo=$(new_repo opt-in)
printf 'cache=/Users/acct1234/.cache\n' >"${repo}/config.ini"
git -C "$repo" add -A
assert_clean "home paths are ignored without --include-paths" "$repo"
assert_violation "home paths are reported with --include-paths" "$repo" --include-paths

# --- forms measured across the fleet that must NOT be flagged ------------------
repo=$(new_repo fleet-false-positives)
# A URL route such as /home/index is NOT covered: it is indistinguishable from a
# home directory belonging to a user called "index". That is a documented limit of
# the opt-in scan, which is why it is opt-in.
{
  printf 'ENV HOME=/home/${USERNAME}\n'
  printf 'curl http://api/Users/1 http://api/Users/2\n'
  printf 'see /Users/<you>/notes and /Users/userid/example\n'
  printf 'win=%%USERPROFILE%%\n'
} >"${repo}/mixed.txt"
git -C "$repo" add -A
assert_clean "variables, URL routes, numeric ids and placeholders" "$repo" --include-paths

if [ "$FAIL" -ne 0 ]; then
  echo "check-repo-hygiene tests FAILED"
  exit 1
fi
echo "check-repo-hygiene tests passed"
