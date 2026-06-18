#!/usr/bin/env bash
# Detects hardcoded locale lists that should import from @f5xc-salesdemos/i18n-core.
# Run from any repo root: bash scripts/locale-lint.sh
# Exit 0 = clean, Exit 1 = violations found.
set -euo pipefail

VIOLATIONS=0

# Patterns that indicate a hardcoded locale list rather than an i18n-core import
PATTERNS=(
  # Inline slug arrays containing 3+ locale codes (high confidence)
  "'pt-br'.*'zh-cn'.*'zh-tw'"
  '"pt-br".*"zh-cn".*"zh-tw"'
  # Inline constant definitions that should come from i18n-core
  'VALID_LOCALE_SLUGS\s*=\s*new\s+Set'
  '(const|let|var|export)\s+LOCALE_DISPLAY_NAMES'
  '(const|let|var|export)\s+LANG_TO_SLUG'
  # Inline langToSlug function definition (not an import alias)
  'function\s+langToSlug'
)

# Directories and files to exclude
EXCLUDE_DIRS="node_modules|dist|\.git|coverage|\.astro|\.next|out|build"
EXCLUDE_FILES="locale-lint\.sh|\.test\.|\.spec\."

check_pattern() {
  local pattern="$1"
  local results
  results=$(grep -rn --include='*.ts' --include='*.js' --include='*.tsx' --include='*.jsx' \
    -E "$pattern" . 2>/dev/null |
    grep -vE "($EXCLUDE_DIRS)" |
    grep -vE "($EXCLUDE_FILES)" |
    grep -vE "from\s+['\"]@f5xc-salesdemos/i18n-core" |
    grep -vE "i18n-core/(src|dist)/" ||
    true)

  if [ -n "$results" ]; then
    echo "$results"
    return 1
  fi
  return 0
}

echo "Locale lint: checking for hardcoded locale lists..."
echo ""

for pattern in "${PATTERNS[@]}"; do
  if ! check_pattern "$pattern"; then
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done

echo ""
if [ "$VIOLATIONS" -gt 0 ]; then
  echo "FAIL: Found $VIOLATIONS pattern(s) with hardcoded locale data."
  echo "These should import from @f5xc-salesdemos/i18n-core instead."
  exit 1
else
  echo "PASS: No hardcoded locale lists detected."
  exit 0
fi
