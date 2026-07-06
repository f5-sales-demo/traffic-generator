# Contributing

This document describes the workflow and rules that all contributors — human and AI — must follow.

## Workflow Overview

Every change follows this path:

```
Issue → Branch → PR (linked to issue) → CI passes → Merge → Branch auto-deleted
```

No exceptions. PRs without a linked issue will be blocked by CI.

## Step 1: Create an Issue

Every change starts with a GitHub issue. Use one of the provided templates:

- **Bug Report** — for bugs and unexpected behavior
- **Feature Request** — for new features and improvements
- **Documentation** — for docs improvements or missing content

Blank issues are disabled. Pick the template that best fits your change.

## Step 2: Create a Feature Branch

Branch from `main` using one of these naming conventions:

| Prefix | Use for | Example |
| -------- | --------- | --------- |
| `feature/` | New features | `feature/42-add-rate-limiting` |
| `fix/` | Bugfixes | `fix/17-correct-threshold-calc` |
| `docs/` | Documentation | `docs/8-update-setup-guide` |

Format: `<prefix>/<issue-number>-short-description`

```bash
git checkout main
git pull origin main
git checkout -b feature/42-add-rate-limiting
```

## Step 3: Make Changes and Commit

- Write small, focused commits
- Use conventional commit messages:
  - `feat: add rate limiting configuration`
  - `fix: correct threshold calculation`
  - `docs: update setup guide`

## Step 4: Open a Pull Request

1. Push your branch and open a PR against `main`
2. **Link the issue** — use `Closes #42` in the PR description, or link from the sidebar
3. Fill out the PR template (it loads automatically)
4. The `Check linked issues` and `Lint Code Base` CI checks will block merge if no issue is linked or linting fails

## Step 5: Review and Merge

- All CI checks must pass before merge
- PRs require manual review and approval before merge
- Squash merge is preferred
- The branch is automatically deleted after merge (`delete_branch_on_merge` is enabled)

## Branch Protection Rules

The `main` branch is protected. The following rules are enforced:

- No direct pushes to `main` — all changes go through PRs
- No force pushes
- Required status checks: `Check linked issues` and `Lint Code Base` must pass
- Admin enforcement enabled — these rules apply to everyone

## AI Assistant Guidelines

If you are Claude Code, Copilot, or another AI coding assistant, follow these rules:

1. **Always create a GitHub issue before writing code.** No issue = no work.
2. **Always work on a feature branch.** Never commit directly to `main`.
3. **Always link the PR to the issue.** Use `Closes #N` in the PR description.
4. **Use the `/ship` skill** when available — it handles the full Issue → Branch → PR flow.
5. **Never force push** or attempt to bypass branch protection.
6. **Fill out the PR template checklist** completely.
7. **Follow the branch naming convention**: `feature/<issue>-desc`, `fix/<issue>-desc`, `docs/<issue>-desc`.
8. **Respect CODEOWNERS** — Review the CODEOWNERS file for the default reviewer.

## Engineering Standards

These standards apply to all contributors — human and AI — for every change, where
applicable to this repository. Code standards apply to code changes; docs-only repos
apply what fits.

### Detailed issues

- A linked issue is not enough — it must be *detailed*: problem statement, scope, and
  acceptance criteria.
- CI blocks any PR with no linked issue; thin or empty issues are rejected in review.

### Specs and task-driven work

- Start non-trivial work from an engineering-level spec: what and why, the interfaces or
  content affected, and acceptance criteria.
- Break the spec into an explicit task/todo list and work it item by item.

### Test-driven development

- For code changes, write the test first, watch it fail, then write code to make it pass.
- Automate user-acceptance testing wherever possible instead of relying on manual checks.

### Verify before claiming done

- Substantiate every "it works" / "done" claim with evidence: passing tests or
  reproducible output.
- Do not assert completion you have not verified.

### No papering over problems

- When you find a pre-existing problem, fix the root cause. Never skip, ignore, silence,
  patch over, or band-aid it.
- CI rejects changes that mask problems (disabling checks, swallowing errors,
  TODO-and-move-on).

### Prerelease: no backward compatibility

- This is prerelease code heading to production. Make clean-break changes.
- Do not add compatibility shims or preserve deprecated interfaces — remove and replace.

### DRY — reuse first

- Reuse existing code, patterns, and content before adding new. Do not duplicate.

### Clean branches

- Troubleshoot and experiment freely on a branch.
- Never commit broken or experimental code, or speculative work that is not needed
  (YAGNI). Keep merged history green.

### Local checks vs CI

- The authoritative lint gate is CI's `Lint Code Base` (Super-Linter). It runs more
  validators than the local `pre-commit` hooks — notably textlint (`NATURAL_LANGUAGE`)
  prose and terminology, which `pre-commit` does not run.
- Passing `pre-commit` locally is necessary but not sufficient. Terminology is enforced
  (for example `prerelease`, not `pre-release`). Before pushing Markdown or prose,
  reproduce the full gate — run the Super-Linter image, or textlint with the repo's
  `.textlintrc` — so CI-only rules do not surprise you.
