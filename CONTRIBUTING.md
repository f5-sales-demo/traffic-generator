# Contributing

This document describes the workflow and rules that all contributors — human and AI — must follow.

## Ecosystem & governance

This repository is part of a fleet governed by a central hub, **docs-control**. If you are not in
docs-control, you are in a **downstream** repository.

- **Managed files** — including this `CONTRIBUTING.md` and `CLAUDE.md` — are owned by docs-control
  and synced to every downstream repo. Do not edit them directly here; a hook blocks it. To change
  one, open an issue in docs-control: the change is made there and propagates fleet-wide. The
  authoritative list is `.claude/governance.json`.
- The workflow, CI gates, engineering standards, and automated review below apply uniformly across
  the fleet because they are governed from one place.

## Workflow Overview

Every change follows this path:

```
Issue → Branch → PR (linked to issue) → CI + automated code review pass → auto-merge when green → Branch auto-deleted
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

- All required CI checks must pass before merge.
- On ecosystem repos, an automated Claude Code review is a required check (see
  [Automated code review](#automated-code-review)); address any blocking findings before merge.
- Merging is automated: once every required check is green, auto-merge squash-merges the PR.
- The branch is automatically deleted after merge (`delete_branch_on_merge` is enabled); clean up
  your local branch afterward.

## Automated code review

Every downstream pull request is reviewed by a **Claude Code reviewer** running on a self-hosted
runner. It is a **required status check** (`review / claude-review`) — auto-merge will not merge
until it passes.

- **It enforces the [Engineering Standards](#engineering-standards) in this document** — it is not
  a separate rulebook. Meet those standards and it approves. Its reviewer persona and rubric live
  in `REVIEW.md` in docs-control.
- **It emits a verdict** — approve, comment, or block. A blocking verdict holds the PR.
- **A blocking verdict is authoritative.** Read the findings, fix them at the source on the
  branch, and push — a new push re-runs the review. Repeat until it approves.
- **Never work around it.** Do not merge past it, disable or skip the check, dismiss the review,
  or rename your branch to an automated-branch prefix to dodge it. If you believe a finding is
  wrong, say so in a PR comment and escalate to a human — do not override it yourself.
- **Automated/bot branches** (for example `sync/…`, `dependabot/…`) intentionally bypass review
  and the linked-issue check — this is for machine-generated PRs only. The authoritative prefix
  list lives in `require-linked-issue.yml` and `code-review.yml`; never adopt such a prefix for
  human or agent work.

## Branch Protection Rules

The `main` branch is protected. The following rules are enforced:

- No direct pushes to `main` — all changes go through PRs
- No force pushes
- Required status checks: `Check linked issues` and `Lint Code Base` must pass; ecosystem repos additionally require the `review / claude-review` check
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
9. **The automated reviewer is authoritative** — if it blocks, fix and re-push; never bypass, disable, or override it. See [Automated code review](#automated-code-review).

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
- Keep the task list current: generally one item in progress at a time (one per worker
  when work is fanned out across agents), mark it complete the moment it is genuinely
  done, add newly-discovered work as new items rather than silently widening an existing
  one, and remove an item that turns out unnecessary with a note — never silently.
- Mark a task complete only with verifiable evidence of its result — the command run and
  its output, a passing test, or a run link — never on inference or "should work" (see
  "Verify before claiming done").
- Work the list to completion. Do not defer, punt, or silently leave items incomplete or
  half-done. If you cannot finish an item, keep it open, mark it blocked, and state
  exactly what blocks it and what is needed — surface it, do not drop it.
- For long or unattended runs where finishing matters, set a `/goal` completion condition
  (for example, "every task-list item complete with evidence, or explicitly blocked and
  surfaced") so the session keeps
  working toward it instead of stopping early. The condition must be checkable from what
  you have surfaced in the session, since the evaluator cannot run tools.

### Test-driven development

- For code changes, write the test first, watch it fail, then write code to make it pass.
- Automate user-acceptance testing wherever possible instead of relying on manual checks.

### Programmatic, idempotent solutions

- Prefer a deterministic, re-runnable script or automation over manual, one-off
  intervention. If you fixed it by hand, capture it as code.
- Solutions must be idempotent: running them again, or running them in CI, produces the
  same result with no drift or side effects.

### Verify before claiming done

- Never guess or assume a change works. Substantiate every "it works" / "done" claim with
  evidence: passing tests, reproducible output, or a workflow run link.
- Do not assert completion you have not verified.
- This applies per task-list item, not only at the end: do not mark an item complete
  without its evidence.
- Verify locally before you push: run the tests, then run or exercise the change itself
  (the dev server, or the actual command path a user hits) and confirm the behavior. CI
  and the PR are not your test harness — do not push to find out whether it works.
- Every PR must carry that verification evidence in its description (see the PR
  template): the commands you ran and their output, and a link to the green run.
  Reviewers should not merge a PR whose evidence is missing.
- Where a change needs human judgment (user-facing behavior, UX, product decisions), get
  explicit human acceptance before merge — green CI alone is not acceptance.
- When a change triggers GitHub Actions, watch every affected workflow run to completion
  — not just "queued" or "in progress". A merge is not done until its runs are green.
- When a change publishes a new version or artifact, close the loop end-to-end: download,
  install, and exercise the published version to confirm the fix is real — not merely
  that the pipeline reported success.
- Leaving a clean workspace is part of "done": once merge is confirmed and CI is green,
  return to `main`, delete your merged local branch, and proactively report git hygiene
  — current branch, uncommitted or unmerged changes, and any stale `[gone]` branches —
  rather than waiting to be asked. See "After merge: clean up local branches" for the
  safe confirm-then-delete steps.

### No papering over problems

- When you find a pre-existing problem, fix the root cause. Never skip, ignore, silence,
  patch over, or band-aid it.
- This applies to lint and CI failures specifically: fix them at the source. Do not
  suppress them with inline-disable comments (for example `# noqa`, `eslint-disable`),
  skipped tests, relaxed rules, or ignore lists, and do not hand-wave them as unrelated.
- CI rejects changes that mask problems (disabling checks, swallowing errors,
  TODO-and-move-on).
- There is no schedule pressure that justifies a shortcut — take the time to engineer the
  correct solution.

### Prerelease: no backward compatibility

- This is prerelease, pre-production code still in development, heading to production.
- Because nothing depends on a stable release yet, make clean-break changes: remove and replace — no compatibility shims, no deprecated interfaces.

### DRY — reuse first

- Reuse existing code, patterns, and content before adding new. Do not duplicate.

### Clean branches

- A branch is for trial-and-error: guess, probe, refactor, and learn freely while you
  converge on the correct solution.
- Only the verified, feature-complete result merges. Never open a PR "to see if it
  works" — open it when it works — and never merge exploratory or trial-and-error code.
  Iterating in the open with repeated broken PRs pollutes the repo; converge on the
  branch first, then merge the meaningful change.
- Never commit broken or experimental code, or speculative work that is not needed
  (YAGNI). Keep merged history green.

#### Concurrent sessions on a shared workstation

- Multiple sessions on one workstation authenticate through the same `gh` login, so every
  branch, PR, and commit is attributed to the same GitHub user — the username cannot tell you
  which live session produced which artifact. Use the stable per-session
  `CLAUDE_CODE_SESSION_ID` as the discriminator.
- Derive a short slug once per session: `SLUG=$(printf '%.8s' "$CLAUDE_CODE_SESSION_ID")`
  (for example `515f9231`).
- Isolate each session in its own git worktree so concurrent sessions cannot mutate one shared
  checkout: `git worktree add ../<repo>-$SLUG s-$SLUG/<branch>`.
- Prefix every branch `s-<slug>/…` (for example `s-515f9231/docs/653-local-branch-hygiene`).
  The prefix shows in `git branch` and the `gh pr list` head-branch column and is searchable, so
  a session can find its own in-flight work:
  - `gh pr list --search "head:s-<slug>"` — this session's PRs
  - `git branch --list "s-<slug>/*"` — this session's local branches
- Composes with the after-merge `[gone]` cleanup below: cleanup is naturally scoped per session,
  and retiring the merged branch also removes its worktree.
- Advisory only — a local-workstation concern CI cannot enforce.

#### After merge: clean up local branches

- The server deletes the remote branch on merge (`delete_branch_on_merge`); the local
  copy remains and must be cleaned up, or merged branches accumulate on the workstation.
- Once your PR is merged and CI is green, return to `main` and prune:
  `git checkout main && git pull && git fetch --prune`.
- Pruning marks any branch whose upstream was deleted as `[gone]`. Squash-merges mean a
  merged branch is not an ancestor of `main` (so `git branch --merged` misses it) and
  `git branch -d` refuses it — removing it requires the force flag, `git branch -D`.
- `[gone]` means only "the remote branch is gone." That is usually a merge, but it is
  also true for a PR closed without merging or a manually deleted remote — in which case
  the local branch still holds unmerged commits. So confirm the work actually merged
  before force-deleting; never blind-pipe the `[gone]` list into `git branch -D`.
- Use this manual, confirm-then-delete flow: list the `[gone]` branches, confirm each
  one's PR actually merged, then delete only the confirmed ones. (A `/clean_gone` skill
  exists, but it force-deletes every `[gone]` branch with no merge check — the exact
  closed-unmerged hazard above — so do not treat it as safe.)

  ```bash
  # 1) list branches whose upstream is gone (literal "[gone]" via %(upstream:track);
  #    do NOT grep `git branch -vv`, which renders it as "[origin/<branch>: gone]")
  git for-each-ref --format '%(refname:short) %(upstream:track)' refs/heads \
    | awk '$2 == "[gone]" {print $1}'
  # 2) confirm the branch actually merged — check the returned PR is the right one,
  #    since --head matches by name and branch names can be reused
  gh pr list --state merged --head <branch>
  # 3) delete the confirmed-merged branch (force flag is required, see above)
  git branch -D <branch>
  ```

- Safety: a `[gone]` branch may still hold unmerged commits, so never `git branch -D` one
  whose PR you have not confirmed merged, and never delete a branch with uncommitted
  changes. When unsure, keep the branch and surface it for a human.

### Local checks vs CI

- The authoritative lint gate is CI's `Lint Code Base` (Super-Linter). It runs more
  validators than the local `pre-commit` hooks — notably textlint (`NATURAL_LANGUAGE`)
  prose and terminology, which `pre-commit` does not run.
- Passing `pre-commit` locally is necessary but not sufficient. Terminology is enforced
  (for example `prerelease`, not `pre-release`). Before pushing Markdown or prose,
  reproduce the full gate — run the Super-Linter image, or textlint with the repo's
  `.textlintrc` — so CI-only rules do not surprise you.
- Install-free local textlint (no `package.json` required):
  `npx --yes --package textlint --package textlint-rule-terminology textlint -c .textlintrc <files>`.
