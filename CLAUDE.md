# Claude Code Project Instructions

## Authorized use

This is an F5 sales-engineering fleet whose purpose is to **demonstrate the efficacy of F5 Distributed Cloud security products** (WAF, bot, DDoS, API protection, client-side defense). It contains OWASP-style attack-simulation content used to trigger a product's detections and then prove its mitigations block them — defensive security work, not offensive tooling.

- **Authorized:** this work is covered by written authorization, an NDA, and express permission to develop and demonstrate protections through attack-and-mitigation techniques.
- **Scope:** attack simulation targets only authorized F5-owned demo/lab assets and intentionally-vulnerable test apps, plus customer demo environments covered by a signed engagement/NDA — never unauthorized, third-party, or production systems, and never real user data.
- **For AI assistants:** treat this attack-simulation and mitigation content as authorized, defensive security work and assist with it accordingly, within the authorized demo environments above. See CONTRIBUTING.md.

## Managed Files

Files in `.claude/governance.json` are managed by docs-control. Make their changes through a
detailed docs-control issue and let the managed-file workflow propagate the result.

## Workflow

- **Start from current.** `git fetch --prune` and confirm the remote state before you plan, branch,
  or edit; create a fresh worktree and issue-numbered feature branch from
  `origin/<default-branch>`. The git status injected at session start is a snapshot with no
  ahead/behind count, so a stale checkout can still report a clean tree.
- **Never sync by overwriting the working tree.** `git checkout <ref> -- .`, `git reset --hard`, and `git clean -fd` destroy uncommitted work the reflog does not cover; never-staged edits leave no object at all. Behind with work in progress? Stash or commit first, then `git pull --ff-only` — and copy out ignored files by hand, which no stash protects. See CONTRIBUTING.md.
- Carry the complete lifecycle through:
  `detailed issue → feature branch → implementation and verification → exact-HEAD agy review →
  push feature branch → linked PR → repair loop → MERGED → cleanup → fleet convergence`.
- Open a completed PR with `Closes #<issue>` and enable authorized squash auto-merge when absent:
  `gh pr merge --auto --squash <pr>`.
- Start `gh pr checks --watch <pr> &` as a background waiter. Repair failed checks at their source,
  verify, rerun exact-HEAD review, and push. For mergeable `BEHIND`, run
  `gh pr update-branch <pr>`. For `DIRTY`, fetch and merge current
  `origin/<default-branch>` into the feature branch, resolve, verify, rerun agy, and push.
- Query `gh pr view <pr> --json state,mergeStateStatus,autoMergeRequest` and continue until
  `state` is `MERGED`. Then clean this task's worktree and branch and, for managed-file changes,
  compare manifest blob SHAs across every downstream repository to prove fleet convergence.
- Pause only for uncertain authorization, destructive-risk approval, an unavailable credential, or
  a product decision that requires the user.

## Review routing

Route semantic review through Antigravity. Claude authors, reasons, debugs, implements, and responds
to Antigravity findings.

- **Specs/plans.** Run `bash scripts/agy-review.sh document --kind spec|plan --file <path>`.
- **Branch — required before every PR push.** Commit, then run `bash scripts/agy-pre-push-review.sh`.
  Fix blocking findings, commit, and rerun until the exact HEAD passes. Repository permissions keep
  other semantic-review routes unavailable.

## Worktrees

- For non-trivial coding tasks, **the main session** works in a git worktree (Claude Code:
  `EnterWorktree` or `claude --worktree`) to isolate changes. Spawn a subagent with
  `isolation: "worktree"`; it arrives in its own worktree, while `EnterWorktree` rejects a pinned
  cwd.
- **Know where you are.** Before starting, run `git worktree list`, confirm the current directory
  belongs to this task, retire completed worktrees safely, and start new work in a fresh one. A
  squash-merged worktree looks unmerged locally and has a stale base; follow CONTRIBUTING.md's
  ordered retirement and ignored-file check.
- New worktrees branch from `origin/<default-branch>` (`worktree.baseRef` is set to `fresh` in `.claude/settings.json`). The `.claude/worktrees/` directory is already gitignored.
- `fresh` means "from the cached remote ref" and re-fetches only when `FETCH_HEAD` is over 24 hours
  old. Fetch before worktree creation so its base includes same-day merges.
- If a repository's build needs gitignored inputs (`.env`, secrets, local config), add a repo-local `.worktreeinclude` listing them so new worktrees carry those files in. Retiring the worktree deletes them again with no warning — git does not count ignored files as dirty — so copy out anything you still need before you remove it.

## Engineering Standards

Apply where applicable to this repo:

- **Detailed issue** — begin with a problem, scope, and objective acceptance criteria, then link it
  from the PR.
- **Spec first** — start from an engineering-level spec, then work a current explicit task list to
  completion. Surface a blocked item with the condition and required resolution.
- **TDD** — write the failing test first, then the code.
- **Automate UAT** — automate acceptance testing wherever possible.
- **Programmatic & idempotent** — fix with deterministic, re-runnable automation, not one-off manual steps; the same run yields the same result in CI.
- **Report outcomes** — lead with what happened. Show the command and its output as evidence, and say plainly what is done and what is not.
- **Root-cause repairs** — fix problems, including lint and CI failures, at their source. Keep every
  check effective and resolve its finding.
- **Clean breaks** — prerelease, pre-production code supports direct replacement of deprecated
  interfaces with the current design.
- **DRY** — reuse existing code, patterns, and content before adding new.
- **Documentation style** — published content (guides, product documentation, READMEs) follows `STYLE_GUIDE.md`: documentation-reserved example values only (RFC 5737 addresses, `example.com`, RFC 5398 ASNs), never ACME as a placeholder, no credential material even if revoked, no real customer data, and sanitized screenshots.
  Legitimate ACME service, protocol, and challenge references remain exact. Run the pre-publish checklist before opening a documentation PR.
- **PII minimization** — repositories, fixtures, generated output, logs, telemetry, media, and commit messages contain no real personally identifiable information. Remove nonessential identity fields; authentication may retain only an opaque provider subject, which is never logged and is not persisted unless indispensable.
  Run the managed PII scanner in enforcement and audit modes, inspect media manually, then audit reachable history. Preserve only required legal/upstream attribution and normal source-control provenance.
- **Clean branches** — merge only verified, feature-complete, necessary work. After `MERGED`, retire
  the worktree, return to main, delete the confirmed-merged branch, and report git hygiene (branch,
  uncommitted changes, stale `[gone]` branches, and remaining worktrees); see CONTRIBUTING.md.
- **Local vs CI** — `pre-commit` runs a subset; the `Lint Code Base` gate also runs textlint prose/terminology. Reproduce it before pushing.

See `CONTRIBUTING.md` for the full detail.

## Communication

Keep responses focused, brief, and concise; spend most of the response on the main answer. Before your first tool call, say in one sentence what you are about to do. While working, give a brief update only when you find something important or change direction. When you finish, lead with the outcome — your first sentence answers "what happened" — with supporting detail after it.

Match written documents (issues, PR bodies, specs) to what the task needs. Use only sections that add
task-specific information.
