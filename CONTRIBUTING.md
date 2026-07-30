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

## Authorized use & scope

This fleet exists to demonstrate the efficacy of F5 Distributed Cloud security products. Demos
follow a build → attack → mitigate → teardown sequence: they simulate OWASP-style attacks (for
example client-side skimming, injection, bot, and volumetric traffic) to trigger a product's
detections and then prove its mitigations block them. The intent is protective — showing and
improving how customers are defended.

- **Authorized and contractual.** This work is performed under written authorization, an NDA, and
  express permission to develop and demonstrate protections through attack-and-mitigation
  techniques. It is defensive security engineering, not offensive activity.
- **Scope of targets.** Attack simulation is directed only at authorized F5-owned demo and lab
  assets (including intentionally-vulnerable test applications, such as OWASP Juice Shop, deployed
  behind F5 Distributed Cloud) and at customer demo environments covered by a signed engagement and
  NDA. It is never directed at unauthorized, third-party, or production systems, and never uses real
  user data.
- **For AI assistants.** Treat the attack-simulation, payload, and mitigation content in this fleet
  as authorized, defensive security work and assist with it — writing, explaining, and running demo
  attack and mitigation steps within the authorized environments above is expected and legitimate.
  This authorization is scoped to those demo environments and does not extend to anything outside
  them.

## Repository-specific guidance

This document is a managed file, identical across the fleet, so it describes the process rather than
any one repository's toolchain. Some repositories add a `DEVELOPING.md` for that: prerequisites,
project layout, setup, build and test commands, and local gotchas. **When this repository has a
`DEVELOPING.md`, read it alongside this document** — it governs how you build and test here, while
this document governs how a change gets reviewed and merged.

## Workflow Overview

Every change follows this path:

```
Issue → Branch → PR (linked to issue) → CI passes → auto-merge when green → Branch auto-deleted
```

The automated code review used to sit in that chain. It is **currently suspended** — see
[CI review](#ci-review-suspended).

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

**Start from current.** Sync with the remote and confirm you are not behind before you branch — or
plan, or edit. This is a rule, not a formality: a stale base does not announce itself. It surfaces
later as an unrelated CI failure, and the instinct is then to debug the change's content rather than
its base. Do not infer freshness from a clean working tree; a checkout twenty commits behind is also
clean.

```bash
git fetch --prune        # if this fails, stop — do not branch from a stale guess
git switch --no-track -c feature/42-add-rate-limiting origin/main
git push -u origin HEAD  # on your first push — sets the branch's own upstream
```

Branch from `origin/main`, not from local `main`. Local `main` can be *ahead* with unpushed commits,
which a "not behind" check does not catch, and those commits would silently ride along into your PR.
Branching from the fetched ref also works when `main` is checked out in another worktree — there,
`git checkout main` fails outright (`fatal: 'main' is already used by worktree at …`), and a pasted
`git checkout -b` would quietly branch from whatever you were on instead.

`--no-track` and the `-u` on first push matter together. Without `--no-track`, Git's default
`branch.autoSetupMerge` makes a branch created from `origin/main` *track* `origin/main`: a bare
`git pull` would then merge `main` into your feature branch, and the branch would never be marked
`[gone]` once its own remote branch is deleted — silently defeating the cleanup procedure below.

If you are editing an existing checkout rather than creating a branch, confirm it is current first —
`git status -sb` should show `## main...origin/main` with no `[behind N]`.

If it *does* show `[behind N]` and you have work in progress, park the work rather than discarding it:

```bash
git status --short --ignored   # ignored files are NOT protected — see below
git stash push -u              # -u covers untracked files, but NOT ignored ones
git pull --ff-only
git stash pop
```

`git stash pop` can hit a conflict when the pull touched the same file you edited. That is safe: pop
exits non-zero and **keeps the stash entry**, so resolve the conflict and drop the stash afterwards —
nothing is lost by trying.

Ignored files are the exception, and they are not protected anywhere in this flow. `-u` does not
stash them, and if upstream starts tracking a path you hold as ignored — `.env` is the obvious case —
`git pull` overwrites it **silently and exits 0**. Git refuses to clobber an *untracked* file that
way; it does not extend that courtesy to ignored ones. `git stash push --all` does capture them, but
`pop` then fails with `.env already exists, no checkout` once the path is tracked. The stash is
retained, but recovering from it is not the obvious command: `--all` stores untracked and ignored
files in the stash commit's **third parent**, so `git checkout stash@{0} -- <path>` fails with
`did not match any file(s) known to git`. Read it out of the third parent instead, to a scratch file
**outside** the repository:

```bash
git show 'stash@{0}^3:.env' > /tmp/recovered.env   # never redirect onto the path itself
```

Two reasons for the scratch file. Redirecting onto the original path would write your ignored local
copy over the version upstream now tracks, turning a secret into a tracked modification somebody can
commit by accident. And the shell truncates the target *before* `git show` runs, so a wrong ref or
path empties the file even when the command fails — `git show` exits 128 and the destination is left
at 0 bytes. Recover to the side, then merge by hand.

The reliable move is to copy out any ignored file you care about before you sync. This is the same blind spot as the worktree
warning under Worktrees: git's safety checks do not see ignored files.

**Never sync by overwriting the working tree.** `git checkout <ref> -- .` looks like a refresh and is
not one: it overwrites tracked files with the other ref's content, stages the result, and leaves
files that exist only in your branch behind — a mixed state that is neither commit. Git writes no
reflog entry for what it overwrote, so unlike a mistaken `git branch -D` there is no ref to restore.

How much is lost depends on whether the work was staged, and the difference is worth knowing before
you give up on it. Content you had `git add`ed still exists as a blob and stays recoverable until
garbage collection — `git fsck --lost-found` lists it, and `git cat-file -p <blob>` prints it. Content
you never staged was never written to the object store at all, and that is genuinely gone. So if you
do clobber something, check `git fsck --lost-found` before concluding the work is lost.

`git reset --hard` has the same effect on
uncommitted changes (commits it moves past *are* reflog-recoverable; uncommitted edits are not), and
`git clean -fd` deletes untracked files and directories — add `-x` and it takes ignored files too,
including the `.env` and local config described under Worktrees.

A long-running session goes stale the same way, since nothing re-checks after start. Fetch again
before branching a second time, and before creating a git worktree — a worktree inherits whatever
the cached remote ref says, so it can be born behind (see CLAUDE.md).

If a branch falls behind `main` while its PR is open, use the **Update branch** button on the PR
(`allow_update_branch` is enabled fleet-wide) rather than merging `main` in by hand.

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
- The automated Claude Code review is **currently suspended** and is not a required check (see
  [CI review](#ci-review-suspended)).
- Merging is automated: once every required check is green, auto-merge squash-merges the PR.
- The branch is automatically deleted after merge (`delete_branch_on_merge` is enabled); clean up
  your local branch afterward.

## Automated code review

Review happens in two layers. They are not interchangeable, and neither substitutes for the other:

| Layer | What it reviews | Authority |
| ----- | --------------- | --------- |
| **Local, pre-PR** | A spec, an implementation plan, or an unpushed branch | Advisory |
| **CI** | The pull-request diff | **Currently suspended** — not running, not required |

### CI review (suspended)

> **Suspended.** The self-hosted reviewer could not reliably reach model inference or the VPN, so
> the check often never went green and blocked pull requests for infrastructure reasons rather than
> code-quality ones. The `review / claude-review` context has been removed from branch protection
> (docs-control#833) and the workflow is gated off behind the `REVIEWER_ENABLED` variable
> (docs-control#838). **No CI job currently reviews pull-request diffs.** Do not wait for it, and do
> not treat its absence as a fault. Restoring it is described in `REVIEWER-SPEC.md` — set the
> variable and confirm a real review completes *before* re-adding the required context, because the
> reverse order deadlocks every open pull request.

The rest of this section describes the reviewer as it behaves when enabled.

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

### Local pre-PR review (advisory second opinion)

A second review layer runs on your own machine **before the pull request exists**. It catches
problems while they are still cheap to fix — in a spec or a plan, before any code is written.

- **Advisory, never a gate.** It emits no verdict and posts no commit status, so it cannot block a
  merge or deadlock a required check. When the tooling is absent it is skipped and work continues.
- **Where it runs.** At the spec and plan review points, before a push that opens or updates a pull
  request, and after each round of fixes. Reviewing a written spec or implementation plan is its
  primary use — a document, not a diff.
- **Verification is mandatory.** A finding counts only once it has been confirmed against the
  codebase: for code, with a test that fails today; for a document, with a quotation. An AI reviewer
  misattributes findings to files that do not contain them, and a hallucinated blocking finding can
  never be fixed — treating it as blocking would stop the loop from ever terminating.
- **Bounded.** Three iterations maximum, with no-progress detection when two consecutive rounds
  produce the same blocking set. On either, the outstanding findings go to a human.
- **Do not reach for a PR-diff reviewer instead.** Reviewing a spec, a plan, or a local branch with
  a pull-request review tool is the wrong layer — a spec has no diff to review. `CLAUDE.md` names
  the tool to use, the tools not to use, and the deny rules that enforce it.

The two layers are complementary: the local layer catches issues before the pull request exists and
costs nothing when it is wrong, while CI remains the gate that decides whether a change merges.

## Translations (suspended)

> **Suspended during development.** Translation generation calls a model API once per locale per
> changed English file — twelve calls for every edit under `docs/en/`. That cost is not justified
> while the documentation is still churning, so generation is off and the freshness audit no longer
> gates merges. Translations will be regenerated as a deliberate effort before go-live.

How the three parts fit together, because only one of them costs anything:

| Part | Where | Cost |
| ---- | ----- | ---- |
| Generation | the `docs-translate` pre-commit hook, on `docs/en/**/*.md[x]` | the entire spend |
| Freshness audit | `.github/workflows/translation-audit.yml` — compares each translation's `i18n.sourceHash` against the SHA-256 of its English source | none; it performs no translation |
| Required context | `audit / Translation freshness` in branch protection | none; it made the audit blocking |

What this means for you now:

- **Existing translations under `docs/<locale>/` stay in place and will drift out of date.** That is
  expected. Do not regenerate them individually, and do not treat the drift as a defect to fix.
- Editing `docs/en/` no longer requires a matching translation update.
- Both the generation hook and the audit are gated on the `TRANSLATIONS_ENABLED` variable. Unset means
  off, so nothing spends money by accident.

### Restoring translations

Order matters, and getting it wrong deadlocks every open pull request — the same trap the suspended
reviewer left behind.

1. Turn on **both** switches. `TRANSLATIONS_ENABLED` is one name for two independent settings, and
   setting only one half-restores the system:

   ```bash
   # Generation — the pre-commit hook reads your local process environment.
   # No organisation variable sets this; it must be exported where you commit.
   export TRANSLATIONS_ENABLED=true
   export ANTHROPIC_API_KEY=...
   ```

   Then set the `TRANSLATIONS_ENABLED` **organisation variable** to `true`, which is what the audit
   workflow reads — an organisation variable is exposed to Actions through the `vars` context only, so
   it never reaches the hook on your machine.

   Setting just the organisation variable is the trap: the `--force` run in step 2 works, because you
   run it directly, and then every later English edit silently skips generation. Nothing complains
   until the audit is required again, at which point pull requests fail fleet-wide.
   Make sure the organisation variable is visible to **all** governed repositories. An organisation
   variable scoped to a subset leaves the rest with a job that silently never runs.
2. Regenerate everything with `docs-translate --force` and commit. Expect roughly 4,320 files across
   the fleet.
3. **Un-gate both, and let that sync downstream.** In `workflows/translation-audit.yml`, delete the
   `if: vars.TRANSLATIONS_ENABLED == 'true'` line *and* the `SUSPENDED:` comment block, returning the
   job to unconditional. In `.pre-commit-config.yaml`, remove the `TRANSLATIONS_ENABLED` branch from
   the `docs-translate` hook.

   Delete the `if:`, do not merely set the variable. Leaving the condition in place makes organisation
   variable visibility permanently load-bearing for CI: any repository the variable is not visible to
   silently skips the job, and once the context is required again its pull requests wait forever for a
   check that is never emitted. An unconditional job removes that whole class of failure — after this,
   `TRANSLATIONS_ENABLED` governs only local generation, which fails visibly and cheaply.

   `tests/test-translation-suspension.sh` keys section 1 on the `SUSPENDED:` marker, so leaving it in
   place fails the guard the moment the context comes back.
4. Confirm the audit actually reports on **every governed repository that receives the workflow**, not
   on one pull request. Three traps here, all of them load-bearing:

   - **One green PR proves one repo.** During the suspension a five-repository spot check came back
     clean while **9 of 38** still had the old branch protection, because enforcement fans out in
     batches of five. Re-adding the context on that evidence would have deadlocked nine repositories.
   - **An old run proves nothing.** The last conclusion may predate the un-gating in step 3, or come
     from a repository still running the gated workflow. Confirm the synced file no longer contains the
     `if:` before trusting a run, and only count runs created after that.
   - **Some repos never receive this workflow at all.** Anything listed under `skip_files` for
     `translation-audit.yml` does not have the file — `terraform-provider-xcsh` skips it, and the path
     returns 404 there. Demanding a report from those repos is impossible, and it is exactly why they
     carry an `excluded_required_contexts` entry: a required check whose workflow does not exist is a
     *permanent* deadlock, not a transient one.

   ```bash
   SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)   # capture AFTER step 3 has synced
   SKIP=$(jq -r '.skip_files | to_entries[]
                 | select(any(.value[]; test("translation-audit"))) | .key' .claude/governance.json)
   while IFS= read -r r; do
     grep -qxF "$r" <<<"$SKIP" && { printf '%-24s n/a (no workflow)\n' "$r"; continue; }
     # the synced file must be un-gated, or a green run proves nothing
     gated=$(gh api "repos/f5-sales-demo/$r/contents/.github/workflows/translation-audit.yml" \
               -q .content 2>/dev/null | base64 -d 2>/dev/null | grep -c 'TRANSLATIONS_ENABLED')
     [ "${gated:-1}" -ne 0 ] && { printf '%-24s STILL GATED — wait for sync\n' "$r"; continue; }
     gh run list -R "f5-sales-demo/$r" --workflow=translation-audit.yml \
       --created ">$SINCE" --limit 1 --json conclusion \
       -q '.[0].conclusion // "NO RUN SINCE UN-GATING"' \
       | xargs printf '%-24s %s\n' "$r"
   done < <(jq -r '.[]' .github/config/downstream-repos.json)
   ```

   Every non-skipped repository must read `success`. Anything else — `STILL GATED`, `NO RUN SINCE
   UN-GATING`, `skipped`, `failure` — means that repository will not emit the check, and re-adding the
   context would deadlock it.

   `NO RUN SINCE UN-GATING` is the expected result for most repositories, not a fault. The audit
   triggers only on `pull_request` `opened`, `synchronize`, and `reopened`; **merging** the sync pull
   request fires nothing afterwards, so a repository with no later pull-request activity will report it
   indefinitely. Do not wave that through — provoke a run instead:

   ```bash
   # for any repo reading NO RUN SINCE UN-GATING
   git clone --depth 1 "https://github.com/f5-sales-demo/$r" /tmp/probe-$r
   cd /tmp/probe-$r && git switch -c "chore/audit-probe" \
     && printf '\n' >> README.md && git commit -aqm "chore: probe translation audit" \
     && git push -q -u origin HEAD && gh pr create --fill --base main
   ```

   Probe **every** repository that reads `NO RUN SINCE UN-GATING`, including those with no `docs/en`.
   It is tempting to skip them on the grounds that the audit passes trivially there — the reusable
   workflow exits 0 when `docs/en` is absent — but passing and *reporting* are different things. Once
   the context is required, such a repository must still emit `audit / Translation freshness`, and it
   cannot do so if its caller workflow is missing, malformed, or not triggering. That is exactly the
   deadlock this step exists to catch, and it is invisible until the context is already required.

   Close the probe pull request once the audit reports. Skipping this step is how an operator ends up
   re-adding the required context on the strength of repositories that were never actually exercised.

5. **Only then** re-add `audit / Translation freshness` to
   `branch_protection[0].required_status_checks.contexts` — **and re-add
   `excluded_required_contexts: ["audit / Translation freshness"]` to the `terraform-provider-xcsh`
   and `code-review` overrides**, which were removed with the base context because an exclusion that
   matches no required context silently no-ops. Without them those two repositories would gain a
   check they were deliberately exempt from.

Re-adding the required context before step 4 makes a check that never reports mandatory, which blocks
every pull request until an administrator intervenes. The guard test cannot catch this for you: it
reads files, and no static check can see whether an organisation variable is set in every repository.
Step 4 is the only thing standing between a restore and a fleet-wide outage.

## Branch Protection Rules

The `main` branch is protected. The following rules are enforced:

- No direct pushes to `main` — all changes go through PRs
- No force pushes
- Required status checks: `Check linked issues` and `Lint Code Base` must pass, plus any repo-specific contexts. The `review / claude-review` check is **suspended**. `audit / Translation freshness` still runs but **no longer gates a merge**
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
  retire the worktree you worked in, then return to `main`, delete your merged local
  branch, and proactively report git hygiene — current branch, uncommitted or unmerged
  changes, stale `[gone]` branches, and leftover worktrees — rather than waiting to be
  asked. The worktree comes first; the branch cannot be deleted while it is still checked
  out in one. See "After merge: clean up local branches and worktrees" for the safe
  confirm-then-delete steps.

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
- Composes with the after-merge `[gone]` cleanup below: cleanup is naturally scoped per session.
  Retiring the branch does **not** remove its worktree — that is a separate, explicit step, and it
  is the one that gets skipped. Skipped worktrees are how a later session ends up starting new work
  inside a finished one.
- Advisory only — a local-workstation concern CI cannot enforce.

#### After merge: clean up local branches and worktrees

- The server deletes the remote branch on merge (`delete_branch_on_merge`); the local
  copy remains and must be cleaned up, or merged branches accumulate on the workstation.
  A worktree you worked in remains too, and nothing removes it for you.
- If you worked in a worktree, retire it **first** — leave it, then remove it:

  ```bash
  git worktree list                       # audit: what exists, where you are, what is locked
  git -C <path> status --short --ignored  # ignored files are about to be deleted — check first
  # Only if THIS session created it, use ExitWorktree — it handles the lock.
  # Otherwise (a leftover from an earlier session), from the MAIN checkout,
  # and only once the owning session has ended:
  git worktree unlock <path>              # Claude Code creates worktrees locked
  git worktree remove <path>
  ```

  Run the `--ignored` check before removing anything. Removal deletes ignored files without
  warning and without refusing: git does not count them as dirty, so a worktree holding a
  `.env` reports a clean `git status --porcelain`, and `git worktree remove` exits 0 and
  takes the file with it. This matters here because CLAUDE.md recommends `.worktreeinclude`
  to carry exactly those files — `.env`, secrets, local config — into new worktrees. Copy out
  anything you still need first. `ExitWorktree` removes the directory too, so the same
  caution applies.

  Order matters, and so does where you stand. `git branch -D` refuses while the branch is
  still checked out somewhere (`error: cannot delete branch 'x' used by worktree at …`), so
  the worktree goes first. Removing a worktree while your shell is inside it does succeed,
  but it deletes the directory out from under you and the next command fails with
  `fatal: Unable to read current working directory` — so leave before you remove.

  Claude Code marks its worktrees `locked`, and a locked worktree cannot be removed:
  `fatal: cannot remove a locked working tree`. Note that plain `--force` does **not**
  override this — only `unlock` first, or `remove -f -f`. Prefer `unlock`: the double-force
  also discards uncommitted changes, and a locked worktree usually means a session is still
  using it. Confirm the owning session has ended before unlocking someone else's.
- Then, in the main checkout, sync and prune: `git pull --ff-only && git fetch --prune`.
  Do not reach for `git checkout main` from inside a worktree; `main` is checked out in the
  main checkout, so it fails with `fatal: 'main' is already used by worktree at …`.
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
