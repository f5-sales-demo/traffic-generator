# Claude Code Project Instructions

## Managed Files

Files in `.claude/governance.json` are managed by docs-control.
A hook blocks direct edits — open an issue in docs-control instead.

## Workflow

- `main` is protected — never commit or push to it directly.
- Work on a feature branch and open a pull request.
- Every PR must reference a detailed GitHub issue (CI enforces this).

## Engineering Standards

Apply where applicable to this repo:

- **Detailed issue** — CI stays red until the PR links a detailed issue (problem, scope, acceptance criteria).
- **Spec first** — start from an engineering-level spec, then work a task/todo list.
- **TDD** — write the failing test first, then the code.
- **Automate UAT** — automate acceptance testing wherever possible.
- **Programmatic & idempotent** — fix with deterministic, re-runnable automation, not one-off manual steps; the same run yields the same result in CI.
- **Verify before done (IMPORTANT)** — never guess; verify locally before you push. Watch the GitHub Actions runs to completion; when a change publishes a version, install and exercise it. Every PR must carry evidence (commands, output, run link) — no unverified claims.
- **Root-cause only** — fix problems (including lint and CI failures) at the source; never skip, suppress, inline-disable, or hand-wave them. CI rejects masked issues.
- **No backward compat** — prerelease code; make clean-break changes, no shims or deprecated interfaces.
- **DRY** — reuse existing code, patterns, and content before adding new.
- **Clean branches** — a branch is for trial-and-error; only verified, feature-complete code merges. A PR means "this works", not "does this work?" — never open or merge exploratory code, and drop unneeded (YAGNI) work.
- **Local vs CI** — `pre-commit` runs a subset; the `Lint Code Base` gate also runs textlint prose/terminology. Reproduce it before pushing.

See `CONTRIBUTING.md` for the full detail.
