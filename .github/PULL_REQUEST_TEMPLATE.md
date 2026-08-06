<!-- markdownlint-disable-next-line MD041 -->
## Summary

Brief description of the verified feature branch change and its outcome.

## Related Issue

Closes #

## Changes

-

## Verification evidence

Provide evidence: paste the commands you ran and their output (tests, local run or dev server,
lint), and link the green CI run. Verified output makes the PR ready to merge.

-

## Delivery evidence

Keep this PR moving through the background check and repair loop until GitHub reports `MERGED`.
After merge, record local cleanup. For docs-control managed-file changes, add the manifest and
downstream hash evidence that proves fleet convergence.

-

## Checklist

- [ ] Linked to a detailed issue with `Closes #N`
- [ ] Feature-complete and verified — not exploratory or trial-and-error code
- [ ] Tests written first (TDD) and passing; the issue's acceptance criteria are met
- [ ] Verified locally by running or exercising the change — evidence pasted above
- [ ] Feature branch passed exact-HEAD Antigravity review before every PR push
- [ ] Pending, failed, behind, or conflicted states repaired through `MERGED`
- [ ] Worktree and confirmed-merged branch cleaned; fleet convergence confirmed when applicable
- [ ] Follows project conventions
