# Contributing to ULPF Prism

This guide keeps beginner-friendly Git work safe and makes shared-contract changes visible before they affect another component.

## Start a branch

Never commit directly to `main`. Start each issue from the current remote `main` branch and use `feature/issue-N-short-name`:

```bash
git switch main
git pull origin main
git switch -c feature/issue-N-short-name
```

Replace `N` and `short-name` with the GitHub issue number and a short description, for example `feature/issue-12-add-source-pack-guide`.

## Make a focused change

Keep a branch focused on one issue. Check what will be committed, add only those files, run the relevant checks, then commit and push:

```bash
git status
git add README.md docs/event-schema.md
python -m pytest
ruff check src tests
git commit -m "docs: explain UnifiedEvent validation"
git push -u origin feature/issue-N-short-name
```

Do not use `git add .` until `git status` confirms every changed file belongs to the issue. Do not add credentials, `.env` files, tokens, private logs, or production data.

## Open a pull request

Open the pull request against `main` and use this description:

```text
Closes #N

Completed work:
- What changed and why

Checks:
- Command and result

Help needed:
- None, or the decision/question needed
```

At least one teammate must approve before merge. A change to a shared contract (the schema, `src/contracts/`, shared class name, event field, required enum, or component boundary) needs two approvals: the contract owner and one affected component owner.

## Safe Git rules

- Do not commit directly to `main`.
- Do not force-push a shared branch.
- Do not put secrets or real customer/production logs in Git, issues, or pull requests.
- Do not use destructive recovery commands such as `git reset --hard`, `git clean -fd`, or `git push --force` without the maintainer explicitly coordinating the recovery.
- If a conflict or unexpected change appears, stop, save your work, and ask in the issue or team channel before overwriting anything.

For the daily coordination routine, see the [development workflow](docs/development-workflow.md).
