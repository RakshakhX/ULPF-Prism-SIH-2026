# Development workflow

Use the project board to make work visible before it is merged. Move an issue through these statuses deliberately:

| Status | Meaning |
|---|---|
| Backlog | Valuable work not yet selected. |
| Ready | Clear enough to start; owner and acceptance checks are known. |
| In progress | A member is actively working on a branch. |
| Blocked | Work cannot continue without a decision, access, review, or dependency. Say what is needed. |
| In review | A pull request is open and awaiting review. |
| Testing | Checks are running or a test finding is being resolved. |
| Done | Merged, verified, and documented where needed. |

## Daily update

Post one short update in the issue or agreed team channel:

```text
Yesterday: completed work
Today: planned work
Blocked: required help or decision
```

Write `Blocked: none` when there is no blocker. A useful blocker names the missing decision and who can make it, for example: `Blocked: confirm whether proxy fields belong in extensions; needs normalization owner decision.`

## Beginner loop

1. Pick a Ready issue and assign yourself.
2. Create the branch using [CONTRIBUTING.md](../CONTRIBUTING.md).
3. Make a small, focused change and run the relevant checks locally.
4. Push the branch, open a pull request, and move the issue to In review.
5. Address review comments without overwriting others’ work. After merge and verification, move it to Done.

If an issue becomes unclear, move it to Blocked rather than guessing about a shared field, name, or boundary.
