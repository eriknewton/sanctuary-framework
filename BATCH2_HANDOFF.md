# ESLint Burn-down Batch 2 Handoff

Date: 2026-06-11
Branch: chore/eslint-burndown-batch2-tests
HEAD at start: b65f253300e9e5dd3d77d609e47e2b03f7bfecd5

## Scope

Changed test files only under `server/test/**`.
No `server/src/**`, `eslint.config.js`, or package script changes.

## Lint Counts

Targeted one-off test lint command:

```sh
npx eslint "test/**/*.ts" --no-config-lookup --ext .ts --parser @typescript-eslint/parser --plugin @typescript-eslint --parser-options '{"project":"/tmp/sanctuary-batch2-tsconfig.json","tsconfigRootDir":"/Users/eriknewton/Code/Claude/Sanctuary-worktrees/eslint-batch2/server"}' --rule "@typescript-eslint/no-floating-promises: warn"
```

The temporary TS config included `server/src/**/*` and `server/test/**/*` so the typed rule could evaluate test files without changing repo config.

- `@typescript-eslint/no-floating-promises` in `server/test/**`: 66 before, 1 after.
- Remaining target warning: `server/test/l2/audit-log-flush.test.ts:140`.
- The one-off command also reports unrelated unused `eslint-disable` directive warnings because config lookup is disabled; those were not part of this batch.
- Normal `npm run lint` still reports 234 source warnings before and after, because the checked-in lint script is `eslint src/` and does not lint `server/test/**`. It exits 0.

## Real Finding

`server/test/l2/audit-log-flush.test.ts:140`

Original floating site:

```ts
log.append("l1", "egress_allowed", "fortress-1", { seq: 0 });
await expect(log.flush()).rejects.toThrow(AuditLogPersistenceError);
```

When changed to `await log.append(...)`, the test failed immediately with `AuditPersistenceError: audit persistence write failed: audit disk unavailable` before reaching the `flush()` assertion.

This reveals that, for this failure mode, `append()` itself can reject instead of deferring the persistence failure to `flush()`. Per the batch instruction, this site was reverted to leave the warning in place and keep the behavior visible.

## Verification

From `server/`:

- `npm run typecheck`: pass.
- `npm test`: pass, 493 files passed, 1 skipped; 5936 tests passed, 8 skipped.
- `npm run lint`: exit 0, 234 warnings.

