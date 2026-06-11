## Summary

- Awaited previously floating async test calls/assertion setup across `server/test/**`.
- Converted compliance seed helpers to async so their `AuditLog.append()` calls are awaited.
- Marked two genuinely fire-and-forget audit-log tests with explicit `void` and comments.
- Left one `no-floating-promises` warning in place as a real finding: `server/test/l2/audit-log-flush.test.ts:140`.

## Counts

- Targeted `server/test/**` `@typescript-eslint/no-floating-promises`: 66 -> 1.
- Normal `npm run lint`: 234 warnings -> 234 warnings, exit 0. This script only runs `eslint src/`, so test-only changes do not affect its count.

## Real Finding

Awaiting `log.append("l1", "egress_allowed", ...)` in `test/l2/audit-log-flush.test.ts` makes `flush() rejects when audit persistence fails and no entry is durable` fail immediately at `append()` with `AuditPersistenceError`, before the test can assert `flush()` rejection. The site was reverted per batch instructions and documented in `BATCH2_HANDOFF.md`.

## Verification

- `npm run typecheck`
- `npm test`
- `npm run lint`

