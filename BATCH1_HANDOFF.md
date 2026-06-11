# Batch 1 ESLint Handoff

## Scope

Mechanical ESLint burn-down only:

- `prefer-const`
- `no-useless-assignment`
- `@typescript-eslint/no-unused-vars`
- `no-useless-escape`

No rule levels were changed.

## Counts

- Baseline HEAD: `b382a526dd26aa09b219f582ff4c72e511cbb849`
- Baseline lint: 281 warnings, 0 errors
- Final lint: 234 warnings, 0 errors
- Net reduction: 47 warnings

Scoped warning inventory:

- Baseline in-scope warnings: 52
- Fixed in this batch: 47
- Skipped in-scope warnings: 5

## Verification

- `npm run typecheck`: passed
- `npm test`: passed, 493 files passed, 5936 tests passed, 8 skipped
- `npm run lint -- --format json --output-file /tmp/eslint-batch1-after4.json`: passed, 234 warnings

## Skipped Items

### `no-useless-assignment`

- `server/src/l2-operational/task-coordination/task-service.ts:354`
- `server/src/mesh/envelope.ts:166`

Both warnings are on ULID-style write indexes initialized to `10` and then consumed by `chars[out++]`. The initial value is read as part of post-increment indexing. Treating these as mechanical deletions would change ID generation behavior, so they were skipped.

### `no-useless-escape`

- `server/src/proxy/client-manager.ts:166`
- `server/src/proxy/client-manager.ts:350`
- `server/src/storage/filesystem.ts:47`

These regexes are security validation or sanitization filters. Even where the escape may be trivially removable in isolation, the prompt explicitly excludes this surface unless it is both trivial and low-risk. They were left unchanged for a later security-aware pass.

## Notes

- Signature verifier destructuring keeps ignored fields excluded from canonical payloads by aliasing unused fields with `_` names instead of deleting them.
- Catch bindings were removed only where the caught error was genuinely unused.
