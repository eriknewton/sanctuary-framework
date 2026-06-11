## Summary

- Reduced server ESLint warning count from 281 to 234.
- Fixed mechanical `prefer-const`, `no-useless-assignment`, `@typescript-eslint/no-unused-vars`, and safe `no-useless-escape` warnings.
- Left five scoped warnings in place where the fix was outside the mechanical boundary; details are in `BATCH1_HANDOFF.md`.

## Verification

- `npm run typecheck`
- `npm test`  
  493 files passed, 5936 tests passed, 8 skipped
- `npm run lint -- --format json --output-file /tmp/eslint-batch1-after4.json`  
  234 warnings, 0 errors
