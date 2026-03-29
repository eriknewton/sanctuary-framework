# SPRINT RESULT — SEC-019: Config Silently Accepts Unimplemented Features

**Sprint Date:** 2026-03-28
**Finding:** SEC-019 (High)
**Branch:** `security-review`
**Implementer:** Claude (sprint session)

---

## What Changed and Why

### Changes

**`server/src/config.ts`:**
- Added `validateConfig()` function (exported) that checks three config fields against whitelists of implemented values:
  - `state.key_protection`: allows `"passphrase"`, `"none"` — rejects `"hardware-key"`
  - `execution.environment`: allows `"local-process"`, `"docker"` — rejects `"tee"`
  - `disclosure.proof_system`: allows `"commitment-only"` — rejects `"groth16"`, `"plonk"`
- Collects all violations into a single error message (does not fail on first violation)
- Error messages name the specific field, the invalid value, and the implemented alternatives
- Called from `loadConfig()` after merging file config into defaults
- Validation errors are re-thrown through the catch block (file-not-found errors still fall back to defaults)

**`server/test/security/reject-unimplemented-features.test.ts`** (new file):
- 13 regression tests covering:
  - 4 tests for each unimplemented value (groth16, plonk, hardware-key, tee) — verifies throw with descriptive error
  - 1 test for multiple unimplemented features in a single config — verifies all are reported
  - 5 tests for implemented values (commitment-only, passphrase, none, local-process, docker) — verifies acceptance
  - 1 test for default config with no overrides — verifies normal operation
  - 2 unit tests for `validateConfig()` directly

### Why

The root cause was that `loadConfig()` had no semantic validation. TypeScript union types defined the valid values but were erased at runtime. Any JSON value from a config file was merged in without checking implementedness. This allowed users to configure `proof_system: "groth16"` and believe they had SNARK proofs, when the system silently operated in commitment-only mode.

This violates CLAUDE.md constraint #5: "Never silently degrade to a less-secure behavior on error."

---

## Test Suite Output

```
Test Files  28 passed (28)
     Tests  278 passed (278)
  Duration  20.13s
```

Test count: 265 → 278 (+13 new regression tests)

---

## New Risk Introduced

None significant. Users with unimplemented values in their config will now get a startup error instead of silent operation. This is the intended behavior — converting a silent security misrepresentation into an explicit, actionable failure.

The only edge case: a user who had `proof_system: "groth16"` in their config but never noticed (because the system silently ignored it) will now need to change it to `"commitment-only"`. The error message tells them exactly what to do.

---

## Adjacent Findings Noticed

None. This fix is isolated to the config parser and does not touch any other security surface.

---

## Sprint Contract Criteria Assessment

| Criterion | Met? |
|-----------|------|
| `loadConfig()` rejects all three unimplemented feature values | ✅ |
| Error messages name the specific feature and its current value | ✅ |
| All implemented values accepted without error | ✅ |
| Default config (no file) continues to work | ✅ |
| Regression tests cover all unimplemented and implemented values | ✅ (13 tests) |
| Full test suite passes with count >= 265 | ✅ (278 tests) |

All sprint contract criteria are met.
