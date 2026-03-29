# SPRINT RESULT — SEC-020: Recovery Key Path Regenerates Master Key on Restart

**Sprint Date:** 2026-03-28
**Finding:** SEC-020 (High — Critical data-loss impact)
**Branch:** `security-review`
**Implementer:** Claude (sprint session)

---

## What Changed and Why

### Changes

**`server/src/index.ts` (lines 98-124, recovery key branch):**

The entire `else` branch (no passphrase path) was rewritten:

1. **Existing installation (recovery-key-hash found):**
   - Reads `SANCTUARY_RECOVERY_KEY` from `process.env`
   - If missing: throws descriptive error listing both credential options (`SANCTUARY_PASSPHRASE` or `SANCTUARY_RECOVERY_KEY`)
   - Decodes recovery key from base64url with format and length validation
   - Hashes the decoded key via `hashToString()` (SHA-256 → base64url)
   - Compares against stored hash using `constantTimeEqual()` on the hash bytes
   - If mismatch: throws error stating the recovery key is incorrect
   - If match: sets `masterKey = recoveryKeyBytes` (the recovery key IS the master key)
   - Does NOT set `recoveryKey` (no first-run banner displayed)

2. **First run (no recovery-key-hash):**
   - Added safety net: checks `_meta` for orphaned `key-params` entries
   - If key-params exist without a recovery-key-hash: throws error (corrupted/incomplete installation)
   - Otherwise: proceeds with existing first-run behavior (generate key, store hash, display banner)

**`server/test/security/sec-020-recovery-key-restart.test.ts` (new file):**
- 9 regression tests covering:
  - First run generates and stores recovery key hash
  - Subsequent run with correct recovery key succeeds (verifies data encrypted in run 1 is decryptable after recovery)
  - Subsequent run without any credentials fails with descriptive error
  - Subsequent run with incorrect recovery key fails
  - Invalid base64url encoding rejected
  - Incorrect key length rejected
  - Orphaned key-params without recovery-key-hash triggers safety net
  - Passphrase path unaffected (non-regression)
  - Constant-time hash comparison unit test

### Why

The root cause was a `TODO` at line 107 that was never completed. When `_meta/recovery-key-hash` existed (indicating prior encrypted data), the code called `generateRandomKey()` — creating a fresh master key that couldn't decrypt any prior state. Every restart silently orphaned all existing data.

This violates CLAUDE.md constraint #5 ("Never silently degrade to a less-secure behavior on error") and the sovereignty property that encrypted state must remain accessible to its owner.

---

## Test Suite Output

```
Test Files  29 passed (29)
     Tests  287 passed (287)
  Duration  20.06s
```

Test count: 278 → 287 (+9 new regression tests)

---

## New Risk Introduced

1. **Environment variable exposure:** The `SANCTUARY_RECOVERY_KEY` env var carries the master key in base64url form. This is the same risk class as the existing `SANCTUARY_PASSPHRASE` env var — both are readable via `/proc/PID/environ` by a process owner. Acceptable trade-off for a server that already accepts its primary credential via environment variable.

2. **Breaking change for broken deployments:** Users who were unknowingly restarting in recovery-key mode without credentials will now get an error instead of a silently-broken server. This is the correct behavior — the previous behavior was destroying their data.

---

## Adjacent Findings Noticed

None. This fix is isolated to the key initialization path in `createSanctuaryServer()` and does not touch any other security surface.

---

## Sprint Contract Criteria Assessment

| Criterion | Met? |
|-----------|------|
| Code path at index.ts:104-109 no longer calls `generateRandomKey()` when existing data present | ✅ |
| Recovery key hash verified with constant-time comparison | ✅ (`constantTimeEqual` on hash bytes) |
| Error messages clearly explain what the user must do | ✅ (lists both credential options) |
| All 5+ regression tests pass | ✅ (9 tests) |
| Full test suite count does not decrease from 278 | ✅ (287 tests, +9) |
| Data written under one master key is readable after restart with correct recovery key | ✅ (test 2 verifies encrypt/decrypt roundtrip) |

All sprint contract criteria are met.
