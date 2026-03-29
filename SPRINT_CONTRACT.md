# SPRINT CONTRACT — SEC-020: Recovery Key Path Regenerates Master Key on Restart

**Sprint Date:** 2026-03-28
**Finding:** SEC-020 (High — Critical data-loss impact)
**Branch:** `security-review`
**Implementer:** Claude (sprint session)

---

## Step 2 — Architecture Decision

### a) Root Cause

The root cause is an incomplete implementation at `server/src/index.ts:104-109`. When the recovery key path detects an existing `recovery-key-hash` in `_meta` storage (indicating a prior installation with encrypted data), the code falls through to `generateRandomKey()` instead of requiring the user to supply the original recovery key. A `TODO` comment at line 107 explicitly acknowledges this gap.

The consequence is catastrophic: every restart without a passphrase silently generates a new master key. All previously encrypted state — identities, commitments, reputation, audit logs — becomes permanently unreadable because the new key derives different namespace keys via HKDF. The old data remains on disk as unreachable ciphertext.

### b) Smallest Change That Closes the Vulnerability

Three changes to the recovery key branch in `index.ts`:

1. **When existing recovery-key-hash is found:** Read the recovery key from `SANCTUARY_RECOVERY_KEY` environment variable. If not provided, throw an error explaining the two options (set `SANCTUARY_PASSPHRASE` or `SANCTUARY_RECOVERY_KEY`). Never generate a new random key when existing encrypted data is present.

2. **Verify the recovery key:** Decode from base64url, hash, and compare against the stored hash using constant-time comparison. If the hash doesn't match, throw an error. If it matches, use the decoded bytes as the master key (the recovery key IS the base64url-encoded master key, matching first-run behavior).

3. **Safety net:** Before generating a fresh master key on first run (no existing hash), verify no encrypted data already exists under the storage path. If encrypted data exists but no recovery-key-hash is found, abort — this indicates corrupted metadata.

### c) Interactions with Other Findings

None. This fix is self-contained within the key initialization path. It does not touch the approval gate (SEC-001/002), signature verification (SEC-005/010/014), config validation (SEC-019), or any Concordia code.

### d) New Risk Introduced

- If the `SANCTUARY_RECOVERY_KEY` environment variable is set in a shell profile or process manager config, it could be exposed via `/proc/PID/environ` or process listing. This is the same risk class as `SANCTUARY_PASSPHRASE` and is an acceptable trade-off for a server that already reads its passphrase from an env var.
- Users who previously relied on the (broken) behavior of silently regenerating keys will now get a startup error. This is the correct behavior — the previous behavior was silently destroying their data.

---

## Step 3 — Sprint Contract

### Fix Chosen

Modify the recovery key branch in `createSanctuaryServer()` at `server/src/index.ts` lines 98-124 to:

1. When `_meta/recovery-key-hash` exists: require `SANCTUARY_RECOVERY_KEY` from environment, verify against stored hash, derive master key from it
2. When `_meta/recovery-key-hash` does not exist (first run): check for orphaned encrypted data as a safety net before proceeding with key generation

### Files Modified

| File | Change |
|------|--------|
| `server/src/index.ts` | Lines 98-124: Replace recovery key branch with verify-and-recover logic |
| `server/test/security/sec-020-recovery-key-restart.test.ts` | New: regression tests for SEC-020 |

### Behavior Before and After

**Before:** Server starts without passphrase when `_meta/recovery-key-hash` exists → generates new random master key → all prior encrypted state silently inaccessible → displays new recovery key as if first run.

**After:** Server starts without passphrase when `_meta/recovery-key-hash` exists → reads `SANCTUARY_RECOVERY_KEY` from env → verifies against stored hash (constant-time) → if valid, uses as master key (all prior state accessible) → if missing or invalid, throws descriptive error and refuses to start.

### What Happens to Existing Encrypted State If Key Changes

This fix ensures the key **never** changes on restart. The recovery path now recovers the original key (verified by hash) rather than replacing it. No migration path is needed because:
- The recovery key IS the master key (base64url-encoded). Recovering it restores the exact same key bytes.
- All HKDF-derived namespace keys are deterministic from the master key, so all existing encrypted state remains readable.

### Migration Path

No data migration is required. The fix is purely in the startup path. Existing deployments that have been restarting without credentials have already lost access to their original data (the old master key is gone). This fix prevents future occurrences. Users who saved their first-run recovery key can now use it via `SANCTUARY_RECOVERY_KEY` to start the server correctly.

### Regression Tests

1. **First run generates and stores recovery key hash** — Start without passphrase, verify `_meta/recovery-key-hash` written, recovery key returned
2. **Subsequent run with correct recovery key succeeds** — Write data in run 1, restart with `SANCTUARY_RECOVERY_KEY`, verify data readable
3. **Subsequent run without any credentials fails** — `_meta/recovery-key-hash` exists, no env vars set → throws error
4. **Subsequent run with incorrect recovery key fails** — Wrong `SANCTUARY_RECOVERY_KEY` → throws with "incorrect" message
5. **First run with orphaned encrypted data fails** — Pre-populate storage with data but no recovery-key-hash → throws safety net error

### Definition of Done

The evaluator will verify:
1. The code path at `index.ts:104-109` no longer calls `generateRandomKey()` when existing encrypted data is present
2. The recovery key hash is verified with constant-time comparison
3. Error messages clearly explain what the user must do
4. All 5 regression tests pass
5. Full test suite count does not decrease from 278
6. Data written under one master key is readable after restart with the correct recovery key

### Prompt Injection Assessment

This fix does not touch any input/output path that reaches a model prompt. The `SANCTUARY_RECOVERY_KEY` is read from the process environment, not from MCP tool arguments. No prompt injection surface is introduced.
