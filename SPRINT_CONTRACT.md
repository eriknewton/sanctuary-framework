# SPRINT CONTRACT — SEC-005: Import Skips Signature Verification

**Sprint Date:** 2026-03-28
**Finding:** SEC-005 (High)
**Branch:** `security-review`
**Cluster:** First of three (SEC-005, SEC-010, SEC-014) — this sprint establishes the verification architecture.

---

## Architecture Decision

### a) Root cause — not the symptom

The `import()` method in `state-store.ts:518-598` writes each `StateEntry` directly to storage without verifying the Ed25519 signature (`sig` field) against the public key of the claimed signer (`kid` field). The root cause is that the import path has no concept of identity resolution — it receives entries with `kid` and `sig` fields but never looks up the corresponding public key to verify. This is not a missing call to an existing verification path; it is a missing *capability*: the `StateStore.import()` method has no access to identity data and no mechanism to resolve a `kid` to a public key.

### b) Smallest change that closes the vulnerability

Add a `publicKeyResolver` callback parameter to `StateStore.import()` that maps a `kid` (identity ID) to its public key (`Uint8Array | null`). For each entry in the import bundle:

1. Resolve `kid` via the callback. If the identity is unknown (returns `null`), reject the entry.
2. Verify the `sig` against the entry's `payload.ct` (ciphertext) using the resolved public key — the same verification logic already used in `StateStore.read()` at line 297-307.
3. If verification fails, reject the entry.
4. Track rejection counts in the response: `skipped_invalid_sig` and `skipped_unknown_kid`.

The callback pattern is the correct architectural choice because:
- It avoids coupling `StateStore` to `IdentityManager` (the state store currently knows nothing about identities).
- It establishes a **verification interface** that SEC-010 (session state machine) and SEC-014 (attestation verification) can conform to — both will need the same pattern of "resolve identity, verify signature" without coupling their modules to identity storage.
- The `IdentityManager.get()` method already returns `StoredIdentity | undefined`, which includes `public_key` (base64url). The tool handler wires the callback.

### c) Interactions with other findings

**SEC-010** (session state machine never verifies signatures) and **SEC-014** (attestation signature verification is optional) form a cluster with SEC-005. This sprint establishes the verification pattern:
- Signature verification is **mandatory, not optional**.
- The verifier receives a key-resolver function, not a pre-loaded key map.
- Entries with unresolvable identities are **rejected, not accepted with a warning**.
- The response includes structured rejection counts so callers can distinguish "clean import" from "partially rejected import".

SEC-010 and SEC-014 are in Concordia (Python), but the design principle — mandatory verification with structured rejection — must carry forward.

### d) New risk introduced

- An import bundle created by an instance with identities not present on the importing instance will have all entries rejected. This is the **correct** behavior (CLAUDE.md constraint 4: "Never assume trust across the Sanctuary-Concordia boundary"), but it changes the behavior for bundles that previously imported successfully. The import response now includes `skipped_unknown_kid` so the caller can diagnose this.
- No risk of breaking existing write/read paths — those are not modified.

---

## Fix Specification

### Files to modify

1. **`server/src/l1-cognitive/state-store.ts`** — `import()` method (lines 518-598)
   - Add `publicKeyResolver` parameter: `(kid: string) => Uint8Array | null`
   - Add signature verification loop before writing each entry
   - Expand return type to include `skipped_invalid_sig` and `skipped_unknown_kid`

2. **`server/src/l1-cognitive/tools.ts`** — `state_import` handler (lines 614-619)
   - Wire `publicKeyResolver` callback using `identityMgr.get()` to resolve `kid` to public key

### Behavior before

Import accepts any `StateEntry` from a non-reserved namespace regardless of `sig` validity or `kid` existence. An entry with a forged signature or a nonexistent `kid` is written to storage.

### Behavior after

Import verifies every entry before writing:
- If `kid` does not resolve to a known identity, the entry is skipped and counted in `skipped_unknown_kid`.
- If `sig` does not verify against the ciphertext using the resolved public key, the entry is skipped and counted in `skipped_invalid_sig`.
- Only entries passing both checks are written to storage.
- The response includes `{ imported_keys, skipped_keys, skipped_invalid_sig, skipped_unknown_kid, conflicts, namespaces, imported_at }`.

### Regression tests

New file: `server/test/security/import-verifies-signatures.test.ts`

Tests:
1. **Valid import succeeds** — export a bundle, re-import it, all entries accepted.
2. **Forged signature rejected** — create a bundle, tamper with one entry's `sig`, import rejects that entry, others succeed.
3. **Unknown kid rejected** — create a bundle with a `kid` that doesn't exist on the importing instance, entry is rejected.
4. **All entries invalid** — import a bundle where every entry has a bad signature, result shows 0 imported, N skipped.
5. **Reserved namespace still skipped** — entries in `_identities` namespace are still skipped (existing behavior preserved).

### Prompt injection

The import path accepts a base64url-encoded JSON bundle. The bundle contents are parsed as JSON and written as `StateEntry` objects — they do not reach any model prompt. No prompt injection surface.

### Definition of done (evaluator criteria)

1. The `import()` method rejects entries with invalid signatures (forged or absent).
2. The `import()` method rejects entries with unresolvable `kid` values.
3. The verification uses the same `verify()` function from `core/identity.ts` that `read()` uses.
4. The return type includes `skipped_invalid_sig` and `skipped_unknown_kid` counts.
5. All 5 regression tests pass.
6. Full test suite count >= 247 (no decrease).
7. The callback-based resolver pattern does not couple `StateStore` to `IdentityManager`.
