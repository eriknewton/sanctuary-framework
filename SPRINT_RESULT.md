# SPRINT RESULT — SEC-005: Import Skips Signature Verification

**Sprint Date:** 2026-03-28
**Finding:** SEC-005 (High)
**Branch:** `security-review`

---

## What Changed and Why

### `server/src/l1-cognitive/state-store.ts` — `import()` method

Added a third parameter `publicKeyResolver?: (kid: string) => Uint8Array | null` to the import method. Before writing any entry from the import bundle, the method now:

1. **Resolves the `kid`** — calls the resolver to obtain the signer's Ed25519 public key. If the resolver returns `null` (identity unknown), the entry is rejected and counted in `skipped_unknown_kid`.
2. **Verifies the `sig`** — decodes the ciphertext (`entry.payload.ct`) and signature (`entry.sig`) from base64url, then calls the same `verify()` function from `core/identity.ts` that `read()` uses. If verification fails (including malformed data), the entry is rejected and counted in `skipped_invalid_sig`.

The return type is expanded to include `skipped_invalid_sig` and `skipped_unknown_kid` alongside the existing counters.

The resolver parameter is optional to maintain backward API compatibility for internal callers, but the tool handler always provides it.

### `server/src/l1-cognitive/tools.ts` — `state_import` handler

Wired a `publicKeyResolver` callback that looks up identities via `identityMgr.get(kid)` and returns the decoded public key. This keeps `StateStore` decoupled from `IdentityManager` — the state store receives a pure function, not a class dependency.

### `server/test/security/import-verifies-signatures.test.ts` — new file (5 tests)

1. Valid import with correct signatures — accepted (2 entries imported, 0 skipped)
2. Forged signature — 1 entry rejected, 1 accepted
3. Unknown kid — entry rejected, `skipped_unknown_kid` = 1
4. All entries invalid — 0 imported, 3 skipped
5. Reserved namespace — still skipped regardless of signature (existing behavior preserved)

---

## Test Suite Output

```
Test Files  25 passed (25)
     Tests  252 passed (252)
  Duration  20.06s
```

Previous count: 247. New count: 252 (+5). No regressions.

---

## New Risk Introduced

Import bundles from instances whose identities are not present on the importing instance will now be fully rejected. This is intentional and correct per CLAUDE.md constraint 4 ("Never assume trust across the Sanctuary-Concordia boundary"), but it changes behavior for bundles that previously imported silently. The structured response (`skipped_unknown_kid`) makes this diagnosable.

---

## Adjacent Findings Noticed (Not Fixed)

- **SEC-010 and SEC-014** are next in the cluster queue. The callback-based resolver pattern established here (`(identifier: string) => PublicKey | null`) is the design contract they should conform to. SEC-010 will need a Concordia-side equivalent — `signing.py` already has `verify_signature()` but it is never called.
- The `export()` method does not include identity public keys in the bundle. A future enhancement could embed the public keys needed for verification, making bundles self-verifiable. This is not a security issue (rejection is the correct behavior for unknown identities) but is a UX consideration. Logging as an observation, not fixing.

---

## Sprint Contract Criteria Assessment

| Criterion | Met? |
|-----------|------|
| `import()` rejects entries with invalid signatures | Yes — test 2 and 4 confirm |
| `import()` rejects entries with unresolvable `kid` | Yes — test 3 confirms |
| Uses same `verify()` from `core/identity.ts` | Yes — same function as `read()` |
| Return type includes `skipped_invalid_sig` and `skipped_unknown_kid` | Yes |
| All 5 regression tests pass | Yes |
| Full test suite count >= 247 | Yes — 252 |
| Callback pattern does not couple StateStore to IdentityManager | Yes — StateStore receives `(kid: string) => Uint8Array \| null` |

**Self-assessment: All sprint contract criteria are met.**
