# Secret Gate Build Report

Branch: `v1.x-secret-gate-hardening-2026-06-09`
Base HEAD: `65c05575`

## H-1 Replay Anchor Validation

Replay-anchor writes now call the SDW gate validation path before authorization. `prepareReplayAnchorWrite` synthesizes a bounded `replay_anchor` record, then runs the same schema and classifier checks used by normal SDW writes before the MAC envelope is authorized for `_sdw_meta`.

Additional hardening added for malformed replay-anchor data:
- missing `chain_head`, `manifests`, or `tombstones` arrays rejects with `schema_mismatch`
- malformed counter objects reject with `schema_mismatch`
- negative counters reject through the existing integer validation
- oversized anchor data rejects with `record_too_large`

## H-2 Taint Join

`combineTaint` is now written as an explicit rank comparison and is pinned by F-10. The checked-out expression already behaved as the restrictive join for the current rank order, but the test now locks the safety direction:
- `user_content + secret -> secret`
- `agent_derived_clean + identity_key -> identity_key`
- `policy + system_generated -> policy`

## Adversarial Fixture Outcomes

Fixture file: `server/test/sdw/sdw-secret-gate-adversarial.test.ts`

- F-1 encoded-key: blocked. Existing PEM marker detection did not cover encoded DER-shaped Ed25519 PKCS8 material, so a narrow base64/hex DER-prefix detector was added. Normal nearby text that is not the DER prefix still passes.
- F-2 split-field: documented limit. PEM marker fragments split across non-adjacent fields currently pass, and the stored bytes remain encrypted. This is left for M-1 provenance-derived taint work.
- F-3 forbidden taints: covered by existing `sdw-phase1.test.ts` forbidden taint fixtures. Referenced in the new suite.
- F-4 mislabeled clean generic token: documented limit. A generic third-party-token-shaped string labeled `agent_derived_clean` currently passes and is persisted only as encrypted envelope bytes. This pins M-1 honestly.
- F-5 forged brand: covered by existing `sdw-phase1.test.ts` forged persistable revalidation. Referenced in the new suite.
- F-6 raw write bypass: covered by existing architecture mutation checks, with an added direct never-authorized runtime assertion in the new suite.
- F-7 metadata smuggle: PEM-shaped metadata value blocks, invalid metadata key blocks, generic-token-shaped metadata/source URI content currently passes and is encrypted. The generic pass is an M-1 documented limit.
- F-8 broker-output persist: broker-output-shaped generic token text currently passes when mislabeled clean and is encrypted; PEM-shaped broker output blocks.
- F-9 anchor schema fuzz: malformed, negative, missing-array, and oversized anchor data reject before raw-write authorization.
- F-10 combineTaint direction: restrictive join is pinned.

## F-1 Detector

Needed: yes.

The existing classifier blocked plain PEM/private-key markers but not encoded Ed25519 PKCS8 DER material with the PEM header removed. The added detector is intentionally narrow:
- hex prefix: Ed25519 PKCS8 DER prefix
- base64 prefix: the base64 encoding of the same DER prefix

It does not attempt generic entropy detection for arbitrary 32-byte or 64-byte blobs because that would risk false positives on hashes, identifiers, and ordinary binary-derived content.

## Files Changed

- `.test-baseline`
- `BUILD_REPORT_secret_gate.md`
- `server/src/sdw/write-gate.ts`
- `server/test/sdw/sdw-secret-gate-adversarial.test.ts`

## Gate Output

- `npm run typecheck`: passed
- `npm test -- test/sdw/sdw-secret-gate-adversarial.test.ts`: passed, 9 tests
- `npm test -- test/sdw`: passed, 5 files and 38 tests
- `.test-baseline`: raised from `5453` to `5462`

## Left For M-1 Provenance Follow-Up

- Provenance-derived taint instead of caller-asserted clean labels.
- Split-field content reconstruction or a stronger non-regex content policy, if still desired after provenance is enforced.
- Generic third-party token handling in free-text fields, document metadata values, source URIs, and broker-output-shaped strings.
- A precise product claim separating structural crown-jewel blocking from general secret/content detection.
