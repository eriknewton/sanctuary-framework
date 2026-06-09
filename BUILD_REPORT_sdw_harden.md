# SDW replay-floor and list-honesty hardening build report

Date: 2026-06-09
Branch: `v1.x-sdw-replay-floor-hardening-2026-06-09`
Base: `6c5baf7f`

## Findings Closed

### Catalog replay floor

Fix:
- Added `assertReplayAnchorPresentForEstablishedStore`.
- `SdwCatalogStore.openExisting` now reads the replay anchor and fails closed with `replay_anchor_invalid` when the catalog store is established and the anchor is absent or stripped.
- Existing valid-anchor rollback detection remains unchanged.

Empty-vs-established distinction:
- Empty store with no catalog and no anchor still returns `empty_environment`, preserving first-boot behavior.
- Established store with catalog bytes and stripped anchor now fails closed.

### Query-history replay floor

Fix:
- `SdwQueryHistoryStore` now retains the master key so it can read `_sdw_meta` replay anchors.
- `readChainHead` and transactional chain-head reads compare `head.latest_sequence` with the meta anchor `chain_head` floor for the fortress.
- A replayed or truncated chain head below the floor throws `SdwReplayAnchorError` with `replay_detected`.
- Query-history append and rebuild update the meta anchor `chain_head` sequence inside the same `sdwTransaction` as the chain-head write.

Empty-vs-established distinction:
- First append on an anchorless empty chain is allowed and creates the anchor floor.
- A persisted chain head with a stripped anchor now fails closed with `replay_anchor_invalid`.

### Catalog list honesty

Fix:
- `SdwListAccounting` now includes `auth_failed` and `auth_failed_keys`.
- `loadCatalogList` keeps forward-version records in `skipped` but surfaces authentication failures separately.
- Direct `openExisting` fail-closed behavior is unchanged.

### Content classifier honesty

Fix:
- Reframed the write-gate regex classifier comment as defense in depth.
- The enforced control remains the structural taint allow-list, persistable brand, and raw-write re-validation.

Skipped:
- Did not add base64, hex, or DER detectors. The heuristic would carry false-positive risk for legitimate user content, and the structural gate is the actual enforced control.

### Envelope timestamp note

Fix:
- Added a code comment on `EncryptedPayload.ts` equivalent location in `server/src/core/encryption.ts`.
- The comment states that envelope `ts` is plaintext metadata and must not be used for security decisions.
- Envelope format was not changed.

## Files Changed

- `.test-baseline`
- `server/src/core/encryption.ts`
- `server/src/sdw/catalog-store.ts`
- `server/src/sdw/errors.ts`
- `server/src/sdw/query-history-store.ts`
- `server/src/sdw/replay-anchor.ts`
- `server/src/sdw/write-gate.ts`
- `server/test/sdw/sdw-phase1.test.ts`
- `server/test/sdw/sdw-phase2-stores.test.ts`

## Updated Assertion

Updated `sdw-phase1.test.ts` from the old expectation that stripped anchors were "no trusted floor" to the new rule:
- `readReplayAnchor` can still report `stripped` for raw anchor absence or marker stripping.
- `openExisting` on an established catalog must now fail closed with `replay_anchor_invalid`.
- Empty first-boot still reports `empty_environment`, not replay-anchor failure.

## New Tests

- Established catalog plus stripped replay anchor fails closed.
- Empty catalog store plus no anchor preserves first-boot behavior.
- Tampered catalog entry reports `auth_failed` and does not appear in benign `skipped`.
- Query-history append advances the meta anchor chain-head floor.
- Replayed chain head below the meta floor fails closed.
- Established query-history chain plus stripped meta anchor fails closed.

## Gates

- `npm run typecheck`: passed.
- `npm test -- test/sdw`: passed.
  - 4 test files passed.
  - 29 tests passed.

Note:
- `npm test -- server/test/sdw` from `server/` built successfully but Vitest found no files because the filter was package-relative. The successful targeted gate used `test/sdw`.

## Baseline

- `.test-baseline` raised from `5423` to `5426`.
- Net test additions: 3.
- The updated stripped-anchor assertion was not counted as a deletion.

## Deviations

- No AAD or on-disk envelope format change was made.
- No content-classifier detectors were added, for the false-positive risk noted above.
- No push, PR, or merge performed.
