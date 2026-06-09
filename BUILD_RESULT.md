# SDW Phase 1 Build Result

Date: 2026-06-08
Branch: `feat/sdw-phase1-foundation`

## What Changed

- Added `server/src/sdw/` as a new SDW module boundary.
- Added `LmdbStorageBackend` over the published lmdb-js npm package (`lmdb@3.4.2`) with raw-byte `StorageBackend` methods and an optional `SdwTransactional` capability.
- Added the SDW v1 identifier grammar, length-prefixed AAD construction, generated storage-key helpers, and `source_ref_id` derivation so raw `source.uri` never enters keys or AAD.
- Added the closed `SdwRecord` union for Phase 1 and referenced later protected record types without raw JSON escape hatches in the union.
- Added the D3 write gate: branded `Persistable<T>`, single `mintPersistable` brand factory, taint enforcement, size/schema checks, grammar checks, AAD construction, defense-in-depth classifier, and centralized `sdwBackendWrite`.
- Closed adversarial review P1s: `sdwBackendWrite` now revalidates the runtime persistable at the actual write boundary, including taint, schema, namespace, storage key, fortress id, classifier, and recomputed AAD. The TypeScript brand remains a compile-time aid, not the load-bearing persistence guarantee.
- Closed raw SDW write bypasses: `LmdbStorageBackend.write` and transactional `SdwTxn.write` reject direct SDW namespace writes unless the bytes were produced by the SDW write gate for the exact namespace/key; transactions now expose `writePersistable` for gated encrypted SDW writes.
- Closed R2/R3 public and direct-module authority bypasses: `server/src/sdw/index.ts` explicitly re-exports only public write-gate APIs; `runWithSdwWriteAuthority` and `sdwBackendWriteAuthenticatedMeta` no longer exist as exported helpers; callers cannot import the public SDW barrel or `write-gate.ts` directly to open raw LMDB write authority or perform arbitrary `_sdw_meta` writes.
- Replaced ambient SDW write authority with private prepared-payload authorization tied to `{ namespace, storageKey, data }`, so copying a prepared payload to another `_sdw_*` key or importing a raw authority helper cannot bypass the gate.
- Routed replay-anchor `_sdw_meta` persistence through the existing `writeReplayAnchor` API, which constructs the MAC-authenticated marker envelope before authorizing the prepared meta payload.
- Added catalog store support for `_sdw_catalog/catalog.environment` under `sdw-catalog-v1`, including fortress binding and fail-closed open behavior.
- Added the MAC-authenticated replay anchor at `_sdw_meta/sdw-replay-anchors-v1`, following the existing `{ marker, data, mac }` anchor pattern.
- Added typed `UnsupportedRecordVersion` behavior: direct read throws; list rehydration skips with accounting.
- Closed catalog list rehydration P3: listed `catalog.*` keys now derive AAD from the listed key, so future unsupported catalog records account as `unsupported_version`.
- Added SDW supply-chain documentation in `server/docs/sdw/supply-chain.md`.

## Dependency / Native Binary Pin

- Added exact dependency `lmdb@3.4.2`.
- `server/package-lock.json` pins `lmdb@3.4.2` and optional prebuilt native packages:
  `@lmdb/lmdb-darwin-arm64`, `@lmdb/lmdb-darwin-x64`, `@lmdb/lmdb-linux-arm`,
  `@lmdb/lmdb-linux-arm64`, `@lmdb/lmdb-linux-x64`, `@lmdb/lmdb-win32-arm64`,
  and `@lmdb/lmdb-win32-x64`, all at `3.4.2` with integrity hashes.
- Install-time network path: npm registry tarballs for the package and optional platform prebuilds. Runtime LMDB use is embedded and requires no Castle Wall egress exception.
- Note: `lmdb-js` is the upstream project/repository name; the published npm package name is `lmdb`.

## Bypass / Gate Tests Added

- Compile-time contracts in `server/src/sdw/type-contracts.ts`:
  - `sdwBackendWrite` rejects raw records.
  - `Persistable` cannot be structurally forged outside the write-gate module.
  - `SdwRecord` rejects raw/unknown payload members.
- Runtime tests in `server/test/sdw/sdw-phase1.test.ts`:
  - forbidden and missing taints are rejected;
  - forged/mutated persistables are revalidated at write time and rejected for secret classifier hits or forbidden taint;
  - Principal-Policy, Ed25519 private-key, and recovery-key fixtures are rejected without echoing matched material;
  - SDW writes persist encrypted envelope bytes, not plaintext;
  - direct LMDB and transactional raw writes to SDW namespaces are rejected, while transactional `writePersistable` writes encrypted bytes through the gate;
  - key/AAD grammar vectors cover catalog, working-state, query-history, document, chunk, vector, map, and segment keys;
  - hostile `source.uri` stays out of storage keys and AAD;
  - catalog missing/mismatched fortress behavior fails closed;
  - replay anchor valid/invalid/stripped semantics are covered;
  - unknown-newer direct read throws `UnsupportedRecordVersion`, while list rehydration skips with accounting, including non-primary `catalog.*` keys.
- Architecture test in `server/test/sdw/sdw-architecture.test.ts` scans every TypeScript file under `server/src` and fails if raw write authority helpers are exported or imported, if any source file imports `LmdbStorageBackend.write` directly, if any non-gated source path calls `backend.write`/`storage.write`/`txn.write`/`SdwTxn.write` against an `_sdw_*` namespace, or if LMDB's allowed write sites lose the reachable guard/prepare sequence.

## Verification

- `cd server && npm run typecheck`: passed.
- `cd server && npm test -- --run test/sdw/sdw-phase1.test.ts test/sdw/sdw-architecture.test.ts`: passed, 2 files / 14 tests.
- `cd server && npm test`: passed.
- Final test summary: `446 passed | 1 skipped` test files; `5472 passed | 8 skipped` tests.
- `.test-baseline`: `5423`; final passing count is above baseline.
- No transform or collection errors in the final Vitest summary.

## Deferred To Later Phases

- Phase 2: working-state store behavior, query-history store, audit-log reconciliation, document-corpus store.
- Phase 3: vector-memory/HNSW, HNSW snapshot serialization proof, hnswlib-node supply-chain pin, and remote-embedding pre-egress gate.
- Phase 4: export/import, signed manifests, AAD rebind, and target-fortress re-encryption.
