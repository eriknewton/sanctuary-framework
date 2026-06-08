# SDW Phase 1 Build Result

Date: 2026-06-08
Branch: `feat/sdw-phase1-foundation`

## What Changed

- Added `server/src/sdw/` as a new SDW module boundary.
- Added `LmdbStorageBackend` over the published lmdb-js npm package (`lmdb@3.4.2`) with raw-byte `StorageBackend` methods and an optional `SdwTransactional` capability.
- Added the SDW v1 identifier grammar, length-prefixed AAD construction, generated storage-key helpers, and `source_ref_id` derivation so raw `source.uri` never enters keys or AAD.
- Added the closed `SdwRecord` union for Phase 1 and referenced later protected record types without raw JSON escape hatches in the union.
- Added the D3 write gate: branded `Persistable<T>`, single `mintPersistable` brand factory, taint enforcement, size/schema checks, grammar checks, AAD construction, defense-in-depth classifier, and centralized `sdwBackendWrite`.
- Added catalog store support for `_sdw_catalog/catalog.environment` under `sdw-catalog-v1`, including fortress binding and fail-closed open behavior.
- Added the MAC-authenticated replay anchor at `_sdw_meta/sdw-replay-anchors-v1`, following the existing `{ marker, data, mac }` anchor pattern.
- Added typed `UnsupportedRecordVersion` behavior: direct read throws; list rehydration skips with accounting.
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
  - Principal-Policy, Ed25519 private-key, and recovery-key fixtures are rejected without echoing matched material;
  - SDW writes persist encrypted envelope bytes, not plaintext;
  - key/AAD grammar vectors cover catalog, working-state, query-history, document, chunk, vector, map, and segment keys;
  - hostile `source.uri` stays out of storage keys and AAD;
  - catalog missing/mismatched fortress behavior fails closed;
  - replay anchor valid/invalid/stripped semantics are covered;
  - unknown-newer direct read throws `UnsupportedRecordVersion`, while list rehydration skips with accounting.
- Architecture test in `server/test/sdw/sdw-architecture.test.ts` fails if SDW files call backend writes outside `write-gate.ts`.

## Verification

- `cd server && npm run typecheck`: passed.
- `cd server && npm test`: passed.
- Final test summary: `446 passed | 1 skipped` test files; `5469 passed | 8 skipped` tests.
- `.test-baseline`: `5423`; final passing count is above baseline.
- No transform or collection errors in the final Vitest summary.

## Deferred To Later Phases

- Phase 2: working-state store behavior, query-history store, audit-log reconciliation, document-corpus store.
- Phase 3: vector-memory/HNSW, HNSW snapshot serialization proof, hnswlib-node supply-chain pin, and remote-embedding pre-egress gate.
- Phase 4: export/import, signed manifests, AAD rebind, and target-fortress re-encryption.
