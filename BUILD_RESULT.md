# SDW Phase 2 Build Result

Date: 2026-06-08
Branch: `feat/sdw-phase2-stores`

## Built

- Working-state store: added `_sdw_working_state` store API for `state.{scope}.{state_id}` records, using the closed `retrieval_context`, `tool_result_summary`, and `task_checkpoint` payload variants. Writes mint a `Persistable` through `mintPersistable`, then use the Phase 1 write gate. Reads decrypt with `sdw-working-state-v1` and reject unknown versions, auth failures, scope mismatch, or `state_id` mismatch.
- Query-history store: added `_sdw_query_history` store API for audit-derived query cache records and `chain-head.{fortress_id}`. Appends require `SdwTransactional`, materialize from audit event inputs, compute monotonic per-fortress sequence plus `previous_record_hash`, `record_hash`, and `previous_query_key`, and advance the chain head in the same local SDW transaction via `txn.writePersistable`. Boot reconciliation verifies the backward hash chain and rebuilds/repoints from audit events when the cache is missing or tampered. Query history remains untrusted cache data, not audit or authorization evidence.
- Document-corpus store: added `_sdw_document_corpus` store API for `doc.{document_id}` and `chunk.{document_id}.{ordinal}.{chunk_id}`. Document metadata and chunk text are encrypted record bodies under `sdw-document-corpus-v1`; `source.uri` remains only in the encrypted body and is never used in keys or AAD. No URL fetch path was added.
- Shared SDW contracts: extended the Phase 1 record union for the full Phase 2 query-history and document-corpus fields, and tightened `mintPersistable` runtime validation for the Phase 2 variants, enums, refs, hashes, policy visibility, and document/chunk metadata.
- Tests: added `server/test/sdw/sdw-phase2-stores.test.ts` covering schema validation, size bound rejection, taint rejection, encrypted writes, direct-read fail-closed identity/version checks, query hash-chain integrity and audit replay, document `source.uri` key/AAD isolation, and absence of URL-fetch methods. Existing SDW architecture tests continue to cover raw write bypasses.

## Gates

- Confirmed Phase 1 is merged at `HEAD` / `origin/main`: `217d767c feat(sdw): Phase 1 foundation — storage spine + enforced can't-persist-secrets write gate (#420)`.
- `cd server && npm run typecheck`: pass.
- Focused SDW gate: `npx vitest run test/sdw/sdw-phase1.test.ts test/sdw/sdw-architecture.test.ts test/sdw/sdw-phase2-stores.test.ts`: pass, 19 passed / 1 skipped.
- Full required gate: `cd server && npm run typecheck && npm test`: pass, 450 test files passed / 1 skipped, 5511 tests passed / 8 skipped.

Note: the full gate must run outside the filesystem/network sandbox because many existing tests bind loopback TCP or Unix sockets. The sandboxed attempt failed with `listen EPERM`; the escalated run passed.

## Deferred

- Phase 3 vector-memory and HNSW implementation remains deferred pending the HNSW serialization proof, supply-chain pinning, and remote-embedding pre-egress gate.
- Phase 4 export/import remains deferred, including Microsoft PAM interoperability and signed manifest routing.
- D4 query timestamp blinding (`query.{seq_padded}.{query_id}`) remains the scheduled follow-up; Phase 2 preserves the ratified v1 plaintext normalized timestamp key shape.
