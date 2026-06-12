# SDW Memory-Backend Adapter (Letta-first) Design

Status: v1, Sanctuary-side half shipped (`server/src/sdw/adapters/`).
Posture: SDW is the sovereign substrate UNDER agent memory. We interoperate
with memory engines; we do not compete with them. The adapter ships before
any spec or format work.

## What this is

A small, dependency-free adapter layer that lets an OSS agent-memory engine
(Letta, formerly MemGPT, is the primary target) use the Sovereign Data
Warehouse as its passage storage backend. Letta's archival memory is a set of
"passages": units of text with an id, tags, metadata, and a creation
timestamp, exposed through insert / search / get / delete operations. The
adapter maps that operation shape onto SDW's existing document-corpus store,
so every passage a memory engine persists becomes an encrypted, operator-held,
inspectable, exportable, deletable SDW record.

## Adapter boundary

```
Letta (engine side, later lane)          Sanctuary side (this change)
--------------------------------        ------------------------------------
Letta server / archival memory          MemoryBackendAdapter contract
  passage CRUD calls          --------->  SdwMemoryBackendAdapter
  embeddings + semantic ranking            -> SdwDocumentCorpusStore
  retrieval IQ (RRF, recency)              -> SDW write gate (taint + classifier)
                                           -> AES-256-GCM at rest, HKDF per-store key
                                           -> ~/.sanctuary/state (operator custody)
```

Sanctuary side (this change):
- `MemoryBackendAdapter`: an engine-neutral TypeScript contract with
  insert / get / search / list / delete / count over passages.
- `SdwMemoryBackendAdapter`: the implementation. One passage becomes one
  `SdwDocumentRecord` plus one or more `SdwDocumentChunkRecord`s in the
  `_sdw_document_corpus` namespace, written through the SDW write gate
  (`mintPersistable` + `sdwBackendWrite`), never around it.
- Deterministic, sovereign-side lexical search (case-insensitive substring
  plus tag filter) so the operator can always query their own vault without
  any engine running.

Letta side (later lane, deliberately not built here):
- The Python connector that plugs this backend into a running Letta server.
- Embedding computation, vector indexes, semantic / hybrid ranking (RRF),
  recency weighting. The engine keeps all retrieval IQ.
- Any transport between the Letta process and the Sanctuary MCP server.

## Mapping

| Letta passage field | SDW representation |
|---|---|
| `id` | `document_id = mem.<owner_ref>.<passage_id>` (SDW identifier grammar) |
| `text` | one or more `document_chunk` records (`c0`, `c1`, ...), chunked to stay far below the 1 MiB record cap |
| `tags` | `SdwDocumentRecord.tags` (validated SDW identifiers) |
| `metadata` | `SdwDocumentRecord.metadata` key/value entries |
| `created_at` | `SdwDocumentRecord.created_at` |
| integrity | `content_hash` over the full passage text; `get` verifies the reassembled text against it and fails closed on any missing or mismatched chunk |
| `embedding` | NOT stored in v1 (see non-goals) |

`owner_ref` scopes one engine instance (or one Letta archive) to its own key
prefix, so multiple engines under one operator stay isolated and listable.

## Custody invariants preserved

1. Encrypted at rest. Every passage is encrypted with the document-corpus
   HKDF-derived key and fortress-bound AAD before it touches the backend;
   plaintext never reaches `~/.sanctuary/state`.
2. Write-gate enforced. All writes pass `mintPersistable` (persistable-taint
   check plus the secret classifier) and the raw-write authorization guard.
   A memory engine cannot persist policy, identity-key, or secret-tainted
   material through this adapter, and classifier hits fail closed.
3. Operator inspectable / exportable / deletable. Passages are ordinary
   document-corpus records: covered by the existing SDW export bundle, the
   operator query path, and secure deletion (delete uses the 3-pass
   overwrite option).
4. No silent external transmission. The adapter makes zero network calls and
   adds zero dependencies. Data leaves the vault only through the existing
   gated export path.
5. Fail closed. Decryption, authentication, identity, or chunk-completeness
   failures raise; nothing degrades to plaintext or partial reads.

## Non-goals (v1)

- No Letta dependency, no Python connector, no network transport (later lane).
- No embedding-vector custody: `_sdw_vector_memory` records exist in the SDW
  schema, but the HNSW store lane is separate; v1 deliberately omits an
  `embedding` field rather than store vectors it cannot index.
- No semantic ranking. Sovereign-side search is deterministic lexical match;
  semantic relevance is the engine's job.
- No competing serialization format: nothing here defines a bundle or wire
  format (per the interop posture, PAM/AVP conformance is a later, separate
  decision).
- No passage mutation (Letta's modify-passage). Insert / delete only in v1;
  update lands with the engine-side lane where its semantics are observable.

## Follow-on lanes

1. Letta-side Python connector (insert/search/get/delete against this
   backend, engine keeps embeddings + ranking).
2. Vector custody: persist engine-supplied embeddings as
   `SdwVectorRecord`s once the HNSW segment store lands.
3. PAM / AVP conformance profile, only after a real external adopter exists.
