# SDW Memory Conformance Profile for Microsoft Agent Framework

Status: Phase 0 profile for the Microsoft Agent Framework memory provider
(SDW-backed).
Date: 2026-06-23.
Author: Erik Newton.

This profile describes how Sanctuary's Sovereign Data Warehouse (SDW) maps to
the real Microsoft Agent Framework memory extension point and to the Foundry
memory object model. It does not claim conformance to any nonexistent Microsoft
standard name.

## Scope

This build targets the long-term-memory `ContextProvider` lifecycle:

- `before_run`: retrieve relevant memory before an agent turn.
- `after_run`: store selected memory after an agent turn.

The full `HistoryProvider` path for lossless Microsoft `Message` round-trips is
deferred. SDW memory passages are flat text plus tags, metadata, timestamps,
and content hashes. That shape is appropriate for long-term context injection,
but it is not yet a full `Message` serialization layer.

## Concept Mapping

| Microsoft Agent Framework or Foundry concept | SDW concept | Status |
|---|---|---|
| `ContextProvider.before_run` context retrieval | `memory_search` followed by explicit `memory_get` for full body reads | Implemented by the Python provider shim; lexical search only |
| `ContextProvider.after_run` memory persistence | `memory_insert` | Implemented by the Python provider shim |
| Session or thread scope | Provider-derived `owner_ref` plus a `session_id:*` SDW tag | Implemented in the provider; the live Sanctuary MCP server supplies the actual adapter owner scope |
| Remember command | Provider-selected `memory_insert` call | Implemented; still subject to SDW write gate and secret classifier |
| Forget command | `memory_delete` | Intentionally returns "deletion requested, pending operator approval" unless an operator-approved Sanctuary gate permits execution |
| Foundry procedural memory | SDW passage tagged `mem_type:procedural` with profile metadata | Convention defined here and emitted by the provider as tags; metadata is documented for adapter bindings that expose metadata |
| Foundry user-profile memory | SDW passage tagged `mem_type:user-profile` with profile metadata | Convention defined here and emitted by the provider as tags |
| Foundry chat-summary memory | SDW passage tagged `mem_type:chat-summary` with profile metadata | Convention defined here and emitted by the provider as tags |
| Foundry TTL | No silent SDW auto-expiry | Intentional sovereignty difference |
| Hosted semantic ranking | Swappable memory engine above SDW | Intentional composable-sovereignty boundary |
| `HistoryProvider` `Message` persistence | Canonical `Message` serialization into SDW passages | Deferred fast-follow |

## Intentional Differences

These are not hidden gaps or conformance tricks. They are explicit sovereignty
differences.

1. No silent TTL auto-expiry.

   SDW does not silently delete memory because an age counter expired. A future
   operator-run TTL sweep would be a Tier-1 write tool and must receive the same
   approval, audit, and fail-closed treatment as `memory_delete`.

2. Forget is not instant by default.

   `memory_delete` is irreversible secure deletion and remains Tier 1. A
   Microsoft-style forget command is surfaced as deletion requested, pending
   operator approval. The provider never auto-approves a delete to appear more
   conformant.

3. Semantic ranking stays in the swappable engine.

   SDW is the custody floor: encrypted storage, audit, inspectability, export,
   deletion, and deterministic lexical search. Embeddings, reranking, recency
   heuristics, and richer retrieval IQ stay in the agent memory engine above
   SDW.

## Foundry Memory Type Convention

Every memory inserted by the provider carries exactly one type tag:

| Foundry type | SDW tag |
|---|---|
| Procedural | `mem_type:procedural` |
| User profile | `mem_type:user-profile` |
| Chat summary | `mem_type:chat-summary` |

The profile metadata convention for bindings that expose metadata is:

| Metadata key | Value |
|---|---|
| `ms_agent_framework_provider` | `SanctuaryContextProvider` |
| `ms_memory_type` | `procedural`, `user-profile`, or `chat-summary` |
| `session_id_hash` | `base64url_sha256("sdw-ms-session-v1\0" || session_id)` |
| `agent_id_hash` | `base64url_sha256("sdw-ms-agent-v1\0" || agent_id)` |
| `sdw_owner_ref` | Deterministic owner reference for the operator and agent |
| `ttl_policy` | `operator_controlled_no_silent_expiry` |

The current shipped MCP `memory_insert` tool accepts tags, text, taint, and an
optional passage id. It does not accept a metadata argument. The provider
therefore emits the type, combined scope, session, and agent conventions as tags
on the current MCP path, and exposes the metadata convention in its write result
for future adapter bindings that can pass metadata through directly.

## Session Mapping

The provider maps Microsoft session and agent identity to SDW-safe identifiers:

- `owner_ref = base64url_sha256("sdw-ms-owner-v1\0" || operator_id || "\0" || agent_id)`
- `ms_scope_tag = "ms_scope:" || base64url_sha256("sanctuary-ms-scope-v1\0" || operator_id || "\0" || agent_id || "\0" || session_id)`
- `session_tag = "session_id:" || base64url_sha256("sdw-ms-session-v1\0" || session_id)`
- `agent_tag = "agent_id:" || base64url_sha256("sdw-ms-agent-v1\0" || agent_id)`

The `owner_ref` is the stable memory archive scope for one operator plus one
agent. The `ms_scope:*` tag is the isolation boundary for current reads and
writes: the provider writes it on `memory_insert` and passes the exact same tag
to the existing `memory_search` tag filter. `session_id:*` and `agent_id:*`
remain observability tags but are not the retrieval isolation boundary.

Live Sanctuary currently wires the memory MCP tools to a configured adapter
owner scope inside the Sanctuary server. The Python provider cannot pass
`owner_ref` as a tool argument through the existing six-tool surface. This
profile therefore treats `owner_ref` as the provider's documented scope value
and `ms_scope:*` as the interoperable filter on the current MCP surface.

## Taint and Secret Boundary

Provider writes assert one of the SDW persistable taints:

- `user_content`
- `agent_derived_clean`
- `system_generated`

This assertion does not prove the text is secret-free. SDW's structural
provenance guarantee applies to values routed through SDW provenance minters;
the current provider path is a caller-asserted-taint consumer, so the SDW secret
classifier is the fail-closed backstop for free text. A classifier hit rejects
the write before encryption.

## Conformance Honesty

This profile claims only the verified scope:

- Python `SanctuaryContextProvider` against the documented
  `before_run` / `after_run` lifecycle.
- MCP-stdio client code targeting the shipped six SDW memory tools.
- Stubbed in-process conformance tests for request and response mapping.

Live subclassing against Microsoft's `agent_framework` package is unverified in
this environment because `agent_framework` and `agent_framework_core` are not
importable from the provided Python venv and network installation is disabled.

Deferred work:

- Live MCP-stdio end-to-end round-trip against a pre-seeded, keychain-free
  Sanctuary fortress.
- `HistoryProvider` with lossless `Message` fidelity.
- .NET `AIContextProvider`.
- STATE-Bench effectiveness testing.
- Operator-run TTL sweep tool with full Tier-1 gate treatment.
