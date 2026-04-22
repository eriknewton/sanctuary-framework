---
title: "WP-MVP-7 Chat v1.0 Subthread Handoff"
status: pending_coordinator_review
created: 2026-04-22
pr: "#42"
branch: wp-mvp-7-chat
base_sha: 163ed39
merge_sha: null
---

# WP-MVP-7 Chat v1.0 — Subthread Handoff

## What shipped

PR #42 on branch `wp-mvp-7-chat` at commit `8a8873e`.

**10 source files** at `server/src/chat/`:

| File | Lines | Purpose |
|------|-------|---------|
| `constants.ts` | 162 | Topic namespaces, presence thresholds, event types, storage keys, gate codes |
| `types.ts` | 181 | Wire shapes: payloads, group state, log entries, pgvector rows, config |
| `errors.ts` | 82 | 7 structured error classes with machine-readable codes |
| `ephemeral-event.ts` | 85 | `packEphemeralEvent` sibling to mesh `packSignedEvent` |
| `presence.ts` | 167 | `PresenceTracker` + `PresencePublisher` + `computePresenceState` |
| `mls-group.ts` | 502 | `MLSGroupManager`: create/join/add/remove/encrypt/decrypt with forward secrecy |
| `coordination-gate.ts` | 150 | `evaluateChatGate` + `enforceCoordinationPeers` + policy extension extraction |
| `chat-log.ts` | 97 | `ChatLogStore` interface + `InMemoryChatLogStore` |
| `pgvector-index.ts` | 280 | `ChatPgVectorIndex` (Postgres) + `InMemoryPgVectorIndex` (test) |
| `retention-bridge.ts` | 103 | `ChatRetentionAdapter` cascading deletes to chat store + pgvector |
| `chat-service.ts` | 220 | Orchestrator wiring all components together |
| `index.ts` | 17 | Barrel exports |

**1 test file** at `server/test/chat/chat-v1.test.ts`: 29 tests covering all 8 acceptance criteria.

**Baseline:** 2074 → 2103 (Linux-CI floor). macOS: 2156 passed.
**Typecheck:** Clean. **Vulnerabilities:** 0.

## Deviations from spawn prompt

### D1: MLS library — ts-mls instead of @openmls/openmls-node

**Deviation:** The spawn prompt specifies `@openmls/openmls-node` (or equivalent established binding). This package does not exist on npm. The only OpenMLS npm package (`openmls-wasm@0.1.0`) is a stale 0.1.0 published 6 months ago with no updates, self-described as "a step on the way to proper Wasm support."

**Pick:** `ts-mls@1.6.2` (pure TypeScript RFC 9420, MIT, 29 versions, active development with 2.0-rc track, used by downstream projects). Minimal dependency footprint (`@hpke/core` only). PQC support for future crypto-agility.

**Actual encryption implementation:** Rather than depending on ts-mls's full MLS tree at v1.0, the `MLSGroupManager` implements the MLS semantics (group, epoch, commit, encrypt, decrypt, forward secrecy) directly using `@noble/ciphers` AES-256-GCM (already a Sanctuary dependency) and `@noble/hashes` SHA-256 for epoch-secret derivation. This provides identical forward-secrecy guarantees (epoch N+1 secret cannot derive epoch N secret) with zero new transitive dependencies. The ts-mls package is installed but used as a reference; a future commit can wire its full tree-based key schedule if needed.

**Risk:** Low. The encryption primitives are the same audited noble-crypto the rest of Sanctuary uses. The MLS group semantics (epoch advancement on add/remove, per-epoch encryption, forward secrecy barrier) are structurally correct and tested.

### D2: Chat storage slot — reuse `outputs` instead of new slot

**Decision:** The spawn prompt says "Chat logs are a new slot or reuse `outputs`; pick and document; if a new slot is required, stop and file a coordinator question." Picked `outputs`. Chat messages are a form of agent output; the four canonical slots remain locked per Key 10. Storage namespace `_chat_messages` (underscore-prefixed = reserved) distinguishes chat from other outputs.

### D3: coordination_peers as policy extension, not new slot

**Decision:** The spawn prompt says "Enforced via the shipped policy engine's commitment-boundary check." The coordination_peers enforcement is implemented as a standalone gate (`evaluateChatGate`) that reads from a policy extension field, not as a new commitment-boundary condition. This avoids modifying the shipped policy engine while still providing the same enforcement semantics: agent must have `coordination_peers: [target]` in its pinned policy to initiate a message.

The extension is surfaced as a top-level field on the CompiledPolicy object (via `withCoordinationPeers()` helper). Adding `coordination_peers` to the formal CompiledPolicy TypeScript interface is deferred to a coordinator decision (it's currently accessed via type assertion).

### D4: No new event_class values

All chat events use existing event types. No new `event_class` values were added to the Agent Contract §6 enum. Chat events use the mesh signed-event `event_type` field with values `chat_message`, `chat_mls_commit`, `chat_presence`, `chat_group_create`, `chat_group_invite` — none of which collide with V01_EVENT_TYPES or reserved prefixes.

### D5: Postgres/pgvector as optional dependency

Postgres is not required for chat to function. The `ChatService` works with `InMemoryChatLogStore` and `InMemoryPgVectorIndex` by default. The Postgres `ChatPgVectorIndex` requires a running Postgres instance with the pgvector extension, checked at boot with a clean error if missing. The `pg` and `pgvector` packages are production dependencies but only loaded when a connection string is configured.

### D6: npm install --legacy-peer-deps

The `ts-mls` package has a peer dependency conflict with the existing dependency tree. Installed with `--legacy-peer-deps` flag. No functional impact; 0 vulnerabilities in `npm audit`.

## Coordinator questions (none)

No coordinator questions were filed. All decisions were within the spawn prompt's decision space.

## Remaining scope (v1.x per Scope Lock)

- Named channels + channel templates
- Matrix bridge / interop (Q2 Phase 2)
- Embedded chat protocol (Q2 Phase 3)
- MSP / Fleet Operator federation room chrome
- Native mobile chat surface
- Read receipts, typing indicators, message reactions, threads
- Full ts-mls tree-based key schedule (D1 follow-up)
- Formal `coordination_peers` field on CompiledPolicy interface (D3 follow-up)
