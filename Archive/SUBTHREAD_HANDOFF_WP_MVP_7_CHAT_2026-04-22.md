---
title: "WP-MVP-7 Chat v1.0 Subthread Handoff (Rework)"
status: pending_coordinator_review
created: 2026-04-22
rework_date: 2026-04-22
pr: "#42"
branch: wp-mvp-7-chat
base_sha: 6329767
merge_sha: null
path_chosen: B
---

# WP-MVP-7 Chat v1.0 — Subthread Handoff (Rework)

## Rework summary

**Path B chosen.** The original PR #42 shipped a chat implementation that:
1. Declared `ts-mls@^1.6.2` as a dependency but never imported it at runtime
2. Labeled the implementation "MLS RFC 9420" in comments and docstrings
3. Actually used hand-rolled AES-256-GCM per-epoch encryption with SHA-256 epoch derivation

The rework strips the unused `ts-mls` dependency, rewrites all inaccurate MLS/RFC 9420 claims to honest descriptions, and surfaces a Scope Lock escalation for Erik's decision.

### Rework commits (on top of original PR #42 history)

| # | SHA | Description |
|---|-----|-------------|
| 1 | `f26120b` | Strip unused ts-mls dependency; regenerate lockfile |
| 2 | `92a81ff` | Rewrite all MLS/RFC 9420 claims to honest descriptions |
| 3 | (this commit) | Update handoff with Scope Lock escalation |

## What shipped

PR #42 on branch `wp-mvp-7-chat`, force-pushed with rework commits.

**10 source files** at `server/src/chat/`:

| File | Lines | Purpose |
|------|-------|---------|
| `constants.ts` | 162 | Topic namespaces, presence thresholds, event types, storage keys, gate codes |
| `types.ts` | 181 | Wire shapes: payloads, group state, log entries, pgvector rows, config |
| `errors.ts` | 82 | 7 structured error classes with machine-readable codes |
| `ephemeral-event.ts` | 85 | `packEphemeralEvent` sibling to mesh `packSignedEvent` |
| `presence.ts` | 167 | `PresenceTracker` + `PresencePublisher` + `computePresenceState` |
| `mls-group.ts` | ~500 | `MLSGroupManager`: create/join/add/remove/encrypt/decrypt with forward secrecy |
| `coordination-gate.ts` | 150 | `evaluateChatGate` + `enforceCoordinationPeers` + policy extension extraction |
| `chat-log.ts` | 97 | `ChatLogStore` interface + `InMemoryChatLogStore` |
| `pgvector-index.ts` | 280 | `ChatPgVectorIndex` (Postgres) + `InMemoryPgVectorIndex` (test) |
| `retention-bridge.ts` | 103 | `ChatRetentionAdapter` cascading deletes to chat store + pgvector |
| `chat-service.ts` | 220 | Orchestrator wiring all components together |
| `index.ts` | 17 | Barrel exports |

**1 test file** at `server/test/chat/chat-v1.test.ts`: 29 tests covering all 8 acceptance criteria.

**Baseline:** 2103 (Linux-CI floor). macOS: 2156 passed.
**Typecheck:** Clean. **Vulnerabilities:** 0. **npm ci:** Clean on Node 22 (no --legacy-peer-deps).

## Scope Lock Escalation: WP-MVP-7 chat confidentiality downgrade

### Integration gaps encountered

1. **Peer dependency conflict (hard blocker).** Every published version of `ts-mls` (1.0.1 through 1.6.2 and 2.0.0-rc.0) requires `@noble/curves@2.0.1` as a peerOptional dependency. The Sanctuary repo uses `@noble/curves@^1.8.0`, required by `@chainsafe/libp2p-noise@^16.1.5`. These cannot coexist: `npm ci` fails on Node 22+.

2. **Upgrading libp2p-noise to v17 (which uses `@noble/curves@^2.0.1`) would force a repo-wide noble v2 migration** across `@noble/curves`, `@noble/hashes`, and `@noble/ciphers`. This touches the entire Sanctuary crypto stack (L1 encryption, L3 commitments, L4 attestations, mesh signatures). A repo-wide crypto library major-version upgrade is not in scope for a chat thread.

3. **Even with deps resolved, the actual MLS integration was not done.** The original build thread's `MLSGroupManager` does not use any `ts-mls` API. The key schedule is `SHA-256(group_secret || epoch_bytes)`, not MLS's tree-based key schedule. The wire format is JSON, not MLS TLS-serialization. There is no `ts-mls` import anywhere in the source.

### What actually shipped (honest description)

**AES-256-GCM per-epoch forward-secret group chat:**

- Each chat group has a random 32-byte group secret generated at creation
- Each epoch derives a unique AES-256-GCM key via `SHA-256(group_secret || epoch_bytes)`
- Adding or removing a member advances the epoch; new epoch secret derived from group secret
- 12-byte random IV per message; epoch bound to ciphertext via AAD
- Forward secrecy: a member added at epoch N receives only epoch N's secret and cannot derive epoch N-1 secrets (SHA-256 pre-image resistance)
- Member removal advances the epoch; the removed member cannot derive subsequent epoch secrets

### Confidentiality properties it DOES provide

- **Epoch forward secrecy:** knowing epoch N's secret does not reveal epoch N-1's secret (SHA-256 pre-image resistance). New members cannot read history; removed members cannot read future messages.
- **Confidentiality under the symmetric key:** AES-256-GCM with unique IV per message, epoch bound via AAD.
- **Integrity:** GCM authentication tag prevents tampering.
- **Wire confidentiality:** zero plaintext bytes on the wire (tested in AC-1c).

### Confidentiality properties it DOES NOT provide vs. real MLS (RFC 9420)

- **No post-compromise security (PCS):** if a member's key is compromised, the attacker can derive all future epoch secrets from the group secret. Real MLS uses a tree-based key schedule where compromising one leaf doesn't compromise the tree; an Update proposal re-randomizes the compromised path.
- **No tree-based efficient member removal:** removing a member in real MLS re-keys only the affected path in O(log n); the hand-rolled scheme derives from a shared group secret, so removal is O(1) but doesn't have the same security properties.
- **No standard interop:** messages from this implementation cannot be processed by other MLS implementations (no TLS-serialization, no standard key schedule, no KeyPackage format).
- **No key independence:** all epoch secrets are derived from a single group secret. In real MLS, each member contributes entropy to the group state.

### Recommendation

**(i) Accept the downgrade for v1.0; file a v1.1 ticket for real MLS.** The hand-rolled layer provides the two properties operators care about most: forward secrecy (new members can't read history, removed members can't read future) and wire confidentiality (no plaintext on the wire). The missing properties (PCS, tree-based removal, standard interop) matter for cross-organization federation and post-compromise scenarios, which are v1.x concerns. The v1.0 pilot is single-operator fortresses with trusted agents; PCS is not the primary threat.

**(ii) Block v1.0 release on real MLS.** This requires: (a) resolving the noble v1 -> v2 migration across the entire repo (or finding/building an MLS library compatible with noble v1); (b) integrating the MLS key schedule, TreeKEM, and TLS serialization; (c) substantial new test surface. Estimated: separate dedicated thread, 2-4 weeks.

**Erik decides.**

## Deviations from original spawn prompt (carried forward)

### D2: Chat storage slot: reuse `outputs` instead of new slot

Chat messages stored under `_chat_messages` namespace within the `outputs` policy slot. Four canonical slots remain locked per Key 10.

### D3: coordination_peers as policy extension, not new slot

Standalone gate (`evaluateChatGate`) reads from a policy extension field, not a new commitment-boundary condition. Avoids modifying the shipped policy engine.

### D4: No new event_class values

All chat events use existing `event_type` field values: `chat_message`, `chat_mls_commit`, `chat_presence`, `chat_group_create`, `chat_group_invite`. None collide with V01_EVENT_TYPES or reserved prefixes.

### D5: Postgres/pgvector as optional dependency

Chat works without Postgres. `InMemoryChatLogStore` and `InMemoryPgVectorIndex` are defaults.

### D6 (original): --legacy-peer-deps (ELIMINATED by rework)

The original build used `--legacy-peer-deps` to paper over the `ts-mls` conflict. The rework removes `ts-mls` entirely; `npm ci` is now clean with no flags.

## Remaining scope (v1.x per Scope Lock)

- **Real MLS (RFC 9420) integration** (Scope Lock escalation item above)
- Named channels + channel templates
- Matrix bridge / interop (Q2 Phase 2)
- Embedded chat protocol (Q2 Phase 3)
- MSP / Fleet Operator federation room chrome
- Native mobile chat surface
- Read receipts, typing indicators, message reactions, threads
- Formal `coordination_peers` field on CompiledPolicy interface (D3 follow-up)
