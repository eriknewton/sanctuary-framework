---
review_status: pending_erik_review
author: Erik Newton
date: 2026-04-21
companion_to: federation-protocol-v0.1-spec.md
satisfies: Acceptance criterion 10 of Federation Protocol v0.1 (the hard gate)
---

# Federation Protocol v0.1; Hard-Gate Design Walkthrough

## Purpose

Acceptance criterion 10 of the Federation Protocol v0.1 spec is the hard gate:

> The v1.x MSP / Fleet Operator Console extension can be added by setting capability bits, populating extension envelopes, and adding the new message classes, without altering the v0.1 wire format, without re-spec'ing the trust-root model, and without re-issuing existing v0.1 certificates.

This document demonstrates, step by step, that the v0.1 design as implemented in `server/src/mesh/` satisfies that gate. It is written so a reviewer can read it alongside the v0.1 source and trace every reservation in the spec (§10) to the code that honors it, and so a future v1.x build thread can walk the same path in the opposite direction and add the MSP extension without breaking any v0.1 invariant.

This is a design artifact, not an implementation artifact. Drew's MSP / Fleet Operator Console is v1.x scope. v0.1 ships only the reservations that let v1.x build cleanly atop.

---

## 1. The v1.x extension in plain English

Drew is a managed-service-provider principal. Drew's clients are independent operators, each runs their own Sanctuary fortress with their own fortress-master key, their own principal hierarchy, their own mesh of nodes. Drew does **not** share key material with any client. Drew is not a co-principal in any client's fortress.

What Drew needs at v1.x: a single console that lets Drew see the operational state of every client mesh that has **explicitly authorized Drew to read a defined scope** of their fortress. Concretely: "Show me the audit summary for the last 24 hours across my twelve clients who have signed a cross-fortress read grant."

What Drew explicitly does not need at v1.x first cut: the ability to write into a client's fortress. Writes are out of scope for the MSP console v1.x. They may or may not arrive at v1.x+N.

The v1.x mechanism, at the architectural level:

1. **Each client operator signs a `cross_fortress_read_grant`** authorizing Drew's MSP principal to read a scoped surface of their fortress. The grant names specific agents, receipt ranges, audit ranges, or entire categories. The grant is itself a Concordia commitment between client-operator and MSP-operator. Verascore can ingest it. The audit trail on both sides records the grant issuance.

2. **Drew's MSP node sets capability bit 4** (guardian-delegated principal endpoint).

3. **Each client's fortress nodes set capability bit 3** (cross-fortress read endpoint) for the nodes Drew is authorized to query. This is a per-node operator decision, a client might authorize Drew to query the cold-storage audit replica but not the active agent nodes.

4. **Read queries flow** as `cross_fortress_read_query` events (extension envelope key) from Drew's MSP node → routed via the client's canonical audit node → matching client node serves the scoped data → `cross_fortress_read_response` (extension envelope key) signed by the client's per-node key, carrying the grant `event_id` so the response is auditable end-to-end.

5. **Writes are not enabled** in this v1.x first cut. If authorized at v1.x+N, they flow through the same per-client policy gate and per-client attestation context Drew would encounter if Drew were physically at the client's console, i.e., the write is recorded as a guardian-delegated-write commitment with the client's principal as the ultimate authorizing signature.

Cross-operator trust is **not** added to the federation-protocol trust model. Cross-operator trust is established at the Concordia-commitment layer (the signed grant). Federation just transports the resulting messages. This is load-bearing and gets its own walkthrough in §3.

---

## 2. The seven reservations, traced to v0.1 code

The spec reserves seven surfaces at v0.1 that v1.x will populate. This section takes each reservation and traces it to the v0.1 source, what is reserved, where in the code it is honored, and what the reviewer should check to verify v0.1 does not accidentally burn the reservation.

### 2.1 Reservation: seven extension envelope keys

**Spec ref:** §10.1.

**v0.1 source:** `server/src/mesh/types.ts`: the `SignedEvent.extension_envelope` field is a typed object with seven explicitly-named optional keys:

| Key | Type at v0.1 | Purpose at v1.x |
|---|---|---|
| `cross_fortress_read_grant` | `unknown` (reserved) | Delegation grant from operator A's principal to a named reader principal in operator B's fortress. |
| `cross_fortress_read_query` | `unknown` (reserved) | Read query from operator B's delegated reader against operator A's mesh. |
| `cross_fortress_read_response` | `unknown` (reserved) | Scoped data response signed by operator A's per-node key, carrying the grant `event_id`. |
| `multi_master_policy_merge` | `unknown` (reserved) | CRDT-style merge events for concurrent multi-principal policy edits. |
| `audit_replication_full_n_way` | `unknown` (reserved) | Coordination events for full N-way audit replication. |
| `auto_promote_canonical_audit` | `unknown` (reserved) | Pre-declared canonical-audit promotion-order events. |
| `agent_live_migration` | `unknown` (reserved) | Live-state transfer coordination beyond v0.1 checkpoint-and-resume. |

**v0.1 invariants that protect the reservation:**

1. **Emitters MUST NOT populate any reserved key.** Enforced at envelope construction: `packSignedEvent()` refuses any payload where `extension_envelope` contains a key in the reserved list. Test: `mesh/envelope.test.ts` → `emitter refuses to populate reserved extension keys`.

2. **Receivers MUST ignore unknown keys.** Enforced at verification: `verifySignedEvent()` does not fail on unknown `extension_envelope` keys. It ignores them. Test: `mesh/envelope.test.ts` → `receiver accepts envelope with unknown extension keys`.

3. **Signature covers `extension_envelope` bit-for-bit.** The canonical-JSON-over-envelope construction includes the `extension_envelope` object verbatim, so a v1.x signature over a payload containing an extension key remains valid on v0.1 receivers (they verify it and ignore the key) and on v1.x receivers (they verify it and parse the key). Test: `mesh/envelope.test.ts` → `signature validates across extension-envelope forward-compat boundary`.

**What a v1.x build thread does:** populates one or more reserved keys, keeps signing the envelope the same way, ships. v0.1 receivers keep working.

### 2.2 Reservation: capability bits 3–7 in `NodeIdentityCertificate`

**Spec ref:** §10.2.

**v0.1 source:** `server/src/mesh/types.ts`: `CapabilityBit` enum:

```
Bit 0 — standard_fortress_node           (v0.1 default, set on every v0.1 node)
Bit 1 — audit_replica_eligible            (v0.1 operator opt-in)
Bit 2 — cold_storage_receipt_replica      (v0.1 operator opt-in)
Bit 3 — RESERVED (v1.x cross-fortress read endpoint)
Bit 4 — RESERVED (v1.x guardian-delegated principal endpoint)
Bit 5 — RESERVED (v1.x multi-master policy author)
Bit 6 — RESERVED (v1.x auto-promote canonical-audit candidate)
Bit 7 — RESERVED (v1.x unallocated)
Bits 8–31 — RESERVED (future allocation)
```

**v0.1 invariants that protect the reservation:**

1. **v0.1 issuers MUST NOT set bits 3–31.** Enforced at cert issuance: `issueNodeIdentityCertificate()` refuses `capabilities` values where any of bits 3–31 are set. Test: `mesh/trust-root.test.ts` → `cert issuance rejects reserved capability bits`.

2. **v0.1 verifiers tolerate reserved bits when set on an otherwise-valid cert.** A v1.x cert carrying bit 4 verifies on a v0.1 verifier as "valid cert, unknown capability, treat as bit 0 only", the v0.1 verifier does not know what bit 4 means, so it does not route bit-4-gated traffic, but it does not reject the cert. This is forward-compat. Test: `mesh/trust-root.test.ts` → `v0.1 verifier tolerates unknown capability bits on v1.x certs`.

3. **Capability bits are carried in the signed certificate body.** Master-signature or principal-signature over the cert covers the capability bitmap verbatim, so a v1.x cert with bit 4 set survives round-trip through v0.1 transport.

**What a v1.x build thread does:** issues new certs with bit 3 or bit 4 set. Existing v0.1 certs are untouched, they keep bit 0 only and Drew simply does not target them with MSP queries.

### 2.3 Reservation: message-class namespaces

**Spec ref:** §10.3.

**v0.1 source:** `server/src/mesh/constants.ts`: `V01_MESSAGE_CLASSES` enumerates exactly the v0.1 set (`heartbeat`, `policy_update`, `audit_batch`, `locator_update`, `node_lifecycle`, `receipt_replicate`, plus the three RPC shapes `sync_request`, `sync_response`, `rejoin_request`, `rejoin_response`, `key_attestation`).

Three namespaces are reserved:

- `EXTENSION_*`: v1.x general extension namespace.
- `cross_fortress_*`: v1.x MSP / Fleet Operator Console namespace.
- `multi_master_*`: v1.x multi-master policy namespace.

**v0.1 invariants that protect the reservation:**

1. **v0.1 emitters MUST NOT emit any reserved-namespace event_type.** Enforced at envelope construction: `packSignedEvent()` refuses event_types matching `/^(EXTENSION_|cross_fortress_|multi_master_)/`. Test: `mesh/envelope.test.ts` → `emitter refuses to emit reserved-namespace event_types`.

2. **v0.1 receivers MUST ignore unknown event_types.** Enforced at message dispatch: the router in `mesh/router.ts` (stub at v0.1) routes known types and drops unknown ones with a one-line log entry. This is the forward-compat hinge. Test: `mesh/envelope.test.ts` → `receiver silently ignores unknown event_types`.

3. **Signature validation happens before dispatch.** An unknown event_type with a valid signature is still processed through the verifier (which succeeds) and THEN dropped at dispatch (not verified). This keeps the audit trail of "we received this thing, it was signed by a valid key, we chose not to process it." Useful for v1.x forward-compat debugging and for any v1.x operator who wants to know whether their v1.x message reached a v0.1 node.

**What a v1.x build thread does:** introduces new event_types in the reserved namespaces, wires them into the v1.x router. v0.1 nodes continue to see them, verify signatures, drop at dispatch.

### 2.4 Reservation: certificate fields

**Spec ref:** §10.4.

**v0.1 source:** `server/src/mesh/types.ts`: `NodeIdentityCertificate` includes three reserved fields:

- `delegated_grants?: unknown[]`: optional at v0.1, always empty. v1.x populates with cross-fortress grants the node honors.
- `attestation_lineage_chain?: unknown[]`: optional at v0.1, always empty. v1.x populates with TCB lineage history per Key 7 fourth-badge work.
- `master_signature?: string`: OPTIONAL at v0.1, REQUIRED at v1.x. v0.1 certs may or may not carry it. v1.x certs MUST carry it so the cross-fortress-read-endpoint verifier on the MSP side can validate cert provenance without trusting any single principal in the client operator's hierarchy.

**v0.1 invariants that protect the reservation:**

1. **Signature of the cert covers these fields verbatim** when they are present, and covers their absence when they are absent. The canonical-JSON signing construction treats undefined fields as absent (omitted from the canonical output), so v0.1 and v1.x signatures are interoperable.

2. **v0.1 verifiers accept certs with or without `master_signature`.** The field is optional. Test: `mesh/trust-root.test.ts` → `v0.1 verifier accepts cert with and without master_signature`.

3. **v0.1 emitters MAY include `master_signature`** (it's an option, not a requirement). The code supports it at v0.1 for operators who want the extra verification rigor. This means v0.1 → v1.x cert migration is painless, operators who already included `master_signature` are already v1.x-ready.

4. **Chain validation covers the `master_signature` when present**: if a v0.1 cert carries it, `verifyCertChain()` checks it against the pinned fortress-master public key. This is the v1.x-readiness hook at v0.1.

**What a v1.x build thread does:** makes `master_signature` required at v1.x cert issuance, extends `delegated_grants[]` to carry real grants. Existing v0.1 certs that already carry `master_signature` remain valid without reissue.

### 2.5 Reservation: v1.x extension does not add cross-operator primitives to the federation-protocol trust model

**Spec ref:** §10.5, §2.3, §1.2.

This is the most important reservation. It is not a single data-structure reservation; it is an architectural invariant.

**The invariant:** the federation protocol's trust model is rooted entirely at the operator's fortress-master. It does not know anything about cross-operator trust. Cross-operator trust is established at a layer above federation: the Concordia-commitment layer.

**Why this matters for the v1.x MSP extension:** Drew's authorization to read client A's mesh is a Concordia commitment between A and Drew. The commitment is signed by A's principal (authorizing) and Drew's principal (accepting). It lives outside the federation protocol. When Drew's MSP node wants to read A's mesh, Drew attaches the signed grant (the commitment record) to the `cross_fortress_read_query` event. A's nodes verify the grant against A's own principal-signature chain (they recognize A's own principal key, that's the trust boundary they already respect) and against the query-time scope (bounded by the grant's named scope). A's nodes do **not** need to recognize or trust Drew's fortress-master. They trust A's own principal's signature on the grant and enforce the grant's scope.

**The v0.1 invariants that protect this architecture:**

1. **Per-node certificates anchor only at the fortress-master.** `verifyCertChain()` in `mesh/trust-root.ts` walks the chain `node → principal → fortress-master` and refuses any cert that does not terminate at the pinned master pubkey. It has no concept of cross-master trust. Test: `mesh/trust-root.test.ts` → `cert chain validation rejects foreign fortress-master`.

2. **`SignedEvent.principal_signature` identifies a principal within the event's stated fortress.** The envelope carries `fortress_id` and the receiver validates that the `emitter_principal`'s cert chain terminates at the fortress-master associated with the stated `fortress_id`. Cross-fortress events are, at v0.1, impossible to construct in a way that passes verification, the cert chain will not terminate at the pinned master for any non-self `fortress_id`. Test: `mesh/envelope.test.ts` → `receiver rejects envelope whose principal chain terminates at foreign master`.

3. **At v1.x, cross-fortress reads work by having Drew's MSP node sign the query with DREW'S per-node key (chain terminates at DREW'S fortress-master, valid in Drew's fortress)** but the query carries as payload the signed grant issued by client A's principal (chain terminates at A's fortress-master, valid in A's fortress). A's receiving node verifies: (a) the query's per-node signature against DREW's pubkey (not trusted by default, but the incoming-connection handshake verifies it as "some node claiming to be from Drew's mesh"; (b) the attached grant's principal signature against A's OWN master) which IS trusted, because A pinned A's own master. Trust flows from A-trusts-A's-own-grant + grant-authorizes-Drew's-reader + query-matches-grant-scope. v0.1's hard chain-terminates-at-our-master invariant doesn't break, it just isn't the only invariant anymore at v1.x.

**What a v1.x build thread does:** adds cross-fortress signature verification as an **application-layer** concern in the v1.x `cross_fortress_read_query` handler. The federation-protocol trust-root model at `mesh/trust-root.ts` is unchanged. The grant verification is new code in `mesh/extensions/cross-fortress.ts` (v1.x). It is composed with, not substituted for, the v0.1 chain validator. Drew's MSP node still passes v0.1 chain validation on A's mesh because Drew's incoming connection is to a specific endpoint capability (bit 3 on A's node) that delegates a narrow authority path, the path does not require Drew to be trusted as a principal in A's fortress. It requires Drew to be **named in a grant that A's principal signed**. The signature A's principal put on the grant is the trust anchor for this interaction, and that signature IS v0.1-verifiable against A's pinned master.

**This is the heart of why the hard gate holds.** Cross-operator trust does not join the federation protocol at v1.x. It is established at Concordia, recorded as a signed grant, and the grant is the passport the cross-fortress request carries into A's mesh. Federation at v1.x merely transports the passport and recognizes its issuer (A's own principal). No protocol change. No trust-root surgery.

### 2.6 Reservation: canonical audit node re-designation is an operator action, not a protocol action

**Spec ref:** §5.4 (replica election on canonical-node loss), §10.1 (`auto_promote_canonical_audit`).

**v0.1 source:** `server/src/mesh/constants.ts`: the canonical audit node is recorded in the fortress's persistent state, changed only via an operator-signed `canonical_audit_change` event.

**Why this is a reservation:** v1.x will want deterministic auto-promotion of the next canonical audit node when the current one fails. v0.1 explicitly refuses to ship auto-promotion because we don't want a split-brain scenario where two nodes each think they are canonical. v1.x will safely add auto-promotion via the `auto_promote_canonical_audit` extension envelope key, which pre-declares an operator-signed promotion order before failure.

**What a v1.x build thread does:** reads the pre-declared promotion order from the extension envelope key, watches for canonical-audit-node heartbeat gap beyond threshold, promotes deterministically, records the promotion as a v1.x-only audit entry. v0.1 nodes receiving v1.x-era audit entries post-promotion treat them as valid (signature verifies against the NEW canonical's per-node cert, which was valid in the v0.1 roster from the moment it joined).

### 2.7 Reservation: recovery cascade integration is master-level, not federation-level

**Spec ref:** §9.

**v0.1 source:** `server/src/mesh/trust-root.ts`: master rotation is handled via `applyMasterRotation()` which atomically replaces the pinned master public key and re-validates all certificates under the new chain. The event `master_rotation` is a signed event class but it is v0.1 scope, not v1.x.

**Why the design accommodates v1.x:** recovery under guardian quorum is a fortress-level operation that flows through the federation protocol the same way any other signed event does. The guardians produce an event signed by M guardian keys; every node receives it, verifies against the guardian roster, and applies. The federation protocol does not need to know about MSP-related delegation for this to work. A v1.x MSP extension simply adds MSP-specific recovery paths, e.g., "Drew's MSP fortress undergoes guardian recovery; every client whose grant named Drew's previous MSP master must re-sign the grant under the new master." That re-signing is a new event class (`cross_fortress_grant_refresh`, call it whatever v1.x names it) in the reserved `cross_fortress_*` namespace. No v0.1 surface breaks.

---

## 3. The end-to-end v1.x MSP read flow, annotated against v0.1

This section walks one concrete flow from start to finish so a reviewer can see exactly which v0.1 surfaces are touched and which are left alone.

**Scenario.** Drew operates MSP fortress M. Client Alice operates fortress A with three nodes: `A-local-1` (canonical audit node), `A-cloud-1`, `A-tee-1`. Alice has signed a grant authorizing Drew to read 24-hour audit summaries and receipt IDs (not receipt contents) from `A-local-1`. Drew's MSP principal is `drew-msp-root`. Drew's MSP node is `M-msp-console-1`, capability bit 4 set. `A-local-1` capability bit 3 set (opt-in by Alice). All other A-nodes do NOT have bit 3 set.

**Setup (v1.x-only):**

1. Alice opens her console, authors a grant: `{grantee: drew-msp-root, scope: "audit_summary+receipt_ids on A-local-1, 24h rolling", expires: 2026-05-21}`. Her console signs the grant with Alice's principal key; the signature chains to A's fortress-master. The grant is written to A's audit log as a standard v0.1 audit entry (the v0.1 audit infrastructure is sufficient; a grant is just a signed event), event_type = `EXTENSION_cross_fortress_grant_issued`, payload = the grant object, extension_envelope.cross_fortress_read_grant = the grant object. <-- v0.1 receivers on A's mesh see this event, don't recognize the event_type (it's in the reserved EXTENSION_ namespace), verify the signature (succeeds), drop at dispatch. No v0.1 invariant broken. The grant is durably recorded in the audit log.

2. Alice sends the grant to Drew via Concordia. The Concordia session records the grant exchange as a standard Concordia commitment. Drew's fortress M ingests the grant into M's local state as "grants I hold against foreign fortresses". Pure Concordia flow; federation protocol not involved.

**Runtime (v1.x-only):**

3. Drew wants to see Alice's last-24h audit summary. Drew clicks "View Alice's mesh" in the MSP console.

4. M's `M-msp-console-1` constructs a `cross_fortress_read_query` event:
   - `event_type = "cross_fortress_read_query"` (in reserved namespace, v0.1 dispatcher drops but v1.x dispatcher routes)
   - `emitter_node = "M-msp-console-1"` (valid node in M's roster)
   - `emitter_principal = "drew-msp-root"` (valid principal in M's roster)
   - `fortress_id = M` <-- critical: the event declares it originates in M's fortress
   - `extension_envelope.cross_fortress_read_query = { grant_event_id: ..., scope: "audit_summary last 24h" }`
   - `node_signature = sign_with(M-msp-console-1 per-node key)` <-- valid in M, cert chains to M's fortress-master
   - `principal_signature = sign_with(drew-msp-root principal key)` <-- valid in M, cert chains to M's fortress-master

5. M transmits the event to `A-local-1` over libp2p (v1.x adapter resolves A-local-1's multiaddr via DID resolution or operator-configured address book, orthogonal to v0.1 federation).

6. **A-local-1 receives the event. What does v0.1 do vs. v1.x?**

   **v0.1 receiver path:** the event is inspected. `event_type` starts with `cross_fortress_`: reserved namespace. The v0.1 `verifySignedEvent()` is invoked anyway; it validates `node_signature` and `principal_signature` against the chain (but the stated `fortress_id` is M, and A's receiver does not have M's fortress-master pinned. So v0.1 signature validation **fails** at "chain does not terminate at pinned master". The event is logged as "unknown/foreign and unverified" and dropped. This is correct for v0.1) a v0.1 node receiving a v1.x cross-fortress query has no way to honor it safely. The v0.1 door is closed to strangers.

   **v1.x receiver path on capability-bit-3-enabled A-local-1:** the event is inspected. `event_type` is `cross_fortress_read_query`: v1.x dispatcher recognizes it. The v1.x handler is invoked. The handler:
   - Extracts `extension_envelope.cross_fortress_read_query.grant_event_id`.
   - Looks up the grant in A's local audit log (grant was written there in step 1 via `EXTENSION_cross_fortress_grant_issued`: that event was dropped by v0.1 dispatch but v1.x stores a copy from the audit log for this purpose).
   - Verifies the grant's `principal_signature` against A's OWN fortress-master. <-- This is the cross-operator trust establishment step. It uses ONLY A's v0.1 trust-root. No surgery.
   - Verifies the query matches the grant scope (requested range within grant range, requested surface within grant surface, current time within grant validity).
   - Verifies the event's `node_signature` and `principal_signature` against **the grant's named grantee identity**: not against A's roster. (The grant names `drew-msp-root` as an external pubkey. Drew's event was signed by `drew-msp-root`. That signature is verifiable by anyone with the pubkey.) <-- This is also application-layer, not federation-protocol-layer, trust evaluation.
   - If all checks pass, executes the scoped read: gathers audit summary for the last 24h, serializes, packages a `cross_fortress_read_response` event.

7. `A-local-1` replies with a `cross_fortress_read_response`:
   - `event_type = "cross_fortress_read_response"` (reserved namespace)
   - `emitter_node = "A-local-1"`, valid in A
   - `emitter_principal = alice-principal-root`, valid in A
   - `fortress_id = A` <-- critical: the response declares it originates in A's fortress
   - `extension_envelope.cross_fortress_read_response = { grant_event_id: ..., data: <the scoped read> }`
   - Signed by A-local-1 per-node key and alice-principal-root principal key, both chains terminate at A's fortress-master.

8. M receives the response. v1.x handler routes it. M's handler verifies the response's `node_signature` and `principal_signature` against **the pubkeys named in the grant** (which M has in local state as "pubkey of A-local-1 that signed grant-receipt acks" + "alice-principal-root pubkey"). Again: application-layer trust, anchored in the grant.

9. M displays the audit summary in Drew's console.

10. M records the entire exchange (the query it sent, the response it received, the grant it invoked) as a normal v0.1 audit entry in M's own audit log, event_type = `EXTENSION_cross_fortress_exchange_completed`. <-- v0.1 audit infrastructure at M is sufficient. The entry is durable, auditable, replayable.

**Every v0.1 invariant that matters in this flow:**

- **V0.1 envelope shape:** unchanged. The v1.x events use the same `SignedEvent` structure, same signing rules, same canonical-JSON serialization.
- **V0.1 chain validation:** unchanged. A's nodes still enforce `chain terminates at A's master` for all events that claim `fortress_id = A`. The v1.x extension operates within its own `fortress_id = M` events; when those events land at A, A's v0.1 validator correctly rejects them (and A's v1.x dispatcher catches them before rejection and runs the extension-layer trust path instead. **A v0.1-only node of A, ignorant of the extension, rejects the event and nothing bad happens) A's mesh just doesn't expose cross-fortress-read on that node.**
- **V0.1 cert issuance:** unchanged. A's existing v0.1 per-node certs don't get reissued. Alice just issues new certs for nodes she wants bit 3 on, or re-issues the cert for `A-local-1` with bit 3 set (same node, same per-node pubkey, new cert). The old `A-local-1` cert is revoked via standard v0.1 `node_revoke` flow.
- **V0.1 audit log:** unchanged. The extension events ride as normal audit entries with reserved-namespace event_types; v0.1 nodes store them faithfully because they verify the signature and pass through.
- **V0.1 recovery cascade:** unchanged. If A undergoes guardian recovery, the grant gets re-verifiable under A's new master (M re-signs the grant or Alice re-issues). Standard flow.

**Every v1.x-only concept used in this flow:**

- Capability bits 3 and 4 (set on specific nodes).
- Extension envelope keys `cross_fortress_read_grant`, `cross_fortress_read_query`, `cross_fortress_read_response`.
- Event_type namespaces `EXTENSION_cross_fortress_*` and `cross_fortress_*`.
- Application-layer grant validator in v1.x handler code.
- Concordia-commitment flow for grant exchange (already exists outside federation).

No wire format change. No trust-root model change. No v0.1 certificate reissue.

**The hard gate holds.**

---

## 4. What a v1.x build thread will write, concretely

A v1.x MSP build thread adds:

- New file `server/src/mesh/extensions/cross-fortress.ts`: the v1.x handler for the three `cross_fortress_*` event types, the grant validator, the grant-store.
- Schema additions in `server/src/mesh/types.ts` for `CrossFortressGrant`, `CrossFortressReadQuery`, `CrossFortressReadResponse`: all optional, under the reserved extension envelope keys.
- New capability-bit constants for bit 3 and bit 4 (the bit positions are already reserved at v0.1; v1.x gives them names).
- New event-type constants `cross_fortress_read_query`, `cross_fortress_read_response`, `cross_fortress_grant_issued`, `cross_fortress_grant_refresh`: all in the reserved namespace.
- Wiring in `server/src/mesh/router.ts` to dispatch the reserved namespace to the new handler when bits 3 or 4 are set on the local node.
- Concordia-side integration: the grant is a commitment; Concordia's SDK produces it, Sanctuary's bridge already ingests commitments today.

A v1.x build thread does NOT touch:

- `server/src/mesh/trust-root.ts`: cert issuance, chain validation, HKDF derivation. All v0.1.
- `server/src/mesh/envelope.ts`: SignedEvent packing, canonical-JSON serialization, signature verification. All v0.1.
- `server/src/mesh/audit-batch.ts`: batch chaining, prev_batch_hash, HKDF chain proof. All v0.1.
- Any existing v0.1 certificate. Reissue is optional (to set bit 3), not mandatory.

That's the shape of the future v1.x build thread, a new extension module, a handful of constants, a router wire-up. Nothing more.

---

## 5. Reviewer checklist

For Erik or a future reviewer to confirm the hard gate holds, trace each row:

| v0.1 invariant | Source location | Test |
|---|---|---|
| Reserved extension keys are rejected at emission | `mesh/envelope.ts` (packSignedEvent) | `mesh/envelope.test.ts` → `emitter refuses to populate reserved extension keys` |
| Unknown extension keys are ignored at verification | `mesh/envelope.ts` (verifySignedEvent) | `mesh/envelope.test.ts` → `receiver accepts envelope with unknown extension keys` |
| Signature covers extension_envelope bit-for-bit | `mesh/envelope.ts` (canonicalize) | `mesh/envelope.test.ts` → `signature validates across extension-envelope forward-compat boundary` |
| Reserved capability bits 3–31 are rejected at cert issuance | `mesh/trust-root.ts` (issueNodeIdentityCertificate) | `mesh/trust-root.test.ts` → `cert issuance rejects reserved capability bits` |
| v0.1 verifier tolerates unknown cap bits on otherwise-valid cert | `mesh/trust-root.ts` (verifyCertChain) | `mesh/trust-root.test.ts` → `v0.1 verifier tolerates unknown capability bits on v1.x certs` |
| Reserved event_type namespaces are rejected at emission | `mesh/envelope.ts` (packSignedEvent) | `mesh/envelope.test.ts` → `emitter refuses to emit reserved-namespace event_types` |
| Unknown event_types are silently ignored at dispatch | `mesh/router.ts` (stub at v0.1) | `mesh/envelope.test.ts` → `receiver silently ignores unknown event_types` |
| master_signature is optional and, when present, validated | `mesh/trust-root.ts` (verifyCertChain) | `mesh/trust-root.test.ts` → `v0.1 verifier accepts cert with and without master_signature` |
| Chain terminates at pinned master, no foreign-master trust | `mesh/trust-root.ts` (verifyCertChain) | `mesh/trust-root.test.ts` → `cert chain validation rejects foreign fortress-master` |
| fortress_id-bound event validation | `mesh/envelope.ts` (verifySignedEvent) | `mesh/envelope.test.ts` → `receiver rejects envelope whose principal chain terminates at foreign master` |

If any of these fails in the v0.1 implementation, the hard gate is compromised and v0.1 must be re-spec'd.

---

## 6. Conclusion

The v0.1 federation protocol, as implemented in `server/src/mesh/`, reserves exactly the surfaces the v1.x MSP / Fleet Operator Console extension will need: seven extension envelope keys, five capability bits, three event-type namespaces, three certificate fields, and the architectural invariant that cross-operator trust is a Concordia-layer concern composed with federation-layer transport rather than baked into federation-layer trust-roots.

A v1.x build thread can add the MSP extension by writing new code in a new module, touching a handful of constants, and wiring a dispatcher. No v0.1 wire format changes. No v0.1 trust-root surgery. No v0.1 certificate reissue.

Acceptance criterion 10 is satisfied.

**Open for Erik review.** If the §10.5 narrative in the source spec or the v1.x shape in this walkthrough does not match Drew's actual envisioned MSP usage, flag for rework before v1.x build thread spawn. The reservations themselves are conservative (we are reserving more than we strictly know we need), so narrowing is safer than widening later.
