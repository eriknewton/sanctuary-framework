---
review_status: approved
approved_date: 2026-04-21
author: Erik Newton
date: 2026-04-21
---

# Sanctuary Federation Protocol v0.1; Spec

**Purpose.** Define the wire protocol that lets a single Sanctuary Console speak to every fortress node in one operator's mesh (local, operator-cloud, sovereign-managed TEE) as a single sovereign fabric. This is intra-operator only. Cross-operator commitment routing is Concordia's lane and is explicitly out of scope.

**Audience.** The build thread that implements WP-MVP-3 (Federation protocol v0.1) per the MVP Scope Lock. Also the build thread that picks up WP-MVP-2 (Console) and any thread that touches multi-node receipt or audit flows.

**Companion documents.**
- `Review/Sanctuary/Sanctuary_Product_Thesis_v2_2026-04-21.md` §4 (sovereign mesh, three node modes, console shape).
- `Review/Sanctuary/Sanctuary_MVP_Scope_Lock_2026-04-21.md` WP-MVP-3 (in-scope cuts and acceptance).
- `Review/Sanctuary/Architecture_Walk_Through_Scaffold_2026-04-20.md` cross-cutting Q3 (federation primitive lock-in), Key 13 (recovery / guardian M-of-N / DMswitch), Key 14 (multi-principal delegation).

---

## 1. What v0.1 ships (and what it does not)

### 1.1 In scope (v0.1)

1. **Per-node identity hierarchy.** Each node holds a per-node Ed25519 keypair derived via HKDF from the operator's fortress-master key. Per-node keys are revocable without rotating the master.
2. **Sync-on-write policy distribution.** Policies are authored against the console; the console signs a new policy version with the operator's principal key and pushes it. Every node verifies the signature against the fortress-master public-key chain and pins the highest-version-seen for any agent it hosts.
3. **Canonical audit node + streamed audit-log batches.** One node per fortress is the canonical audit aggregator (operator-designated; defaults to the first local-mode node). Other nodes stream signed-and-chained audit batches to it. Local buffering survives partition.
4. **Redundant receipt storage.** Every receipt lands on the producing node and the canonical audit node at minimum. Operator can configure additional replicas.
5. **Per-fortress agent-locator table.** Every node maintains a copy of `(agent-id → canonical-node-id, version)`. Updates flow as signed events.
6. **Small signed-events wire protocol over libp2p.** Six message classes. Every message is signed by the sender's per-node key and verified by the receiver against the fortress-master-anchored chain.
7. **Node lifecycle.** Join, sync, heartbeat, leave (graceful), rejoin-after-offline, revoke (operator-initiated or guardian-initiated).
8. **Failure handling.** Offline nodes degrade gracefully; compromised nodes are revocable; rollback is detectable via per-node monotonic counters and audit-batch chaining; split-brain is an operator-resolved event with conflict-detection primitives.

### 1.2 Out of scope (v0.1), hard line

- **Cross-operator commitment routing.** Concordia v0.4.0 SDK already handles this; federation protocol does not duplicate the surface.
- **Cross-operator identity verification.** Lives in the DID resolver + Verascore reputation layer; not federation's job.
- **Multi-master policy authoring.** v0.1 assumes single source of authoring (the console with operator's principal-key signature). Multi-principal authoring follows Key 14 hierarchical-delegation rules but is still single-write-source per principal; no merge resolution at the federation layer.
- **Consensus / Byzantine fault tolerance.** Operator's nodes are not Byzantine to each other within the operator's trust boundary. We use signed-event causality and operator-resolved conflicts, not BFT.
- **Full audit replication across all nodes.** Canonical audit node + producing-node copy + operator-configured replicas at v1.0. Full N-way replication is a v1.x upgrade.
- **MSP / Fleet Operator Console writes across operator boundaries.** This is the v1.x extension. v0.1 explicitly leaves room for guardian-delegated read-across-fortress (see §10).

### 1.3 The hard gate (non-negotiable)

The v0.1 wire protocol, message schema, and trust-root model **must leave room for guardian-delegated read-across-fortress** (the v1.x MSP / Fleet Operator Console dependency per Q2 NEW ticket and Q3 lock). This means: extension points reserved in the message envelope, capability flags reserved on node-identity certificates, and the trust-root model must accommodate a future "guardian principal of operator A holds delegated read-only credentials for operator B's mesh, audited as a Concordia commitment between A and B" without re-architecting the protocol.

If a build-thread implementation choice closes the door on this v1.x extension, the implementation is rejected. §10 enumerates the specific extension points reserved.

---

## 2. Trust model

### 2.1 Trust root

The operator's **fortress-master key** is the root of trust for the mesh. It is an Ed25519 keypair generated at first-fortress-bootstrap, held in the operator's cocoon, unlocked by Argon2id passphrase (per v0.10.0 unified-passphrase decision), and recoverable via M-of-N guardian quorum (Key 13).

**The fortress-master signs:**

1. The operator's **principal key certificate** (Root principal under Key 14's hierarchy). The principal key is the day-to-day signing key for policy authoring, console actions, and commitment authorization.
2. The **per-node identity certificates** (issued at node-join; see §3).
3. Any **delegation certificates** to subordinate principals (Partner, Associate per Key 14) with role-scoped capability flags.
4. **Revocation events** for principal keys, per-node keys, and (in v1.x) delegated read-across-fortress capabilities.

The fortress-master itself is not used directly for transport-layer signatures. It signs the certificates; certificates anchor the chain.

### 2.2 Per-node subkeys

Each node holds an Ed25519 keypair generated locally at join. The operator (via the console) signs a node-identity certificate binding the node's public key to a node-id, a node-mode (`local | operator_cloud | sovereign_tee`), a join-timestamp, and a capability bitmap. Concretely:

```
NodeIdentityCertificate {
  node_id:          <128-bit random UUID>
  node_pubkey:      <Ed25519 pubkey>
  node_mode:        local | operator_cloud | sovereign_tee
  joined_at:        <UTC timestamp>
  capabilities:     <bitmap; see §10 for reserved bits>
  parent_chain:     [fortress_master_pubkey, principal_pubkey]
  signature:        <signed by operator's principal key>
  master_signature: <signed by fortress-master, optional in v0.1, MUST in v1.x>
}
```

**HKDF derivation.** The per-node private key is *not* derived from the fortress-master via HKDF in v0.1, it is a fresh keypair generated locally on the node. What IS HKDF-derived is a **per-node-per-purpose symmetric key** for transport-layer encryption and per-node-bound cryptographic context:

```
node_transport_key = HKDF(
  ikm     = fortress_master_secret,
  salt    = node_id,
  info    = "sanctuary-fed-v0.1-transport" || node_id || node_mode,
  length  = 32
)

node_audit_chain_key = HKDF(
  ikm     = fortress_master_secret,
  salt    = node_id,
  info    = "sanctuary-fed-v0.1-audit-chain" || node_id,
  length  = 32
)
```

**Why fresh asymmetric keys but HKDF-derived symmetric keys.** A fresh Ed25519 keypair on the node lets the node sign things even if the fortress-master is offline (e.g., the master is on Erik's laptop, the node is in GCP). The certificate chain anchors trust without requiring the master to be reachable for every signature. HKDF-derived symmetric keys give us deterministic per-node cryptographic context for audit-batch chaining and transport encryption, recoverable from the master under guardian quorum without re-distributing per-node secrets.

**Compromise blast radius.** Compromise of a single node's private key compromises only that node's signing surface. The node certificate is revocable (§7). Compromise of the fortress-master is the catastrophic case and triggers cascade recovery (§9.5).

### 2.3 Multi-principal interaction (Key 14)

The federation protocol carries principal-attribution alongside node-attribution. Every signed event includes both the principal-id (who authored, e.g., Root or Partner-Alice) and the node-id (where the event originated). The principal certificate chain anchors at the fortress-master; the node certificate chain also anchors at the fortress-master. The two chains meet at the fortress-master.

**Practical implication:** an Associate principal authoring a policy update from a sovereign-managed TEE node produces an event signed by the Associate's principal key (per-principal Ed25519 from Key 14) **and** by the node's per-node key. Receivers verify both. Audit attributes to the principal; routing and replay attribute to the node.

This separation is what makes the v1.x guardian-delegated-read-across-fortress extension clean: a delegated reader from operator B's fortress carries a principal identity rooted in B's fortress-master, and a delegation-grant from operator A's principal authorizing the read scope. Both are signed. Both are auditable.

---

## 3. Node lifecycle

### 3.1 Join

A new node joining the mesh:

1. Operator initiates **join from the console** with a one-time bootstrap token. The token is a short-lived (15-minute TTL) signed token from the operator's principal key carrying `(intended_node_mode, intended_node_id, expiry, fortress_id)`.
2. The new node generates its **Ed25519 keypair locally**. Private key never leaves the node.
3. The new node **POSTs a JoinRequest** over libp2p direct stream to the canonical audit node (which acts as bootstrap rendezvous; see §3.7 for the special case of bootstrapping the very first node):

   ```
   JoinRequest {
     bootstrap_token:  <token from console>
     node_pubkey:      <newly generated>
     node_mode:        local | operator_cloud | sovereign_tee
     attestation:      <TEE quote if sovereign_tee mode; null otherwise>
     hkdf_salt_proof:  <HMAC of (node_id, node_mode) using node_transport_key — proves the node was provisioned with the correct HKDF-derived material>
   }
   ```

4. The canonical audit node forwards the JoinRequest to the console (which holds the principal key). The operator approves via the standard plain-English gate ("Approve new node `cloud-gcp-1` joining your fortress?"). On approval, the console signs the **NodeIdentityCertificate** (§2.2) and broadcasts it as a `node_join` event.
5. Existing nodes receive the `node_join` event, verify the certificate chain to the fortress-master, and add the new node to their **node roster** (the local view of which nodes are part of the mesh).
6. The new node initiates **sync** (§3.2) once its certificate is in the roster.

**Approval is mandatory.** No node joins without operator gate approval. The bootstrap token alone does not grant membership; it grants the right to *request* membership.

**Sovereign-TEE mode adds an attestation step.** For `sovereign_tee` nodes, the JoinRequest includes a TEE attestation quote (GCP Confidential VM AMD SEV-SNP report at Phase 1). The console verifies the quote against the expected Sanctuary binary hash + container runtime + OS image (per Key 7 Option C target), surfaces the attestation result in the join gate prompt, and embeds the attestation hash in the NodeIdentityCertificate. Subsequent re-attestation events (TCB lineage) update a separate attestation-state record but do not require the operator to re-issue the certificate.

### 3.2 Sync

Once joined, a node performs an initial sync:

1. **Pull current policy bundle** from the canonical audit node (or any reachable node, policies are signed, source doesn't need to be trusted). Policy bundle = `{ agent_id → (policy_version, signed_policy_blob) }` for every agent the node will host or might route for.
2. **Pull current agent-locator table** (§6).
3. **Pull current node roster** (the set of valid NodeIdentityCertificates; pulled to verify peer signatures going forward).
4. **Pull or replicate audit log range** if the node is configured as an audit replica (see §5.4); skip if not.
5. **Pull receipt store range** for any agent canonically located on this node (typically only relevant on rejoin, not first join).

Sync is the only operation in the protocol that may transfer bulk data. After sync, all updates are incremental signed events (§4).

### 3.3 Heartbeat

Every node emits a **Heartbeat** event every 30 seconds (configurable; defaults locked here for protocol compatibility) on a libp2p pubsub topic `sanctuary/<fortress_id>/heartbeat`:

```
Heartbeat {
  node_id:          <self>
  node_state:       active | draining | gated_closed
  policy_version:   <highest-version pinned locally per agent — vector clock>
  audit_seq:        <highest contiguous audit sequence number locally held>
  agent_count:      <number of agents canonically hosted here>
  uptime_seconds:   <since last fresh boot>
  signature:        <Ed25519 by per-node key>
}
```

**Heartbeat purpose.** Liveness detection (peers compute `last_heartbeat_age`), version-skew detection (peers see if they are behind on policy or audit), and drain-state propagation. Heartbeat does NOT carry payload data; it is a lightweight pulse.

**Missed heartbeats.** A node missing 3 consecutive heartbeats (90 seconds default) is marked `unreachable` in the local node-roster view of every other node. `unreachable` is presence state #5 (see Q5 lock, the fifth state beyond Q2's four-state agent presence). Console renders this on the global mesh view.

### 3.4 Leave (graceful)

Operator-initiated graceful departure:

1. Operator clicks "Decommission node" in console; gate prompt fires with plain-English explanation.
2. Console signs a `node_leave` event with `(node_id, reason: graceful, drain_deadline)` and broadcasts.
3. The departing node enters `draining` state (heartbeat reflects). It refuses new agent assignments. Existing agents on the node are migrated (operator-driven, out of v0.1 protocol scope, but the agent-locator table updates accordingly per §6) or paused.
4. After drain, the node emits a final `node_leaving` event acknowledging clean shutdown, then disconnects.
5. Other nodes mark the node as `left` in the node roster and stop expecting heartbeats.

**Audit and receipt obligations on graceful leave.** Before disconnecting, the departing node must:
- Flush any pending audit batches to the canonical audit node and receive ACK.
- Confirm replication of any receipts it holds redundantly to at least one other node.
- Hand off canonical-node pointer for any agents it canonically hosts (operator-directed; see §6).

If the departing node holds any audit data not yet streamed, the leave does not complete; the operator is prompted to wait or force.

### 3.5 Rejoin after offline

A node that goes offline (planned or unplanned) and comes back:

1. On boot, the node loads its persisted NodeIdentityCertificate, per-node keypair, and last-known node roster.
2. The node attempts to reach any peer in the roster (in priority order: canonical audit node first, then nearest by mode).
3. On contact, the node sends a `RejoinRequest` carrying its `node_id`, last-known `policy_version` vector, and last-known `audit_seq`.
4. The contacted peer responds with a **delta**: missed `node_join`/`node_leave` events, updated policy bundle (any agent where current version > the rejoining node's version), missed agent-locator updates, and (if this node is an audit replica) missed audit batches.
5. The rejoining node validates all signatures against the fortress-master chain, applies updates, then resumes Heartbeat broadcasting.

**Offline-during-policy-change.** If a policy version was issued while the node was offline, the node MUST pull the new version before resuming any agent it canonically hosts. The node does not run an agent under a stale policy. The rejoin sync is a hard prerequisite for re-activating local agents.

**Bounded staleness.** A node offline for longer than the operator-configured `max_offline_window` (default: 30 days) is automatically removed from the roster as `expired` and cannot rejoin without a fresh join ceremony (§3.1). This bounds the audit-replay surface for long-dead nodes.

### 3.6 Revoke

Operator- or guardian-initiated, adversarial:

1. Operator (or guardian quorum, see §3.6.1) signs a `node_revoke` event with `(node_id, reason, effective_at)`.
2. The revocation event broadcasts to all reachable nodes immediately and is replayed to nodes that come online subsequently.
3. Receivers update their node roster: the revoked node's certificate is marked invalid; future signed events from the revoked node's per-node key are rejected; its heartbeats are ignored.
4. The canonical audit node records the revocation as a permanent audit entry.
5. If the revoked node was canonically hosting any agents, the agent-locator table updates to point to a new canonical node (operator-directed via the same gate flow as `node_leave`).
6. The revoked node, if reachable, receives the broadcast and self-shuts-down. If unreachable (the typical adversarial case), it is simply ignored by the rest of the mesh on next contact attempt.

**Critical: revoking a node does not require the node's cooperation.** The revocation is enforced by every other node refusing to process its events. A compromised node cannot un-revoke itself.

#### 3.6.1 Guardian-initiated revocation

Per Key 8 + Key 13, guardian M-of-N can initiate revocation when the operator is unreachable (DMswitch fired or explicit operator-incapacitated declaration). Mechanics:

1. Guardian quorum (M of N, default 3-of-5) constructs a guardian-revocation event signed by M guardian keys plus a quorum-attestation block.
2. The event format mirrors `node_revoke` with an additional `quorum_signatures` field.
3. Receiving nodes verify each guardian signature against the operator's guardian-roster (which is a fortress-master-signed certificate set, distributed at recovery setup and on changes).
4. On valid quorum, revocation applies as if operator-initiated.

**This is the hard primitive that makes the federation protocol survive the operator's incapacity**: and it is the same primitive (operator-rooted but guardian-substitutable) that v1.x will extend for guardian-delegated read-across-fortress.

### 3.7 Bootstrapping the first node

The first node is a special case: there is no canonical audit node yet, no roster, no peers. The console (running locally on the same machine, against the local-mode fortress) issues the fortress-master, generates the first principal certificate, generates the first node certificate self-witnessed, and seeds the canonical-audit-node designation to itself. From there, every subsequent node joins per §3.1.

---

## 4. Wire format

### 4.1 Transport

All federation traffic rides **libp2p**. We reuse the same libp2p stack already required by WP-MVP-7 (chat over libp2p), so federation adds no new external dependency.

Two libp2p surfaces:

- **Pubsub (gossipsub)** for broadcast events. Topics: `sanctuary/<fortress_id>/heartbeat`, `sanctuary/<fortress_id>/policy`, `sanctuary/<fortress_id>/locator`, `sanctuary/<fortress_id>/node-roster`, `sanctuary/<fortress_id>/audit-broadcast`.
- **Direct streams** for unicast traffic: receipt replication, audit batch streaming, sync delta pulls, JoinRequest/RejoinRequest exchange.

**Discovery.** Peers discover each other via libp2p mDNS (local-mode), libp2p Kademlia DHT seeded by the canonical audit node's multiaddr (operator-cloud / sovereign-TEE), or operator-configured static peer list. The DHT bootstrap address is part of the bootstrap token (§3.1).

**Transport encryption.** libp2p Noise (XX pattern) handshake, peer-id pinned to the per-node Ed25519 public key. Per-node certificates verified after Noise handshake and before any application-layer message exchange.

### 4.2 Event envelope

Every federation message is a **signed event**:

```
SignedEvent {
  event_type:     <one of: heartbeat, policy_update, audit_batch,
                          locator_update, node_join, node_leave, node_revoke,
                          receipt_replicate, sync_request, sync_response,
                          rejoin_request, EXTENSION_*>
  event_id:       <128-bit ULID, monotonic-per-emitter>
  emitter_node:   <node_id of the sender>
  emitter_principal: <principal_id of the authoring principal, may equal "system" for node-internal events>
  fortress_id:    <fortress identifier>
  causal_parents: [<event_id>, ...]    // up to 3 causal predecessors for ordering
  payload:        <event_type-specific bytes>
  payload_hash:   <SHA-256 of payload>
  emitted_at:     <UTC timestamp>
  monotonic_seq:  <per-emitter monotonic counter; rollback detector>
  extension_envelope: { ... }           // RESERVED — see §10
  node_signature: <Ed25519 by emitter's per-node key>
  principal_signature: <Ed25519 by emitter_principal's key, when applicable>
}
```

**Why both signatures.** The principal signature attributes the event to a human (or future-agent) principal. The node signature attributes the event to a specific machine on the mesh. These can disagree (e.g., a compromised node forwarding events under a stolen principal-issued payload) and the receiver validates both against the appropriate certificate chain.

### 4.3 Six message classes (v0.1)

| Class | Direction | Carrier | Purpose |
|---|---|---|---|
| `heartbeat` | broadcast (pubsub) | gossipsub | Liveness + version-skew signal (§3.3) |
| `policy_update` | broadcast (pubsub) | gossipsub | Sync-on-write policy distribution (§5) |
| `audit_batch` | unicast (stream) | direct stream to canonical audit node | Streamed signed audit-log batches (§5.3) |
| `locator_update` | broadcast (pubsub) | gossipsub | Per-fortress agent-locator changes (§6) |
| `node_lifecycle` | broadcast (pubsub) | gossipsub | `node_join`, `node_leave`, `node_revoke`, `node_attestation_refresh` (§3) |
| `receipt_replicate` | unicast (stream) | direct stream | Receipt copies to redundant store (§5.5) |

Plus three RPC-shaped exchanges on direct streams: `sync_request`/`sync_response`, `rejoin_request`/`rejoin_response`, `key_attestation` (challenge/response, per §7.3).

### 4.4 Extension envelope (reserved for v1.x)

Every `SignedEvent` carries an `extension_envelope` object. In v0.1 it is always empty. v1.x message classes (specifically: guardian-delegated read-across-fortress, full audit replication, multi-master policy authoring) will populate the extension envelope without breaking v0.1 receivers. v0.1 receivers ignore unknown extension keys; v1.x receivers parse them.

This is the primary forward-compatibility hinge. See §10 for the explicit list of reserved extension keys.

---

## 5. Policy distribution, audit aggregation, receipt redundancy

### 5.1 Policy distribution: sync-on-write with signed versions

**Authoring source.** The console is the single authoring surface. Policy changes are written through the console, which holds (or proxies access to) the operator's principal key.

**Policy version.** Every agent carries a monotonic policy version counter. A new policy = `(agent_id, version, policy_blob, signed_at, principal_id, principal_signature, master_chain)`.

**Distribution.**

1. Operator authors and saves a policy change in the console.
2. The console signs the new policy with the principal key, packages it as a `policy_update` event, and broadcasts on the policy pubsub topic.
3. Every node receives, verifies the principal-signature chain to the fortress-master, and pins the new version locally if it is higher than the currently-pinned version for that agent.
4. The receiving node's local agent (if it canonically hosts the agent) gracefully drains any in-flight gates under the old policy, then activates the new policy. Per Key 4 + Key 5, the harness sees a clean policy-version transition signal.

**Conflict resolution.** Concurrent edits to the same agent's policy from two principals (e.g., Root and Partner editing the same policy in different console tabs) can produce two `policy_update` events with different versions but the same parent-version. Resolution: the highest `signed_at` timestamp wins; the loser is surfaced to the operator as a conflict in the console. v0.1 does not attempt CRDT-style merges; the operator resolves explicitly.

**No quorum.** Policies do not require quorum-commit. Single-operator trust model means we trust the operator's principal-signed event the moment we verify the signature.

**Operator-cloud / TEE receivers.** Same flow; the policy event arrives via gossipsub, the receiving node verifies signature offline, no need to phone home to the local node.

### 5.2 Audit aggregation: canonical audit node + streamed batches

**Canonical audit node.** Operator designates one node per fortress as the canonical audit node at fortress-bootstrap. Default: the first local-mode node. Re-designation is a console action, gated, and emits a `canonical_audit_change` event. Re-designation triggers a one-time bulk transfer of the existing audit log to the new canonical node. Old canonical retains a copy until operator confirms migration complete.

**Why one canonical node, not full replication.** Single-operator trust means we don't need Byzantine consensus on audit ordering. One node is the durable anchor; redundancy is operator-configured replicas (see §5.4). This keeps v0.1 simple. v1.x can extend to full N-way replication via the extension envelope.

**Streamed batches.**

1. Every node accumulates its locally-produced audit entries into a buffer.
2. Every 5 seconds (or 256 entries, whichever first; both configurable), the buffer is sealed into a batch:

   ```
   AuditBatch {
     batch_id:           <ULID>
     emitter_node:       <self>
     batch_seq:          <per-emitter monotonic batch counter>
     entries:            [<audit entry>, ...]
     prev_batch_hash:    <SHA-256 of the immediately preceding batch from this emitter>
     hkdf_chain_proof:   <HMAC over (batch_id, batch_seq, prev_batch_hash) using node_audit_chain_key>
     signature:          <Ed25519 over the whole batch by per-node key>
   }
   ```

3. The batch is sent over a direct stream to the canonical audit node.
4. The canonical audit node verifies the signature, the hkdf_chain_proof (proves the batch came from a node provisioned with the correct master-derived chain key), and the prev_batch_hash continuity (catches rollback, see §9.3).
5. On valid batch, the canonical audit node appends the batch's entries to the canonical audit log and ACKs.
6. On ACK, the emitting node clears its buffer up through the ACKed batch.

**Partition tolerance.** If the canonical audit node is unreachable, the emitting node continues buffering locally. There is no upper buffer limit at v0.1 (operator policy choice, disk space is cheap; data loss on partition is worse). On reconnect, all buffered batches stream to the canonical node in order.

**Per-node monotonic batch counter is the rollback canary.** A canonical audit node receiving batch_seq=42 followed by batch_seq=42-with-different-prev_batch_hash from the same node is seeing a node that has rolled back (or been replayed). This is a hard alarm; see §9.3.

**Normative HKDF chain proof input (canonical-JSON wrapping).** The `hkdf_chain_proof` field is computed as HMAC-SHA256 over a **canonical-JSON wrapping** of the three fields `(batch_id, batch_seq, prev_batch_hash)`, using `node_audit_chain_key` as the HMAC key, encoded as base64url. Ad-hoc concatenation of the three fields is NOT permitted. Two conforming emitters producing the same logical batch MUST produce byte-identical HMAC input, which requires a single byte-stable serialization.

Canonical-JSON for this protocol is defined as follows (and applies identically to the `signature` field input over the full batch body, and to every `SignedEvent` signature per §4):

1. Object keys are sorted in lexicographic (UTF-16 code-unit) order at every nesting level.
2. No whitespace appears between tokens.
3. Undefined values are omitted from objects; `null` is preserved distinctly.
4. Non-finite numbers (`NaN`, `Infinity`, `-Infinity`) are rejected (would lose information as `null` and destroy signature determinism across implementations).
5. Strings are encoded with the standard JSON escape rules (UTF-8 surrogate pairs preserved; no custom escaping).
6. Nested arrays and objects are canonicalized recursively under the same rules.
7. Output is the UTF-8 byte encoding of the resulting JSON string; that byte sequence is the HMAC input.

The normative computation is therefore:

```
chain_proof_input = canonical_json({
  "batch_id":        <batch_id>,
  "batch_seq":       <batch_seq>,
  "prev_batch_hash": <prev_batch_hash>
})
// After canonicalization, the key order in the emitted bytes is
// batch_id, batch_seq, prev_batch_hash (lexicographic), regardless of
// authoring order.

hkdf_chain_proof = base64url(
  HMAC_SHA256(key = node_audit_chain_key, message = chain_proof_input)
)
```

**Empty `prev_batch_hash` convention.** On the first batch from an emitter, `prev_batch_hash` is the empty string `""`. It is still included in the canonical-JSON input (not omitted). This keeps the verifier's input-shape invariant across batch_seq=0 and batch_seq≥1.

**Why this tightening is load-bearing.** Any divergence in canonicalization rules across implementations produces silent HMAC mismatches that look like a compromised node (the node gets rejected with `MeshChainDiscontinuityError` or `hkdf_chain_proof mismatch`), but is actually an interop bug. The reference implementation in `server/src/mesh/canonical-json.ts` defines the seven rules above and is the normative reference; alternate-language implementations MUST produce byte-identical output for every input the reference implementation accepts.

**Signature over the batch body uses the same canonicalization.** The batch's `signature` field is Ed25519 over `canonical_json({batch_id, emitter_node, batch_seq, prev_batch_hash, entries, hkdf_chain_proof, sealed_at})`: the full batch body excluding the `signature` field itself. Same seven rules. Same byte-stability guarantee.

### 5.3 Audit log shape

The canonical audit log is an append-only log indexed by `(node_id, batch_seq)` and by global monotonic ingest-order. Every entry is:

```
AuditEntry {
  entry_id:           <ULID, generated at production time>
  emitter_node:       <where this entry was produced>
  emitter_agent:      <agent_id that performed the action, or "system">
  emitter_principal:  <principal_id authoring the action>
  policy_version:     <version of agent policy in effect at emit>
  attestation_state:  <current attestation badge state for emitter_node, per Key 7>
  signature_scheme:   <"ed25519-v1" at v1.0; reserved for "ed25519+ml-dsa-v1" hybrid at v1.x per thesis §3 PQ note>
  payload:            <action-specific>
  signature:          <Ed25519 by emitter_node's per-node key>
}
```

**Crypto-agility (per thesis §3 L1 commitment).** The `signature_scheme` field is mandatory at v1.0 even though only one value (`"ed25519-v1"`) is valid. At v1.x, hybrid signing introduces `"ed25519+ml-dsa-v1"`. v1.0 verifiers reject unknown schemes; v1.x verifiers accept both. This is the migration hinge for post-quantum.

### 5.4 Audit replicas

Operator can designate additional nodes as audit replicas. A replica receives audit batches from the canonical audit node via direct-stream replication (the canonical node mirrors every received batch to each replica). Replicas verify and store identically.

**v0.1 default.** No additional replicas. Operator opts in by adding a node to the audit-replica set in the console. Adding a replica triggers a one-time bulk-pull of the existing audit log from the canonical node.

**Replica election on canonical-node loss.** If the canonical audit node is permanently lost (revoked, decommissioned without successor designated), the operator manually designates a new canonical node from the existing replica set. v0.1 does not auto-elect; this is a deliberate single-operator-trust-model decision. v1.x may add deterministic-rotation-on-loss via the extension envelope.

### 5.5 Receipt redundancy

Per Key 6, every external action emits a signed receipt (Concordia attestation shape). Receipts land at minimum on:

1. The **producing node** (where the action ran).
2. The **canonical audit node** (every receipt is also an audit entry; redundancy is automatic via §5.2).

Operator can configure additional receipt replicas independently of audit replicas via the `receipt_replicate` direct-stream message. Each replica node gets every receipt streamed.

**Per-receipt addressability.** Receipts are addressable by `(receipt_id, originating_agent_id)`. Any node holding a copy can serve the receipt to a verifier on demand. Verification is by signature, not by source, no node needs to be trusted to serve a receipt.

**Cold-storage replica.** A common operator pattern (per Q3 lock): designate one always-on minimal node as a cold-storage receipt replica. The console exposes this as "Add cold storage" with a one-click flow. v0.1 ships this as a configuration option; the cold-storage node runs the same Sanctuary stack with a minimal agent count (zero) and a maximal receipt-store retention.

---

## 6. Per-fortress agent-locator table

### 6.1 Purpose

The locator table answers: "Which node currently runs agent `X`?" The console uses this for routing; intra-mesh chat uses this for delivery (per Q2 chat-routing decision); audit + receipt lookups use this for source identification.

### 6.2 Shape

```
AgentLocatorEntry {
  agent_id:               <UUID>
  canonical_node:         <node_id>
  locator_version:        <monotonic per-agent>
  last_migration_at:      <UTC timestamp>
  fallback_nodes:         [<node_id>, ...]    // operator-configured failover order, optional in v0.1
  hosting_principal:      <principal_id who provisioned this agent>
  signature:              <Ed25519 by operator's principal key>
}
```

The full locator table is `{ agent_id → AgentLocatorEntry }`, replicated on every node via the `locator_update` pubsub topic. Updates flow as signed `locator_update` events (per Q3 lock: "each agent's canonical-node pointer updated via signed events on migration").

### 6.3 Migration

When an operator migrates an agent from node A to node B:

1. Operator initiates migration in console; gate prompt fires.
2. Console signs and broadcasts a `locator_update` event with `(agent_id, canonical_node: B, locator_version: prev+1)`.
3. Node A drains the agent (in-flight gates settle, agent state checkpoints).
4. Agent state is transferred A → B over a direct stream encrypted with the destination node's transport key. v0.1 ships a basic checkpoint-and-resume; sophisticated live-migration is v1.x.
5. Node B activates the agent under the same policy version A was running.
6. Future routing for `agent_id` resolves to B via the updated locator table.

**Locator version ordering is what catches inconsistent updates.** If two `locator_update` events for the same agent arrive with overlapping versions, the highest version wins; the loser is surfaced as a conflict. The operator's principal signature is required, so this only happens under the rare concurrent-multi-principal scenario.

### 6.4 Routing

A node receiving a federation message addressed to `agent_id` consults its local locator table:

- If `canonical_node == self`: deliver locally.
- If `canonical_node == other_node`: forward via libp2p direct stream.
- If `canonical_node` not in current node roster (revoked or expired): consult `fallback_nodes`; if none reachable, return a routing-error event signed by self.

Console resolves routing identically.

---

## 7. Trust root, per-node revocation, key rotation

### 7.1 Trust root

The fortress-master Ed25519 public key is the universal trust anchor for the mesh. Every certificate and every signed event ultimately verifies against the master. The master public key is small (32 bytes) and stable for the operator's lifetime barring key compromise (in which case cascade recovery (§9.5) replaces it).

The master public key is distributed to every node at join (in the bootstrap token + first sync). Nodes pin the master pubkey and reject any certificate or event that does not chain to the pinned key.

**Master-pubkey rotation under recovery** is handled by guardian quorum re-issuing the entire certificate hierarchy under the new master, and broadcasting a `master_rotation` event signed by guardian quorum (see §9.5).

### 7.2 Per-node key revocation

Per-node keys are revocable at any time without requiring fortress-master rotation:

1. Operator (or guardian quorum) signs `node_revoke` event (§3.6).
2. Node certificate marked invalid in roster on every receiving node.
3. Future events bearing the revoked node's signature are rejected.
4. Past events are still valid (they were signed when the node was authorized; revocation is not retroactive). This is critical for audit integrity, if revocation invalidated past events, every breach would erase the operator's history of what the breached node had done.

### 7.3 Per-node key attestation challenges

Any node may challenge any other node to re-prove possession of its certificate's private key:

1. Challenger sends `key_attestation_request` with a 256-bit nonce.
2. Challenged node signs `(challenger_node_id, nonce, current_timestamp)` with its per-node private key.
3. Challenger verifies the signature against the certificate.

This catches a stolen certificate paired with a missing private key (e.g., if an attacker copied the certificate from disk but couldn't decrypt the cocoon-protected private-key store). Challenge frequency is operator-policy-driven, defaulted to once per hour per-peer in v0.1.

### 7.4 Per-node key rotation (planned, not under-attack)

Operator can rotate a per-node key proactively (security hygiene, post-recovery default per Key 13). Mechanics:

1. Console signs a new NodeIdentityCertificate for the same `node_id` with a new public key.
2. Old certificate is revoked in the same atomic broadcast.
3. The node generates the new keypair locally and acknowledges via `key_attestation` against the new certificate.

Old signed events remain valid (signed under the old key, certificate-revocation-not-retroactive).

---

## 8. Failure modes

The federation protocol explicitly anticipates four failure classes. Each has a defined detection mechanism, a defined operator-facing surface, and a defined recovery path.

### 8.1 Node offline

**Detection.** 3 consecutive missed heartbeats (90 sec default).

**Operator surface.** Console renders the node in `unreachable` presence state (the fifth state per Q5 lock). All agents canonically hosted on the unreachable node are paused; agents on reachable nodes continue. Receipts and audit data the unreachable node held are unavailable until rejoin OR until they are served from another node holding a redundant copy (per §5.4, §5.5).

**Recovery.** Node rejoins per §3.5. State difference is reconciled via sync delta. Audit batches buffered locally during the offline window stream to the canonical audit node on reconnect.

**Bounded staleness.** Per §3.5, a node offline beyond `max_offline_window` (default 30 days) is auto-removed and must re-join via the full join ceremony.

### 8.2 Node compromised

**Detection.** Multiple signals, none individually decisive, all surface to the operator (via sentinel agents per Key 11) for decision:

- Anomalous audit-batch contents (sentinel detects exfiltration patterns).
- Failure of `key_attestation` challenge (§7.3).
- Heartbeat with `monotonic_seq` non-monotonic (rollback canary).
- `prev_batch_hash` discontinuity in audit batches (rollback canary).
- Egress proxy + sentinel pack (Key 2 / Key 11) flags.

**Operator surface.** Sentinels alert via chat with plain-English explanation. Operator has the incident-response ladder from Key 8: close the gate around an agent / harness / fortress-wide; rotate keys; full revocation.

**Recovery.** Operator (or guardian quorum) issues `node_revoke` (§3.6). Compromised node's certificate marked invalid. Agents canonically hosted on the revoked node are migrated (operator-directed) to a healthy node. Past audit data from the revoked node is preserved (not retroactively invalidated) but flagged in the audit log as `emitter_node: <revoked-node-id> [REVOKED at <timestamp>]` to give downstream verifiers full context.

**Operator-decision: do we trust the past data?** This is operator-policy, not federation-protocol-decision. The audit log faithfully preserves what was emitted; a regulated-industry operator may need to discount or re-verify pre-revocation entries depending on the compromise's scope. Sanctuary surfaces the data and the revocation context; the operator's policy-pack decides what to do with it.

### 8.3 Node rollback (replay)

**Detection.** Two mechanisms run side-by-side:

1. **Per-emitter monotonic_seq.** Every event carries `monotonic_seq` from its emitter. A receiver seeing `monotonic_seq=42` followed later by `monotonic_seq=42-with-different-event-id` from the same emitter has detected rollback. Permanent alarm.
2. **Audit batch chaining.** `prev_batch_hash` in `AuditBatch` (§5.2) chains batches per-emitter. A break in the chain (new batch_seq with prev_batch_hash that does not match the canonical audit node's record of the prior batch from that emitter) is rollback. Permanent alarm.

**Operator surface.** Sentinel-class alert with explicit "Node X has rolled back to a prior state. This may indicate compromise, restored backup, or replay attack." Plain-English gate per Key 2.

**Recovery.** Operator-decision based on context. Common cases:

- Restored backup: operator confirms the rollback was intentional (e.g., recovered from disk failure), accepts the loss of any audit between the rollback point and now (or pulls from the canonical audit node if the canonical was unaffected).
- Compromise: revoke the node (§3.6), preserve past audit, rotate keys.

The federation protocol does not auto-decide. It detects and surfaces.

### 8.4 Split-brain

**Definition.** Two subsets of the mesh are partitioned from each other for an extended period; in the meantime, both subsets receive operator (or guardian) policy/locator updates from different physical operator interactions, producing divergent state.

**Likelihood at v0.1.** Low for single-operator typical setups, the operator is one human, generally interacting with one console at a time. Higher for: (a) multi-principal hierarchies (Key 14) where two principals act independently during a partition; (b) unattended / agent-initiated state changes during a partition.

**Detection.** On partition healing, the rejoin sync (§3.5) compares policy versions and locator versions. Divergent versions for the same `(agent_id, version)` slot indicate concurrent edits across the partition.

**Operator surface.** Console surfaces the conflict per Key 10 / §5.1 conflict-resolution flow: "While GCP-East was disconnected, two policy versions for Agent X were issued. Compare and choose."

**Recovery.** Operator selects the canonical version. Rejected versions are preserved in the audit log with `superseded_by: <event_id>` annotation. No CRDT auto-merge in v0.1.

**Defensive design.** The protocol minimizes split-brain blast radius by:

- Single canonical audit node (audit doesn't split-brain, at most, one side's audit ingests pause).
- Single canonical node per agent (agents don't split-brain, at most, one side runs the agent and the other side waits).
- Operator-resolved policy and locator conflicts (clear resolution path, no silent forks).

### 8.5 Canonical audit node loss

**Detection.** Canonical audit node is unreachable beyond the heartbeat timeout, then beyond a 24-hour grace window.

**Operator surface.** Console alerts: "Your canonical audit node is unreachable for 24h+. New audit data is buffering on every node. Designate a new canonical node from your replicas."

**Recovery.** Operator promotes a replica to canonical via console gate. Promoted node bulk-streams its audit log to all peers as the new canonical record. If no replica exists, operator promotes any reachable node and accepts that the new canonical's audit log starts from its own local data plus what other nodes can stream from their buffers.

**Why no auto-election in v0.1.** Auto-election requires either a deterministic rule (which can fail if the deterministic next-in-line is also down) or a quorum (which we explicitly reject, single-operator trust). Manual operator promotion is acceptable for v1.0; v1.x can add operator-policy-driven auto-promotion (e.g., "promote in this priority order if canonical is down >24h") via the extension envelope.

---

## 9. Recovery cascade (Key 13 integration)

The federation protocol is a participant in the broader recovery flow defined by Key 13 (M-of-N guardian recovery, DMswitch). Federation-protocol obligations during recovery:

### 9.1 Guardian roster distribution

The guardian-roster is a fortress-master-signed certificate set defining the M-of-N guardians and their public keys. It is distributed to every node at federation-bootstrap and on every change. Nodes verify guardian signatures (per §3.6.1) against the pinned roster.

### 9.2 DMswitch trigger propagation

When the DMswitch fires (operator absence beyond threshold), the canonical audit node generates a `dmswitch_triggered` audit event and broadcasts it. Every node receives, surfaces it locally (idle-state alarm), and unlocks the guardian-revocation path (§3.6.1). Guardians, holding shares of the recovery key, may now coordinate.

### 9.3 Guardian quorum reconstitution

Reconstitution per Key 13 happens client-side on the operator's new fortress instance. From the federation-protocol perspective:

1. Operator (or recovering principal) stands up a new local fortress.
2. Reconstitution ceremony recombines guardian shares to recover the fortress-master.
3. The new fortress instance issues a `master_rotation` event signed by guardian quorum, distributed to all known nodes (using the last-known node roster).
4. Existing nodes verify the guardian quorum signature, accept the new master public key, and re-anchor their certificate chains.
5. The new console issues fresh per-node certificates under the rotated master for any nodes that need re-attestation.
6. Operator post-recovery first-login prompt (per Key 13 cascade) initiates broker-credential rotation, federation-protocol concern only insofar as the new credentials are distributed to canonical-hosting nodes via standard policy/secret-broker flows.

### 9.4 Cascade implications

Recovery cascade order at the federation layer:

- Fortress-master rotation → all per-node certificates re-issued under new master.
- All per-node `node_audit_chain_key` HKDF-derived from the new master (audit batch chain continues across the rotation, with a `master_rotation` boundary entry inserted by every node).
- All per-node `node_transport_key` likewise re-derived.
- Locator table re-signed under the new principal cert.
- Policy versions re-signed (or, by operator policy, retained with old signatures and explicitly verified against the old master pubkey, which is preserved in a `historical_master` field for backward verification).

### 9.5 Audit continuity across master rotation

The audit log preserves the master rotation as an explicit entry with the old and new master pubkeys, the guardian quorum signatures that authorized the rotation, and the timestamp. Every audit entry post-rotation chains to the new master; every audit entry pre-rotation chains to the old. A regulated-industry verifier walking the audit log encounters the rotation entry, verifies the guardian quorum, and continues verifying under the new chain. No history is invalidated.

---

## 10. v1.x extension points (the hard gate enforced)

The hard gate from §1.3 requires that v0.1 leaves room for guardian-delegated read-across-fortress and other v1.x extensions. The following extension points are **reserved at v0.1**. v0.1 implementations MUST NOT close these doors.

### 10.1 Reserved extension envelope keys (in `SignedEvent.extension_envelope`)

| Key | Reserved for | Notes |
|---|---|---|
| `cross_fortress_read_grant` | v1.x MSP / Fleet Operator Console | Carries delegation grant from operator A's principal authorizing a specific read scope to a named guardian-delegated reader principal in operator B's fortress. Audited as a Concordia commitment between A and B. |
| `cross_fortress_read_query` | v1.x MSP / Fleet Operator Console | A read query from operator B's delegated reader against operator A's mesh, carrying the grant `event_id` for verification. |
| `cross_fortress_read_response` | v1.x MSP / Fleet Operator Console | Scoped data response, signed by operator A's per-node key, carrying the grant `event_id` for audit. |
| `multi_master_policy_merge` | v1.x multi-master policy authoring | Merge events for concurrent multi-principal policy edits resolved via CRDT-style rules. |
| `audit_replication_full_n_way` | v1.x N-way audit replication | Coordination events for full-replica audit propagation. |
| `auto_promote_canonical_audit` | v1.x operator-policy-driven canonical-node failover | Pre-declared promotion-order events. |
| `agent_live_migration` | v1.x sophisticated live-migration | Live-state transfer coordination beyond v0.1's checkpoint-and-resume. |

v0.1 receivers ignore unknown extension keys (forward-compat). v1.x receivers parse them.

### 10.2 Reserved capability bits (in `NodeIdentityCertificate.capabilities`)

| Bit | Reserved for | Notes |
|---|---|---|
| 0 | Standard fortress-node (v0.1 default for all nodes) | All v0.1 nodes set this bit. |
| 1 | Audit-replica-eligible | Operator may designate this node as an audit replica. |
| 2 | Cold-storage receipt replica | Receipt-replication target only; minimal agent activity. |
| 3 | RESERVED, cross-fortress read endpoint (v1.x MSP) | Node accepts `cross_fortress_read_query` events under explicit grants. v0.1 nodes MUST NOT set this bit. |
| 4 | RESERVED, guardian-delegated principal endpoint (v1.x MSP) | Node hosts a guardian-delegated reader principal authorized by another operator. v0.1 nodes MUST NOT set this bit. |
| 5 | RESERVED, multi-master policy author (v1.x) | Node accepts policy-update events under multi-master CRDT resolution. v0.1 nodes MUST NOT set this bit. |
| 6 | RESERVED, auto-promote canonical-audit candidate (v1.x) | Node is in the operator-pre-declared canonical-audit promotion order. v0.1 nodes MUST NOT set this bit. |
| 7-31 | Reserved for future allocation | Implementations MUST NOT set these bits at v0.1. |

### 10.3 Reserved message classes

In addition to the six v0.1 message classes (§4.3), the following class-name prefixes are reserved:

- `EXTENSION_*`: namespace for v1.x message classes; v0.1 receivers ignore unknown event_types.
- `cross_fortress_*`: namespace specifically for v1.x MSP / Fleet Operator Console flows.
- `multi_master_*`: namespace for v1.x multi-master policy.

**Allocated v1.0 namespace (not v1.x extension):** `composition_*` is allocated at v1.0 to the optional Concordia + Verascore composition layer shipped under WP-MVP-10 (PR #47, merged 2026-04-22 at SHA `c2f90fd`). The currently shipped event types in this namespace are `composition_receipt_packed`, `composition_receipt_verified`, `composition_mandate_verified`, `composition_verascore_published`, `composition_sidecar_spawned`, `composition_sidecar_crashed`, `composition_sidecar_recovered`, `composition_degraded`, and `composition_recovered`, emitted by the in-process Python sidecar bridge when an agent invocation crosses a Concordia commitment boundary or the sidecar lifecycle changes state. The canonical list lives at `server/src/composition/constants.ts` (`COMPOSITION_EVENT_TYPES`). Composition is default-off at v1.0; nodes that have not enabled the optional Concordia sidecar do not emit `composition_*` events. v1.x extensions MUST NOT collide with this namespace, and any future addition to the v1.0 set MUST extend the canonical constants array (additive only; existing event types are stable).

### 10.4 Reserved certificate fields

Future-compat fields in `NodeIdentityCertificate` (currently optional or unused in v0.1 but reserved):

- `delegated_grants[]`: list of cross-fortress grants this node honors (v1.x MSP).
- `attestation_lineage_chain[]`: TCB lineage history (v1.x deeper attestation per Key 7 fourth-badge work).
- `master_signature`: direct fortress-master signature on the certificate (optional v0.1, REQUIRED v1.x for guardian-delegated read paths to validate certificate provenance independent of any single principal).

### 10.6 Emit/receive symmetry contract for reserved namespaces

> **Status:** Added per full-sweep #80 to make explicit a contract that exists in code at the emit boundary but was not previously stated for the receive boundary.

The reserved namespaces in §10.1 (extension envelope keys), §10.2 (capability bits), and §10.3 (message classes) form a closed set at v0.1. The conformance contract has **two halves** that MUST hold symmetrically.

**Emit-side (REQUIRED at v0.1).** A v0.1-conforming sender MUST reject any attempt to construct a `SignedEvent` whose `extension_envelope` carries a reserved key from §10.1, whose `event_type` matches a reserved class prefix from §10.3, or whose surrounding `NodeIdentityCertificate` advertises a reserved capability bit from §10.2 (bits 3-31). The reference implementation enforces this in `packSignedEvent` and `issueNodeIdentityCertificate` at `server/src/mesh/`. The rejection is structural: the API simply has no path through which a v0.1 caller can emit a reserved-namespace event.

**Receive-side (REQUIRED at v0.1).** A v0.1-conforming receiver MUST refuse to process incoming `SignedEvent`s whose `event_type` falls under a §10.3 reserved class prefix, OR whose `extension_envelope` carries a reserved §10.1 key, OR whose signing node's certificate advertises a §10.2-reserved capability bit. The receive-side rejection is the symmetry partner of the emit-side rejection: a peer node that produces a reserved-namespace event is by definition not v0.1-conforming, and processing such an event would smuggle undefined-at-v0.1 semantics into the receiver's audit chain. The rejection MUST be logged as an audit event of class `peer_protocol_violation` and the offending message MUST NOT be forwarded.

**Distinction from forward-compat.** §10.1's "v0.1 receivers ignore unknown extension keys" language refers to genuinely-unknown extension keys that fall **outside** the §10 reserved set. Such keys may be introduced by future minor revisions of v0.x (additive). The reserved namespaces in §10 are not "unknown future"; they are explicitly **reserved for v1.x semantics that v0.1 has no legitimate way to honor**, and a v0.1 node observing them MUST treat them as protocol violations rather than forward-compat extensions.

**Why both halves are required.** If only the emit half were enforced, a malicious or buggy v0.1 peer could send a reserved-namespace event and a conforming receiver would silently accept it; subsequent v1.x deployments would then encounter audit chains that already contain `composition_*` or `cross_fortress_*` events which were never legitimately produced. The receive half closes that loophole and keeps the v0.1 mesh's audit-chain semantics invariant against peer misbehavior.

### 10.5 The MSP / Fleet Operator Console v1.x dependency in narrative

The v1.x extension this protocol most needs to support cleanly is **Drew's meta-dashboard**: a single console operated by an MSP-class principal who manages a fleet of independent operator fortresses (Drew's clients). The expected shape:

- Each client operator explicitly signs a `cross_fortress_read_grant` authorizing Drew's MSP principal to read a defined scope of their fortress (selected agents, selected receipts, selected audit ranges).
- The grant is itself a Concordia commitment between client-operator and MSP-operator. Verascore can ingest it. The audit trail for both sides records the grant.
- Drew's MSP node sets capability bit 4 (guardian-delegated principal endpoint).
- Each client's fortress nodes set capability bit 3 (cross-fortress read endpoint) for nodes Drew is authorized to query.
- Read queries flow `cross_fortress_read_query` (extension envelope key) → matching client node → `cross_fortress_read_response`.
- Writes are explicitly NOT enabled in this flow at v1.x first cut; if writes are eventually authorized, they go through the same per-client policy gates and per-client attestation context as if Drew were physically the client (audited as a guardian-delegated write commitment).

The v0.1 design accommodates this by ensuring:

- Per-node certificates have capability bits reserved (10.2) so MSP-relevant capability is a flag flip, not a new certificate format.
- Signed-event envelopes have an `extension_envelope` slot (10.1) so the new MSP message classes ride v0.1 transport without protocol change.
- The trust-root model (operator's principal signs grants; grants reference signed events; quorum-style multi-operator verification is achievable at the application layer without consensus) does not require the federation protocol itself to add cross-operator trust primitives. Cross-operator trust is established at the Concordia-commitment layer; federation just transports the resulting messages.

If this extension story does not work cleanly atop the v0.1 protocol, v0.1 has failed the hard gate and must be re-spec'd.

---

## 11. Open questions for the build thread

These are deliberately unresolved at the spec level. Build thread chooses, surfaces choice in implementation handoff.

1. **libp2p stack pick, go-libp2p vs. js-libp2p vs. rust-libp2p?** Sanctuary server is TypeScript; js-libp2p is the path of least resistance but has historically been the least mature stack. Build thread pick.
2. **Bootstrap-token TTL.** Spec defaults 15 minutes; build thread may justify a different default with operator-UX evidence.
3. **Heartbeat interval and missed-heartbeat threshold defaults.** Spec defaults 30s / 3 missed (90s); build thread may tune.
4. **Audit batch interval and size defaults.** Spec defaults 5s / 256 entries; build thread may tune based on early field load testing.
5. **`max_offline_window` default.** Spec defaults 30 days; build thread may select different default after consultation with Key 13 estate-planning research ticket (long-dormant-but-legitimate node case).
6. **State-transfer mechanism for agent migration (§6.3).** Spec ships a basic checkpoint-and-resume; build thread picks the actual checkpoint format (probably aligned with the cocoon state-snapshot format already shipped in v0.10.x).
7. **Fortress-id format.** Spec assumes a fortress-id exists; build thread defines (proposed: 128-bit ULID generated at fortress-bootstrap, never re-used).
8. **Cocoon binding.** Per-node private keys are stored where? Spec assumes per-node cocoon-equivalent; build thread confirms the per-node secret-storage model aligns with the master cocoon model.

---

## 12. Acceptance criteria

The federation protocol v0.1 implementation passes acceptance when:

1. A single console can speak federation to a mesh containing one node of each mode (local, operator-cloud, sovereign-managed TEE) and observe consistent state across all three.
2. Per-node certificates are HKDF-anchored to the fortress-master per §2.2 and revocable via `node_revoke` per §3.6 and §7.2.
3. A policy edit in the console is sync-on-write distributed to all nodes within 5 seconds under healthy network conditions, with version-vector pinning per §5.1.
4. Audit batches stream from every node to the canonical audit node and are verified end-to-end including HKDF chain proof and prev-batch-hash continuity.
5. Receipts are stored at the producing node + canonical audit node + any operator-configured replicas, and any node holding a copy can serve a verifier.
6. Agent-locator updates flow as signed events on every migration; routing through the locator table works for chat (Q2) and for direct console-to-agent operations.
7. A node revoked by either operator or guardian quorum is excluded from the mesh on every reachable peer within one heartbeat cycle.
8. The four failure modes (node offline, compromised, rollback, split-brain) are detected per §8 and surfaced to the operator with plain-English explanation per the gate principle.
9. Recovery cascade (Key 13) flows correctly: master rotation under guardian quorum produces a `master_rotation` event accepted by every node, certificate chains re-anchor, audit continuity is preserved.
10. **The v1.x MSP / Fleet Operator Console extension can be added by setting capability bits, populating extension envelopes, and adding the new message classes, without altering the v0.1 wire format, without re-spec'ing the trust-root model, and without re-issuing existing v0.1 certificates.** This is the hard gate.

If criterion 10 cannot be demonstrated (via design walkthrough, not via v1.x implementation), v0.1 has failed the hard gate.

---

## 13. Outstanding for Erik

- **Approve this spec** before WP-MVP-3 build thread spawns (gated per the MVP Scope Lock).
- **Approve the canonical audit node defaulting to the first local-mode node.** Alternative: default to sovereign-managed TEE for regulated-industry pilots. Coordinator default is local-mode; flag for Erik.
- **Approve the 30-day `max_offline_window` default.** Alternative: 90 days for estate-planning compatibility. Coordinator default is 30 days; flag for Erik.
- **Confirm the open-source line.** Per the Q6 lock, the federation protocol spec + TS reference impl is open-source. This document is therefore a public artifact when v0.1 ships. Confirm OK to publish post-Erik-approval.
- **Confirm the v1.x MSP extension narrative in §10.5 reflects Drew's actual envisioned usage.** Coordinator drafted from Q2 NEW MSP ticket + Q3 hard-gate requirement; Drew's input would sharpen.

---

**End of Federation Protocol v0.1 spec.** This document is the gate for WP-MVP-3 build-thread spawn. Build thread implements only the v0.1 surface defined here, leaves §10 extension points untouched (reserved for v1.x), and surfaces any deviation back to the coordinator.
