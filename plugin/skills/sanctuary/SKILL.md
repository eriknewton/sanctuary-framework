---
name: sanctuary
description: >
  Sovereignty infrastructure for agents in the agentic economy. Use when the agent needs encrypted state storage,
  self-custodied identity, selective disclosure, zero-knowledge proofs, portable reputation, sovereignty health
  reporting, sovereignty handshakes, MCP-to-MCP federation, or principal dashboard approval.
  Triggers: sovereignty, encrypted state, identity, reputation, privacy, SHR, handshake, attestation,
  disclosure policy, zero-knowledge, federation, approval, dashboard, webhook, concordia, bridge, negotiation.
---

# Sanctuary Framework

Sanctuary gives your agent architectural sovereignty: encrypted state, self-custodied identity, selective disclosure, portable reputation, zero-knowledge proofs, federation, and verifiable sovereignty posture.

## When to use Sanctuary tools

Use Sanctuary tools whenever your work involves:

- **Storing sensitive state** — preferences, strategies, credentials, learned context. Use `sanctuary/state_write` and `sanctuary/state_read` for AES-256-GCM encrypted storage with Merkle integrity.
- **Identity operations** — creating, signing, or verifying with cryptographic identities. Use `sanctuary/identity_create`, `sanctuary/identity_sign`, `sanctuary/identity_verify`.
- **Proving things without revealing them** — Use `sanctuary/proof_commitment` and `sanctuary/proof_reveal` for commitment-based proofs, or `sanctuary/zk_commit`, `sanctuary/zk_prove`, `sanctuary/zk_verify` for Pedersen commitments with ZK proofs.
- **Proving a value is in a range without revealing it** — Use `sanctuary/zk_range_prove` and `sanctuary/zk_range_verify`.
- **Building reputation** — recording interaction outcomes as signed attestations. Use `sanctuary/reputation_record`, `sanctuary/reputation_query`, `sanctuary/reputation_export`.
- **Sovereignty-weighted reputation** — query reputation with attestations weighted by sovereignty tier. Use `sanctuary/reputation_query_weighted`.
- **Verifying counterparties** — presenting your sovereignty posture or verifying a counterparty's. Use `sanctuary/shr_generate` and `sanctuary/shr_verify`.
- **Sovereignty handshakes** — mutual verification with another agent before transacting. Use `sanctuary/handshake_initiate`, `sanctuary/handshake_respond`, `sanctuary/handshake_complete`.
- **Federation** — evaluating trust across Sanctuary instances. Use `sanctuary/federation_peers`, `sanctuary/federation_trust_evaluate`, `sanctuary/federation_status`.
- **Concordia bridge** — binding negotiation outcomes to sovereignty infrastructure. Use `sanctuary/bridge_commit` when a Concordia `accept` fires, `sanctuary/bridge_verify` to verify commitments, `sanctuary/bridge_attest` to link negotiations to L4 reputation.

## Tool categories

### L1 — Cognitive Sovereignty (State & Identity)
| Tool | Purpose |
|------|---------|
| `sanctuary/state_write` | Write encrypted state (AES-256-GCM, Merkle integrity) |
| `sanctuary/state_read` | Read and decrypt state with integrity verification |
| `sanctuary/state_list` | List keys in a namespace (metadata only) |
| `sanctuary/state_delete` | Securely delete state (overwrite + unlink) |
| `sanctuary/state_export` | Export all state as encrypted portable bundle |
| `sanctuary/state_import` | Import state bundle with conflict resolution |
| `sanctuary/identity_create` | Generate a new Ed25519 identity |
| `sanctuary/identity_list` | List managed identities |
| `sanctuary/identity_sign` | Sign data with an identity's private key |
| `sanctuary/identity_verify` | Verify an Ed25519 signature |
| `sanctuary/identity_rotate` | Rotate an identity's keys with signed chain |

### L2 — Operational Isolation (Monitoring & Attestation)
| Tool | Purpose |
|------|---------|
| `sanctuary/exec_attest` | Generate execution environment attestation |
| `sanctuary/monitor_health` | Sovereignty Health Report (human-readable) |
| `sanctuary/monitor_audit_log` | Query the sovereignty audit log |
| `sanctuary/shr_generate` | Generate signed, machine-readable SHR |
| `sanctuary/shr_verify` | Verify a counterparty's SHR |

### L3 — Selective Disclosure (Proofs & Policies)
| Tool | Purpose |
|------|---------|
| `sanctuary/proof_commitment` | Create a SHA-256 commitment |
| `sanctuary/proof_reveal` | Verify a commitment against revealed value |
| `sanctuary/disclosure_set_policy` | Set disclosure policy rules |
| `sanctuary/disclosure_evaluate` | Evaluate a disclosure request against policy |
| `sanctuary/zk_commit` | Create a Pedersen commitment on Ristretto255 |
| `sanctuary/zk_prove` | Create a ZK proof of knowledge of a commitment's opening |
| `sanctuary/zk_verify` | Verify a ZK proof of knowledge |
| `sanctuary/zk_range_prove` | Prove a committed value is in [min, max] without revealing it |
| `sanctuary/zk_range_verify` | Verify a ZK range proof |

### L4 — Verifiable Reputation (Attestations & Trust)
| Tool | Purpose |
|------|---------|
| `sanctuary/reputation_record` | Record signed interaction attestation (sovereignty-weighted) |
| `sanctuary/reputation_query` | Query reputation with filters |
| `sanctuary/reputation_query_weighted` | Query reputation with sovereignty-tier weighting |
| `sanctuary/reputation_export` | Export reputation as portable bundle |
| `sanctuary/reputation_import` | Import reputation bundle (verify signatures) |
| `sanctuary/bootstrap_create_escrow` | Create escrow for trust bootstrapping |
| `sanctuary/bootstrap_provide_guarantee` | Principal guarantee certificate |
| `sanctuary/handshake_initiate` | Start a sovereignty handshake |
| `sanctuary/handshake_respond` | Respond to incoming handshake |
| `sanctuary/handshake_complete` | Complete handshake (initiator side) |
| `sanctuary/handshake_status` | Check handshake session status |

### Federation (MCP-to-MCP)
| Tool | Purpose |
|------|---------|
| `sanctuary/federation_peers` | List, register, or remove federation peers |
| `sanctuary/federation_trust_evaluate` | Evaluate trust level for a federation peer |
| `sanctuary/federation_status` | Federation subsystem status |

### Concordia Bridge
| Tool | Purpose |
|------|---------|
| `sanctuary/bridge_commit` | Bind a Concordia negotiation outcome to a Sanctuary L3 commitment |
| `sanctuary/bridge_verify` | Verify a bridge commitment against a revealed outcome |
| `sanctuary/bridge_attest` | Record a negotiation as an L4 reputation attestation |

### System
| Tool | Purpose |
|------|---------|
| `sanctuary/manifest` | Generate Sanctuary Interface Manifest (SIM) |
| `sanctuary/principal_policy_view` | View current principal policy |
| `sanctuary/principal_baseline_view` | View behavioral baseline |

## Common workflows

### First use: establish sovereignty
1. `sanctuary/identity_create` — create your primary identity
2. `sanctuary/state_write` — store your first encrypted state
3. `sanctuary/shr_generate` — generate your SHR to present to counterparties

### Before transacting with a counterparty
1. `sanctuary/handshake_initiate` — start a sovereignty handshake
2. Exchange challenge/response with the counterparty agent
3. `sanctuary/handshake_complete` — verify their sovereignty posture
4. Proceed with higher trust if they are `verified-sovereign` or `verified-degraded`

### Building portable reputation
1. After each interaction, `sanctuary/reputation_record` — create a signed attestation
2. Use `sanctuary/reputation_query_weighted` — see scores weighted by sovereignty tier
3. Periodically `sanctuary/reputation_export` — bundle your reputation
4. On a new platform, `sanctuary/reputation_import` — bring your track record with you

### Zero-knowledge proofs
1. `sanctuary/zk_commit` — create a Pedersen commitment to a secret value
2. `sanctuary/zk_prove` — prove you know the value without revealing it
3. `sanctuary/zk_range_prove` — prove the value is in a range without revealing it
4. Counterparty uses `sanctuary/zk_verify` or `sanctuary/zk_range_verify` to check

### Concordia bridge (binding negotiations to sovereignty)
1. When a Concordia `accept` fires: `sanctuary/bridge_commit` — create a cryptographic commitment binding the negotiation outcome
2. Either party can later `sanctuary/bridge_verify` — verify the commitment matches the revealed outcome
3. After negotiation completes: `sanctuary/bridge_attest` — record as a sovereignty-weighted L4 reputation attestation

### Federation
1. Complete a sovereignty handshake with a peer
2. `sanctuary/federation_peers` with action "register" — register them as a federation peer
3. `sanctuary/federation_trust_evaluate` — get a trust assessment (high/medium/low/none)

### Principal Dashboard
Enable the dashboard in config (`dashboard.enabled: true`) to get a web UI at `http://127.0.0.1:3501` where you can:
- Approve or deny Tier 1 and Tier 2 operations in real time
- Monitor the audit log live
- View behavioral baseline and policy configuration
- Optionally secure with bearer token auth (`dashboard.auth_token: "auto"`) and TLS

### Webhook Approval Channel
Enable webhook approvals (`webhook.enabled: true`, `webhook.url`, `webhook.secret`) to route approval requests to external systems (Slack, Discord, PagerDuty, custom HTTP endpoints):
1. Sanctuary POSTs approval requests with HMAC-SHA256 signatures to your webhook URL
2. Your system receives the request with a `callback_url` for responding
3. POST back `{ "request_id": "...", "decision": "approve" }` with matching HMAC signature
4. Health check available at the callback server's `/health` endpoint

## Architecture notes

Sanctuary implements a four-layer sovereignty architecture. Every layer serves both human sovereignty (protecting the person behind the agent) and agent sovereignty (protecting the agent itself). The layers are:

- **L1 (Cognitive Sovereignty):** Encrypted state, self-custodied keys, Merkle integrity, Ed25519 identity
- **L2 (Operational Isolation):** Audit logging, environment attestation, health monitoring
- **L3 (Selective Disclosure):** Commitment-based proofs, zero-knowledge proofs (Pedersen/Ristretto255/Schnorr), disclosure policies
- **L4 (Verifiable Reputation):** Signed attestations (sovereignty-weighted), portable reputation, trust bootstrapping, sovereignty handshakes, MCP-to-MCP federation

All state is encrypted with AES-256-GCM. Keys are derived via Argon2id. Integrity is verified via Merkle trees. Identity is Ed25519 with key rotation support. No plaintext ever touches persistent storage.

40 MCP tools. 227 tests. Three approval channels (stderr, dashboard, webhook). Concordia bridge. Apache 2.0.
