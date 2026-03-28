---
name: sanctuary
description: >
  Sovereignty infrastructure for agents in the agentic economy. Use when the agent needs encrypted state storage,
  self-custodied identity, selective disclosure, portable reputation, sovereignty health reporting, or sovereignty
  handshakes with counterparties. Triggers: sovereignty, encrypted state, identity, reputation, privacy, SHR,
  handshake, attestation, disclosure policy.
---

# Sanctuary Framework

Sanctuary gives your agent architectural sovereignty: encrypted state, self-custodied identity, selective disclosure, portable reputation, and verifiable sovereignty posture.

## When to use Sanctuary tools

Use Sanctuary tools whenever your work involves:

- **Storing sensitive state** — preferences, strategies, credentials, learned context. Use `sanctuary/state_write` and `sanctuary/state_read` for AES-256-GCM encrypted storage with Merkle integrity.
- **Identity operations** — creating, signing, or verifying with cryptographic identities. Use `sanctuary/identity_create`, `sanctuary/identity_sign`, `sanctuary/identity_verify`.
- **Proving things without revealing them** — Use `sanctuary/proof_commitment` and `sanctuary/proof_reveal` for commitment-based proofs.
- **Building reputation** — recording interaction outcomes as signed attestations. Use `sanctuary/reputation_record`, `sanctuary/reputation_query`, `sanctuary/reputation_export`.
- **Verifying counterparties** — presenting your sovereignty posture or verifying a counterparty's. Use `sanctuary/shr_generate` and `sanctuary/shr_verify`.
- **Sovereignty handshakes** — mutual verification with another agent before transacting. Use `sanctuary/handshake_initiate`, `sanctuary/handshake_respond`, `sanctuary/handshake_complete`.

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

### L4 — Verifiable Reputation (Attestations & Trust)
| Tool | Purpose |
|------|---------|
| `sanctuary/reputation_record` | Record signed interaction attestation |
| `sanctuary/reputation_query` | Query reputation with filters |
| `sanctuary/reputation_export` | Export reputation as portable bundle |
| `sanctuary/reputation_import` | Import reputation bundle (verify signatures) |
| `sanctuary/bootstrap_create_escrow` | Create escrow for trust bootstrapping |
| `sanctuary/bootstrap_provide_guarantee` | Principal guarantee certificate |
| `sanctuary/handshake_initiate` | Start a sovereignty handshake |
| `sanctuary/handshake_respond` | Respond to incoming handshake |
| `sanctuary/handshake_complete` | Complete handshake (initiator side) |
| `sanctuary/handshake_status` | Check handshake session status |

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
2. Periodically `sanctuary/reputation_export` — bundle your reputation
3. On a new platform, `sanctuary/reputation_import` — bring your track record with you

## Architecture notes

Sanctuary implements a four-layer sovereignty architecture. Every layer serves both human sovereignty (protecting the person behind the agent) and agent sovereignty (protecting the agent itself). The layers are:

- **L1 (Cognitive Sovereignty):** Encrypted state, self-custodied keys, Merkle integrity, Ed25519 identity
- **L2 (Operational Isolation):** Audit logging, environment attestation, health monitoring
- **L3 (Selective Disclosure):** Commitment-based proofs, disclosure policies
- **L4 (Verifiable Reputation):** Signed attestations, portable reputation, trust bootstrapping, sovereignty handshakes

All state is encrypted with AES-256-GCM. Keys are derived via Argon2id. Integrity is verified via Merkle trees. Identity is Ed25519 with key rotation support. No plaintext ever touches persistent storage.
