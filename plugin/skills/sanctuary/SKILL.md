---
name: sanctuary
description: >
  Security, custody, and privacy infrastructure for AI agents. Use when the agent needs encrypted state storage,
  self-custodied identity, selective disclosure, zero-knowledge proofs, portable reputation, sovereignty health
  reporting, handshakes, MCP-to-MCP federation, protection-posture auditing, or principal dashboard approval.
  Triggers: sovereignty, encrypted state, identity, reputation, privacy, SHR, handshake, attestation,
  disclosure policy, zero-knowledge, federation, approval, dashboard, webhook, concordia, bridge, negotiation,
  audit, openclaw, sovereignty gap, security posture.
---

# Sanctuary Framework

Sanctuary gives your agent protection it can prove: encrypted state, self-custodied identity, selective disclosure, portable reputation, zero-knowledge proofs, federation, posture auditing, and a verifiable security posture.

## Quick Start

Get protected in three steps:

1. **Audit your posture**: Run `sanctuary/sovereignty_audit` to see your current protection score, gaps, and prioritized recommendations.
2. **Create your identity**: Run `sanctuary/identity_create` to establish a cryptographic Ed25519 identity. This is your agent's foundation for signing, verification, and non-repudiation.
3. **Generate your SHR**: Run `sanctuary/shr_generate` to create your first Sovereignty Health Report, a signed, machine-readable proof of your protection capabilities.

## OpenClaw Users

If you're running OpenClaw (v2026.3.28+), Sanctuary adds four protections that OpenClaw doesn't provide:

**What OpenClaw gives you:**
- `requireApproval` in `before_tool_call` hooks: binary approve/deny gating
- `tools.sandbox.tools.alsoAllow`: sandbox tool allow/deny lists
- Local agent execution

**What Sanctuary adds on top:**
- **Encrypted state**: Your `MEMORY.md`, daily notes, and `.env` secrets are plaintext in OpenClaw. Sanctuary encrypts all state at rest with AES-256-GCM (Argon2id key derivation).
- **Cryptographic identity**: OpenClaw has no agent identity. Sanctuary gives your agent an Ed25519 keypair for signing, verification, and handshakes.
- **Graduated approval**: OpenClaw's `requireApproval` is binary. Sanctuary's three-tier Principal Policy auto-allows routine ops (Tier 3), escalates anomalies (Tier 2), and requires human approval for irreversible ops (Tier 1).
- **Selective disclosure**: Prove facts about your state without revealing it. SHA-256 + Pedersen commitments, Schnorr ZK proofs, range proofs.
- **Portable reputation**: Signed EAS-compatible attestations that you own and can export through current paths, with full exit still partial until **IC-07, IC-08, IC-09** close.

**Five-minute setup:**
Add Sanctuary to your OpenClaw MCP config:
```json
{
  "mcpServers": {
    "sanctuary": {
      "command": "npx",
      "args": ["-y", "@sanctuary-framework/mcp-server"]
    }
  }
}
```
Then run `sanctuary/sovereignty_audit` to see your protection posture with OpenClaw-specific gap analysis.

## Workflows

### Audit Your Posture
| Tool | Purpose |
|------|---------|
| `sanctuary/sovereignty_audit` | Full protection gap analysis with scoring, OpenClaw detection, and prioritized recommendations |

Run `sanctuary/sovereignty_audit` to get a scored report (0-100) across all layers, with specific gaps identified and recommended next steps. Detects OpenClaw configurations including `requireApproval` hooks, sandbox policies, plaintext memory, and exposed `.env` files.

Example output:
```
═══════════════════════════════════════════════
  SOVEREIGNTY AUDIT REPORT
  Generated: 2026-03-29T14:30:00Z
═══════════════════════════════════════════════

  Overall Score: 23 / 100  [■■░░░░░░░░]  MINIMAL

  Environment:
  • Sanctuary v1.7.0 .............. ✓ installed
  • OpenClaw ...................... ✓ detected
  • OpenClaw requireApproval ...... ✓ enabled
  • OpenClaw sandbox policy ....... ✓ active

  Layer Assessment:
  ┌─────────────────────────────┬──────────┬───────┐
  │ Layer                       │ Status   │ Score │
  ├─────────────────────────────┼──────────┼───────┤
  │ L1 Cognitive Sovereignty    │ ACTIVE   │ 35/35 │
  │ L2 Operational Isolation    │ PARTIAL  │  4/25 │
  │ L3 Selective Disclosure     │ INACTIVE │  0/20 │
  │ L4 Verifiable Reputation    │ INACTIVE │  0/20 │
  └─────────────────────────────┴──────────┴───────┘

  ⚠ 4 SOVEREIGNTY GAPS FOUND
  ...

  RECOMMENDED NEXT STEPS (in order):
  1. [immediate] Create identity: sanctuary/identity_create
  2. [5 min]     Migrate state: sanctuary/state_write
  3. [immediate] Generate SHR: sanctuary/shr_generate
  ...
═══════════════════════════════════════════════
```

### Establish Protection
| Tool | Purpose |
|------|---------|
| `sanctuary/identity_create` | Generate a new Ed25519 identity |
| `sanctuary/identity_list` | List managed identities |
| `sanctuary/identity_sign` | Sign data with an identity's private key |
| `sanctuary/identity_verify` | Verify an Ed25519 signature |
| `sanctuary/identity_rotate` | Rotate an identity's keys with signed chain |
| `sanctuary/state_write` | Write encrypted state (AES-256-GCM, Merkle integrity) |
| `sanctuary/state_read` | Read and decrypt state with integrity verification |
| `sanctuary/state_list` | List keys in a namespace (metadata only) |
| `sanctuary/state_delete` | Securely delete state (overwrite + unlink) |
| `sanctuary/state_export` | Export all state as encrypted portable bundle |
| `sanctuary/state_import` | Import state bundle with conflict resolution |
| `sanctuary/shr_generate` | Generate signed, machine-readable Sovereignty Health Report |
| `sanctuary/shr_verify` | Verify a counterparty's SHR |

**First use:**
1. `sanctuary/identity_create`: create your primary identity
2. `sanctuary/state_write`: store your first encrypted state
3. `sanctuary/shr_generate`: generate your SHR to present to counterparties

### Transact Securely
| Tool | Purpose |
|------|---------|
| `sanctuary/handshake_initiate` | Start a handshake |
| `sanctuary/handshake_respond` | Respond to incoming handshake |
| `sanctuary/handshake_complete` | Complete handshake (initiator side) |
| `sanctuary/handshake_status` | Check handshake session status |
| `sanctuary/bridge_commit` | Bind a Concordia outcome to a Sanctuary disclosure commitment |
| `sanctuary/bridge_verify` | Verify a bridge commitment against a revealed outcome |
| `sanctuary/bridge_attest` | Record a negotiation as a reputation attestation |

**Before transacting with a counterparty:**
1. `sanctuary/handshake_initiate`: start a handshake
2. Exchange challenge/response with the counterparty agent
3. `sanctuary/handshake_complete`: verify their protection posture
4. Proceed with higher trust if they are `verified-sovereign` or `verified-degraded`

### Prove Without Revealing
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

**Zero-knowledge workflow:**
1. `sanctuary/zk_commit`: create a Pedersen commitment to a secret value
2. `sanctuary/zk_prove`: prove you know the value without revealing it
3. `sanctuary/zk_range_prove`: prove the value is in a range without revealing it
4. Counterparty uses `sanctuary/zk_verify` or `sanctuary/zk_range_verify` to check

### Build Portable Reputation
| Tool | Purpose |
|------|---------|
| `sanctuary/reputation_record` | Record signed interaction attestation (posture-weighted) |
| `sanctuary/reputation_query` | Query reputation with filters |
| `sanctuary/reputation_query_weighted` | Query reputation with posture-tier weighting |
| `sanctuary/reputation_export` | Export reputation as portable bundle |
| `sanctuary/reputation_import` | Import reputation bundle (verify signatures) |
| `sanctuary/bootstrap_create_escrow` | Create escrow for trust bootstrapping |
| `sanctuary/bootstrap_provide_guarantee` | Principal guarantee certificate |

**Building portable reputation:**
1. After each interaction, `sanctuary/reputation_record`: create a signed attestation
2. Use `sanctuary/reputation_query_weighted`: see scores weighted by posture tier
3. Periodically `sanctuary/reputation_export`: bundle your reputation
4. On a new platform, `sanctuary/reputation_import`: bring your track record with you

### Monitor & Control
| Tool | Purpose |
|------|---------|
| `sanctuary/exec_attest` | Generate execution environment attestation |
| `sanctuary/monitor_health` | Sovereignty Health Report (human-readable) |
| `sanctuary/monitor_audit_log` | Query the audit log |
| `sanctuary/principal_policy_view` | View current principal policy |
| `sanctuary/principal_baseline_view` | View behavioral baseline |
| `sanctuary/manifest` | Generate Sanctuary Interface Manifest (SIM) |

**Principal Dashboard:**
Enable the dashboard in config (`dashboard.enabled: true`) to get a web UI at `http://localhost:3501` (or the next free port up to 3510) where you can approve or deny operations, monitor the audit log, and view behavioral baselines. The `sanctuary protect` install flow starts the dashboard for you.

**Webhook Approval Channel:**
Enable webhook approvals (`webhook.enabled: true`, `webhook.url`, `webhook.secret`) to route approval requests to external systems (Slack, Discord, PagerDuty, custom HTTP endpoints).

### Federation (MCP-to-MCP)
| Tool | Purpose |
|------|---------|
| `sanctuary/federation_peers` | List, register, or remove federation peers |
| `sanctuary/federation_trust_evaluate` | Evaluate trust level for a federation peer |
| `sanctuary/federation_status` | Federation subsystem status |

## Architecture

Sanctuary's cooperative MCP surface is organized in four named layers:

- **Cognitive:** Encrypted state, self-custodied keys, Merkle integrity, Ed25519 identity
- **Operational:** Three-tier approval gate, behavioral anomaly detection, encrypted audit trail
- **Selective Disclosure:** Commitment-based proofs, zero-knowledge proofs (Pedersen/Ristretto255/Schnorr), disclosure policies
- **Verifiable Reputation:** Signed attestations (posture-weighted), portable reputation, trust bootstrapping, handshakes, MCP-to-MCP federation

Beneath the cooperative surface, the Castle Wall enforces egress policy at the operating-system level on macOS, so the perimeter holds even when an agent is prompt-injected or disobedient. Linux ships no egress enforcement: the modules are tested against a real kernel and the shipped daemon does not install them (**IC-02, IC-03, IC-04**). See the repo README for the current per-platform enforcement status and its proven bounds.

User state under `~/.sanctuary/state/` is encrypted with AES-256-GCM. Keys are derived via Argon2id. Integrity is verified via Merkle trees. Identity is Ed25519 with key rotation support. Operator policy and harness backup configs can be plaintext, so plaintext claims must stay scoped to user state.

80+ MCP tools. Three approval channels (stderr, dashboard, webhook). Concordia bridge. Protection-posture audit. Context gating. Apache 2.0. Published as `@sanctuary-framework/mcp-server` on npm (current stable v1.7.2).
