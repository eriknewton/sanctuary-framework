# @sanctuary-framework/mcp-server

Sovereignty infrastructure for agent harnesses, delivered as an MCP server.

Sanctuary gives agents (and their human principals) encrypted state, sovereign identity, selective disclosure, and portable reputation — without requiring any changes to the host harness.

## What it does

**L1 Cognitive Sovereignty** — All agent state is encrypted at rest with AES-256-GCM. Keys are participant-held. Identity is Ed25519-based with DID support. Merkle tree integrity verification prevents tampering and rollback.

**L2 Operational Isolation** — Environment attestation, health monitoring, encrypted audit log, and **Principal Policy** — a human-controlled, agent-immutable approval system that defends against prompt injection by gating high-risk operations.

**L3 Selective Disclosure** — SHA-256 commitments, Pedersen commitments on Ristretto255, zero-knowledge proofs of knowledge (Schnorr/Fiat-Shamir), and ZK range proofs (bit-decomposition with CDS OR-proofs). Disclosure policies define what information flows where.

**L4 Verifiable Reputation** — Signed attestations (EAS-compatible) with sovereignty-gated tiers. Weighted scoring based on counterparty sovereignty posture. Export/import for cross-platform portability. Trust bootstrapping via escrow and principal guarantees. Sovereignty handshakes and MCP-to-MCP federation.

## Quick start

### Install

```bash
npm install @sanctuary-framework/mcp-server
```

### Connect to Claude Code

Add to your Claude Code MCP configuration (`~/.claude/mcp_servers.json`):

```json
{
  "sanctuary": {
    "command": "npx",
    "args": ["@sanctuary-framework/mcp-server"],
    "env": {
      "SANCTUARY_PASSPHRASE": "your-passphrase-here"
    }
  }
}
```

Or run directly:

```bash
SANCTUARY_PASSPHRASE="your-passphrase" npx @sanctuary-framework/mcp-server
```

### First run

On first launch, Sanctuary will:

1. Derive a master encryption key from your passphrase (Argon2id)
2. Create the storage directory (`~/.sanctuary/`)
3. Display a recovery key if no passphrase is set (save it — shown once)

## Key protection modes

Sanctuary supports three key protection modes:

- **Passphrase** — Master key derived via Argon2id. Set `SANCTUARY_PASSPHRASE` env var.
- **Recovery key** — Random master key generated on first run. Recovery key displayed once.
- **Hardware key** — FIDO2/WebAuthn support planned for v0.3.0.

## MCP tools

Once connected, your agent has access to these tools:

### L1 — Cognitive Sovereignty
| Tool | Description |
|------|-------------|
| `sanctuary/identity_create` | Create a new Ed25519 identity |
| `sanctuary/identity_list` | List all managed identities |
| `sanctuary/identity_sign` | Sign data with an identity's private key |
| `sanctuary/identity_verify` | Verify an Ed25519 signature |
| `sanctuary/identity_rotate` | Rotate an identity's keys (signed chain) |
| `sanctuary/state_write` | Write encrypted state (signed, Merkle-verified) |
| `sanctuary/state_read` | Read and verify encrypted state |
| `sanctuary/state_list` | List keys in a namespace |
| `sanctuary/state_delete` | Securely delete state (overwrite + unlink) |
| `sanctuary/state_export` | Export state as encrypted portable bundle |
| `sanctuary/state_import` | Import state bundle with conflict resolution |

### L2 — Operational Isolation
| Tool | Description |
|------|-------------|
| `sanctuary/exec_attest` | Environment attestation with sovereignty assessment |
| `sanctuary/monitor_health` | Sanctuary Health Report (all four layers) |
| `sanctuary/monitor_audit_log` | Query the sovereignty audit log |
| `sanctuary/principal_policy_view` | View the current Principal Policy (read-only) |
| `sanctuary/principal_baseline_view` | View the behavioral baseline profile (read-only) |

### L3 — Selective Disclosure
| Tool | Description |
|------|-------------|
| `sanctuary/proof_commitment` | Create a SHA-256 cryptographic commitment |
| `sanctuary/proof_reveal` | Verify a commitment against revealed value |
| `sanctuary/disclosure_set_policy` | Define disclosure rules for different contexts |
| `sanctuary/disclosure_evaluate` | Evaluate a disclosure request against policy |
| `sanctuary/zk_commit` | Create a Pedersen commitment on Ristretto255 |
| `sanctuary/zk_prove` | ZK proof of knowledge of a commitment's opening |
| `sanctuary/zk_verify` | Verify a ZK proof of knowledge |
| `sanctuary/zk_range_prove` | Prove a value is in [min, max] without revealing it |
| `sanctuary/zk_range_verify` | Verify a ZK range proof |

### L4 — Verifiable Reputation
| Tool | Description |
|------|-------------|
| `sanctuary/reputation_record` | Record signed interaction attestation (sovereignty-weighted) |
| `sanctuary/reputation_query` | Query aggregated reputation data |
| `sanctuary/reputation_query_weighted` | Query with sovereignty-tier weighting |
| `sanctuary/reputation_export` | Export portable reputation bundle |
| `sanctuary/reputation_import` | Import bundle with signature verification |
| `sanctuary/bootstrap_create_escrow` | Create escrow for trust bootstrapping |
| `sanctuary/bootstrap_provide_guarantee` | Principal signs guarantee for agent |
| `sanctuary/handshake_initiate` | Start a sovereignty handshake |
| `sanctuary/handshake_respond` | Respond to incoming handshake |
| `sanctuary/handshake_complete` | Complete handshake (initiator side) |
| `sanctuary/handshake_status` | Check handshake session status |

### Federation (MCP-to-MCP)
| Tool | Description |
|------|-------------|
| `sanctuary/federation_peers` | List, register, or remove federation peers |
| `sanctuary/federation_trust_evaluate` | Evaluate trust level for a federation peer |
| `sanctuary/federation_status` | Federation subsystem status |

### Concordia Bridge
| Tool | Description |
|------|-------------|
| `sanctuary/bridge_commit` | Bind a Concordia negotiation outcome to a Sanctuary L3 commitment |
| `sanctuary/bridge_verify` | Verify a bridge commitment against a revealed outcome |
| `sanctuary/bridge_attest` | Record a negotiation as an L4 reputation attestation |

### Meta
| Tool | Description |
|------|-------------|
| `sanctuary/manifest` | Sanctuary Interface Manifest (SIM) — machine-readable capabilities |
| `sanctuary/shr_generate` | Generate signed, machine-readable sovereignty health report |
| `sanctuary/shr_verify` | Verify a counterparty's SHR |

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SANCTUARY_PASSPHRASE` | Passphrase for master key derivation | _(none — uses recovery key)_ |
| `SANCTUARY_STORAGE_PATH` | Storage directory path | `~/.sanctuary` |
| `SANCTUARY_TRANSPORT` | Transport mode (`stdio` or `http`) | `stdio` |
| `SANCTUARY_DASHBOARD_ENABLED` | Enable web dashboard (`true`/`false`) | `false` |
| `SANCTUARY_DASHBOARD_PORT` | Dashboard port | `3501` |
| `SANCTUARY_DASHBOARD_AUTH_TOKEN` | Bearer token (`"auto"` to generate) | — |
| `SANCTUARY_DASHBOARD_TLS_CERT` | TLS certificate path | — |
| `SANCTUARY_DASHBOARD_TLS_KEY` | TLS private key path | — |
| `SANCTUARY_WEBHOOK_ENABLED` | Enable webhook approvals | `false` |
| `SANCTUARY_WEBHOOK_URL` | Webhook target URL | — |
| `SANCTUARY_WEBHOOK_SECRET` | HMAC-SHA256 shared secret | — |
| `SANCTUARY_WEBHOOK_CALLBACK_PORT` | Callback listener port | `3502` |

## Principal Policy (prompt injection defense)

The Principal Policy is the human-controlled, agent-immutable configuration that gates operations through a three-tier approval system. It sits between the MCP router and every tool handler — no tool call can bypass it.

**Tier 1 — Always requires approval:** High-risk operations like `state_export`, `state_import`, `identity_rotate`, and `reputation_import` always require explicit human approval before execution.

**Tier 2 — Behavioral anomaly detection:** The system tracks a behavioral baseline (namespaces accessed, counterparties seen, signing frequency, read patterns). Deviations trigger approval — a compromised agent accessing unfamiliar data or signing at unusual rates is caught automatically.

**Tier 3 — Always allowed (audit only):** Standard read/write/sign operations pass through without interruption, but every operation is audit-logged.

The policy file lives at `~/.sanctuary/principal-policy.yaml`. It is loaded once at startup and frozen — no MCP tool can modify it. The agent cannot see the policy rules in denial responses (preventing attacker learning). Approval requests flow through out-of-band channels the agent cannot access. Three channels are available: **stderr** (default, auto-deny), **dashboard** (browser-based web UI with real-time SSE, optional bearer token auth and TLS), and **webhook** (POST to external endpoints like Slack or Discord with HMAC-SHA256 signatures).

On first session, non-Tier-3 operations require approval (no baseline exists yet). As the system learns normal patterns, approval fatigue decreases — you only get asked about genuinely unusual behavior.

See [`rfcs/RFC-0002-principal-policy-operational-approval.md`](../rfcs/RFC-0002-principal-policy-operational-approval.md) for the complete specification.

## Security model

- AES-256-GCM authenticated encryption with unique 12-byte IVs (NIST SP 800-38D)
- Ed25519 keypairs for identity and signing
- Argon2id key derivation (m=64MB, t=3, p=4) for passphrase protection
- HKDF-SHA256 for namespace and purpose key derivation
- Merkle trees for namespace integrity verification
- 3-pass secure deletion (random overwrite before unlink)
- Private keys never appear in any MCP tool response
- Monotonic version numbers prevent state rollback
- Principal Policy gates every tool call (three-tier approval)
- Behavioral baseline detects anomalous agent behavior
- Approval channel (stderr) is outside MCP protocol — agent cannot intercept

## Development

```bash
git clone https://github.com/eriknewton/sanctuary-framework.git
cd sanctuary-framework/server
npm install
npm run build
npm test
```

## Architecture

```
src/
├── core/                  # Cryptographic primitives
│   ├── encryption.ts      # AES-256-GCM
│   ├── hashing.ts         # SHA-256, HMAC, Merkle trees
│   ├── identity.ts        # Ed25519, DID generation
│   ├── key-derivation.ts  # Argon2id, HKDF
│   ├── encoding.ts        # Base64url, constant-time compare
│   └── random.ts          # CSPRNG
├── storage/               # Pluggable storage backends
│   ├── interface.ts       # Abstract StorageBackend
│   ├── filesystem.ts      # Encrypted filesystem (default)
│   └── memory.ts          # In-memory (testing)
├── l1-cognitive/          # L1: Encrypted state + identity
│   ├── state-store.ts     # StateStore with Merkle verification
│   └── tools.ts           # MCP tool definitions
├── l2-operational/        # L2: Attestation + monitoring
│   └── audit-log.ts       # Encrypted append-only audit log
├── l3-disclosure/         # L3: Commitments + ZK proofs + policies
│   ├── commitments.ts     # SHA-256 commitment schemes
│   ├── zk-proofs.ts       # Pedersen/Ristretto255, Schnorr proofs, range proofs
│   ├── policies.ts        # Disclosure policy engine
│   └── tools.ts           # MCP tool definitions
├── l4-reputation/         # L4: Reputation + bootstrap + tiers
│   ├── reputation-store.ts # Signed attestations, escrow, guarantees
│   ├── tiers.ts           # Sovereignty-gated reputation tiers
│   └── tools.ts           # MCP tool definitions
├── shr/                   # Machine-readable sovereignty health reports
├── handshake/             # Sovereignty handshake protocol
├── federation/            # MCP-to-MCP federation registry
├── bridge/                # Concordia bridge (negotiation → sovereignty)
│   ├── types.ts           # Interface contract (ConcordiaOutcome, BridgeCommitment)
│   ├── bridge.ts          # Core: canonicalize, commit, verify
│   └── tools.ts           # MCP tools + BridgeStore
├── principal-policy/      # Principal Policy (prompt injection defense)
│   ├── types.ts           # Policy, gate, baseline type definitions
│   ├── loader.ts          # YAML/JSON policy parser + defaults
│   ├── baseline.ts        # Behavioral baseline tracker (encrypted)
│   ├── approval-channel.ts # Stderr + callback approval channels
│   ├── dashboard.ts       # Browser-based approval UI (SSE, auth, TLS)
│   ├── dashboard-html.ts  # Embedded HTML/CSS/JS template
│   ├── webhook.ts         # External webhook approval (HMAC-SHA256)
│   ├── gate.ts            # Three-tier approval gate
│   └── tools.ts           # Read-only policy/baseline MCP tools
├── router.ts              # MCP SDK tool router (with gate integration)
├── config.ts              # Configuration management
├── index.ts               # Server factory
└── cli.ts                 # CLI entry point
```

## Specification

See [`rfcs/RFC-0001-sanctuary-mcp-server.md`](../rfcs/RFC-0001-sanctuary-mcp-server.md) for the core specification and [`rfcs/RFC-0002-principal-policy-operational-approval.md`](../rfcs/RFC-0002-principal-policy-operational-approval.md) for the Principal Policy specification.

## License

Apache-2.0 (code) / CC-BY-4.0 (specification)
