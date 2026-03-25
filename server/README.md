# @sanctuary-framework/mcp-server

Sovereignty infrastructure for agent harnesses, delivered as an MCP server.

Sanctuary gives agents (and their human principals) encrypted state, sovereign identity, selective disclosure, and portable reputation — without requiring any changes to the host harness.

## What it does

**L1 Cognitive Sovereignty** — All agent state is encrypted at rest with AES-256-GCM. Keys are participant-held. Identity is Ed25519-based with DID support. Merkle tree integrity verification prevents tampering and rollback.

**L2 Operational Isolation** — Environment attestation, health monitoring, and an encrypted audit log of all sovereignty operations.

**L3 Selective Disclosure** — Cryptographic commitments let an agent prove a claim without revealing it. Disclosure policies define what information flows where, evaluated per-field against context-specific rules.

**L4 Verifiable Reputation** — Signed attestations of interaction outcomes (EAS-compatible). Queryable aggregates. Export/import for cross-platform portability. Trust bootstrapping via escrow and principal guarantees.

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

### L3 — Selective Disclosure
| Tool | Description |
|------|-------------|
| `sanctuary/proof_commitment` | Create a cryptographic commitment to a value |
| `sanctuary/proof_reveal` | Verify a commitment against revealed value |
| `sanctuary/disclosure_set_policy` | Define disclosure rules for different contexts |
| `sanctuary/disclosure_evaluate` | Evaluate a disclosure request against policy |

### L4 — Verifiable Reputation
| Tool | Description |
|------|-------------|
| `sanctuary/reputation_record` | Record signed interaction attestation |
| `sanctuary/reputation_query` | Query aggregated reputation data |
| `sanctuary/reputation_export` | Export portable reputation bundle |
| `sanctuary/reputation_import` | Import bundle with signature verification |
| `sanctuary/bootstrap_create_escrow` | Create escrow for trust bootstrapping |
| `sanctuary/bootstrap_provide_guarantee` | Principal signs guarantee for agent |

### Meta
| Tool | Description |
|------|-------------|
| `sanctuary/manifest` | Sanctuary Interface Manifest (SIM) — machine-readable capabilities |

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SANCTUARY_PASSPHRASE` | Passphrase for master key derivation | _(none — uses recovery key)_ |
| `SANCTUARY_STORAGE_PATH` | Storage directory path | `~/.sanctuary` |
| `SANCTUARY_TRANSPORT` | Transport mode (`stdio` or `http`) | `stdio` |

## Security model

- AES-256-GCM authenticated encryption with unique 12-byte IVs (NIST SP 800-38D)
- Ed25519 keypairs for identity and signing
- Argon2id key derivation (m=64MB, t=3, p=4) for passphrase protection
- HKDF-SHA256 for namespace and purpose key derivation
- Merkle trees for namespace integrity verification
- 3-pass secure deletion (random overwrite before unlink)
- Private keys never appear in any MCP tool response
- Monotonic version numbers prevent state rollback

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
├── l3-disclosure/         # L3: Commitments + policies
│   ├── commitments.ts     # SHA-256 commitment schemes
│   ├── policies.ts        # Disclosure policy engine
│   └── tools.ts           # MCP tool definitions
├── l4-reputation/         # L4: Reputation + bootstrap
│   ├── reputation-store.ts # Signed attestations, escrow, guarantees
│   └── tools.ts           # MCP tool definitions
├── router.ts              # MCP SDK tool router
├── config.ts              # Configuration management
├── index.ts               # Server factory
└── cli.ts                 # CLI entry point
```

## Specification

See [`rfcs/RFC-0001-sanctuary-mcp-server.md`](../rfcs/RFC-0001-sanctuary-mcp-server.md) for the complete technical specification.

## License

Apache-2.0 (code) / CC-BY-4.0 (specification)
