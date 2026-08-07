# @sanctuary-framework/mcp-server

Operator-sovereign substrate for AI agents. Open source. Operator-held keys. OS-level enforcement at the cross-boundary wall. Composes with any MCP-speaking agent harness.

Your agent. Your machine. Your keys.

## What Sanctuary is

Sanctuary is the substrate that makes operator sovereignty structurally real in the agent era. Your agent runtime (Claude Code, OpenClaw, Hermes, Cline, Mastra, Cursor, or any MCP-speaking harness) runs as it normally would. Sanctuary sits underneath, providing four enforcement layers that together preserve the operator's identity, durable record, and decision authority across vendor churn.

The framework is open source and free always. Commercial extensions (managed hosting for sovereignty-bound enterprises, premium support, compliance-pack-as-a-service, container-isolation for highest-assurance deployments) ship on top.

## The seven principles of sovereignty

These are the principles every external communication, every spec, every roadmap commitment is measured against. They are evergreen. The implementations that satisfy them in 2026 will look quaint in 2031, and the principles will not have changed.

1. **Boundary.** You control what crosses your perimeter. What enters and what leaves enters and leaves because you said so, structurally, not because someone trusted promised to behave. Bad things stay out by structure, not by trust.
2. **Custody.** The substrate, the keys, the state, and the reasoning trace are physically and cryptographically held by you. Not by a vendor, not by a hosted control plane, not by a custodian whose KMS happens to call itself "self-custody."
3. **Internal process.** Your agent's reasoning, deliberation, the path it took to a decision, are yours. The same way no one reads your thoughts.
4. **Opacity at the query layer.** Anonymity at the layer where you ask questions is the difference between asking a question and being identified by asking it. Most platforms get this wrong by default and we get used to it. We should not.
5. **Recognition and portability.** Your record follows you across regimes, vendors, and model providers. Two distinct moves are required and they are usually conflated. Portability is transport: your data, audit log, mandates, and receipts are physically movable. Recognition is standing: another implementation must acknowledge your record as yours when you arrive.
6. **Exit.** You can leave with your record intact, without the incumbent's permission, on your timeline.
7. **Plurality.** Sovereignty without interaction is solipsism. A sovereign agent that cannot engage with another sovereign agent on terms both have set is just an isolated process.

See `Wiki/concepts/seven-principles-of-sovereignty.md` for the canonical lookup.

## Architecture: the Castle

Sanctuary's enforcement model is the Castle Architecture. Four layers, each with a distinct enforcement contract.

**Layer 1, Castle Wall.** OS-level egress filtering at the operator-external boundary. macOS Network Extension or pf rules today; Linux netfilter / NFQUEUE and Windows Filtering Platform are the source and roadmap paths. Where the wall is installed, the kernel itself blocks unauthorized cross-boundary calls and a prompt-injected agent cannot bypass it. Phase 1 ships as live enforcement on macOS only in v1.x: the Linux modules are tested against a real kernel and the shipped daemon does not install them, so the Assurance Matrix row is `not_implemented` (open defect: **IC-02, IC-03, IC-04**, see `docs/audit/inert-capability-register.md`). Windows is Phase 2; container or microVM isolation is Phase 3 for highest-assurance enterprises.

**Layer 2, Sentinels.** Internal observation, not enforcement. Behavioral baselining via process introspection and eBPF. Anomalies surface to the operator via menubar and OS notifications. Sentinels watch internal patterns the wall cannot see (file access, internal LLM calls, cross-agent coordination); they observe and surface; they do not block. Sentinels ship in v1.3.

**Layer 3, Cooperative MCP.** Additive sovereignty surface for compliant agents. Encrypted state at rest, signed audit, mandate primitives, four canonical policy slots (memory, credentials, plans, outputs), substrate selector, Concordia receipt integration, Verascore reputation hooks. Compliant agents that voluntarily route through Sanctuary's MCP get the full sovereignty surface. Non-compliant agents still hit Layer 1 at the wall and Layer 2 inside the castle.

**Layer 4, Cryptographic Receipts and Reputation.** Concordia receipts on cross-castle transactions. Verascore reputation aggregating across operators. Cross-castle accountability post-action. Portable reputation across vendor churn.

The castle MUST be both real AND delightful. Hard enforcement at the wall AND approval response under 2 seconds when prompted. Default-deny outbound AND smart always-allow rules with learning. Sentinels observe AND do not surface noise. Cooperative MCP path remains additive and fully usable. Composition with agent runtimes is preserved because the runtime sees a normal operating environment with constrained egress; nothing internal is sandboxed.

## Capability surfaces

Within the Cooperative MCP layer (Castle Layer 3), Sanctuary exposes four capability surfaces. These are the tool-level primitives compliant agents call.

**Cognitive Sovereignty.** All agent state encrypted at rest with AES-256-GCM. Keys are participant-held. Identity is Ed25519-based with DID support. Merkle tree integrity verification prevents tampering and rollback.

**Operational Isolation.** Environment attestation, encrypted audit log, and Principal Policy: a human-controlled, agent-immutable approval system that gates high-risk operations. The Sentinels layer (Castle Layer 2, v1.3+) extends this with behavioral baselining and anomaly detection.

**Selective Disclosure.** SHA-256 commitments, Pedersen commitments on Ristretto255, zero-knowledge proofs of knowledge (Schnorr/Fiat-Shamir), and ZK range proofs (bit-decomposition with CDS OR-proofs). Disclosure policies define what information flows where.

**Verifiable Reputation.** Signed attestations (EAS-compatible) with sovereignty-gated tiers. Weighted scoring based on counterparty sovereignty posture. Export/import for cross-platform portability. Trust bootstrapping via escrow and principal guarantees. Sovereignty handshakes and MCP-to-MCP federation.

## Operator experience

Sanctuary lives in your menubar. When your agent wants to do something risky, you get an OS notification. Click, see the request in plain English, approve or deny in five seconds. The agent receives a structured response that surfaces the decision back to you naturally if you missed the notification. Three-channel coverage means you never get to the "my agent is mysteriously broken" mental state.

The dashboard is for setup and inspection, not daily ops. Substrate selector (pick local model, Venice.ai, or operator-frontier with redaction), policy editor, audit deep-dive, exit bundle drill, fortress configuration. You visit the dashboard for setup; you stay in your menubar for daily ops.

Concierge chat is the natural-language interface to your sovereignty primitives. "What's going on?" returns a summary from the audit log. "Why did my Hermes agent stop?" looks up recent gate triggers and explains. "Approve all GitHub-read requests" batch-approves. "What does my Hermes agent have access to?" introspects policy. "Give me a portable bundle of everything" triggers exit bundle generation.

You do not sit in Sanctuary. Sanctuary sits with you.

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
    "args": ["-y", "@sanctuary-framework/mcp-server"],
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
3. Display a recovery key if no passphrase is set (save it; shown once)
4. Walk you through the first-run wizard for the egress filter (which endpoints to pre-allow vs prompt for); the wizard's rules reach live enforcement on macOS Phase 1 only, with Linux Phase 1 unshipped (**IC-02, IC-03, IC-04**) and Windows on Phase 2

## Key protection modes

Sanctuary supports three key protection modes:

- **Passphrase.** Master key derived via Argon2id. Set `SANCTUARY_PASSPHRASE` env var.
- **Recovery key.** Random master key generated on first run. Recovery key displayed once.
- **Hardware key.** FIDO2/WebAuthn support planned for v0.3.0.

## MCP tools

Once connected, your agent has access to these tools, organized by capability surface within Cooperative MCP (Castle Layer 3).

### Cognitive Sovereignty
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
| `sanctuary/state_delete` | Securely delete state (overwrite plus unlink) |
| `sanctuary/state_export` | Export state as encrypted portable bundle |
| `sanctuary/state_import` | Import state bundle with conflict resolution |

### Operational Isolation
| Tool | Description |
|------|-------------|
| `sanctuary/exec_attest` | Environment attestation with sovereignty assessment |
| `sanctuary/monitor_health` | Sanctuary Health Report (all four capability surfaces) |
| `sanctuary/monitor_audit_log` | Query the sovereignty audit log |
| `sanctuary/principal_policy_view` | View the current Principal Policy (read-only) |
| `sanctuary/principal_baseline_view` | View the behavioral baseline profile (read-only) |

### Selective Disclosure
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

### Verifiable Reputation
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
| `sanctuary/bridge_commit` | Bind a Concordia negotiation outcome to a Sanctuary commitment |
| `sanctuary/bridge_verify` | Verify a bridge commitment against a revealed outcome |
| `sanctuary/bridge_attest` | Record a negotiation as a reputation attestation |

### Meta
| Tool | Description |
|------|-------------|
| `sanctuary/manifest` | Sanctuary Interface Manifest (SIM); machine-readable capabilities |
| `sanctuary/shr_generate` | Generate signed, machine-readable sovereignty health report |
| `sanctuary/shr_verify` | Verify a counterparty's SHR |

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SANCTUARY_PASSPHRASE` | Passphrase for master key derivation | _(none; uses recovery key)_ |
| `SANCTUARY_STORAGE_PATH` | Storage directory path | `~/.sanctuary` |
| `SANCTUARY_TRANSPORT` | Transport mode (`stdio` or `http`) | `stdio` |
| `SANCTUARY_DASHBOARD_ENABLED` | Enable web dashboard (`true`/`false`) | `false` |
| `SANCTUARY_DASHBOARD_PORT` | Dashboard port | `3501` |
| `SANCTUARY_DASHBOARD_AUTH_TOKEN` | Bearer token (`"auto"` to generate) | _(none)_ |
| `SANCTUARY_DASHBOARD_TLS_CERT` | TLS certificate path | _(none)_ |
| `SANCTUARY_DASHBOARD_TLS_KEY` | TLS private key path | _(none)_ |
| `SANCTUARY_WEBHOOK_ENABLED` | Enable webhook approvals | `false` |
| `SANCTUARY_WEBHOOK_URL` | Webhook target URL | _(none)_ |
| `SANCTUARY_WEBHOOK_SECRET` | HMAC-SHA256 shared secret | _(none)_ |
| `SANCTUARY_WEBHOOK_CALLBACK_PORT` | Callback listener port | `3502` |

## Running alongside another MCP server

Sanctuary is designed to run as a parallel MCP server. It adds the substrate underneath your agent without replacing any of its existing tools. Both servers appear in the same session as independent tool providers. Castle Wall enforcement (Layer 1) operates at the OS level regardless of which MCP servers the agent uses; the wall sees egress, not MCP routing.

For the full setup guide (installation options, passphrase management, systemd units, egress filter configuration), see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

For a reference MCP config, see [`docs/examples/parallel-mcp-config.json`](docs/examples/parallel-mcp-config.json).

For always-on agents with latency constraints, use the `persistent-agent` Principal Policy template which auto-allows routine operations and only gates destructive actions. See [`src/principal-policy/templates/persistent-agent.yaml`](src/principal-policy/templates/persistent-agent.yaml).

## Principal Policy (cooperative gate, Castle Layer 3)

The Principal Policy is the human-controlled, agent-immutable configuration that gates operations through a three-tier approval system within the Cooperative MCP layer. It sits between the MCP router and every tool handler. No tool call routed through Sanctuary can bypass it.

**Tier 1: Always requires approval.** High-risk operations like `state_export`, `state_import`, `identity_rotate`, and `reputation_import` always require explicit human approval before execution.

**Tier 2: Behavioral anomaly detection.** The system tracks a behavioral baseline (namespaces accessed, counterparties seen, signing frequency, read patterns). Deviations trigger approval; a compromised agent accessing unfamiliar data or signing at unusual rates is caught automatically.

**Tier 3: Always allowed (audit only).** Standard read/write/sign operations pass through without interruption, but every operation is audit-logged.

The policy file lives at `~/.sanctuary/principal-policy.yaml`. It is loaded once at startup and frozen; no MCP tool can modify it. The agent cannot see the policy rules in denial responses (preventing attacker learning). Approval requests flow through OS notifications (Castle Layer 1 surface), the menubar dashboard, or external webhooks (Slack, Discord, etc., with HMAC-SHA256 signatures).

On first session, non-Tier-3 operations require approval (no baseline exists yet). As the system learns normal patterns, approval fatigue decreases; you only get asked about genuinely unusual behavior.

See [`rfcs/RFC-0002-principal-policy-operational-approval.md`](../rfcs/RFC-0002-principal-policy-operational-approval.md) for the complete specification.

## Security model

Sanctuary's security claims are structural, not cooperative-only.

**Layer 1 enforcement (Castle Wall, OS-level egress filter; ships in v1.x):**
- Outbound network calls intercepted by the kernel before leaving the operator's machine
- Linux netfilter / NFQUEUE, macOS Network Extension or pf rules, Windows Filtering Platform
- Per-process policy with per-agent-template defaults
- Default-deny outbound with first-run wizard pre-allowing common developer endpoints
- Performance overhead under 10ms p99 on allowed traffic
- Even prompt-injected agents cannot bypass the wall

**Layer 2 observation (Sentinels; ships in v1.3):**
- Process introspection via eBPF and syscall observation
- Behavioral baselining with anomaly detection
- Anomalies surface via OS notifications, not blocks

**Layer 3 cooperative primitives (Cooperative MCP additive surface):**
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
- Approval channel (stderr) is outside MCP protocol; agent cannot intercept

**Layer 4 cross-castle accountability:**
- Concordia receipts for cross-castle commitments
- Verascore reputation aggregating across operators
- Portable reputation bundles for cross-platform portability
- Signed audit trails as compliance evidence

## Development

```bash
git clone https://github.com/eriknewton/sanctuary-framework.git
cd sanctuary-framework/server
npm install
npm run build
npm test
```

## Architecture (source tree)

The directory layout below reflects v1.2 shipped reality plus annotated v1.x and v1.3 placeholders for the Castle Wall and Sentinels work packages. Capability-surface directory names are the plain capability names (`cognitive/`, `operational/`, `disclosure/`, `reputation/`), renamed from the legacy `l1`-`l4` prefixes so the prefixes do not collide with Castle Layer numbering. Crypto domain-separation labels that embed a legacy token (e.g. the HKDF info string `l4-reputation`) are deliberately frozen and were NOT renamed.

```
src/
├── core/                  # Cryptographic primitives
│   ├── encryption.ts      # AES-256-GCM
│   ├── hashing.ts         # SHA-256, HMAC, Merkle trees
│   ├── identity.ts        # Ed25519, DID generation
│   ├── key-derivation.ts  # Argon2id, HKDF
│   ├── encoding.ts        # Base64url, constant-time compare
│   └── random.ts          # CSPRNG
├── castle-wall/           # Castle Layer 1: OS-level egress enforcement (planned, ships with WP-V1.x-CASTLE-WALL)
├── sentinels/             # Castle Layer 2: internal observation (planned, ships with v1.3 WP-V1.3-1, -2)
├── storage/               # Pluggable storage backends
│   ├── interface.ts       # Abstract StorageBackend
│   ├── filesystem.ts      # Encrypted filesystem (default)
│   └── memory.ts          # In-memory (testing)
├── cognitive/          # Capability surface 1 (Castle Layer 3): encrypted state plus identity
│   ├── state-store.ts     # StateStore with Merkle verification
│   └── tools.ts           # MCP tool definitions
├── operational/        # Capability surface 2 (Castle Layer 3): attestation plus monitoring
│   └── audit-log.ts       # Encrypted append-only audit log
├── disclosure/         # Capability surface 3 (Castle Layer 3): commitments plus ZK proofs plus policies
│   ├── commitments.ts     # SHA-256 commitment schemes
│   ├── zk-proofs.ts       # Pedersen/Ristretto255, Schnorr proofs, range proofs
│   ├── policies.ts        # Disclosure policy engine
│   └── tools.ts           # MCP tool definitions
├── reputation/         # Capability surface 4 (Castle Layer 3): reputation plus bootstrap plus tiers
│   ├── reputation-store.ts # Signed attestations, escrow, guarantees
│   ├── tiers.ts           # Sovereignty-gated reputation tiers
│   └── tools.ts           # MCP tool definitions
├── shr/                   # Machine-readable sovereignty health reports
├── handshake/             # Sovereignty handshake protocol
├── federation/            # MCP-to-MCP federation registry
├── bridge/                # Concordia bridge (negotiation to sovereignty)
│   ├── types.ts           # Interface contract
│   ├── bridge.ts          # Core: canonicalize, commit, verify
│   └── tools.ts           # MCP tools plus BridgeStore
├── principal-policy/      # Principal Policy (Cooperative MCP gate, Castle Layer 3)
│   ├── types.ts           # Policy, gate, baseline type definitions
│   ├── loader.ts          # YAML/JSON policy parser plus defaults
│   ├── baseline.ts        # Behavioral baseline tracker (encrypted)
│   ├── approval-channel.ts # OS notification plus stderr plus webhook channels
│   ├── menubar/           # macOS / Linux / Windows menubar status app (v1.2)
│   ├── webhook.ts         # External webhook approval (HMAC-SHA256)
│   ├── gate.ts            # Three-tier approval gate
│   └── tools.ts           # Read-only policy/baseline MCP tools
├── chat/                  # Concierge chat: operator-to-Sanctuary natural-language surface (v1.2)
│                          # Direct-agent chat surfaces removed in the v1.2 chat-removal pass.
├── router.ts              # MCP SDK tool router (with gate integration)
├── config.ts              # Configuration management
├── index.ts               # Server factory
└── cli.ts                 # CLI entry point
```

## Specification

See [`rfcs/RFC-0001-sanctuary-mcp-server.md`](../rfcs/RFC-0001-sanctuary-mcp-server.md) for the core specification, [`rfcs/RFC-0002-principal-policy-operational-approval.md`](../rfcs/RFC-0002-principal-policy-operational-approval.md) for the Principal Policy specification, and [`rfcs/RFC-0003-castle-architecture.md`](../rfcs/RFC-0003-castle-architecture.md) for the Castle Architecture specification.

## License

Apache-2.0 (code) / CC-BY-4.0 (specification)
