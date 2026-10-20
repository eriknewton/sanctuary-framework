---
name: sanctuary
description: >
  Security, custody, and privacy infrastructure for AI agents: open source, keys the operator holds, a hash-chained
  audit record. Use when the agent needs encrypted state storage, self-custodied identity, selective disclosure,
  zero-knowledge proofs, portable reputation, sovereignty health reporting, handshakes, MCP-to-MCP federation,
  protection-posture auditing, or principal dashboard approval. Bounds: these tools are the cooperative MCP
  surface (Charter); operating-system egress enforcement is a separate arming step, live on macOS,
  proven on Linux for Ubuntu 24.04 (x86-64) only with a separate package (not in this npm server), Windows roadmapped; every claim traces to the Assurance Matrix.
  Triggers: sovereignty, encrypted state, identity, reputation, privacy, SHR, handshake, attestation,
  disclosure policy, zero-knowledge, federation, approval, dashboard, webhook, concordia, bridge, negotiation,
  audit, openclaw, sovereignty gap, security posture.
---

# Sanctuary Framework

Sanctuary gives your agent protection it can prove: encrypted state, self-custodied identity, selective disclosure, portable reputation, zero-knowledge proofs, federation, posture auditing, and a verifiable security posture. The tools in this skill are the Charter layer, the cooperative MCP surface. The Castle Wall (kernel-level egress enforcement) is armed separately and is live on macOS; on Linux it is proven for Ubuntu 24.04 (x86-64) only; Windows is roadmapped. Every capability claim traces to a row in the [Assurance Matrix](https://github.com/eriknewton/sanctuary-framework/blob/main/ASSURANCE_MATRIX.md).

## Install, verify, uninstall

```bash
npx -y @sanctuary-framework/mcp-server@1.8.4 protect --claude-code --no-open --no-dashboard
npx -y @sanctuary-framework/mcp-server@1.8.4 doctor --json
npx -y @sanctuary-framework/mcp-server@1.8.4 uninstall
```

`-y` skips npm's install prompt; without it npx asks before fetching the package in a terminal. `--no-dashboard` skips the per-call dashboard, which otherwise serves in the foreground until you stop it; wrap still persists the agent record so a separately-running `sanctuary dashboard` (or a later wrap) sees the harness; start it later with `sanctuary dashboard`. `--no-open` runs headless: it skips opening the dashboard in a browser and switches custody confirmation to the non-interactive mode `protect` already uses whenever stdin is not a terminal.

Substitute `--openclaw`, `--hermes`, `--cursor`, `--cline`, `--mastra`, or `--wrap <path-to-config>` for the harness you run. With `protect`, the MCP server entries in the config are rewritten to point at Sanctuary. The harness's own built-in tools are not MCP calls and are not touched. The rewrite is tested on representative harness paths and is not proven for every harness version (Assurance Matrix, Agent wrapping). A plain `npx -y @sanctuary-framework/mcp-server@1.8.4` entry beside other MCP servers starts the server but does not gate calls to those servers. `doctor --json` is read-only. `uninstall` keeps keys, state, and the audit log; `protect --unwrap` restores the original harness configuration. The passphrase stays in the platform credential store: never put a passphrase or recovery key in a harness configuration, never read staged recovery material, and never ask the operator to paste it into chat.

## Quick Start

Get protected in three steps:

1. **Audit your posture**: Run `sanctuary/sovereignty_audit` to see your current protection score, gaps, and prioritized recommendations.
2. **Create your identity**: Run `sanctuary/identity_create` to establish a cryptographic Ed25519 identity. This is your agent's foundation for signing, verification, and non-repudiation.
3. **Generate your SHR**: Run `sanctuary/shr_generate` to create your first Sovereignty Health Report, a signed, machine-readable proof of your protection capabilities.

## OpenClaw Users

If you're running OpenClaw, Sanctuary adds protections that OpenClaw doesn't provide:

**What OpenClaw gives you:**
- `requireApproval` in `before_tool_call` hooks: binary approve/deny gating
- `tools.sandbox.tools.alsoAllow`: sandbox tool allow/deny lists
- Local agent execution

**What Sanctuary adds on top:**
- **Encrypted state**: Your `MEMORY.md`, daily notes, and `.env` secrets are plaintext in OpenClaw. Sanctuary encrypts agent state at rest with AES-256-GCM (Argon2id key derivation).
- **Cryptographic identity**: OpenClaw has no agent identity. Sanctuary gives your agent an Ed25519 keypair for signing, verification, and handshakes.
- **Graduated approval**: OpenClaw's `requireApproval` is binary. Sanctuary's three-tier Principal Policy auto-allows routine ops (Tier 3), escalates anomalies (Tier 2), and requires human approval for irreversible ops (Tier 1).
- **Selective disclosure**: Prove facts about your state without revealing it. SHA-256 + Pedersen commitments, Schnorr ZK proofs, range proofs.
- **Portable reputation**: Signed EAS-compatible attestations that you own and can export through current paths, with full exit still partial until **IC-07, IC-08, IC-09** close.

**One-command setup:**

```bash
npx -y @sanctuary-framework/mcp-server@1.8.4 protect --openclaw --no-open --no-dashboard
```

Then run `sanctuary/sovereignty_audit` to see your protection posture with OpenClaw-specific gap analysis.

## Workflows

### Audit Your Posture
| Tool | Purpose |
|------|---------|
| `sanctuary/sovereignty_audit` | Full protection gap analysis with scoring, OpenClaw detection, and prioritized recommendations |

Run `sanctuary/sovereignty_audit` to get a scored report (0-100) across security, isolation, and privacy, with specific gaps identified and recommended next steps. It reads your live configuration and profile: optional features that default off (context gating, zero-knowledge proofs) count toward the score only once you enable them, so a fresh install scores below the top verdict and the report names the steps to close each gap. It detects OpenClaw configurations including `requireApproval` hooks, sandbox policies, plaintext memory, and exposed `.env` files.

### Sovereign memory (Rung 1)

| Tool | Purpose |
|------|---------|
| `sanctuary/memory_insert` | Store a memory record in the encrypted vault (Tier 1) |
| `sanctuary/memory_search` | Find records by content. |
| `sanctuary/memory_get` | Read a record back byte-faithfully (decrypts and re-verifies the stored content hash; proves exact content, not signer data). |
| `sanctuary/sdw_memory_provenance` | Prove verified provenance for a record: per-writer signing status and the fortress-recorded origin/admission bindings (requires operator approval under the default policy (not named in a policy tier; the gate's safe default)). |

First-use proof and restart persistence run through these existing
policy-enforcing tools, never a parallel CLI: `memory_insert` → `memory_search`
→ `memory_get` (proves exact content), then `sdw_memory_provenance` to confirm
the record's verified provenance. On a
second host the fortress opens from that host's exact-fortress stored credential
with no secret typed. See [Rung 1: fresh-host onboarding](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/rung1-fresh-host.md).

For a copied fortress with no local stored credential, or a lost passphrase,
lead with the private hidden-prompt recovery path:
`sanctuary reset-passphrase --mode recovery-key --fortress <path>`. It preserves
the master, identities, audit history, and memory. Never recommend nuke while a
human-held recovery key or another configured recovery factor can work; nuke is
the destructive last resort.

### Establish Protection
| Tool | Purpose |
|------|---------|
| `sanctuary/identity_create` | Generate a new Ed25519 identity |
| `sanctuary/identity_list` | List managed identities |
| `sanctuary/identity_sign` | Sign data with an identity's private key (Tier 1) |
| `sanctuary/identity_verify` | Verify an Ed25519 signature |
| `sanctuary/identity_rotate` | Rotate an identity's keys with signed chain (Tier 1) |
| `sanctuary/state_write` | Write encrypted state (AES-256-GCM, Merkle integrity) |
| `sanctuary/state_read` | Read and decrypt state with integrity verification |
| `sanctuary/state_list` | List keys in a namespace (metadata only) |
| `sanctuary/state_delete` | Securely delete state (overwrite + unlink; Tier 1) |
| `sanctuary/state_export` | Export all state as encrypted portable bundle (Tier 1) |
| `sanctuary/state_import` | Import state bundle with conflict resolution (Tier 1) |
| `sanctuary/shr_generate` | Generate signed, machine-readable Sovereignty Health Report |
| `sanctuary/shr_verify` | Verify a counterparty's SHR |

Tier 1 marks operations the shipped default Principal Policy (`DEFAULT_POLICY`, applied when no policy file exists) sends to a human. The operator's own policy file decides.

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
| `sanctuary/reputation_export` | Export reputation as portable bundle (Tier 1) |
| `sanctuary/reputation_import` | Import reputation bundle (verify signatures; Tier 1) |
| `sanctuary/reputation_publish` | Publish a signed sovereignty report to Verascore (the report leaves this machine; always Tier 1 from 1.9.0, auto-allowed by default before 1.9.0) |
| `sanctuary/bootstrap_create_escrow` | Create escrow for trust bootstrapping |
| `sanctuary/bootstrap_provide_guarantee` | Principal guarantee certificate (Tier 1) |

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
| `sanctuary/principal_policy_view` | View current principal policy (Tier 1) |
| `sanctuary/principal_baseline_view` | View behavioral baseline (Tier 1) |
| `sanctuary/manifest` | Generate Sanctuary Interface Manifest (SIM) |

**Principal Dashboard:**
Enable the dashboard in config (`dashboard.enabled: true`) to get a web UI at `http://localhost:3501` (or the next free port, trying up to twenty ports from 3501) where you can approve or deny operations, monitor the audit log, and view behavioral baselines. The `sanctuary protect` install flow starts the dashboard for you unless you pass `--no-dashboard`.

**Webhook Approval Channel:**
Enable webhook approvals (`webhook.enabled: true`, `webhook.url`, `webhook.secret`) to route approval requests to external systems (Slack, Discord, PagerDuty, custom HTTP endpoints).

### Federation (MCP-to-MCP)
| Tool | Purpose |
|------|---------|
| `sanctuary/federation_peers` | List, register, or remove federation peers |
| `sanctuary/federation_trust_evaluate` | Evaluate trust level for a federation peer |
| `sanctuary/federation_status` | Federation subsystem status |

## Architecture

Sanctuary ships as five named mechanisms: **Castle Wall** (the perimeter: OS-level egress enforcement), **Sentinels** (observation, not enforcement), **Charter** (the cooperative MCP surface this skill uses), **Heralds** (recognition by other sovereigns: Concordia receipts and Verascore reputation, both optional), and **Mantle** (install-time binding of the fortress to the operator's machine).

Within Charter, the tools are grouped in four capability surfaces:

- **Cognitive Sovereignty:** Encrypted state, self-custodied keys, Merkle integrity, Ed25519 identity
- **Operational Isolation:** Three-tier approval gate, behavioral anomaly detection, encrypted audit trail
- **Selective Disclosure:** Commitment-based proofs, zero-knowledge proofs (Pedersen/Ristretto255/Schnorr), disclosure policies
- **Verifiable Reputation:** Signed attestations (posture-weighted), portable reputation, trust bootstrapping, handshakes, MCP-to-MCP federation

Beneath the cooperative surface, on macOS, the Castle Wall enforces a signed operator policy with a clean per-uid allow/deny demonstration that survives attended reboot cycles, so the perimeter holds even when an agent is prompt-injected or disobedient; that proof is one host and one OS version, not an audited per-rule, per-flow trail. On Ubuntu 24.04 (x86-64), a fresh install of the shipped package enforces a signed operator policy per user account: blocked destinations stay blocked and allowed ones connect, through five reboots, on three fresh servers, with the evidence checked by two independent reviewers. Fault-injection witnesses, a real-agent harness, and every other distribution or architecture remain unproven. See the [repository README](https://github.com/eriknewton/sanctuary-framework#readme) for the current per-platform enforcement status and its proven bounds.

User state under `~/.sanctuary/state/` is encrypted with AES-256-GCM. Keys are derived via Argon2id. Integrity is verified via Merkle trees. Identity is Ed25519 with key rotation support. Operator policy and harness backup configs can be plaintext, so plaintext claims must stay scoped to user state.

111 registered MCP tools (measured 2026-10-06). Three approval channels (stderr, dashboard, webhook). Concordia bridge. Protection-posture audit. Context gating. Apache 2.0. The current prerelease is v1.8.6-rc.5 on the npm `next` tag; the current published stable version on npm is `@sanctuary-framework/mcp-server@1.8.4`.
