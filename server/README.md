# @sanctuary-framework/mcp-server

**Your agent will know you better than you know yourself. Make sure that data stays between you.**

An AI agent running on your machine can do anything your account can do. It holds your credentials, reads your files, and talks to the whole internet, and a single poisoned web page can turn that into exfiltration. Every sandbox on offer today is one the agent, or its vendor, chooses to run inside. That is not a wall. That is a request.

Sanctuary is the wall under the agent, imposed by the operating system under a policy you sign, on a patched host, and it does not depend on the agent's cooperation. The keys never leave hardware you control. What the agent did is written to a hash-chained record you can read. No vendor, including us, sits in the path or can decrypt your state. It works with the harness you already run: Claude Code, Cursor, Hermes, OpenClaw, Cline, Mastra (fixture-tested only; no live Mastra-agent drill is recorded), or any MCP-compatible agent, on your own machine today, any number of wrapped harnesses behind one persistent dashboard; the fleet console and operator-cloud deployment are roadmapped (see [Deployment modes](https://github.com/eriknewton/sanctuary-framework/blob/main/README.md#deployment-modes)).

## What is proven, and what is not

Every capability claim in this repository traces to a row in the [Assurance Matrix](https://github.com/eriknewton/sanctuary-framework/blob/main/ASSURANCE_MATRIX.md), and a row reads `proven` only when a captured drill on the platform that matters says so. A green test suite is not a claim. Read the matrix before you believe anything below.

| What you get | Status today |
|---|---|
| **The wall.** Outbound traffic from a wrapped agent is allowed or denied below the agent, per operator policy, per agent account | **macOS: proven, on a patched host.** A signed operator policy with a clean per-uid allow/deny demonstration that survives attended reboot cycles. Not an audited per-rule, per-flow trail. **Linux: proven on Ubuntu 24.04 (x86-64) only, on a patched host.** On Ubuntu 24.04 (x86-64), on a patched host, a fresh install of the shipped package enforces a signed operator policy per user account: blocked destinations stay blocked and allowed ones connect, through five reboots, on three fresh servers, with the evidence checked by two independent reviewers. Fault-injection witnesses, a real-agent harness, and every other distribution or architecture remain unproven. **Windows: roadmapped.** |
| **Custody.** Keys and state under your passphrase, on your hardware | **Proven.** Ed25519 identity, Argon2id unlock, per-purpose derived subkeys, encrypted state at rest. The passphrase lives in the macOS Keychain or Linux Secret Service and generation fails closed without it. |
| **The gate.** Policy you set, frozen at startup, the agent cannot read or infer; three approval tiers with a human on the irreversible ones | **Proven.** Cooperative gates on every MCP call Sanctuary executes or forwards. The wall is what makes the gate more than a request. |
| **The record.** Append-only, hash-chained audit of what the agent did | **Partial.** The chain is live; production call sites sign checkpoints when the fortress holds an identity. Fortresses with no identity and the root daemon split audit store write honest unsigned checkpoints. The row stays partial pending the IC-05 external-verifier drill and the remaining local tamper-evidence follow-up. |
| **Exit.** Keys, state, memory and reputation leave with you | **Partial.** Export and import ship; three exit-bundle gaps are open (IC-07, IC-08, IC-09). |

## Install, verify, uninstall

Three commands, run in order. Substitute `--openclaw`, `--hermes`, `--cursor`, `--cline`, `--mastra`, or `--wrap <path-to-config>` for the harness you run.

```bash
npx -y @sanctuary-framework/mcp-server protect --claude-code --no-open --no-dashboard
npx -y @sanctuary-framework/mcp-server doctor --json
npx -y @sanctuary-framework/mcp-server uninstall
```

`-y` skips npm's install prompt; without it npx asks before fetching the package in a terminal. `--no-dashboard` skips the per-call dashboard, which otherwise serves in the foreground until you stop it; wrap still persists the agent record so a separately-running `sanctuary dashboard` (or a later wrap) sees the harness; start it later with `sanctuary dashboard`. `--no-open` runs headless: it skips opening the dashboard in a browser and switches custody confirmation to the non-interactive mode `protect` already uses whenever stdin is not a terminal.

`protect` backs up the harness configuration to `~/.sanctuary/backup/`, rewrites it (the MCP server entries in the config are rewritten to point at Sanctuary; the harness's own built-in tools are not MCP calls and are not touched; the rewrite is tested on representative harness paths and is not proven for every harness version, per the Assurance Matrix "Agent wrapping" row), generates a passphrase that lives only in the macOS Keychain or Linux Secret Service, and, without `--no-dashboard`, starts the Sovereignty Dashboard on `http://localhost:3501` (or the next free port, trying up to twenty ports from 3501). `doctor --json` is a read-only diagnostic of the state directory, identity, principal policy, audit-chain integrity, runtime versions, and Castle Wall status. `uninstall` removes the installed enforcement footprint and preserves the fortress state, keys, passphrase custody, recovery material, and audit log; it reports any residue that needs sudo, the Castle Wall host app, or a reboot. `protect --unwrap` restores the original harness configuration from the backup. Every verb and flag in this section is on v1.8.4, the npm `latest` channel.

That one command puts the keys, audit trail, and policy gates around the agent you already use, and the dashboard too unless you pass `--no-dashboard`. The operating-system wall is a separate privileged arming step on macOS through the signed app and extension path; see the [Castle Wall macOS install and arm guide](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/castle-wall-macos-install.md).

## The secret boundary

The passphrase stays in the platform credential store. Do not put a passphrase or recovery key in a harness configuration or an environment block. If you are an agent installing on an operator's behalf, never read the staged recovery file, run `sanctuary export-passphrase`, capture secret output, or ask the operator to paste recovery material into chat; `--agent-guided` stages the recovery key outside the fortress without printing it. There is no `SANCTUARY_PASSPHRASE` snippet on this page on purpose: a passphrase written into harness configuration is readable by the very agent the fortress is meant to protect against.

## Platform bounds

Every enforcement sentence below assumes a patched host. On macOS, the Castle Wall enforces a signed operator policy with a clean per-uid allow/deny demonstration that survives attended reboot cycles, captured on one host and one OS version with a Dev-ID-signed and notarized binary; it is not an audited per-rule, per-flow trail. On Ubuntu 24.04 (x86-64), on a patched host, a fresh install of the shipped package enforces a signed operator policy per user account: blocked destinations stay blocked and allowed ones connect, through five reboots, on three fresh servers, with the evidence checked by two independent reviewers. Fault-injection witnesses, a real-agent harness, and every other distribution or architecture remain unproven. Windows is roadmapped. This npm package installs the cooperative surface (keys, state, gates, record, dashboard) on every platform it supports; the wall is armed separately, through the signed macOS app and extension or the Linux package the matrix row cites.

## Evidence

- [ASSURANCE_MATRIX.md](https://github.com/eriknewton/sanctuary-framework/blob/main/ASSURANCE_MATRIX.md): every claim, its platform, its evidence, its gap, and the next proof owed.
- macOS wall drills: [allow/deny](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/audit/castle-wall-macos-allow-deny-drill-2026-06-11.md), [boot survival](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/audit/castle-wall-macos-boot-survival-redrill-2026-06-22.md), [full scope](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/audit/castle-wall-macos-fullscope-redrill-2026-06-20.md).
- Linux wall drill: [install-grade drill, 2026-10-04](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/audit/castle-wall-linux-install-grade-drill-2026-10-04.md).
- Releases: the current stable release is [v1.8.4](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/releases/v1.8.4.md) on the npm `latest` channel; the opt-in preview is [v1.8.6-rc.5](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/releases/v1.8.6.md) on `next`, and it does not widen any capability claim. Full history in [CHANGELOG.md](https://github.com/eriknewton/sanctuary-framework/blob/main/CHANGELOG.md).
- Vulnerability reports: [SECURITY.md](https://github.com/eriknewton/sanctuary-framework/blob/main/SECURITY.md).

## For AI coding agents installing on behalf of an operator

Do not translate the manual Castle Wall reference into a pile of shell commands. Use the resumable observed-state contract:

```bash
npx -y @sanctuary-framework/mcp-server install --profile memory --harness claude-code --json
```

For the full macOS sovereignty surface, use Hermes:

```bash
npx -y @sanctuary-framework/mcp-server install --profile full --harness hermes --json
```

Execute only an `agent_action` argument vector, then rerun the same planner. Stop on `human_action` and guide the operator through the named Apple consent, exact privileged command, or private custody step; never execute a human action on the operator's behalf. Stop on `blocked` and report the missing trust input rather than improvising. Installation is mechanically finished only at `complete`.

The `memory` profile is the sovereign encrypted-memory and cooperative-policy rung. The `full` profile adds the signed macOS app, dedicated Hermes account, boot service, content filter, and observed live enforcement on a patched host. The full planner does not download an enforcement binary or guess its provenance; a verified signed release artifact or explicitly supplied drill candidate must already be installed. See [Agent-guided installation](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/agent-guided-install.md) for the contract and the cold-install acceptance criterion, and [Rung 1: fresh-host sovereign-memory onboarding](https://github.com/eriknewton/sanctuary-framework/blob/main/docs/rung1-fresh-host.md) for first-use proof, restart persistence, and second-host recovery. For a copied fortress or lost passphrase, begin with the hidden-prompt `sanctuary reset-passphrase --mode recovery-key --fortress <path>` path; it preserves custody and data. Nuke is a destructive last resort, not a recovery shortcut.

## Useful `protect` flags

All on v1.8.4 unless marked. `--dry-run` previews changes without touching anything. `--no-open` runs headless: it skips opening the dashboard in a browser and switches custody confirmation to the non-interactive mode `protect` already uses whenever stdin is not a terminal. `--fortress <path>` keeps multiple fortresses isolated on one host (honors `SANCTUARY_FORTRESS_PATH` when the flag is absent). `--port <port>` and `--dashboard-port <port>` choose the dashboard port. `--unwrap` restores the original harness configuration. `--passphrase-stdin` reads the fortress passphrase from piped stdin (from 1.8.6; not in 1.8.6-rc.5). Run `sanctuary protect --help` for the full list on your installed version.

**Back up your passphrase:** `sanctuary export-passphrase` prints it to stdout after a confirmation prompt. Store it in a password manager. If you lose it, encrypted state cannot be recovered. An agent never runs this command on an operator's behalf.

## Running alongside another MCP server

`sanctuary protect` preserves the harness's existing tool configuration and routes configured MCP servers through Sanctuary's cooperative gateway. Merely adding Sanctuary as an independent parallel MCP server (for example a bare `npx -y @sanctuary-framework/mcp-server` entry) starts a stdio server but does not apply cooperative policy gates to calls made directly to another server. Castle Wall enforcement, when installed and armed on a patched macOS host, operates at the OS level regardless of MCP routing; the wall sees egress, not MCP tool calls.

For the full setup guide (installation options, passphrase management, service managers, bootstrap, rollback), see [DEPLOYMENT.md](https://github.com/eriknewton/sanctuary-framework/blob/main/server/docs/DEPLOYMENT.md). For the deliberately ungated parallel shape, see the caveats in [docs/examples](https://github.com/eriknewton/sanctuary-framework/blob/main/server/docs/examples/README.md). Prefer `sanctuary protect`.

## Key protection modes

Sanctuary supports host-local custody with explicit recovery:

- **Passphrase.** The master key is derived with Argon2id. Interactive setup enrolls the credential in the platform keyring rather than writing it into a harness configuration.
- **Recovery key.** Agent-guided setup stages recovery material for private operator custody without exposing it to the agent or stdout.
- **Hardware-backed custody.** A roadmap item, not a shipped capability.

## Principal Policy (cooperative gate, Charter)

The Principal Policy is the human-controlled, agent-immutable configuration that gates operations through a three-tier approval system within the cooperative MCP layer. It sits between the MCP router and every tool handler. No tool call routed through Sanctuary can bypass it.

**Tier 1: Always requires approval.** High-risk operations like `state_export`, `state_import`, `identity_rotate`, and `reputation_import` always require explicit human approval before execution.

**Tier 2: Behavioral anomaly detection.** The system tracks a behavioral baseline (namespaces accessed, counterparties seen, signing frequency, read patterns). Deviations trigger approval; a compromised agent accessing unfamiliar data or signing at unusual rates is caught automatically.

**Tier 3: Always allowed (audit only).** Only operations explicitly classified as Tier 3 pass without interruption, and they remain audit-logged. An unclassified operation fails closed to Tier 1 rather than inheriting a broad read, write, or sign default.

The policy file lives at `~/.sanctuary/principal-policy.yaml`. It is loaded once at startup and frozen; no MCP tool can modify it. The agent cannot see the policy rules in denial responses. Approval requests flow through OS notifications, the menubar dashboard, or external webhooks (Slack, Discord, and similar, with HMAC-SHA256 signatures). On first session, non-Tier-3 operations require approval because no baseline exists yet; as the system learns normal patterns, you are asked only about genuinely unusual behavior.

See [RFC-0002](https://github.com/eriknewton/sanctuary-framework/blob/main/rfcs/RFC-0002-principal-policy-operational-approval.md) for the complete specification.

## MCP tools

Once connected, your agent has access to these selected foundational tools, organized by capability surface within the cooperative MCP layer (Charter). The MCP protocol advertises bare tool names such as `identity_create`; clients may display them with the configured server namespace, for example `sanctuary/identity_create`. Tier 1 marks operations the shipped default Principal Policy (`DEFAULT_POLICY`, applied when no policy file exists) sends to a human.

### Cognitive Sovereignty
| Tool | Description |
|------|-------------|
| `sanctuary/identity_create` | Create a new Ed25519 identity |
| `sanctuary/identity_list` | List all managed identities |
| `sanctuary/identity_sign` | Sign data with an identity's private key (Tier 1) |
| `sanctuary/identity_verify` | Verify an Ed25519 signature |
| `sanctuary/identity_rotate` | Rotate an identity's keys (signed chain; Tier 1) |
| `sanctuary/state_write` | Write encrypted state (signed, Merkle-verified) |
| `sanctuary/state_read` | Read and verify encrypted state |
| `sanctuary/state_list` | List keys in a namespace |
| `sanctuary/state_delete` | Securely delete state (overwrite plus unlink; Tier 1) |
| `sanctuary/state_export` | Export state as encrypted portable bundle (Tier 1) |
| `sanctuary/state_import` | Import state bundle with conflict resolution (Tier 1) |

### Operational Isolation
| Tool | Description |
|------|-------------|
| `sanctuary/exec_attest` | Environment attestation with sovereignty assessment |
| `sanctuary/monitor_health` | Sanctuary Health Report (all four capability surfaces) |
| `sanctuary/monitor_audit_log` | Query the sovereignty audit log |
| `sanctuary/principal_policy_view` | View the current Principal Policy (read-only; Tier 1) |
| `sanctuary/principal_baseline_view` | View the behavioral baseline profile (read-only; Tier 1) |

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
| `sanctuary/reputation_export` | Export portable reputation bundle (Tier 1) |
| `sanctuary/reputation_import` | Import bundle with signature verification (Tier 1) |
| `sanctuary/bootstrap_create_escrow` | Create escrow for trust bootstrapping |
| `sanctuary/bootstrap_provide_guarantee` | Principal signs guarantee for agent (Tier 1) |
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
| `sanctuary/sovereignty_audit` | Score your setup 0-100 across security, isolation, and privacy from live configuration |

## Configuration

Environment variables. There is deliberately no passphrase variable in this table; the passphrase is enrolled in the platform credential store by `protect`, and service-manager cases follow [DEPLOYMENT.md](https://github.com/eriknewton/sanctuary-framework/blob/main/server/docs/DEPLOYMENT.md).

| Variable | Description | Default |
|----------|-------------|---------|
| `SANCTUARY_FORTRESS_PATH` | Operator-facing fortress directory override | _(none)_ |
| `SANCTUARY_STORAGE_PATH` | Storage directory path | `~/.sanctuary` |
| `SANCTUARY_TRANSPORT` | Transport mode (`stdio` or `http`) | `stdio` |
| `SANCTUARY_DASHBOARD_ENABLED` | Enable web dashboard (`true`/`false`) | `false` |
| `SANCTUARY_DASHBOARD_PORT` | Dashboard port | `3501` |
| `SANCTUARY_DASHBOARD_AUTH_TOKEN` | Bearer token (`"auto"` creates a read-only launch session, not a decision-ready approval channel) | _(none)_ |
| `SANCTUARY_DASHBOARD_TLS_CERT` | TLS certificate path | _(none)_ |
| `SANCTUARY_DASHBOARD_TLS_KEY` | TLS private key path | _(none)_ |
| `SANCTUARY_WEBHOOK_ENABLED` | Enable webhook approvals | `false` |
| `SANCTUARY_WEBHOOK_URL` | Webhook target URL | _(none)_ |
| `SANCTUARY_WEBHOOK_SECRET` | HMAC-SHA256 shared secret | _(none)_ |
| `SANCTUARY_WEBHOOK_CALLBACK_PORT` | Callback listener port | `3502` |

## Security model

Sanctuary's security claims are structural, not cooperative-only, and each traces to a matrix row.

**Castle Wall enforcement (macOS live; Ubuntu 24.04 x86-64 bounded proof; Windows roadmap), on a patched host:**
- macOS Network Extension or pf rules intercept outbound calls before they leave the operator's machine when the signed extension is installed and armed
- Ubuntu 24.04 x86-64 fresh installs carry the narrowed per-account signed-policy proof in the Assurance Matrix; other Linux platforms, DNS and hostname paths, a real-agent harness, and Windows Filtering Platform are roadmap
- Per-process policy with per-agent-template defaults
- Default-deny outbound with first-run wizard pre-allowing common developer endpoints where the macOS wall is armed
- A prompt-injected agent cannot bypass the macOS wall within the proven scope: one patched host, one OS version, signed extension installed and armed

**Sentinels observation (shipped; observation only):**
- Process introspection via auditd-tail fallback and syscall-observation scaffolding; the eBPF probe loader is a placeholder today
- Behavioral baselining with anomaly detection
- Anomalies surface via OS notifications, not blocks

**Charter cooperative primitives (cooperative MCP additive surface):**
- AES-256-GCM authenticated encryption with unique 12-byte IVs (NIST SP 800-38D)
- Ed25519 keypairs for identity and signing
- Argon2id key derivation (m=64MB, t=3, p=4) for passphrase protection
- HKDF-SHA256 for namespace and purpose key derivation
- Merkle trees for namespace integrity verification
- 3-pass secure deletion (random overwrite before unlink)
- Private keys never appear in any MCP tool response
- Monotonic version numbers prevent state rollback
- Principal Policy gates every MCP call Sanctuary executes or forwards (three-tier approval)
- Behavioral baseline detects anomalous agent behavior
- Stderr is informational and deny-only; decision-ready Tier 1 approval requires an authenticated configured approval channel

**Heralds cross-castle accountability:**
- Concordia receipts for cross-castle commitments
- Verascore reputation aggregating across operators
- Portable reputation bundles for cross-platform portability
- Hash-chained audit with current checkpoint-signing bounds as compliance evidence; production call sites sign checkpoints when the fortress holds an identity, and the audit-chain row stays partial pending the external-verifier drill (**IC-05**)

## Architecture: the Castle

Sanctuary's enforcement model is the Castle Architecture. Five named mechanisms, each with a distinct contract.

**Castle Wall: the perimeter.** OS-level egress enforcement at the operator-external boundary, on a patched host. On a patched host, macOS enforces through the signed Network Extension or pf path when installed and armed: a signed operator policy with a proven per-uid allow/deny demonstration that survives attended reboot cycles, one host, one OS version. On Ubuntu 24.04 (x86-64), on a patched host, a fresh install of the shipped package enforces a signed operator policy per user account: blocked destinations stay blocked and allowed ones connect, through five reboots, on three fresh servers, with the evidence checked by two independent reviewers. Fault-injection witnesses, a real-agent harness, and every other distribution or architecture remain unproven. Windows is roadmapped. Where the macOS wall is installed and armed within the proven scope, the kernel blocks unauthorized cross-boundary calls and a prompt-injected agent cannot bypass it.

**Sentinels: the nerves.** Internal observation, not enforcement. Behavioral baselining via process introspection, auditd-tail fallback, and an eBPF watcher scaffold that currently falls back to stub mode because the real probe loader is not implemented. Anomalies surface to the operator via menubar and OS notifications. Sentinels observe and surface; they do not block, and they are unrelated to any vendor's "sentinel."

**Charter: the will.** The additive cooperative MCP surface for compliant agents. Encrypted state at rest, hash-chained audit with current checkpoint-signing bounds, mandate primitives, four canonical policy slots (memory, credentials, plans, outputs), substrate selector, Concordia receipt integration, Verascore reputation hooks. Compliant agents that route through Sanctuary's MCP get the full sovereignty surface. Non-compliant agents still meet the Castle Wall where it is installed and armed, and Sentinels inside the castle.

**Heralds: the voice.** How your agent is recognized by other sovereigns. Concordia receipts on cross-castle transactions, Verascore reputation aggregating across operators, cross-castle accountability after the fact, portable reputation across vendor churn. Default off; both compositions are optional, and neither repo imports the other.

**Mantle: the unique-substrate binding.** What makes this install yours. An install-time check that locks Sanctuary to the operator's machine and rejects orphan agent identifiers that are not bound to a wrapped harness.

The castle must be both real and delightful: hard enforcement at the wall, approval response under 2 seconds when prompted, default-deny outbound with always-allow rules that learn, Sentinels that observe without surfacing noise, and a cooperative MCP path that stays additive and fully usable. The runtime sees a normal operating environment with constrained egress; nothing internal is sandboxed.

## Capability surfaces

Within the cooperative MCP layer (Charter), Sanctuary exposes four capability surfaces. These are the tool-level primitives compliant agents call.

**Cognitive Sovereignty.** All agent state encrypted at rest with AES-256-GCM. Keys are participant-held. Identity is Ed25519-based with DID support. Merkle tree integrity verification detects tampering and rollback.

**Operational Isolation.** Environment attestation, encrypted audit log, and Principal Policy: a human-controlled, agent-immutable approval system that gates high-risk operations. The shipped Sentinels observation layer exposes behavioral-baselining signals; the real eBPF probe loader remains a roadmap item.

**Selective Disclosure.** SHA-256 commitments, Pedersen commitments on Ristretto255, zero-knowledge proofs of knowledge (Schnorr/Fiat-Shamir), and ZK range proofs (bit-decomposition with CDS OR-proofs). Disclosure policies define what information flows where.

**Verifiable Reputation.** Signed attestations (EAS-compatible) with sovereignty-gated tiers. Weighted scoring based on counterparty sovereignty posture. Export/import for cross-platform portability. Trust bootstrapping via escrow and principal guarantees. Sovereignty handshakes and MCP-to-MCP federation.

## The seven principles of sovereignty

These are the principles every external communication, every spec, every roadmap commitment is measured against. They are evergreen. The implementations that satisfy them in 2026 will look quaint in 2031, and the principles will not have changed.

1. **Boundary.** You control what crosses your perimeter. What enters and what leaves enters and leaves because you said so, structurally, not because someone trusted promised to behave. Bad things stay out by structure, not by trust.
2. **Custody.** The substrate, the keys, the state, and the reasoning trace are physically and cryptographically held by you. Not by a vendor, not by a hosted control plane, not by a custodian whose KMS happens to call itself "self-custody."
3. **Internal process.** Your agent's reasoning, deliberation, the path it took to a decision, are yours. The same way no one reads your thoughts.
4. **Opacity at the query layer.** Anonymity at the layer where you ask questions is the difference between asking a question and being identified by asking it. Most platforms get this wrong by default and we get used to it. We should not.
5. **Recognition and portability.** Your record follows you across regimes, vendors, and model providers. Two distinct moves are required and they are usually conflated. Portability is transport: your data, audit log, mandates, and receipts are physically movable. Recognition is standing: another implementation must acknowledge your record as yours when you arrive.
6. **Exit.** You can leave through shipped export paths on your timeline; the full exit guarantee remains partial until the dashboard export, skipped-counter import, and rotated-key import gaps close.
7. **Plurality.** Sovereignty without interaction is solipsism. A sovereign agent that cannot engage with another sovereign agent on terms both have set is just an isolated process.

## Operator experience

Sanctuary lives in your menubar. When your agent wants to do something risky, you get an OS notification. Click, see the request in plain English, approve or deny in five seconds. The agent receives a structured response that surfaces the decision back to you naturally if you missed the notification.

The dashboard is for setup, inspection, and authenticated operator approvals. It includes the substrate selector, policy editor, audit deep-dive, exit bundle drill, and fortress configuration. The menubar keeps routine status and approval entry points close at hand. Concierge chat is a read-oriented natural-language interface to fortress state: "What's going on?" returns a summary from the audit log; "Why did my Hermes agent stop?" looks up recent gate triggers and explains. It does not approve requests or trigger exports on the operator's behalf.

You do not sit in Sanctuary. Sanctuary sits with you.

## Development

```bash
git clone https://github.com/eriknewton/sanctuary-framework.git
cd sanctuary-framework/server
npm install
npm run build
npm test
```

The maintained module map is [server/src/README.md](https://github.com/eriknewton/sanctuary-framework/blob/main/server/src/README.md). It identifies the current module owners, confusable names, and frozen compatibility surfaces. Contributor rules: [CONTRIBUTING.md](https://github.com/eriknewton/sanctuary-framework/blob/main/CONTRIBUTING.md).

## Specification

See [RFC-0001](https://github.com/eriknewton/sanctuary-framework/blob/main/rfcs/RFC-0001-sanctuary-mcp-server.md) for the core specification, [RFC-0002](https://github.com/eriknewton/sanctuary-framework/blob/main/rfcs/RFC-0002-principal-policy-operational-approval.md) for the Principal Policy specification, and [RFC-0003](https://github.com/eriknewton/sanctuary-framework/blob/main/server/rfcs/RFC-0003-castle-architecture.md) for the Castle Architecture specification. Architecture, data flow, and trust model: [SANCTUARY_ARCHITECTURE.md](https://github.com/eriknewton/sanctuary-framework/blob/main/SANCTUARY_ARCHITECTURE.md).

## License

Apache-2.0 (code) / CC-BY-4.0 (specification). Created by Erik Newton.

## Appendix: catalog-v3 verification exports (library reference; inert, no shipped consumer)

This section documents a library export, not an operator feature. Nothing on the install path above calls it, and no signed production catalog ships yet; it is here for integrators who verify signed model catalogs themselves.

The package exposes the Rung 2 S1 verification contracts through
`@sanctuary-framework/mcp-server/intelligence` in both module systems:

```js
// ESM
import {
  COMPILED_CATALOG_KEY_POLICY_DIGEST,
  verifyAndParseSignedCatalogJsonV3,
  verifyAndParseSignedCatalogV3,
} from "@sanctuary-framework/mcp-server/intelligence";
```

```js
// CJS
const {
  verifyAndParseSignedCatalogIndexJsonV1,
} = require("@sanctuary-framework/mcp-server/intelligence");
```

The package also exports exact subpaths for five companion schemas plus their
digest manifest under `./intelligence/catalog-v3/schemas/` and the byte-pinned
Sanctuary SPDX-profile ABNF under `./intelligence/catalog-v3/spdx/`. The exact
manifest bytes are independently pinned by the exported
`CATALOG_V3_ASSET_DIGEST_MANIFEST_SHA256` code constant; the manifest then
roots both the raw bytes and JCS form of every schema plus the ABNF. Raw-byte
schema pins make duplicate-key or alternate-wire tampering visible before
JSON parsing. The SPDX 3.28 identifier table is reproducibly derived at
build/test time from a deterministic, fact-only identifier/deprecated-status
projection. The full upstream `license-list-data` summaries are not committed
or published. Refresh explicitly consumes separately downloaded v3.28.0 source
files whose raw and canonical JSON hashes are pinned; the recorded tag object
and source commit are provenance attestations, while those content hashes are
the integrity roots. There is no executable SPDX dependency. The JSON Schemas are structural prefilters,
not admission decisions. The signed-envelope schemas reference their body
schemas and therefore must be co-registered with those body schemas before
compilation; they are not standalone schema documents. Schema success MUST be followed by the appropriate
runtime `verifyAndParse*` function and, for overlays,
`validateCatalogOverlayCombination`. Untrusted wire bytes MUST enter through
the string-taking `verifyAndParseSigned*Json*` functions; the object-taking
variants are only for objects already produced by an equally strict,
duplicate-key-rejecting decoder. The combined validator accepts only the
exact authenticated envelope or body objects returned by the signature
verifiers; a merely parsed or structurally valid body is refused. Callers must supply the expected
fortress-binding id, last accepted overlay-version floor, catalog-keyring
digest, and operator signer-key id. This binds the private runtime brand to the
trust roots the caller actually pinned. A catalog epoch key authenticates both
catalog bodies and catalog-index segments, under distinct domain-separated
preimages; overlays use the separately pinned fortress operator key. A brand is deliberately local to one
loaded module instance: passing an ESM-verified object to a distinct CJS/root
module instance refuses as unauthenticated. The combined
validator treats the catalog and overlay as one independent, bounded union:
new overlay models are allowed, but model-id, full-identity, and runtime-tag
collisions are refused in either update order, rollback is refused, and the
operator's self-asserted assurance label for every authorized surface must
clear both its catalog-default and compiled assurance floor. This is a label
check against the signed overlay's declared tier, not independent evidence
that the tier is true. A retired catalog-key epoch remains valid only for its closed historical
version range; it cannot sign later versions. A revoked epoch is a compromise
response and intentionally makes even historical signatures unverifiable.
Runtime validation also enforces exact compiled tier/default tables,
strict ascending surface order, cross-field invariants, key policy, and
signatures. License evidence URLs require canonical HTTPS URLs on lowercase
ASCII DNS-shaped names; numeric, shorthand-numeric, punycode, malformed-label,
and path-traversal spellings refuse identically in the TypeScript and
independent Python implementations, per the shared parity corpus both sides
run. Credential (userinfo), query-string, and fragment spellings are refused
by both implementations too, but that refusal is exercised only by each
language's own unit tests today, not by a shared corpus row, so it is not
included in the cross-language parity claim above.

Public unknown-input entry points first copy one bounded, accessor-free JSON
snapshot. Getters, exotic prototypes, cycles, sparse/decorated arrays, and
throwing proxy traps refuse without entering signature or policy logic.

The expression parser implements the deliberately narrower Sanctuary SPDX
expression profile v1 documented in `spdx-expression-3.0.1.abnf`; it is not a
claim to accept every SPDX 3.0.1 expression. Active listed identifiers are
matched case-insensitively and normalized to SPDX list spelling, deprecated
identifiers refuse, and signed catalog input must already equal the normalized
form. Build-source provenance and
refresh instructions are recorded in [THIRD_PARTY_NOTICES.md](https://github.com/eriknewton/sanctuary-framework/blob/main/server/THIRD_PARTY_NOTICES.md). These are pure,
fail-closed parsing and signature-verification contracts. There is no signer
in this module, only verifiers; the verification canonicalizer performs
internal RFC 8785-compatible canonicalization for this integer-only profile
so a verifier can recompute the exact bytes a signature was taken over, and
that helper is intentionally not a public API.
The independent Python parity verifier checks wire bytes, hashes, signatures,
and closed-value semantics; it does not model the TypeScript module's private
in-process verification brand and is not an overlay-admission implementation.
They do not discover models, fetch a catalog, persist continuity, enforce
anti-rollback state, activate a model, or ship a real signed production
catalog/index checkpoint yet. The compiled index record is only an all-null
genesis sentinel. Issued-at freshness/monotonicity and model-to-surface
hardware compatibility are admission policy deferred to S2.
