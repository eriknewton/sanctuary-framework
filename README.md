# Sanctuary

[![CI](https://github.com/eriknewton/sanctuary-framework/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/eriknewton/sanctuary-framework/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@sanctuary-framework/mcp-server.svg)](https://www.npmjs.com/package/@sanctuary-framework/mcp-server)
[![License](https://img.shields.io/npm/l/@sanctuary-framework/mcp-server.svg)](LICENSE)

**Your agent will know you better than you know yourself. Make sure that stays between you.**

Sanctuary is the open source standard for secure, private AI: a wall the operating system enforces in both directions, and your data under your own keys, portable anywhere. Any agent, local or cloud, solo or fleet. One command to get started. One dashboard to secure them all.

Sanctuary wraps any AI agent, on your machine or in your cloud, so every action it takes is blocked at the network layer if you did not allow it, signed with keys only you hold, and logged to an audit trail you can actually read. One dashboard manages the security and privacy of every agent you run, whether that is one agent on your laptop or a whole fleet across your machines. Your data, and the reputation your agents build, stay on hardware you control, and you can pick them up and leave whenever you want. No lock-in.

Already running Claude Code, Cursor, Hermes, OpenClaw, Cline, or Mastra?

```bash
npx @sanctuary-framework/mcp-server protect --claude-code
```

That one command puts the wall, the keys, the audit trail, and the dashboard around the agent you already use. You keep your harness; Sanctuary adds the protection underneath.

**Under the hood:** a kernel-level wall that holds even when a prompt-injected agent tries to misbehave, enforced on Linux and macOS today (drilled on real hardware, signed and notarized, survives reboot; Windows roadmapped), cryptographic identity and encrypted state the platform running your agent cannot read, and full data portability so you are never trapped in one vendor. It composes with Concordia (agent negotiation) and Verascore (portable reputation), each in its own repo and neither required.

**The claim underneath everything: custody.** Plenty of tools can sandbox an agent when the agent, or its harness, chooses to run inside one. Sanctuary is built for the harder promise: the wall is imposed by the operator and does not depend on the agent's cooperation, the keys never leave hardware you control, and no vendor, including us, sits in the path or can decrypt your state. Every public capability claim traces to a proven row in the [Assurance Matrix](ASSURANCE_MATRIX.md), with its limits stated on the row.

Why this exists: [The Base Layer](https://sanctuaryprotocol.ai/2026/07/23/the-base-layer.html).

---

## Install

Already running OpenClaw, Hermes, Claude Code, Cursor, Cline, or Mastra? One command wraps it.

```bash
npx @sanctuary-framework/mcp-server protect --openclaw
```

Or substitute `--hermes`, `--claude-code`, `--cursor`, `--cline`, `--mastra`, or `--wrap <path-to-config>` for any other MCP-compatible harness. Compatibility for the named harnesses is exercised on every release; other MCP-compatible harnesses work via the `--wrap` flag and are covered as drills extend the matrix. See the [Sanctuary Assurance Matrix](ASSURANCE_MATRIX.md) for the current per-harness status. You keep using the harness you already like. Sanctuary adds the substrate underneath, invisibly.

What happens when you run protect:

1. A passphrase is generated and stored in the macOS Keychain (or an encrypted fallback file on Linux/Windows).
2. Your existing harness config is backed up to `~/.sanctuary/backup/`.
3. The config is rewritten so every tool call routes through Sanctuary.
4. The Sovereignty Dashboard starts on `http://localhost:3501` (or the next free port up to 3510) and opens in your browser with a one-click auth token.
5. Every call is logged and policy-gated. Sensitive-content redaction and query-layer anonymity layer on top per the Assurance Matrix: fingerprintable-header stripping is on by default, and an opt-in, consent-gated PII rewrite scrubs query content before it leaves the machine, with the rewrite's internal classifier pinned to local processing so a privacy feature can never become an egress channel. Dangerous operations require your approval.

Useful flags: `--dry-run` previews changes without touching anything. `--no-open` runs headless for CI. `--unwrap` restores the original harness config.

**Back up your passphrase:**

```bash
sanctuary export-passphrase
```

Prints the passphrase to stdout after a confirmation prompt. Store it in a password manager. If you lose it, encrypted state cannot be recovered.

---

## Release status

`main` is the development branch. The current stable release is **v1.7.0** on the npm `latest` channel (released 2026-07-26), the first release whose macOS app artifact is signed and notarized; it also lands the unified-protect exclusive-egress path end to end in code. A follow-up patch release, **v1.7.1**, is staged to complete that gate path: as of v1.7.0 an unmodified agent harness could not reach the exclusive gate, and a gate-daemon plist healed at boot took effect only on the next boot; v1.7.1 carries the reachability fix (#1024) and the boot fixes (#1027, #994). The macOS Castle Wall bounds are unchanged: per-uid allow/deny plus boot-survival plus WAN-containment are proven; there is no per-flow rule-attributed audit trail. See the [v1.7.0 release notes](docs/releases/v1.7.0.md), the [v1.7.1 release notes](docs/releases/v1.7.1.md), and [CHANGELOG.md](CHANGELOG.md) for the full history.

```bash
npm install -g @sanctuary-framework/mcp-server
```

Current capability summary:

| Surface | Current status |
|---|---|
| Local `sanctuary protect` (alias `wrap`), dashboard, policy gates, encrypted state, audit trail, signed exit bundle | Shipped (v1.0 through v1.3) |
| Cooperative MCP gates: three-tier approval, four canonical policy slots, channel templates | Shipped |
| Context gating, sensitive-field redaction, query-layer anonymity (header strip default-on; opt-in PII rewrite live, classifier surface pinned local-only) | Shipped |
| Portable identity, state export/import, recovery flows, reputation bundles | Shipped |
| Local multi-agent coordination, fortress-local hub APIs, signed audit chain | Shipped |
| Federation Protocol v0.1 foundation | Shipped; cross-operator federation hardening underway per Wave 1 design (2026-05-26) |
| Concordia composition (negotiation receipts), Verascore composition (reputation) | Optional, default off; both shipped |
| Castle Wall (OS-level egress enforcement): Linux | Shipped (Phase 1, 2026-05-06) |
| Castle Wall macOS: signed sysext, host app, content-filter provider, retail UX | Shipped; enforces a signed operator policy with a clean per-uid allow/deny demonstration that survives reboot (N=5, drill 2026-06-22, one host / one OS version, Dev-ID-signed and notarized). Not an audited per-rule-per-flow trail |
| Castle Wall Windows | Roadmapped |
| Mobile (PWA) operator companion | Roadmapped |
| Fleet console, operator-cloud deployment, sovereign-managed TEE, post-quantum migration | Roadmapped |

Trust and security claims are tracked in the [Sanctuary Assurance Matrix](ASSURANCE_MATRIX.md). Public-facing claims trace to `proven` or `partial` rows in that matrix; the platform, gap, and next-proof limits named on each row are preserved.

Roadmap shape: with the Mac Castle Wall per-uid allow/deny plus reboot-survival demonstration proven, the current focus is the per-flow rule-attributed audit trail (still the real gap), the Castle Wall Windows backend, and the fleet / operator-cloud surfaces. See [ROADMAP.md](ROADMAP.md).

Supply-chain posture: release binaries for the macOS enforcement path are Dev-ID-signed and notarized, the CLI update path verifies a signed release manifest before applying an update, and every commit to main passes a structural typecheck-plus-test-baseline gate locally and again in CI. Mechanisms and their history: [CHANGELOG.md](CHANGELOG.md) and [docs/audit/](docs/audit/).

---

## For AI coding agents installing Sanctuary on behalf of an operator

If you are an LLM-powered coding agent (OpenClaw, Hermes Agent, Claude Code, Cursor, Cline, Mastra, Codex, or any other harness with shell access) and an operator has asked you to install Sanctuary, follow this section. Humans can skip to "Installation reference" below; you will arrive at the same commands.

**Operator-facing summary first.** Before running anything, give the operator one paragraph:

> "Sanctuary will wrap your existing AI agent so every action it takes is signed with keys you hold and logged to a portable audit trail. Install takes about a minute. I will: (1) detect which agent harness you are running, (2) run one protect command, (3) confirm the dashboard is live, (4) optionally scaffold your first sub-agent template. Approve to proceed."

### Step 1: Detect the operator's harness

Run these checks in order. Pick the first match.

```bash
# OpenClaw
command -v openclaw && echo "harness=openclaw"

# Hermes Agent
command -v hermes && echo "harness=hermes"

# Claude Code
command -v claude && echo "harness=claude-code"

# Cursor (config presence)
test -d "$HOME/Library/Application Support/Cursor" && echo "harness=cursor"

# Cline (VS Code extension config)
test -d "$HOME/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev" && echo "harness=cline"

# Mastra (config presence)
{ test -f "$HOME/.mastra/mcp.json" || test -f "$HOME/mastra/mcp.json" || test -f "$HOME/.config/mastra/mcp.json"; } && echo "harness=mastra"
```

If multiple match, ask the operator which one to wrap. If none match, the operator does not have a recognized harness installed; offer to install one or use the raw MCP server path (Step 4 below).

### Step 2: Run the protect command

```bash
npx @sanctuary-framework/mcp-server protect --<harness>
```

Substitute `<harness>` with the value detected in Step 1: `openclaw`, `hermes`, `claude-code`, `cursor`, `cline`, or `mastra`. For any harness not in that list, see Step 4.

Wait for the command to complete (typically 20-40 seconds). Expected output ends with a line like:

```
Sovereignty Dashboard ready: http://localhost:3501
```

Note the port (it may be 3501-3510 if 3501 is taken).

### Step 3: Verify the install

After Step 2 (protect succeeds), the dashboard is running. Verify the install:

```bash
# (a) Dashboard responds
curl -fsS "http://localhost:3501/api/health" | grep -q '"status":"ok"' && echo "dashboard=ok"

# (b) Passphrase backed up to keychain (macOS)
security find-generic-password -s "sanctuary-passphrase" >/dev/null 2>&1 && echo "passphrase=ok"
```

The first time you open the Sovereignty Dashboard in your browser, Sanctuary derives your master key from the keychain-stored passphrase, creates your fortress's Ed25519 identity, and writes the audit log genesis. The protect command configures these on disk; the first dashboard unlock initializes them. Verify after first unlock:

```bash
# (c) Identities loaded (run after opening the dashboard once)
curl -fsS "http://localhost:3501/api/identities" | grep -q '"identities":\[' && echo "identities=ok"

# (d) Audit log initialized (run after opening the dashboard once)
test -d ~/.sanctuary/state/_audit && echo "audit=ok"
```

If any check fails, see "Troubleshooting" near the bottom of this README.

### Step 4: Scaffold the operator's first governed harness (recommended)

After the protect succeeds, ask the operator: "Which channel shape do you want on this harness? I have one-click archetypes for research-assistant, coding-assistant, ops-runner, planner, and handoff-coordinator. Or I can skip this step."

If they pick an archetype, run:

```bash
curl -X POST "http://localhost:3501/api/templates/<template-name>/init" \
  -H "Authorization: Bearer <operator-dashboard-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "<already-wrapped-agent-id>",
    "model_provider": "<xai|anthropic|openai|mistral>"
  }'
```

Substitute `<template-name>` with the archetype the operator picked (`research-assistant`, `coding-assistant`, etc.). Template init authors and signs a governance policy for the agent, so it is protected like an approval decision: the request requires the operator's dashboard bearer token (printed when the dashboard starts; a tokenless request is rejected), and the operator then confirms a one-click Tier-1 approval card on the dashboard before the policy is signed. If the operator prefers, they can skip the curl and run the same init from the dashboard. The `agent_name` must match an already-wrapped harness; `template init` rejects an orphan `agent_id` that is not bound to a wrapped harness (the install-time check that locks Sanctuary to the operator's machine) and points the operator at `sanctuary protect`. Confirm the response includes a `signed_event_id` and an `attestation_panel_url`. Open that URL in the operator's browser.

### Step 5: Hand back to the operator

Tell them: "Sanctuary is installed and your first sub-agent is scaffolded. Open the Sovereignty Dashboard at http://localhost:3501 to see what your agents are doing in real time. Your passphrase is in your macOS Keychain; if you want a printable backup, run `sanctuary export-passphrase`."

### Raw MCP server path (Step 4 alternative)

If the operator's harness is not in the recognized list, install the MCP server directly and have them point their harness at it:

```bash
npm install -g @sanctuary-framework/mcp-server
```

Then add Sanctuary to the harness MCP config. The exact form depends on the harness; for an MCP-compatible harness the entry is typically:

```json
{
  "command": "npx",
  "args": ["-y", "@sanctuary-framework/mcp-server"],
  "env": {
    "SANCTUARY_PASSPHRASE": "<generated-passphrase>"
  }
}
```

Generate the passphrase with `openssl rand -base64 32` and store it in the operator's keychain or password manager.

---

## Installation reference

**Requirements:** Node.js >= 22.0.0, npm >= 10.0.0.

The canonical install path is `sanctuary protect` (above). The sections below are reference for less common situations.

### Persistent install

```bash
npm install -g @sanctuary-framework/mcp-server
```

Makes the `sanctuary` CLI available without `npx` prefix.

### Manual MCP config

If you prefer to edit your harness MCP config by hand:

```bash
# OpenClaw
openclaw mcp set sanctuary '{"command":"npx","args":["-y","@sanctuary-framework/mcp-server"],"env":{"SANCTUARY_PASSPHRASE":"your-passphrase-here"}}'

# Hermes Agent
hermes mcp set sanctuary '{"command":"npx","args":["-y","@sanctuary-framework/mcp-server"],"env":{"SANCTUARY_PASSPHRASE":"your-passphrase-here"}}'

# Claude Code
claude mcp add sanctuary -- npx -y @sanctuary-framework/mcp-server
```

Generate a passphrase before first launch:

```bash
openssl rand -base64 32
```

Store it securely. It derives the encryption keys for all persistent state. If lost, encrypted state cannot be recovered.

### Health check

```bash
sovereignty_audit
```

Scores your setup 0-100 across security, isolation, and privacy from your live configuration and profile. Optional features that default off (context gating, zero-knowledge proofs) only count toward the score once you enable them, and the top "full" verdict is reserved for a posture where those optional layers are actually on, so a fresh install scores below full, reads below the full verdict, and the report flags the gaps with the steps to close them. Available as both a CLI command and an MCP tool inside any wrapped harness.

---

## First agent after install: scaffold a template

After `protect`, the dashboard exposes a one-click template picker. Click "Add agent" on the Agents view, pick a template, fill in a name and model provider, click Scaffold. The template provisions sensible defaults for egress allowed-hosts, budgets, retention windows, and policy gates.

Channel-shape archetypes that ship with Sanctuary:

| Archetype | Channel shape | Reads from | Recommended model |
|---|---|---|---|
| **research-assistant** | General-purpose research helper | configurable | any |
| **coding-assistant** | Reads your codebase, suggests changes | local + git remote | any |
| **ops-runner** | Runs ops scripts on approval | scoped per agent | any |
| **planner** | Generates plans without executing them | none | any |
| **handoff-coordinator** | Coordinates work across multiple agents | inter-agent only | any |

Sanctuary ships channel-shape governance templates (policy, egress, budgets, retention) rather than named-agent runtimes. Operators bring their own harnesses and protect them; `template init` binds a channel shape to an already-wrapped harness.

Operator authoring beyond this list: copy any template directory under `~/.sanctuary/templates/`, edit `template.json`, `defaults.json`, `policy.md`, `commitments.json`, and `onboarding.md`, then run `sanctuary template init <your-template>`.

CLI scaffolding works the same way the dashboard button does:

```bash
sanctuary template init research-assistant --name my-agent --provider anthropic
```

---

## Deployment modes

Sanctuary is designed to run the same rights substrate in three places. Local mode is shipping today; operator-cloud and sovereign-managed TEE modes are roadmap surfaces that build on the same federation and policy foundations.

| Mode | Status | What it is | Who picks this |
|---|---|---|---|
| **On your machines** (Local) | Shipping | Runs on the Macs, Linux boxes, or Windows machines you already own. Nothing leaves your house unless you tell it to. | Self-hosters, privacy-maximalists, anyone who already runs a homelab. |
| **In your cloud** (Operator cloud) | Roadmapped | Runs in your own GCP / Azure / AWS account with operator-approved scoped node custody. The provider is inside the node runtime trust boundary until sovereign TEE mode is verified by hardware attestation. | Prosumers, small businesses, operators with light IT but no rack at home. |
| **In a sealed cloud box we manage** (Sovereign-managed TEE) | Roadmapped (v2) | Runs on hardware Sanctuary operates, but the hardware proves to your console that even Sanctuary cannot see what's inside. You hold the keys; we hold the metal. | Regulated industries, operators who want sovereignty without operational burden. |

The operator remains the custody root in every mode. Commodity operator-cloud mode does not put the cloud provider outside the runtime trust boundary; sovereign-managed mode requires hardware attestation before it is treated as shipped.

---

## The Castle Architecture

Sanctuary installs the protections your body used to provide by default: a perimeter, custody, memory, and a record of what happened. Everything it protects for you together is **your Sanctuary**: each machine is a rampart the Castle Wall holds, each fortress is a keep inside those walls, and each agent is a resident of exactly one keep. The unit never blurs: one agent, one account, one fortress, one master key. Architecturally it ships as five named mechanisms.

**Castle Wall: the perimeter.** What the world cannot cross without your consent. OS-level egress enforcement at the operator-external boundary. The kernel itself blocks unauthorized cross-boundary calls. Even prompt-injected agents cannot bypass. Linux backend shipped (Phase 1, 2026-05-06). macOS backend (signed system extension + content-filter provider) enforces a signed operator policy with a proven per-uid allow/deny demonstration that survives reboot, captured on a real host (drills 2026-06-11 through 2026-06-22, boot survival 5 of 5 on a Dev-ID-signed and notarized binary): agent egress to a non-allowlisted address blocked, allowlisted egress allowed, operator egress unaffected, and enforcement live again after every reboot. That is a demonstration on one host and one OS version, not an audited per-rule-per-flow trail. Windows on the roadmap.

**Sentinels: the nerves.** What surfaces what's happening to your awareness. Internal observation via process introspection and behavioral baselining. Anomalies surface through the menubar or notifications. Observation, not enforcement.

**Charter: the will.** What you train your agent to choose voluntarily. The additive cooperative MCP surface for compliant agents. Operator-rooted cryptographic identity (Ed25519 signing, Argon2id passphrase unlock, per-purpose HKDF subkeys). Per-agent encrypted state at rest (AES-256-GCM). Three-tier Principal Policy gates with channel-template binding. Signed audit chain with rollback detection.

**Heralds: the voice.** How you speak to and are recognized by other sovereigns. Optional composition surface (Concordia for structured negotiation, Verascore for portable reputation). Receipts and reputation attestations assemble into a single audit trail that travels with the agent across machines. Default off; both compositions are optional.

**Mantle: the unique-substrate-binding.** What makes this install yours, not someone else's. Install-time check that locks Sanctuary to the operator's machine at install time and rejects orphan agent identifiers that are not bound to a wrapped harness.

**Today:** Ed25519 signing, Argon2id passphrase unlock, and per-purpose HKDF subkeys. **Crypto-agility:** every audit entry embeds a scheme identifier so hybrid post-quantum signing (Ed25519 + ML-DSA / FIPS 204) can land without breaking historical receipts. Hardware-backed secure elements are on the roadmap.

**Working on the code?** The TypeScript server has an orientation map at [`server/src/README.md`](server/src/README.md) - a 56-module index of what each module owns, the confusable-name disambiguations, and the frozen surfaces a refactor must never change. Start there, then see [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## The rights you hold by default

The substrate enforces rights that normally only ship to enterprises with dedicated identity and security teams. What they mean for you:

- **Identity.** Your agent has a key you own. No provider can impersonate you or revoke your agent. You can prove the agent is yours without asking anyone's permission.
- **Data.** Your agent's state is encrypted against the provider running it. The platform sees the calls going out; it does not see your life going in. Your conversations, your memory, and your plans stay yours.
- **Portability.** Your agent's memory, reputation, and commitments travel with you. If a provider goes bad, raises prices, or shuts down, you leave without losing what you built.
- **Attestation.** What your agent did is provable. To you, to a third party, to a court if it comes to that. The audit log is signed, append-only, and portable.
- **Exit.** Nothing you build up is locked to a platform that can revoke it. Keys, state, reputation, and commitments are yours to move, copy, or keep offline.

Sanctuary ships the rights substrate. Access (compute, devices, bandwidth, literacy) belongs to civic-infrastructure partners (public libraries, legal-aid organizations, labor unions, public-interest tech groups, community colleges) who host agentic AI on behalf of users who do not self-host. The partner provides access; Sanctuary provides rights. The two compose; they do not substitute.

---

## Works with

Sanctuary wraps MCP-compatible harnesses. The named harnesses below are exercised on every release; other MCP-compatible harnesses work via the `--wrap` flag or direct MCP config and gain release-tested coverage as drills extend the [Assurance Matrix](ASSURANCE_MATRIX.md).

- **OpenClaw** (`sanctuary protect --openclaw`)
- **Hermes Agent** (`sanctuary protect --hermes`)
- **Claude Code** (`sanctuary protect --claude-code`)
- **Cursor** (`sanctuary protect --cursor`)
- **Cline** (`sanctuary protect --cline`)
- **Mastra** (`sanctuary protect --mastra`)
- **LangGraph** and custom harnesses (`sanctuary protect --wrap <path>`)
- Any other MCP-compatible harness via direct MCP config

---

## Composes with Concordia Protocol

When your agent needs to negotiate or make deals, **Concordia Protocol** adds structured negotiation with binding commitments. Sanctuary also composes with **Verascore** for portable agent reputation.

**Sanctuary never requires Concordia, and Concordia never requires Sanctuary.** They compose powerfully when both are deployed: Concordia commitment receipts flow through Sanctuary envelopes, and reputation attestations assemble into a single audit trail. Each ships, runs, and wins on its own. This is a structural commitment, not a tagline. Neither repo imports the other.

Install both if you want the full stack:

```bash
npx @sanctuary-framework/mcp-server
pip install concordia-protocol
```

---

## Open standards

Sanctuary composes with the existing open ecosystem.

- **Identity:** W3C DIDs, KERI, Verifiable Credentials.
- **Execution:** Trusted Execution Environments (Intel TDX, AMD SEV-SNP, ARM CCA) on the v2 roadmap.
- **Cryptography:** Ed25519 today; NIST Post-Quantum Cryptography (ML-DSA / FIPS 204, ML-KEM / FIPS 203) on the migration path; hybrid signing planned after the local sovereignty harness is complete.
- **Settlement:** x402 (Coinbase micropayments), AP2 (Google Agent Payments Protocol), ACP.

---

## Troubleshooting

For AI coding agents handling install failures, here are the common cases.

**Install Step 3 (a) "dashboard=ok" check fails:**
- Wait 10 seconds and retry. Dashboard takes a moment to bind on first launch.
- If still failing, check `lsof -i :3501-3510` to confirm the dashboard chose a port. The protect output line `Sovereignty Dashboard ready: http://localhost:<port>` is authoritative; use that port.

**Install Step 3 (b) "passphrase=ok" check fails on macOS:**
- The protect command may have failed to write to the Keychain (typically a permissions prompt the operator dismissed). Rerun the protect command and approve the Keychain prompt when it appears.

**Install Step 3 (b) on Linux or Windows:**
- The keychain check is macOS-specific. On Linux, Sanctuary uses Secret Service when available and falls back to an encrypted file at `~/.sanctuary/passphrase.enc`. Windows Credential Manager support is queued on the patch track. Test the fallback with `test -f ~/.sanctuary/passphrase.enc && echo "passphrase=ok"`.

**Install Step 3 (c) "identities=ok" check fails:**
- Confirm protect completed without error. If it did, check `~/.sanctuary/identities/` for `.enc` files. If absent, the protect command exited early; rerun with `--dry-run` to see what it would do, then without to retry.

**Install Step 3 (d) "audit=ok" check fails:**
- Confirm `~/.sanctuary/` exists and is writable by the current user. If it doesn't exist, the protect did not complete; rerun.
- Audit entries are stored encrypted under `~/.sanctuary/state/_audit/`, not as plaintext JSONL. Use `audit_export_siem` when you need a decrypted export.

**`sanctuary` CLI not found after `npm install -g`:**
- Confirm `npm bin -g` is on the PATH. On macOS with nvm, this typically lives at `~/.nvm/versions/node/<version>/bin/`.

**Existing harness config overwritten:**
- The original is at `~/.sanctuary/backup/config-backup-<timestamp>-<surface-tag><ext>` (the surface tag is a short hex hash of the config file's path, and the extension matches the source config: `.json` for most harnesses; Hermes wraps two surfaces and backs up both, `.json` for the primary `~/.hermes/cli-config.json` and `.yaml` for the auxiliary `~/.hermes/config.yaml`). Backups written by earlier releases use the older `config-backup-<timestamp>.json` name and remain restorable. Restore with `sanctuary protect --unwrap` from the same fortress/storage context.

For anything not on this list, run `sovereignty_audit` and surface the report to the operator.

---

## Going deeper

Three audiences, three pointers each.

**Operator track:** what this feels like to use.
- ["What Sovereign Actually Means"](https://sanctuaryprotocol.ai/2026/03/30/what-sovereign-actually-means.html): the plain-English version.
- ["Local ≠ Sovereign"](https://sanctuaryprotocol.ai/2026/03/30/local-not-sovereign.html): why running on your laptop isn't enough on its own.
- [sanctuaryprotocol.ai](https://sanctuaryprotocol.ai): ongoing posts in the same voice.

**Developer track:** how it works.
- [CLAUDE.md](CLAUDE.md): complete architecture, security invariants, and threat model.
- [SHR_SPEC.md](docs/SHR_SPEC.md): Sovereignty Health Report format.
- [federation-v0.1-hard-gate-walkthrough.md](server/docs/federation-v0.1-hard-gate-walkthrough.md): federation protocol v0.1 design record.
- [DID_ENCODING.md](docs/DID_ENCODING.md): agent DID encoding (base58btc-compliant `did:key` with legacy base64url migration notes).
- [security audit](docs/audit/): structured review artifacts and remediation history.

**Standards / research track:** where this composes.
- Sanctuary Agent Contract (v0.1 spec, W3C AIVS track, shipping).
- Concordia composition (receipts, negotiation, binding commitments; see the Concordia repo).
- Verascore composition (portable agent reputation; see the Verascore repo).

---

## Interop note: agent DIDs

Sanctuary identifies agents with a `did:key`-style DID derived from the agent's Ed25519 public key, encoded as **base58btc** under the `z` multibase prefix per the W3C `did:key` specification (PR #268). Historical identities created before the base58btc migration may still use the legacy base64url encoding locally; see [`docs/DID_ENCODING.md`](docs/DID_ENCODING.md) for migration notes, the byte layout, and JavaScript and Python decoder snippets with a round-trip verification test.

---

## Contributing

Sanctuary is developed in the open. We welcome:

- **Implementation experience.** Build against the tools, tell us what works and what doesn't.
- **Threat modeling feedback.** Security reviews and gap analysis.
- **Framework integrations.** Bring Sanctuary to other harnesses and agent platforms.
- **Open issues and discussions.** We take feedback seriously.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Local development

On first clone, install the pre-commit hook:

```bash
cd server
npm install
npm run install-hooks
```

`install-hooks` copies `.githooks/pre-commit` into `.git/hooks/pre-commit` and makes it executable. The hook runs two gates on every `git commit`:

1. **Typecheck.** `npm run typecheck` must pass with zero TypeScript errors.
2. **Test baseline guard.** `npm test` must pass; vitest output must not contain any transform/collection error; the number of test files vitest loaded must equal the number of `*.test.ts` files under `server/test/`; the passing-test count must be at least the integer in `.test-baseline` at repo root.

The second gate defends against a failure class documented in [`docs/audit/commit-4ac95830-postmortem.md`](docs/audit/commit-4ac95830-postmortem.md): a parse/transform error silently dropping test files during vitest collection, causing the passing count to look lower without vitest reporting a hard failure.

Total hook runtime: approximately 21 seconds on a modern Mac. Emergency bypass: `SKIP_TEST_BASELINE=1 git commit ...` (logged to `.test-baseline-overrides.log` for audit).

The same two gates run in CI via [`.github/workflows/test-baseline-guard.yml`](.github/workflows/test-baseline-guard.yml) on every PR and push to main. See [`docs/audit/branch-protection-setup.md`](docs/audit/branch-protection-setup.md) for the branch-protection runbook that makes the CI check a hard merge gate.

---

## License

- **Code:** Apache License 2.0
- **Specification:** CC-BY-4.0

Use it, build on it, extend it.

---

**Created by Erik Newton.**
