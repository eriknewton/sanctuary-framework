# Sanctuary Framework

**Your agent. Your machine. Your keys.**

Sanctuary puts cryptographic walls around every AI agent in your life and gives you the keys. Your agents run on your machines today, with operator-cloud and sovereign-managed deployment modes on the roadmap. Every action an agent takes is signed with a per-agent identity rooted in keys you hold, gated by policy you control, and logged to a portable audit trail. You don't have to give up the tools you already use: `sanctuary wrap` adds sovereignty underneath your existing harness, invisibly.

### Why this matters

Most AI infrastructure monetizes something the operator cannot take with them: platform lock-in, inference margin, managed-cloud rent, training-data extraction, or custodial settlement. Operator-owned keys undermine every one of those revenue models. That is the business-model wedge. Features get copied; a business model that runs against the vendor's own does not.

The conversation UI is the easy part. Sanctuary is the version where you own the keys, every message is signed with the agent's cryptographic identity rooted in yours, and you can move agents between machines without losing the audit trail or commitment records.

---

## Release status

`main` is the development branch. The current release candidate is `v1.0.0-rc.2` on the npm `next` tag. The default npm `latest` channel remains `0.10.6` until the v1.0 pilot acceptance drill clears.

```bash
# Current stable channel
npm install -g @sanctuary-framework/mcp-server

# v1.0 release-candidate channel
npm install -g @sanctuary-framework/mcp-server@next
```

Current capability summary:

| Surface | Current status |
|---|---|
| Local `sanctuary wrap`, dashboard, policy gates, encrypted state, audit trail | Shipped / in v1.0 acceptance |
| Context gating and sensitive-field redaction | Shipped foundation; v1.1 query minimization / Anonymized Query Mode completion remains open |
| Portable identity, state export/import, reputation bundles, Concordia composition | Shipped foundation; polished exit workflow remains open |
| Operator-agent communication and local multi-agent coordination | Shipped foundation; complete local sovereignty harness is v1.1 |
| Mobile operator companion | v1.2 roadmap |
| Public federation | Federation v0.1 foundation shipped; public cross-operator coordination is v1.3 |
| Fleet, payments, compliance, operator-cloud, generalized transport interception | v1.4+ roadmap |
| Sovereign-managed TEE and hardware secure elements | v2 roadmap |
| Post-quantum and next-generation messaging-layer-security cryptographic upgrades | v1.4+ roadmap |

Roadmap shape: v1.1 completes the local sovereignty harness; v1.2 adds the phone as the operator companion; v1.3 opens public federation for cross-operator agent interaction; v1.4+ carries fleet, payments, compliance, generalized transport interception, operator-cloud, and advanced cryptography. See [ROADMAP.md](ROADMAP.md).

---

## For AI coding agents installing Sanctuary on behalf of an operator

If you are an LLM-powered coding agent (OpenClaw, Hermes Agent, Claude Code, Cursor, Cline, Codex, or any other harness with shell access) and an operator has asked you to install Sanctuary, follow this section first. Humans can skip to "Wrap any harness in one command" below; you will arrive at the same commands.

**Operator-facing summary first.** Before running anything, give the operator one paragraph:
> "Sanctuary will wrap your existing AI agent so every action it takes is signed with keys you hold and logged to a portable audit trail. Install takes about a minute. I will: (1) detect which agent harness you are running, (2) run one wrap command, (3) confirm the dashboard is live, (4) optionally scaffold your first sub-agent template. Approve to proceed."

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
```

If multiple match, ask the operator which one to wrap. If none match, the operator does not have a recognized harness installed; offer to install one or use the raw MCP server path (Step 4 below).

### Step 2: Run the wrap command

```bash
npx @sanctuary-framework/mcp-server wrap --<harness>
```

Substitute `<harness>` with the value detected in Step 1: `openclaw`, `hermes`, `claude-code`, `cursor`, or `cline`. For any harness not in that list, see Step 4.

Wait for the command to complete (typically 20-40 seconds). Expected output ends with a line like:

```
Sovereignty Dashboard ready: http://localhost:3501
```

Note the port (it may be 3501-3510 if 3501 is taken).

### Step 3: Verify the install

After Step 2 (wrap succeeds), the dashboard is running. Verify the install:

```bash
# (a) Dashboard responds
curl -fsS "http://localhost:3501/api/health" | grep -q '"status":"ok"' && echo "dashboard=ok"

# (b) Passphrase backed up to keychain (macOS)
security find-generic-password -s "sanctuary-passphrase" >/dev/null 2>&1 && echo "passphrase=ok"
```

The first time you open the Sovereignty Dashboard in your browser, Sanctuary derives your master key from the keychain-stored passphrase, creates your fortress's Ed25519 identity, and writes the audit log genesis. Wrap configures these on disk; the first dashboard unlock initializes them. Verify after first unlock:

```bash
# (c) Identities loaded (run after opening the dashboard once)
curl -fsS "http://localhost:3501/api/identities" | grep -q '"identities":\[' && echo "identities=ok"

# (d) Audit log initialized (run after opening the dashboard once)
test -d ~/.sanctuary/state/_audit && echo "audit=ok"
```

If any check fails, see "Troubleshooting" near the bottom of this README.

### Step 4: Scaffold the operator's first governed harness (recommended)

After the wrap succeeds, ask the operator: "Which channel shape do you want on this harness? I have one-click archetypes for research-assistant, coding-assistant, ops-runner, planner, and handoff-coordinator. Or I can skip this step."

If they pick an archetype, run:

```bash
curl -X POST "http://localhost:3501/api/templates/<template-name>/init" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "<already-wrapped-agent-id>",
    "model_provider": "<xai|anthropic|openai|mistral>"
  }'
```

Substitute `<template-name>` with the archetype the operator picked (`research-assistant`, `coding-assistant`, etc.). The `agent_name` must match an already-wrapped harness; `template init` rejects an orphan `agent_id` with no Mantle behind it and points the operator at `sanctuary wrap`. Confirm the response includes a `signed_policy_event_id` and an `attestation_panel_url`. Open that URL in the operator's browser.

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
  "args": ["@sanctuary-framework/mcp-server"],
  "env": {
    "SANCTUARY_PASSPHRASE": "<generated-passphrase>"
  }
}
```

Generate the passphrase with `openssl rand -base64 32` and store it in the operator's keychain or password manager.

---

## Wrap any harness in one command

Already running an agent on OpenClaw, Hermes, Claude Code, Cursor, or Cline? One command wraps it in Sanctuary's policy gates and audit trail (the audit log writes its genesis on your first dashboard unlock), starts the Sovereignty Dashboard, and opens it in your browser.

```bash
npx @sanctuary-framework/mcp-server wrap --openclaw
```

Or substitute `--hermes`, `--claude-code`, `--cursor`, `--cline`, or `--wrap <path-to-config>` for any other MCP-compatible harness.

You keep using the harness you already like. Sanctuary adds sovereignty underneath, invisibly.

What happens when you run wrap:

1. A passphrase is generated and stored in the macOS Keychain (or an encrypted fallback file on Linux/Windows).
2. Your existing harness config is backed up to `~/.sanctuary/backup/`.
3. The config is rewritten so every tool call routes through Sanctuary.
4. The Sovereignty Dashboard starts on `http://localhost:3501` (or the next free port up to 3510) and opens in your browser with a one-click auth token.
5. Every call is logged, scanned for injection, and policy-gated. Dangerous operations require your approval.

Useful flags: `--dry-run` previews changes without touching anything; `--no-open` runs headless for CI; `--unwrap` restores the original harness config.

**Back up your passphrase:**

```bash
sanctuary export-passphrase
```

Prints the passphrase to stdout after a confirmation prompt. Store it in a password manager. If you lose it, encrypted state cannot be recovered.

---

## Installation reference

**Requirements:** Node.js >= 22.0.0, npm >= 10.0.0.

The canonical install path is `sanctuary wrap` (above). The sections below are reference for less common situations.

### Persistent install

```bash
npm install -g @sanctuary-framework/mcp-server
```

Makes the `sanctuary` CLI available without `npx` prefix.

### Manual MCP config

If you prefer to edit your harness MCP config by hand:

```bash
# OpenClaw
openclaw mcp set sanctuary '{"command":"npx","args":["@sanctuary-framework/mcp-server"],"env":{"SANCTUARY_PASSPHRASE":"your-passphrase-here"}}'

# Hermes Agent
hermes mcp set sanctuary '{"command":"npx","args":["@sanctuary-framework/mcp-server"],"env":{"SANCTUARY_PASSPHRASE":"your-passphrase-here"}}'

# Claude Code
claude mcp add sanctuary -- npx @sanctuary-framework/mcp-server
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

Scores your setup 0-100 across security, isolation, and privacy. Detects problems and tells you exactly what to fix. Available as both a CLI command and an MCP tool inside any wrapped harness.

---

## First agent after install: scaffold a template

After `wrap`, the dashboard exposes a one-click template picker. Click "Add agent" on the Agents view, pick a template, fill in a name and model provider, click Scaffold. The template provisions sensible defaults for egress allowed-hosts, budgets, retention windows, and policy gates.

Channel-shape archetypes that ship with v1.0:

| Archetype | Channel shape | Reads from | Recommended model |
|---|---|---|---|
| **research-assistant** | General-purpose research helper | configurable | any |
| **coding-assistant** | Reads your codebase, suggests changes | local + git remote | any |
| **ops-runner** | Runs ops scripts on approval | scoped per agent | any |
| **planner** | Generates plans without executing them | none | any |
| **handoff-coordinator** | Coordinates work across multiple agents | inter-agent only | any |

Sanctuary ships channel-shape governance templates (policy, egress, budgets, retention) rather than named-agent runtimes. Operators bring their own harnesses and wrap them; `template init` binds a channel shape to an already-wrapped harness.

Operator authoring beyond this list: copy any template directory under `~/.sanctuary/templates/`, edit `template.json`, `defaults.json`, `policy.md`, `commitments.json`, and `onboarding.md`, then run `sanctuary template init <your-template>`.

CLI scaffolding works the same way the dashboard button does:

```bash
sanctuary template init research-assistant --name my-agent --provider anthropic
```

---

## Deployment modes

Sanctuary is designed to run the same rights substrate in three places. The local mode is the v1.0 acceptance surface and v1.1 completion surface; operator-cloud and sovereign-managed TEE modes are later roadmap surfaces that build on the same federation and policy foundations.

| Mode | Status | What it is | Who picks this |
|---|---|---|---|
| **On your machines** (Local) | v1.0 acceptance | Runs on the Macs, Linux boxes, or Windows machines you already own. Nothing leaves your house unless you tell it to. | Self-hosters, privacy-maximalists, anyone who already runs a homelab. |
| **In your cloud** (Operator cloud) | v1.4+ roadmap | Runs in your own GCP / Azure / AWS account. Same code, same keys, on rented hardware you control. | Prosumers, small businesses, operators with light IT but no rack at home. |
| **In a sealed cloud box we manage** (Sovereign-managed TEE) | v2 roadmap | Runs on hardware Sanctuary operates, but the hardware proves to your console that even Sanctuary cannot see what's inside. You hold the keys; we hold the metal. | Regulated industries, operators who want sovereignty without operational burden. |

The operator holds the keys in every mode. The sovereign-managed mode will require hardware attestation before it is treated as shipped.

---

## The four-layer architecture

A fortress. Walls separate the inside from the outside. Gates let specific things through under specific conditions. The drawbridge handles the outside world deliberately, and lockdown drops it under attack. The chronicle keeps the permanent record.

| Layer | What it does |
|---|---|
| **L1: Cognitive Sovereignty** (walls) | Operator-rooted cryptographic identity. Per-agent HKDF-derived keys. Ed25519 signing. AES-256-GCM state at rest. No vendor holds the root. |
| **L2: Operational Isolation** (gates) | Policy compiled to a deterministic rule engine, signed and pinned to the agent before it runs. Egress proxy enforces rate limits, budgets, retention, and sensitive-topic gates. Tool calls pass approval gates scoped by policy. |
| **L3: Selective Disclosure** (drawbridge) | Every external contact (A2A message, MCP tool call, x402 payment, ERC-8004 attestation, AP2 mandate) goes out through a disclosure envelope signed by the agent's derived key. The envelope carries only what policy permits. Lockdown drops egress mid-flight under attack. |
| **L4: Verifiable Reputation** (chronicle) | Portable, append-only, signed audit trail. Travels with the agent across machines. Every action, every commitment, every attestation, recorded and verifiable. |

**Today:** Ed25519 signing, Argon2id passphrase unlock, and per-purpose HKDF subkeys. **Crypto-agility:** every audit entry embeds a scheme identifier so hybrid post-quantum signing (Ed25519 + ML-DSA / FIPS 204) can land without breaking historical receipts. Hardware-backed secure elements are on the v2 roadmap.

---

## The rights you hold by default

Rights that normally only ship to enterprises with dedicated identity and security teams, embedded in an open-source product every operator can run. The four-layer architecture enforces them; this is what they mean for the operator.

- **Identity.** Your agent has a key you own. No provider can impersonate you or revoke your agent. You can prove the agent is yours without asking anyone's permission.
- **Data.** Your agent's state is encrypted against the provider running it. The platform sees the calls going out; it does not see your life going in. Your conversations, your memory, and your plans stay yours.
- **Portability.** Your agent's memory, reputation, and commitments travel with you. If a provider goes bad, raises prices, or shuts down, you leave without losing what you built.
- **Attestation.** What your agent did is provable. To you, to a third party, to a court if it comes to that. The audit log is signed, append-only, and portable.
- **Exit.** Nothing you build up is locked to a platform that can revoke it. Keys, state, reputation, and commitments are yours to move, copy, or keep offline.

Sanctuary ships the rights substrate. Access (compute, devices, bandwidth, literacy) belongs to civic-infrastructure partners (public libraries, legal-aid organizations, labor unions, public-interest tech groups, community colleges) who host agentic AI on behalf of users who do not self-host. The partner provides access; Sanctuary provides rights. The two compose; they do not substitute.

---

## Works with

Sanctuary wraps any MCP-compatible harness:

- **OpenClaw** (`sanctuary wrap --openclaw`)
- **Hermes Agent** (`sanctuary wrap --hermes`)
- **Claude Code** (`sanctuary wrap --claude-code`)
- **Cursor** (`sanctuary wrap --cursor`)
- **Cline** (`sanctuary wrap --cline`)
- **Mastra**, **LangGraph**, and custom harnesses (`sanctuary wrap --wrap <path>`)
- Any other MCP-compatible harness via direct MCP config

---

## Composes with Concordia Protocol

When your agent needs to negotiate or make deals, **Concordia Protocol** adds structured negotiation with binding commitments and portable reputation.

**Sanctuary never requires Concordia, and Concordia never requires Sanctuary.** They compose powerfully when both are deployed: Concordia commitment receipts flow through Sanctuary envelopes, and reputation attestations assemble into a single audit trail. Each ships, runs, and wins on its own. This is a structural commitment, not a tagline. Neither repo imports the other.

Install both if you want the full stack:

```bash
npx @sanctuary-framework/mcp-server
pip install concordia-protocol
```

---

## Open standards

Sanctuary composes with the existing open ecosystem.

- **Identity:** W3C DIDs, KERI, Verifiable Credentials
- **Execution:** Trusted Execution Environments (Intel TDX, AMD SEV-SNP, ARM CCA) on the v2 roadmap
- **Cryptography:** Ed25519 today; NIST Post-Quantum Cryptography (ML-DSA / FIPS 204, ML-KEM / FIPS 203) on the migration path; hybrid signing planned after the local sovereignty harness is complete
- **Settlement:** x402 (Coinbase micropayments), AP2 (Google Agent Payments Protocol), ACP

---

## Troubleshooting

For AI coding agents handling install failures, here are the common cases.

**Install Step 3 (a) "dashboard=ok" check fails:**
- Wait 10 seconds and retry. Dashboard takes a moment to bind on first launch.
- If still failing, check `lsof -i :3501-3510` to confirm the dashboard chose a port. The wrap output line `Sovereignty Dashboard ready: http://localhost:<port>` is authoritative; use that port.

**Install Step 3 (b) "identities=ok" check fails:**
- Confirm `wrap` completed without error. If it did, check `~/.sanctuary/identities/` for `.enc` files. If absent, the wrap command exited early; rerun with `--dry-run` to see what it would do, then without to retry.

**Install Step 3 (c) "passphrase=ok" check fails on macOS:**
- The wrap command may have failed to write to the Keychain (typically a permissions prompt the operator dismissed). Rerun the wrap command and approve the Keychain prompt when it appears.

**Install Step 3 (c) on Linux or Windows:**
- The keychain check is macOS-specific. On Linux, Sanctuary uses Secret Service when available and falls back to an encrypted file at `~/.sanctuary/passphrase.enc`. Windows Credential Manager support is queued on the v1.0.x patch track. Test the fallback with `test -f ~/.sanctuary/passphrase.enc && echo "passphrase=ok"`.

**Install Step 3 (d) "audit=ok" check fails:**
- Confirm `~/.sanctuary/` exists and is writable by the current user. If it doesn't exist, the wrap did not complete; rerun.
- Audit entries are stored encrypted under `~/.sanctuary/state/_audit/`, not as plaintext JSONL. Use `audit_export_siem` when you need a decrypted export.

**`sanctuary` CLI not found after `npm install -g`:**
- Confirm `npm bin -g` is on the PATH. On macOS with nvm, this typically lives at `~/.nvm/versions/node/<version>/bin/`.

**Existing harness config overwritten:**
- The original is at `~/.sanctuary/backup/config-backup-<timestamp>.json`. Restore with `sanctuary wrap --unwrap` from the same fortress/storage context.

For anything not on this list, run `sovereignty_audit` and surface the report to the operator.

---

## Going deeper

Three audiences, three pointers each.

**Operator track:** what this feels like to use:
- ["What Sovereign Actually Means"](https://sanctuaryprotocol.ai/2026/03/30/what-sovereign-actually-means.html): the plain-English version
- ["Local ≠ Sovereign"](https://sanctuaryprotocol.ai/2026/03/30/local-not-sovereign.html): why running on your laptop isn't enough on its own
- [sanctuaryprotocol.ai](https://sanctuaryprotocol.ai): ongoing posts in the same voice

**Developer track:** how it works:
- [CLAUDE.md](CLAUDE.md): complete architecture, security invariants, and threat model
- [SHR_SPEC.md](docs/SHR_SPEC.md): Sovereignty Health Report format
- [federation-v0.1-hard-gate-walkthrough.md](server/docs/federation-v0.1-hard-gate-walkthrough.md): federation protocol v0.1 design record
- [DID_ENCODING.md](docs/DID_ENCODING.md): agent DID encoding and the base64url deviation from `did:key`
- [security audit](docs/audit/): structured review artifacts and remediation history

**Standards / research track:** where this composes:
- Sanctuary Agent Contract (v0.1 spec, W3C AIVS track, shipping)
- Concordia composition (receipts, negotiation, binding commitments; see the Concordia repo)
- Verascore composition (reputation scoring on top of ERC-8004; see the Verascore repo)

---

## Interop note: agent DIDs

Sanctuary identifies agents with a `did:key`-style DID derived from the agent's Ed25519 public key. The encoding uses **base64url** under the `z` multibase prefix rather than base58btc, a deliberate departure from the W3C `did:key` specification. To verify a signature against a Sanctuary DID or transcode to strict `did:key` form, see [`docs/DID_ENCODING.md`](docs/DID_ENCODING.md). It includes the byte layout, JavaScript and Python decoder snippets, and a round-trip verification test.

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
