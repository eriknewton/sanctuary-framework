# Sanctuary

[![CI](https://github.com/eriknewton/sanctuary-framework/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/eriknewton/sanctuary-framework/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@sanctuary-framework/mcp-server.svg)](https://www.npmjs.com/package/@sanctuary-framework/mcp-server)
[![License](https://img.shields.io/npm/l/@sanctuary-framework/mcp-server.svg)](LICENSE)

**Your agent will know you better than you know yourself. Make sure that stays between you.**

Sanctuary is the open source standard for secure, private AI: operating-system enforcement is live on macOS today; Linux and Windows are not live enforcement yet. Your data stays under your own keys, with current portability bounds called out in the Assurance Matrix. Any agent, local or cloud, solo or fleet. One command to get started. One dashboard to secure them all.

Sanctuary wraps any AI agent, on your machine or in your cloud, so actions flow through policy gates, platform-proven walls, operator-held keys, and an audit trail you can actually read. One dashboard manages the security and privacy of every agent you run, whether that is one agent on your laptop or a whole fleet across your machines. Your data, and the reputation your agents build, stay on hardware you control, with exit-bundle gaps still open for dashboard export, skipped import counters, and rotated-key import.

Already running Claude Code, Cursor, Hermes, OpenClaw, Cline, or Mastra?

```bash
npx @sanctuary-framework/mcp-server protect --claude-code
```

That one command puts the keys, audit trail, policy gates, and dashboard around the agent you already use. The operating-system wall is a separate privileged arming step on macOS through the signed app and extension path. See the [Castle Wall macOS install and arm guide](docs/castle-wall-macos-install.md) for the customer path from download to verified armed state. You keep your harness; Sanctuary adds the protection underneath.

**Under the hood:** the macOS wall is drilled on real hardware, signed and notarized, and survives attended reboot cycles; the Linux enforcement modules are integration-proven but the shipped daemon does not yet assemble them into live kernel enforcement. Cryptographic identity and encrypted state remain operator-held, and exit-bundle portability is partial while the remaining exit-bundle gaps above are open. It composes with Concordia (agent negotiation) and Verascore (portable reputation), each in its own repo and neither required.

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

`main` is the development branch. The current stable release is **v1.7.2** on the npm `latest` channel. The macOS Castle Wall app for this release is attached to the GitHub release as `Sanctuary-CastleWall.app.zip`, with SHA-256 `0c09842936ffb9d2d65badd6e00638675fbb91756d0efa1ac2eb6d2032ffb736`. The npm package installs the cooperative Sanctuary surface; the signed macOS app, system extension, signer helper, and root boot service are installed and armed through the separate [Castle Wall macOS install and arm guide](docs/castle-wall-macos-install.md). The macOS Castle Wall bounds remain per-uid allow/deny plus attended boot-survival; there is no per-flow rule-attributed audit trail. See the [v1.7.2 release notes](docs/releases/v1.7.2.md), the [v1.7.1 release notes](docs/releases/v1.7.1.md), and [CHANGELOG.md](CHANGELOG.md) for the full history.

```bash
npm install -g @sanctuary-framework/mcp-server
```

Current capability summary:

| Surface | Current status |
|---|---|
| Local `sanctuary protect` (alias `wrap`), dashboard, policy gates, encrypted state, audit trail, exit bundle | Shipped with exit-bundle gaps: dashboard export cannot re-key state, import hides skipped entries, and rotated-key imports can lose pre-rotation state |
| Cooperative MCP gates: three-tier approval, four canonical policy slots, channel templates | Shipped |
| Context gating, sensitive-field redaction, query-layer anonymity (header strip default-on; opt-in PII rewrite live, classifier surface pinned local-only) | Shipped |
| Portable identity, state export/import, recovery flows, reputation bundles | Partial for exit bundles until **IC-07, IC-08, IC-09** are fixed |
| Local multi-agent coordination, fortress-local hub APIs, audit chain | Shipped with audit-chain verifier caveat: production checkpoints are unsigned. Open defect: **IC-05** |
| Federation Protocol v0.1 foundation | Shipped; cross-operator federation hardening underway per Wave 1 design (2026-05-26) |
| Concordia composition (negotiation receipts), Verascore composition (reputation) | Optional, default off; both shipped |
| Castle Wall (OS-level egress enforcement): Linux | Not implemented. Source modules are integration-proven; the shipped daemon installs no enforcement, so the Assurance Matrix row is `not_implemented` and no claim may trace to it |
| Castle Wall macOS: signed sysext, host app, content-filter provider, retail UX | Shipped; enforces a signed operator policy with a clean per-uid allow/deny demonstration that survives attended reboot cycles (N=5, drill 2026-06-22, one host / one OS version, Dev-ID-signed and notarized). Not an audited per-rule-per-flow trail |
| Castle Wall Windows | Roadmapped |
| Mobile (PWA) operator companion | Roadmapped |
| Fleet console, operator-cloud deployment, sovereign-managed TEE, post-quantum migration | Roadmapped |

Trust and security claims are tracked in the [Sanctuary Assurance Matrix](ASSURANCE_MATRIX.md). Public-facing claims trace to `proven` or `partial` rows in that matrix; the platform, gap, and next-proof limits named on each row are preserved.

Roadmap shape: with the Mac Castle Wall per-uid allow/deny plus attended reboot-survival demonstration proven, the current focus is the per-flow rule-attributed audit trail (still the real gap), the Castle Wall Windows backend, and the fleet / operator-cloud surfaces. See [ROADMAP.md](ROADMAP.md).

Supply-chain posture: release binaries for the macOS enforcement path are Dev-ID-signed and notarized, the CLI authenticates update availability with a signed release manifest before showing signed-channel advice, and every commit to main passes a structural typecheck-plus-test-baseline gate locally and again in CI. Sanctuary does not currently download or apply updates for the operator. Mechanisms and their history: [CHANGELOG.md](CHANGELOG.md) and [docs/audit/](docs/audit/).

---

## For AI coding agents installing Sanctuary on behalf of an operator

Do not translate the manual Castle Wall reference into a pile of shell
commands. Use the resumable observed-state contract:

```bash
sanctuary install --profile memory --harness claude-code --json
```

For the full macOS sovereignty surface, use Hermes:

```bash
sanctuary install --profile full --harness hermes --json
```

Execute only an `agent_action` argument vector, then rerun the same planner.
Stop on `human_action` and guide the operator through the named Apple consent,
exact privileged command, or private custody step. Never execute a human action
on the operator's behalf.
Stop on `blocked` and report the missing trust input rather than improvising.
Installation is mechanically finished only at `complete`.

The operator, not the agent, performs three things: Apple consent, bounded
privilege authorization, and private recovery custody. In particular, never read
the staged recovery file, run `sanctuary export-passphrase`, capture secret
output, or ask the operator to paste recovery material into chat. The passphrase
stays in the platform credential store; `--agent-guided` stages the recovery key
outside the fortress without printing it.

The `memory` profile is the sovereign encrypted-memory/cooperative-policy rung.
The `full` profile adds the signed macOS app, dedicated Hermes account, boot
service, content filter, and observed live enforcement. The full planner does
not download an enforcement binary or guess its provenance; a verified signed
release artifact or explicitly supplied drill candidate must already be
installed. See [Agent-guided installation](docs/agent-guided-install.md) for the
contract and cold-install acceptance criterion.

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

Sanctuary ships channel-shape governance templates (policy, egress, budgets, retention) instead of named-agent runtimes. Operators bring their own harnesses and protect them; `template init` binds a channel shape to an already-wrapped harness.

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
| **On your machines** (Local) | Shipping | Runs on the Macs, Linux boxes, or Windows machines you already own. On macOS with the wall armed, unauthorized outbound is blocked below the agent; on Linux and Windows today this is cooperative policy-gating plus local custody. | Self-hosters, privacy-maximalists, anyone who already runs a homelab. |
| **In your cloud** (Operator cloud) | Roadmapped | Runs in your own GCP / Azure / AWS account with operator-approved scoped node custody. The provider is inside the node runtime trust boundary until sovereign TEE mode is verified by hardware attestation. | Prosumers, small businesses, operators with light IT but no rack at home. |
| **In a sealed cloud box we manage** (Sovereign-managed TEE) | Roadmapped (v2) | Runs on hardware Sanctuary operates, but the hardware proves to your console that even Sanctuary cannot see what's inside. You hold the keys; we hold the metal. | Regulated industries, operators who want sovereignty without operational burden. |

The operator remains the custody root in every mode. Commodity operator-cloud mode does not put the cloud provider outside the runtime trust boundary; sovereign-managed mode requires hardware attestation before it is treated as shipped.

---

## The Castle Architecture

Sanctuary installs the protections your body used to provide by default: a perimeter, custody, memory, and a record of what happened. Everything it protects for you together is **your Sanctuary**: each machine is a rampart the Castle Wall holds, each fortress is a keep inside those walls, and each agent is a resident of exactly one keep. The unit never blurs: one agent, one account, one fortress, one master key. Architecturally it ships as five named mechanisms.

**Castle Wall: the perimeter.** What the world cannot cross without your consent. OS-level egress enforcement at the operator-external boundary. macOS enforces a signed operator policy with a proven per-uid allow/deny demonstration that survives attended reboot cycles, captured on a real host (drills 2026-06-11 through 2026-06-22, boot survival 5 of 5 on a Dev-ID-signed and notarized binary): agent egress to a non-allowlisted address blocked, allowlisted egress allowed, operator egress unaffected, and enforcement live again after every attended reboot. Linux ships no egress enforcement: the tested nftables, cgroup, and NFQUEUE modules are not wired into the shipped daemon boot path, and the Assurance Matrix row is `not_implemented`. The macOS proof is one host and one OS version, not an audited per-rule-per-flow trail. Windows on the roadmap.

**Sentinels: the nerves.** What surfaces what's happening to your awareness. Internal observation via process introspection and behavioral baselining. Anomalies surface through the menubar or notifications. Observation, not enforcement.

**Charter: the will.** What you train your agent to choose voluntarily. The additive cooperative MCP surface for compliant agents. Operator-rooted cryptographic identity (Ed25519 signing, Argon2id passphrase unlock, per-purpose HKDF subkeys). Per-agent encrypted state at rest (AES-256-GCM). Three-tier Principal Policy gates with channel-template binding. Hash-chained audit with rollback detection. Production audit checkpoints are currently unsigned until **IC-05** closes. Open defect: **IC-05**.

**Heralds: the voice.** How you speak to and are recognized by other sovereigns. Optional composition surface (Concordia for structured negotiation, Verascore for portable reputation). Receipts and reputation attestations can be exported through current paths; the full exit guarantee remains partial while the remaining exit-bundle gaps are open. Default off; both compositions are optional.

**Mantle: the unique-substrate-binding.** What makes this install yours, not someone else's. Install-time check that locks Sanctuary to the operator's machine at install time and rejects orphan agent identifiers that are not bound to a wrapped harness.

**Today:** Ed25519 signing, Argon2id passphrase unlock, and per-purpose HKDF subkeys. **Crypto-agility:** every audit entry embeds a scheme identifier so hybrid post-quantum signing (Ed25519 + ML-DSA / FIPS 204) can land without breaking historical receipts. Hardware-backed secure elements are on the roadmap.

**Working on the code?** The TypeScript server has an orientation map at [`server/src/README.md`](server/src/README.md) - a 56-module index of what each module owns, the confusable-name disambiguations, and the frozen surfaces a refactor must never change. Start there, then see [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## The rights you hold by default

The substrate enforces rights that normally only ship to enterprises with dedicated identity and security teams. What they mean for you:

- **Identity.** Your agent has a key you own. No provider can impersonate you or revoke your agent. You can prove the agent is yours without asking anyone's permission.
- **Data.** Your agent's state is encrypted against the provider running it. The platform sees the calls going out; it does not see your life going in. Your conversations, your memory, and your plans stay yours.
- **Portability.** Your agent's memory, reputation, and commitments travel through current export paths, with exit-bundle gaps still open for dashboard export, skipped import counters, and rotated-key imports.
- **Attestation.** What your agent did is provable through hash-chained audit entries and signed receipt surfaces. Production audit checkpoints are currently unsigned.
- **Exit.** Keys, state, reputation, and commitments are yours to move, copy, or keep offline through the shipped paths, with the full exit guarantee partial while the remaining exit-bundle gaps are open.

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

**Sanctuary never requires Concordia, and Concordia never requires Sanctuary.** They compose powerfully when both are deployed: Concordia commitment receipts flow through Sanctuary envelopes, and reputation attestations assemble into a single audit trail. Each ships, runs, and wins on its own. The structural commitment shows up in the repos themselves. Neither repo imports the other.

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

**Trust-bearing writes are FROZEN, or a `custody_rollback_suspected` audit finding appears:**
- Sanctuary noticed the fortress looks older than its surviving custody evidence says it should be, which is what a restore looks like from the inside. A Time Machine restore, backup restore, dotfile sync, or cloning to a new machine all trigger this, and you may not have done it knowingly (a migration assistant or sync tool counts). The server keeps running; only trust-bearing writes are held until you acknowledge the restore. Follow the [Restore and recovery section of the Castle Wall macOS install guide](docs/castle-wall-macos-install.md#restore-and-recovery): run `sanctuary restore-attest` with the fortress passphrase to record the restore and unfreeze writes.
- If you did not restore anything, treat the freeze as suspicious and rotate the master before attesting.

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

You never need to edit `.test-baseline` yourself. A pull request that adds tests simply counts higher than the floor and passes; after it merges, a job in the same workflow opens a one-line pull request recording the observed count, which merges itself once the usual checks pass. The one exception is a deliberate removal of platform-agnostic tests, which lowers the floor by hand in an explicitly scoped commit with a written justification. Background: [`docs/audit/test-baseline-hardening-plan.md`](docs/audit/test-baseline-hardening-plan.md).

---

## License

- **Code:** Apache License 2.0
- **Specification:** CC-BY-4.0

Use it, build on it, extend it.

---

**Created by Erik Newton.**
