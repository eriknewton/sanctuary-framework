# Sanctuary Framework

**Your agent. Your machine. Your keys.**

Sanctuary puts cryptographic walls around every AI agent in your life — and gives you the keys. Your agents run on your machines, in your cloud, or in a sealed cloud box we manage. Every action an agent takes is signed with a per-agent identity rooted in keys you hold, gated by policy you control, and logged to a portable audit trail. You don't have to give up the tools you already use: `sanctuary wrap` adds sovereignty underneath your existing harness, invisibly.

### Why this matters

Most AI infrastructure monetizes something the operator cannot take with them — platform lock-in, inference margin, managed-cloud rent, training-data extraction, or custodial settlement. Operator-owned keys undermine every one of those revenue models. That is the business-model wedge. Features get copied; a business model that runs against the vendor's own does not.

The conversation UI is the easy part. Sanctuary is the version where you own the keys, every message is signed with the agent's cryptographic identity rooted in yours, and you can move agents between machines without losing the audit trail or commitment records.

---

## Wrap any harness in one command

Already running an agent on a Claude Code, OpenClaw, or Cursor harness? One command wraps it in Sanctuary's policy gates and audit log, starts the Sovereignty Dashboard, and opens it in your browser.

```bash
npx @sanctuary-framework/mcp-server wrap --openclaw
```

You keep using the harness you already like. Sanctuary adds sovereignty underneath, invisibly.

**Before (four steps):**

```bash
export SANCTUARY_PASSPHRASE=$(openssl rand -base64 32)
npx @sanctuary-framework/mcp-server cocoon --openclaw
npx @sanctuary-framework/mcp-server dashboard --port 3501
open http://localhost:3501
```

**After (one step):**

```bash
npx @sanctuary-framework/mcp-server wrap --openclaw
# → browser opens automatically, dashboard running, agent protected
```

What happens:

1. A passphrase is generated and stored in the macOS Keychain (or an encrypted fallback file on Linux/Windows).
2. Your existing harness config is backed up to `~/.sanctuary/backup/`.
3. The config is rewritten so every tool call routes through Sanctuary.
4. The Sovereignty Dashboard starts on `http://localhost:3501` (or the next free port up to 3510) and opens with a one-click auth token.
5. Every call is logged, scanned for injection, and policy-gated. Dangerous operations require your approval.

Supports `--openclaw`, `--claude-code`, `--cursor`, and `--wrap <path>`. Add `--dry-run` to preview, `--no-open` for CI/headless, or `--unwrap` to restore the original config.

**Back up your passphrase:**

```bash
sanctuary export-passphrase
```

Prints the passphrase to stdout after a confirmation prompt. Store it in a password manager — if you lose it, encrypted state cannot be recovered.

---

## Installation

**Requirements:** Node.js >= 22.0.0, npm >= 10.0.0.

### Canonical path — `sanctuary wrap`

```bash
npx @sanctuary-framework/mcp-server wrap --openclaw
```

`sanctuary wrap` is the one-command install for Claude Code, OpenClaw, and Cursor. It generates keys, patches the harness config, starts the dashboard, and opens your browser. See the section above for the full list of supported harnesses and flags.

### Raw MCP server — for custom integrations

If you're wiring Sanctuary into a harness `wrap` doesn't cover yet, run the MCP server directly:

```bash
npx @sanctuary-framework/mcp-server
```

The dashboard appears at `http://localhost:3501`.

**Persistent install:**

```bash
npm install -g @sanctuary-framework/mcp-server
```

**MCP config, by hand:**

```bash
# Claude Code
claude mcp add sanctuary -- npx @sanctuary-framework/mcp-server

# OpenClaw
openclaw mcp set sanctuary '{"command":"npx","args":["@sanctuary-framework/mcp-server"],"env":{"SANCTUARY_PASSPHRASE":"your-passphrase-here"}}'
```

Generate a passphrase before first launch:

```bash
openssl rand -base64 32
```

Store it securely — it derives the encryption keys for all persistent state. If lost, encrypted state cannot be recovered.

### Health check

```bash
sovereignty_audit
```

Scores your setup 0–100 across security, isolation, and privacy. Detects problems and tells you exactly what to fix.

---

## Three deployment modes, one console

Sanctuary runs the same code in three places. One console speaks to all three. Mix modes as you like — the operator picks per workload.

| Mode | What it is | Who picks this |
|---|---|---|
| **On your machines** (Local) | Runs on the Macs, Linux boxes, or Windows machines you already own. Nothing leaves your house unless you tell it to. | Self-hosters, privacy-maximalists, anyone who already runs a homelab. |
| **In your cloud** (Operator cloud) | Runs in your own GCP / Azure / AWS account. Same code, same keys, on rented hardware you control. | Prosumers, small businesses, operators with light IT but no rack at home. |
| **In a sealed cloud box we manage** (Sovereign-managed TEE) | Runs on hardware Sanctuary operates — but the hardware proves to your console that even Sanctuary cannot see what's inside. You hold the keys; we hold the metal. | Regulated industries, operators who want sovereignty without operational burden. |

The operator holds the keys in every mode. The sovereign-managed mode uses hardware attestation to prove the vendor cannot see the workload.

---

## The four-layer architecture

A fortress. Walls separate the inside from the outside. Gates let specific things through under specific conditions. The drawbridge handles the outside world deliberately, and lockdown drops it under attack. The chronicle keeps the permanent record.

| Layer | What it does |
|---|---|
| **L1: Cognitive Sovereignty** (walls) | Operator-rooted cryptographic identity. Per-agent HKDF-derived keys. Ed25519 signing. AES-256-GCM state at rest. No vendor holds the root. |
| **L2: Operational Isolation** (gates) | Policy compiled to a deterministic rule engine, signed and pinned to the agent before it runs. Egress proxy enforces rate limits, budgets, retention, and sensitive-topic gates. Tool calls pass approval gates scoped by policy. |
| **L3: Selective Disclosure** (drawbridge) | Every external contact — A2A message, MCP tool call, x402 payment, ERC-8004 attestation, AP2 mandate — goes out through a disclosure envelope signed by the agent's derived key. The envelope carries only what policy permits. Lockdown drops egress mid-flight under attack. |
| **L4: Verifiable Reputation** (chronicle) | Portable, append-only, signed audit trail. Travels with the agent across machines. Every action, every commitment, every attestation — recorded and verifiable. |

**Today:** Ed25519 signing, Argon2id passphrase unlock, per-purpose HKDF subkeys, hardware-backed secure-element support where available. **Crypto-agility:** every audit entry embeds a scheme identifier so hybrid post-quantum signing (Ed25519 + ML-DSA / FIPS 204) can land without breaking historical receipts.

---

## Works with

Sanctuary wraps any MCP-compatible harness:

- **Claude Code** (one-command wrap via `sanctuary wrap --claude-code`)
- **OpenClaw** (`sanctuary wrap --openclaw`)
- **Cursor** (`sanctuary wrap --cursor`)
- **Cline**, **Mastra**, **LangGraph**, and custom harnesses (`sanctuary wrap --wrap <path>`)
- Any other MCP-compatible harness via direct MCP config

---

## Composes with Concordia Protocol

When your agent needs to negotiate or make deals, **Concordia Protocol** adds structured negotiation with binding commitments and portable reputation.

**Sanctuary never requires Concordia, and Concordia never requires Sanctuary.** They compose powerfully when both are deployed — Concordia commitment receipts flow through Sanctuary envelopes, and reputation attestations assemble into a single audit trail — but each ships, runs, and wins on its own. This is a structural commitment, not a tagline. Neither repo imports the other.

Install both if you want the full stack:

```bash
npx @sanctuary-framework/mcp-server
pip install concordia-protocol
```

---

## Open standards

Sanctuary composes with the existing open ecosystem.

- **Identity:** W3C DIDs, KERI, Verifiable Credentials
- **Execution:** Trusted Execution Environments — Intel TDX, AMD SEV-SNP, ARM CCA
- **Cryptography:** Ed25519 today; NIST Post-Quantum Cryptography (ML-DSA / FIPS 204, ML-KEM / FIPS 203) on the migration path — hybrid signing planned for v1.x
- **Settlement:** x402 (Coinbase micropayments), AP2 (Google Agent Payments Protocol), ACP

---

## Going deeper

Three audiences, three pointers each.

**Operator track** — what this feels like to use:
- ["What Sovereign Actually Means"](https://sanctuaryprotocol.ai/2026/03/30/what-sovereign-actually-means.html) — the plain-English version
- ["Local ≠ Sovereign"](https://sanctuaryprotocol.ai/2026/03/30/local-not-sovereign.html) — why running on your laptop isn't enough on its own
- [sanctuaryprotocol.ai](https://sanctuaryprotocol.ai) — ongoing posts in the same voice

**Developer track** — how it works:
- [CLAUDE.md](CLAUDE.md) — complete architecture, security invariants, and threat model
- [SHR_SPEC.md](docs/SHR_SPEC.md) — Sovereignty Health Report format
- [federation-v0.1-hard-gate-walkthrough.md](server/docs/federation-v0.1-hard-gate-walkthrough.md) — federation protocol v0.1 design record
- [DID_ENCODING.md](docs/DID_ENCODING.md) — agent DID encoding and the base64url deviation from `did:key`
- [security audit](docs/audit/) — structured review artifacts and remediation history

**Standards / research track** — where this composes:
- Sanctuary Agent Contract (v0.1 spec, W3C AIVS track — shipping)
- Concordia composition — receipts, negotiation, binding commitments (see the Concordia repo)
- Verascore composition — reputation scoring on top of ERC-8004 (see the Verascore repo)

---

## Interop note — agent DIDs

Sanctuary identifies agents with a `did:key`-style DID derived from the agent's Ed25519 public key. The encoding uses **base64url** under the `z` multibase prefix rather than base58btc, a deliberate departure from the W3C `did:key` specification. To verify a signature against a Sanctuary DID or transcode to strict `did:key` form, see [`docs/DID_ENCODING.md`](docs/DID_ENCODING.md) — it includes the byte layout, JavaScript and Python decoder snippets, and a round-trip verification test.

---

## Contributing

Sanctuary is developed in the open. We welcome:

- **Implementation experience** — build against the tools, tell us what works and what doesn't
- **Threat modeling feedback** — security reviews and gap analysis
- **Framework integrations** — bring Sanctuary to other harnesses and agent platforms
- **Open issues and discussions** — we take feedback seriously

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Local development

On first clone, install the pre-commit hook:

```bash
cd server
npm install
npm run install-hooks
```

`install-hooks` copies `.githooks/pre-commit` into `.git/hooks/pre-commit` and makes it executable. The hook runs two gates on every `git commit`:

1. **Typecheck** — `npm run typecheck` must pass with zero TypeScript errors.
2. **Test baseline guard** — `npm test` must pass; vitest output must not contain any transform/collection error; the number of test files vitest loaded must equal the number of `*.test.ts` files under `server/test/`; the passing-test count must be at least the integer in `.test-baseline` at repo root.

The second gate defends against a failure class documented in [`docs/audit/commit-4ac95830-postmortem.md`](docs/audit/commit-4ac95830-postmortem.md): a parse/transform error silently dropping test files during vitest collection, causing the passing count to look lower without vitest reporting a hard failure.

Total hook runtime: ~21 seconds on a modern Mac. Emergency bypass: `SKIP_TEST_BASELINE=1 git commit ...` (logged to `.test-baseline-overrides.log` for audit).

The same two gates run in CI via [`.github/workflows/test-baseline-guard.yml`](.github/workflows/test-baseline-guard.yml) on every PR and push to main. See [`docs/audit/branch-protection-setup.md`](docs/audit/branch-protection-setup.md) for the branch-protection runbook that makes the CI check a hard merge gate.

---

## License

- **Code:** Apache License 2.0
- **Specification:** CC-BY-4.0

Use it, build on it, extend it.

---

**Created by Erik Newton.**
