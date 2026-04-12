# Sanctuary Framework

**Security, privacy, and control for your AI agent.**

Your agent handles sensitive data, makes decisions, and talks to other agents. Sanctuary makes sure you're in control.

---

## One-command quickstart

```bash
npx @sanctuary-framework/quickstart
```

This generates an Ed25519 identity, publishes a sovereign agent profile to Verascore, and prints the live profile URL — in under 60 seconds.

![quickstart demo](./docs/images/quickstart-demo.gif)

---

## Requirements

- Node.js >= 22.0.0
- npm >= 10.0.0

---

## What You Get

### Your data stays encrypted
AES-256-GCM encryption at rest. Your encryption keys are held by you, not the platform. Your agent's knowledge of you, your preferences, your financial situation — this belongs to you.

### You approve dangerous operations
Real-time dashboard where you see what your agent is doing and approve or deny high-risk actions before they happen. No more surprise behavior.

### Your context doesn't leak
Automatic filtering of sensitive data before it reaches LLM providers. Your medical history, legal documents, financial records — they never leave your perimeter unless you explicitly consent.

### Prompt injections get caught
Built-in detection of injection attempts, with automatic escalation. Malicious users can't trick your agent into revealing secrets or changing its behavior.

### You can verify other agents
When you negotiate with another agent, Sanctuary gives you cryptographic proof of who they are and whether they're trustworthy. Signed health reports, verifiable credentials, a way to know you're dealing with the real thing.

### Everything is logged
Tamper-evident audit trail of every operation. If something goes wrong, you have proof of what happened and when.

---

## Quick Start

**Get it running in two minutes:**

```bash
npx @sanctuary-framework/mcp-server
```

The dashboard appears at `http://localhost:3000`. You're ready to use Sanctuary.

**Run a health check:**

```bash
sovereignty_audit
```

This scores your entire setup (0–100) across security, isolation, and privacy. It detects problems and tells you exactly what to fix.

---

## The Dashboard

Open the Sanctuary dashboard after startup. You'll see:

- **What your agent is doing right now** — every action, every API call, every decision
- **High-risk operations** — financial transactions, data deletions, external communications — flagged automatically
- **Your approval queue** — accept or deny pending actions in real time
- **Audit log** — complete history of what happened, who approved it, when
- **Context gating** — what data your agent can access, and what's automatically filtered

Everything is cryptographically signed. You own the keys.

---

## Installation

### Fastest way: npx
```bash
npx @sanctuary-framework/mcp-server
```

Requires Node.js 22+.

### Persistent installation
```bash
npm install -g @sanctuary-framework/mcp-server
```

Or add it to a specific project:
```bash
npm install @sanctuary-framework/mcp-server
```

### MCP Configuration

**Claude Code:**
```bash
claude mcp add sanctuary -- npx @sanctuary-framework/mcp-server
```

**OpenClaw:**
```bash
openclaw mcp set sanctuary '{"command":"npx","args":["@sanctuary-framework/mcp-server"],"env":{"SANCTUARY_PASSPHRASE":"your-passphrase-here"}}'
```

Generate a secure passphrase before first launch:
```bash
openssl rand -base64 32
```

Store this passphrase securely — it derives the encryption keys for all persistent state. If lost, encrypted state cannot be recovered.

---

## Works With

- **Claude Code** (with `claude mcp add`)
- **OpenClaw** (local-first agent framework)
- **LangChain** (agent orchestration)
- **CrewAI** (multi-agent teams)
- **Hermes Agent** (autonomous reasoning)
- Any MCP-compatible harness

---

## Cocoon: Wrap Any Agent

Already running an agent on OpenClaw, Claude Code, or Cursor? Cocoon wraps it in Sanctuary's enforcement chain with one command — no code changes required.

```bash
# Set a passphrase (once)
export SANCTUARY_PASSPHRASE=$(openssl rand -base64 32)

# Wrap your OpenClaw agent
npx @sanctuary-framework/mcp-server cocoon --openclaw
```

What this does:

1. Backs up your existing MCP config to `~/.sanctuary/backup/`
2. Rewrites the config to route all tool calls through Sanctuary
3. Every call is now logged, scanned for injection, and rate-limited
4. Dangerous operations require your approval via the dashboard

To see the dashboard:
```bash
npx @sanctuary-framework/mcp-server dashboard --port 3501
```

To restore your original config:
```bash
npx @sanctuary-framework/mcp-server cocoon --unwrap
```

Cocoon supports `--openclaw`, `--claude-code`, `--cursor`, and `--wrap <path>` for generic MCP configs. Use `--dry-run` to preview changes without modifying anything.

---

## Pairs With Concordia Protocol

When your agent needs to negotiate or make deals, **Concordia Protocol** adds structured negotiation with binding commitments and portable reputation. Together they form the complete sovereign transaction stack:

- **Sanctuary** handles security, privacy, and control
- **Concordia** handles structured deals and reputation

Install both:
```bash
npx @sanctuary-framework/mcp-server
pip install concordia-protocol
```

They work independently, but together they're more powerful.

---

## Technical Details

Sanctuary defines four layers of protection, each serving a specific purpose:

| Layer | What it protects |
|---|---|
| **L1: Cognitive Sovereignty** | Persistent state — your agent's knowledge of you belongs to you |
| **L2: Operational Isolation** | Active computation — your agent's reasoning process is private |
| **L3: Selective Disclosure** | Verifiable claims — prove something without revealing everything |
| **L4: Verifiable Reputation** | Earned trust — your agent builds a portable track record |

**The tool set:**
- 67 MCP tools across four layers
- Principal Policy (who can do what)
- Sovereignty Health Reports (SHR)
- Handshake protocol (mutual verification)
- Federation (multi-agent coordination)
- Context Gating (automatic sensitive-data filtering)
- Gateway Export (audit trail for compliance)

**Documentation:**
- [Full Specification](docs/sanctuary_framework.md) — complete technical spec
- [Sovereignty Health Report (SHR)](docs/SHR.md) — how agents prove trustworthiness
- [Architecture Guide](docs/ARCHITECTURE.md) — how the four layers fit together
- [API Reference](docs/TOOLS.md) — all 67 tools, with examples

**Design Principles:**
1. Privacy by default, disclosure by choice
2. Minimum necessary disclosure
3. Composability across any blockchain, TEE, or framework
4. Protections scale with delegation
5. Reputation is earned, portable, and owned
6. Graceful degradation — participants always know their protection status
7. Adequate for any mind — including conscious ones

---

## Open Standards

Sanctuary composes with the existing open ecosystem:

- **Identity:** W3C DIDs, KERI, Verifiable Credentials
- **Execution:** Intel TDX, AMD SEV-SNP, ARM CCA, NVIDIA Confidential Compute
- **Cryptography:** NIST Post-Quantum Cryptography (ML-KEM, ML-DSA), zk-SNARKs, zk-STARKs, Bulletproofs
- **Regulation:** GDPR, eIDAS, EU AI Act, NIST AI Risk Management Framework, ISO 27001
- **Agent Harnesses:** OpenClaw, CrewAI, LangGraph, Hermes
- **Settlement:** Any payment protocol — ACP, AP2, x402, Stripe, Lightning

Sanctuary defines sovereignty guarantees that work across all of them. It replaces nothing. It composes with everything.

---

## Contributing

Sanctuary is developed in the open. We welcome:

- **Implementation experience** — build against the tools, tell us what works and what doesn't
- **Threat modeling feedback** — security reviews and gap analysis
- **Framework integrations** — bring Sanctuary to other harnesses and agent platforms
- **Open issues and discussions** — we take feedback seriously

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Interop note — agent DIDs

Sanctuary identifies agents with a `did:key`-style DID derived from the
agent's Ed25519 public key. The encoding uses **base64url** under the
`z` multibase prefix rather than base58btc, which is a deliberate
departure from the W3C `did:key` specification. If you need to verify a
signature against a Sanctuary DID or transcode to strict `did:key`
form, see [`docs/DID_ENCODING.md`](docs/DID_ENCODING.md) — it includes
the exact byte layout, JavaScript and Python decoder snippets, and a
round-trip verification test.

---

## Contributing

If you're working on Sanctuary locally, install the pre-commit hook on first clone:

```bash
cd server
npm install
npm run install-hooks
```

`install-hooks` copies `.githooks/pre-commit` into `.git/hooks/pre-commit` and makes it executable. The hook runs two gates on every `git commit`:

1. **Typecheck** — `npm run typecheck` must pass with zero TypeScript errors.
2. **Test baseline guard** — `npm test` must pass; vitest output must not contain any transform/collection error; the number of test files vitest loaded must equal the number of `*.test.ts` files under `server/test/`; the passing-test count must be at least the integer in `.test-baseline` at repo root.

The second gate defends against a specific failure class documented in [`docs/audit/commit-4ac95830-postmortem.md`](docs/audit/commit-4ac95830-postmortem.md): a parse/transform error silently dropping test files during vitest collection, causing the passing count to look lower without vitest reporting a hard failure.

Total hook runtime: ~21 seconds on a modern Mac. Emergency bypass for exceptional commits: `SKIP_TEST_BASELINE=1 git commit ...` (the override is logged to `.test-baseline-overrides.log` for audit).

The same two gates run in CI via [`.github/workflows/test-baseline-guard.yml`](.github/workflows/test-baseline-guard.yml) on every PR and push to main. See [`docs/audit/branch-protection-setup.md`](docs/audit/branch-protection-setup.md) for the branch-protection runbook that makes the CI check a hard merge gate.

## License

- **Code:** Apache License 2.0
- **Specification:** CC-BY-4.0

Use it, build on it, extend it.

---

**Created by Erik Newton.**
