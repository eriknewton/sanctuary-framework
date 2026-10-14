# Sanctuary Framework Plugin

The cooperative control panel for your AI agents, as a Cowork/Claude Code plugin. Open source, created by Erik Newton. Operating-system enforcement is a separate arming step outside this plugin: live on macOS, proven on Linux for Ubuntu 24.04 (x86-64) only, Windows roadmapped. Every claim traces to the [Assurance Matrix](https://github.com/eriknewton/sanctuary-framework/blob/main/ASSURANCE_MATRIX.md).

## What it does

Gives your agent encrypted state storage, self-custodied cryptographic identity, selective disclosure with zero-knowledge proofs, portable reputation, and an audit tool that finds security and privacy gaps in your current setup. These are the Charter tools, the cooperative MCP surface; the Castle Wall (kernel-level egress enforcement) is armed separately.

## Install, verify, uninstall

This plugin's `.mcp.json` starts the Sanctuary MCP server with `npx -y @sanctuary-framework/mcp-server@1.8.4`, pinned to the exact stable release the plugin was shipped with; the commands below use the same version. That is a stdio server running in parallel with your other MCP servers: it gives you the Sanctuary tools, and it does not place calls to those other servers behind Sanctuary's cooperative policy gate. For the gated shape, run `protect` once. The MCP server entries in the config are rewritten to point at Sanctuary. The harness's own built-in tools are not MCP calls and are not touched. The rewrite is tested on representative harness paths and is not proven for every harness version (Assurance Matrix, Agent wrapping).

```bash
npx -y @sanctuary-framework/mcp-server@1.8.4 protect --claude-code --no-open --no-dashboard
npx -y @sanctuary-framework/mcp-server@1.8.4 doctor --json
npx -y @sanctuary-framework/mcp-server@1.8.4 uninstall
```

`-y` skips npm's install prompt; without it npx asks before fetching the package in a terminal. `--no-dashboard` skips the per-call dashboard, which otherwise serves in the foreground until you stop it; wrap still persists the agent record so a separately-running `sanctuary dashboard` (or a later wrap) sees the harness; start it later with `sanctuary dashboard`. `--no-open` runs headless: it skips opening the dashboard in a browser and switches custody confirmation to the non-interactive mode `protect` already uses whenever stdin is not a terminal.

`protect` backs up the existing configuration to `~/.sanctuary/backup/` and generates a passphrase that lives only in the macOS Keychain or Linux Secret Service. `doctor --json` is a read-only health check. `uninstall` removes the enforcement footprint and keeps keys, state, and the audit log; `protect --unwrap` restores the original configuration. Never put a passphrase or recovery key in a harness configuration or an environment block. Details: the [npm page](https://www.npmjs.com/package/@sanctuary-framework/mcp-server) and the [repository README](https://github.com/eriknewton/sanctuary-framework#readme).

## Featured tools

Tier 1 marks operations the shipped default Principal Policy (`DEFAULT_POLICY`, applied when no policy file exists) sends to a human.

- **`sanctuary/sovereignty_audit`**: Audit your protection posture. Scores your environment (0-100) across security, isolation, and privacy, detects OpenClaw configurations, identifies gaps, and provides prioritized recommendations.
- **`sanctuary/identity_create`**: Establish a cryptographic Ed25519 identity for signing and verification.
- **`sanctuary/shr_generate`**: Generate a signed Sovereignty Health Report to prove your capabilities to counterparties.
- **`sanctuary/state_write` / `state_read`**: Encrypted state storage with AES-256-GCM and Merkle integrity. `state_export`, `state_import`, and `state_delete` are Tier 1.
- **`sanctuary/zk_commit` / `zk_prove`**: Pedersen commitments and Schnorr zero-knowledge proofs.
- **`sanctuary/reputation_record`**: Build portable, signed reputation attestations. `reputation_export` and `reputation_import` are Tier 1.
- **`sanctuary/handshake_initiate`**: Handshake protocol for mutual verification between agents.
- **`sanctuary/context_gate_filter`**: Filter agent context before sending to LLM providers, redacting secrets, PII, and internal state.

## OpenClaw Integration

If you're running OpenClaw, wrap it rather than adding a parallel entry:

```bash
npx -y @sanctuary-framework/mcp-server@1.8.4 protect --openclaw --no-open --no-dashboard
```

Then run `sanctuary/sovereignty_audit` to see what Sanctuary adds on top of your existing OpenClaw setup:

- **Encrypted state**: Your MEMORY.md and .env are plaintext in OpenClaw. Sanctuary encrypts agent state at rest.
- **Cryptographic identity**: OpenClaw has no agent identity. Sanctuary provides Ed25519 keypairs.
- **Graduated approval**: OpenClaw's `requireApproval` is binary. Sanctuary adds three-tier approval with anomaly detection.
- **Selective disclosure**: Prove claims without revealing underlying data.
- **Portable reputation**: Signed attestations you own and can export through current paths, with full exit still partial until **IC-07, IC-08, IC-09** close.

## Requirements

- Node.js 22+
- npm (for `npx`)

## Tools provided

111 registered MCP tools (measured 2026-10-06 from `server/test/fixtures/tools-list-wire-golden.json`), spanning the audit tool, context gating, operational hardening, gateway export, federation, the Concordia bridge and system tools. The five named mechanisms of the Castle Architecture are Castle Wall, Sentinels, Charter, Heralds, and Mantle; this plugin exposes Charter. See the skill documentation for the featured workflows.

## License

Apache-2.0
