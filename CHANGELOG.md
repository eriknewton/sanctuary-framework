# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.4.0] - 2026-04-01

### Added

- **Decommissioning Certificate** — 2 new tools (`sanctuary/decommission_certificate`, `sanctuary/decommission_verify`). Proves zero-credential state for decommissioned agents. Addresses RSA 2026 agent lifecycle gap.
- **L2 Hardening Path** — 2 new tools (`sanctuary/l2_hardening_status`, `sanctuary/l2_verify_isolation`). Checks process isolation (container/VM/sandbox), memory protection (ASLR, canaries, Argon2id), filesystem permissions, runtime integrity. New "Hardened" tier between Degraded and Full.
- **SHR Gateway Export** — 1 new tool (`sanctuary/shr_gateway_export`). Transforms SHR into authorization context for Ping Identity Agent Gateway or other identity providers with trust levels and capability signals.
- **Context Gating** — 5 tools for field-level context filtering with policy templates (`context_gate_set_policy`, `context_gate_filter`, `context_gate_apply_template`, `context_gate_list_policies`, `context_gate_recommend`).
- **Concordia Bridge** — 3 tools for optional composition with Concordia Protocol (`bridge_commit`, `bridge_verify`, `bridge_attest`).
- **Hermes Integration** — adapter and examples for Hermes agent framework.
- **LangChain Integration** — adapter using official `langchain-mcp-adapters`.
- **CrewAI Integration** — adapter using native `mcps` field.
- **Incident class mapping** in sovereignty audit — 5 real-world incidents (Meta Sev 1, OpenClaw CVE flood, context leakage, inbox deletion, Claude Code leak) mapped to sovereignty gaps.
- **NIST CAISI mapping** in SHR spec (Section 9) — maps NIST's five security dimensions to SHR coverage.

### Changed

- L3 ZK proofs repositioned: existing Schnorr + range proofs via Fiat-Shamir ARE genuine ZK proofs. "Commitment-only" label was a categorization error.
- Dashboard rate limiting: sliding-window per-IP (120 req/min general, 20 req/min decisions).
- `reputation_export` moved from Tier 3 to Tier 1.
- Version dynamically read from package.json (resolves issue #6).
- Validation added for `withhold-all` and `service-mediated` config values (resolves issue #4).
- Tool surface increased from 46 to 56 tools.

### Fixed

- Issue #6: Version mismatch between package.json and reported version.
- Issue #4: Dead config values (`withhold-all`, `service-mediated`) accepted without validation.
- Issue #3: Tier asymmetry — `reputation_export` now correctly at Tier 1.
- Issue #2: Dashboard had no rate limiting.
- TypeScript strict-mode compilation errors preventing npm publish.

### Security

- SEC-025: Case-insensitive context gate pattern matching.
- SEC-026: Logging-strict template allow list now enforced (removed dead code).
- SEC-027: Size limits for context objects and policy rules.

### Migration from v0.3.1

**No breaking changes to the MCP tool interface.** All v0.3.1 tools remain available with the same names and parameters.

The Concordia Bridge tools are **additive** — they provide optional composition with Concordia Protocol but do not replace any existing tools.

**Critical upgrade step:** After updating the npm package, your MCP host (OpenClaw, Claude Code, etc.) must restart its gateway to re-enumerate the tool surface. A stale gateway registration may show only a subset of tools.

See `docs/MIGRATION_v0.3_to_v0.4.md` for detailed upgrade instructions.

---

## [0.3.1] - 2026-03-29

### Added

- Sovereignty audit tool with security gap analysis and incident class mapping
- SHR (Sovereignty Health Report) generation and verification tools
- Handshake protocol (initiate, respond, complete, status)
- Federation MCP-to-MCP tools
- SHR v1.0 spec published to `docs/SHR_SPEC.md`
- Installation section with OpenClaw and Claude Code setup instructions
- LangChain integration reference with examples
- GitHub Pages blog at sanctuaryprotocol.ai

### Changed

- Author attribution updated from CIMC to Erik Newton across all public-facing docs (per mandatory attribution rule)
- Tool count updated to 46 in all documentation

### Fixed

- GitHub issue #2: Dashboard rate limiting (20–120 req/min sliding window)
- GitHub issue #3: `reputation_export` tier asymmetry
- GitHub issue #4: Dead config values validation
- GitHub issue #6: Version mismatch dynamic resolution

### Security

- Security review findings: all PASS (resolved Critical and High findings before merge)
- SEC-ADDENDUM conditions resolved
- StderrApprovalChannel unused config parameter prefixed with underscore

---

## [0.3.0] - 2026-03-25

### Added

- Principal Policy Framework — govern agent autonomy and delegation across four sovereignty layers
- Bootstrap Escrow and Guarantee tools — secure initial credential exchange
- L2 Context Gating foundations — field-level filtering and obfuscation policies
- Policy templates for enterprise patterns (logging-strict, export-blocked, minimal-context)

---

## [0.2.0] - 2026-03-20

### Added

- Initial L1–L4 tool surface (core 46 tools across four sovereignty layers)
  - **L1 Cognitive Sovereignty:** ED25519 identity, SHR generation, reputation export
  - **L2 Operational Isolation:** state encryption, audit logging, context gating
  - **L3 Selective Disclosure:** cryptographic proofs (Schnorr, range proofs), ZK gates
  - **L4 Verifiable Reputation:** federation handshake, cross-domain trust
- Ed25519 identity management (key generation, recovery, rotation)
- Encrypted state operations (AES-256-GCM)
- Reputation system with tier-based verification (Unverified, Self-Attested, Verified-Degraded, Verified-Full)
- MCP tool schema with 56 tools across all layers
- Comprehensive test suite (482+ tests)
- Apache-2.0 license for code, CC-BY-4.0 for spec

---

## Release Versioning

- **0.2.x:** Initial foundation (L1–L4 core, identity, reputation)
- **0.3.x:** Audit, federation, integration (sovereignty audit, SHR spec, handshake, integrations)
- **0.4.x:** Lifecycle, hardening, composition (decommissioning, L2 hardening, gateway export, context gating)
- **0.5.x (planned):** Signed tool provenance, SIEM integration, delegation chain metadata

