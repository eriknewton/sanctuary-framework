# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.8.0] - unreleased — EU AI Act Compliance Artifact Generator

### Added — Phase 2

- **Annex III classification helper (Deliverable 1).** New module
  `server/src/compliance/eu_ai_act/annex_iii.ts` with a structured
  catalog of all 8 Annex III high-risk categories (18 sub-points
  total) under Regulation (EU) 2024/1689. Each category carries
  verbatim regulation text with `[...]` elisions (same citation
  discipline as `coverage_matrix.ts`) and a keyword catalog with
  coarse discrete weights (1.0 / 0.6 / 0.3).

  `classifyAgentDescription(text)` produces zero or more candidate
  categories with a `rule_based_confidence` score (sum of matched
  keyword weights clamped to `[0, 1]`). The confidence field is
  deliberately named `rule_based_confidence` — not `confidence` or
  `probability` — so downstream consumers cannot mistake the
  classifier for a machine-learning model. Classifier is exposed
  as a standalone MCP tool `compliance_eu_ai_act_annex_iii_classify`
  (Tier 3) and also auto-included as bundle document 07
  (`07_annex_iii_classification.md`).

- **Delta mode (Deliverable 2).** Optional
  `delta_from_bundle_path` parameter on
  `compliance_generate_eu_ai_act_bundle`, plus `--delta-from <path>`
  CLI flag. When supplied, the generator loads the prior bundle's
  manifest, compares coverage rows, and emits `08_delta.md` listing
  regulation_version changes, matrix_version changes, rows added,
  rows removed, and rows changed (with explicit `from → to`
  rendering for coverage flag and evidence_emitter changes). Doc 08
  is itself hashed and Ed25519-signed into the final manifest.

  Delta failure never fails bundle generation: unreadable path,
  malformed manifest, missing files, and fetch errors are all
  captured as warnings and the bundle lands locally unchanged.

- **Verascore publish hook (Deliverable 3).** Optional
  `publish_to_verascore: boolean` parameter on the bundle generator,
  plus `--publish-to-verascore` and `--verascore-url` CLI flags.
  When enabled, POSTs the signed manifest (not the document bodies)
  to Verascore after the bundle is fully built. Reuses the exact
  wire format, signing path, and SSRF allow-list of the existing
  `reputation_publish` tool — no second signing pipeline, no new
  cryptography.

  **Non-dependency principle enforced at every layer:** HTTPS
  required, hostname allow-list (verascore.ai, www.verascore.ai,
  api.verascore.ai), validation failures short-circuit before
  fetch, network errors and non-2xx responses captured in a
  `publish_result` field. Sanctuary bundle generation NEVER
  requires Verascore to be online; the publish is a pure side
  effect at the very end of generation.

- **PDF render (Deliverable 4).** Optional `--pdf` CLI flag that
  writes a single `bundle.pdf` alongside the Markdown files using
  a hand-rolled minimal PDF writer at
  `server/src/compliance/eu_ai_act/pdf.ts`. **No new runtime
  dependency.** The writer produces a valid PDF-1.4 byte stream
  with a correct catalog, pages tree, content streams, and xref
  table, using the Courier and Courier-Bold standard PDF Type1
  fonts (no font embedding, no AFM metric tables). Output is clean
  monospace typography with a cover page, per-document page breaks,
  and a footer on every page showing the manifest SHA-256
  identifier prefix and page numbering.

  The PDF is explicitly NOT cryptographically signed — integrity
  verification remains with the Markdown files and the JSON
  manifest. The PDF is a human-readable render of those already-
  signed artifacts. macOS `file(1)` confirms the output is a
  valid "PDF document, version 1.4" and real PDF readers can open
  the example at `examples/eu_ai_act_bundle_example/bundle.pdf`.

### Fixed — Phase 2

- **PDF footer overlay — truncate digest to 16 hex, ASCII separator, width guard.** The Phase 2 Deliverable 4 footer drew the left "Sanctuary EU AI Act Compliance Bundle · Manifest SHA-256: <48 hex>..." string and the right "Page N of M" label at the same Y baseline, overlapping on Letter-sized pages. Fixed by (a) truncating the footer digest prefix from 48 to 16 hex characters (64 bits — still collision-resistant for visual verification), (b) replacing the `·` middle-dot separator with a plain ASCII pipe `|` so the character substitution table doesn't garble it, and (c) adding an `assertFooterFits` width guard + `MIN_FOOTER_GUTTER = 24pt` constant that throws a recognisable error if left-footer width + right-label width + gutter exceeds the available column width. The guard is exported so the regression test can invoke it directly with pathological dimensions. The example HR bundle regenerated under `GENERATE_EXAMPLE=1` remains byte-stable across runs; only `bundle.pdf` changed relative to the pre-fix state (Markdown and JSON files are untouched). +4 tests on the PDF writer.

### Changed — Phase 2

- **Example bundle is now byte-stable across regenerations.** The
  Phase 1 example fixture used real randomness in three places
  (private key generation, encryption IV, timestamps), causing the
  committed example files to drift from regenerated output. Phase 2
  fixes this with a test-file-local `buildDeterministicIdentity()`
  helper that uses a fixed 32-byte private key seed, a fixed IV
  for AES-GCM, and `vi.useFakeTimers` + `vi.setSystemTime` to
  freeze the clock during the example generation. No production
  code changes — the fixture uses `@noble/curves/ed25519` and
  `@noble/ciphers/aes.js` directly (both already dependencies).
  Verified byte-stable across two consecutive `GENERATE_EXAMPLE=1`
  runs.

- **Bundle document count 6 → 7 (+1 optional).** Bundles now always
  include `07_annex_iii_classification.md` as a content document;
  `08_delta.md` is conditional on `delta_from_bundle_path`;
  `bundle.pdf` is conditional on `--pdf`. The Phase 1 test
  assertion "exactly 6 Markdown documents" is updated to "exactly
  7 Markdown documents and a manifest" for the default bundle.

### Added — Phase 1

- **EU AI Act Compliance Artifact Generator.** New Sanctuary subsystem
  under `server/src/compliance/eu_ai_act/` that generates a signed
  bundle of technical compliance documents from a live Sanctuary
  runtime, aligned to Regulation (EU) 2024/1689.
  - Coverage matrix v1 (`coverage_matrix.ts`) — 46 rows mapping
    Sanctuary primitives to Annex IV §1–§9, Article 12, Article 13,
    Article 14, Article 15, Article 19(1), and Article 26. Honest
    coverage distribution: **5 full rows** (11%, machine-verifiable
    with zero enterprise input), **24 partial rows** (52%, structured
    evidence plus enterprise context), and **17 manual-only rows**
    (37%, enterprise-authored). Every "full" row individually verified
    against v0.7.0 source on 2026-04-10; see per-row `review_notes`
    for verification findings and corrections applied.
  - Six Markdown templates covering Annex IV technical documentation
    (per Article 11), Article 26 deployer log, Article 12 automatic
    record-keeping, risk management summary (Article 9), human
    oversight statement (Article 14), and cryptographic attestations.
    Each template uses verbatim regulation quotes with `[...]`
    elisions and emits explicit `[MANUAL INPUT REQUIRED: hint]`
    markers where the enterprise must supply business context.
  - Hand-rolled minimal template engine (`templates/render.ts`, ~60
    lines) with `{{ var }}` and `{{ var | hint }}` grammar. Zero new
    runtime dependencies.
  - Bundle generator (`generator.ts`) that walks the matrix, renders
    each document, computes SHA-256 (lowercase hex for auditor
    compatibility with `sha256sum`), and signs every file with the
    provider's primary Ed25519 identity via the existing
    `core/identity.ts` sign primitive. Canonical JSON signing for
    the manifest.
  - New MCP tool `compliance_generate_eu_ai_act_bundle` registered
    under Tier 3 (auto-allow, read-only) in the default Principal
    Policy.
  - New CLI subcommand `sanctuary-mcp-server compliance eu-ai-act
    <agent-did>` with flags for deployment context, reporting
    period, and output directory.
  - Example bundle under `examples/eu_ai_act_bundle_example/` — a
    fictional Fortune 2000 enterprise deploying a high-risk Annex
    III §4 HR screening agent. Byte-stable across regeneration via
    the new `generated_at_override` input field. Verified end-to-end
    with `shasum -a 256`; every digest matches the manifest exactly.
  - Documentation at `docs/compliance/eu_ai_act_bundle.md` (usage
    guide) and `docs/compliance/eu_ai_act_coverage_matrix_v1.md`
    (auto-generated from the matrix TypeScript data).
  - 81 new tests across render, coverage matrix schema invariants,
    and end-to-end bundle generation (including signature
    verification against the signer's public key).

### Changed

- **`SanctuaryServer` interface extended** with optional-usage
  `identityManager`, `masterKey`, `auditLog`, and `policy` fields so
  embedding callers (notably the compliance CLI subcommand) can
  reuse the existing `createSanctuaryServer` path without
  duplicating dependency wiring. Non-breaking for existing consumers
  that only use `server` and `config`.

### Fixed

- **`principal-policy/loader.ts` closing `],` absorbed into line
  comment.** A recent memory_attest commit had the closing bracket
  of `tier3_always_allow` tucked onto the same line as a `//`
  comment, absorbing it into the comment and leaving the array
  unclosed. This silently broke esbuild parse for 10 test files,
  dropping the baseline from 1113 to 1015 passing. Fixed in commit
  `3bc5cc6`. Baseline restored to 1113; after the compliance
  generator tests the new baseline is 1193+.

- **Three pre-existing `TS6133` unused-import errors** in
  `src/cocoon/cli.ts`, `src/cocoon/config-reader.ts`, and
  `src/l1-cognitive/memory-attest.ts`. Removed during the session
  that built the compliance generator, because the new
  interim-stopgap test-baseline rule in `Sanctuary/CLAUDE.md`
  requires a clean typecheck before every commit. Commit `d175b23`.

### Documentation

- **`Sanctuary/CLAUDE.md` commit discipline stopgap** (commit
  `e99174f`). Every commit to Sanctuary main must run
  `npm run typecheck && npm test` against a clean working tree
  before staging; block the commit if either fails. Interim
  instruction-layer defense until a pre-commit hook lands in a
  follow-up session per `docs/audit/test-baseline-hardening-plan.md`.

- **`docs/audit/` directory established** as the canonical home for
  long-lived audit-class artifacts (postmortems, hardening plans,
  incident reports). Inaugural artifacts: the commit `4ac95830`
  postmortem and the test baseline hardening plan. Commit `eead299`.

## [0.6.1] - 2026-04-04 — Security remediation pass

### Security

- **DELTA-01 — domain separation in `sanctuary_sign_challenge`.** Tool now
  requires a `purpose` argument and signs
  `"sanctuary-sign-challenge-v1" || 0x00 || purpose || 0x00 || nonce`
  instead of raw nonce bytes. Raw-nonce signatures no longer verify;
  cross-purpose signatures do not verify. Prevents signature replay
  across verifiers.
- **DELTA-05 — handshake auto-publish now signs its payload.** The
  outbound Verascore envelope carries body.signature (Ed25519 over
  JSON.stringify(data)) plus body.publicKey so /api/publish can
  verify it end-to-end.
- **DELTA-04 — handshake auto-publish defaults to false.** When
  enabled, the published envelope strips counterparty-identifying
  fields (counterparty_signed_by → "redacted") until explicit consent
  is wired through.
- **DELTA-08 — `sanctuary_link_to_human` redacts target email.** Tool
  response now returns only `***@domain`; a compromised agent cannot
  read back which address it emailed.
- **DELTA-17 — principal-policy tier alignment test.** New test
  asserts that sanctuary_bootstrap/export_identity_bundle are Tier 1,
  link_to_human/sign_challenge are Tier 2 (anomaly-gated), and
  policy_status is Tier 3 — guards against future drift.

## [0.6.0] - 2026-04-04

### Added

- **Quickstart package** (`@sanctuary-framework/quickstart@0.1.0`) — zero-dep
  `npx` CLI that generates an Ed25519 identity, writes `~/.sanctuary/quickstart-identity.json`
  (0600), and publishes a self-attested SHR to Verascore in under 60 seconds.
  E2E tested against a local node:http mock.
- **5 new MCP tools** (brings total to 72+):
  - `sanctuary/bootstrap` — one-shot setup (identity + bundle + quickstart JSON)
  - `sanctuary/policy_status` — report current Principal Policy state
  - `sanctuary/export_identity_bundle` — portable identity export
  - `sanctuary/link_to_human` — bind an agent identity to a human principal
  - `sanctuary/sign_challenge` — sign a Verascore claim nonce with the agent key
- **Post-handshake auto-publish hook** — `handshake_respond` POSTs a handshake
  attestation envelope to Verascore `/api/publish` after a successful response.
  Gated by `config.verascore.auto_publish_handshakes` (default true). HTTPS-only.
  Failures are audit-logged but non-blocking.
- **Docs** — `server/docs/OWASP.md` (OWASP LLM Top-10 mapping) and
  `server/docs/DID.md` (did:key method and identity bundle format).
- Integration test `server/test/integration/auto-publish-handshake.test.ts`
  exercising auto-publish against a real local HTTP mock.

### Changed

- Server version bumped to `0.6.0`.

## [0.4.2] - 2026-04-01

### Fixed

- **sovereignty_audit blocked on existing installations** — The v0.4.1 fix added `sovereignty_audit` to `DEFAULT_POLICY.tier3_always_allow`, but existing installations already had a `principal-policy.yaml` on disk from v0.3.1 that was loaded instead. The policy loader now **merges** default tier3 entries into user policy files, so new read-only tools from upgrades are automatically permitted without requiring operators to edit their policy file. This is upgrade-safe: user customizations are preserved and defaults are additive.

## [0.4.1] - 2026-04-01

### Fixed

- **Critical: Packaging bug** — `dist/cli.js` contained a wrong require path for `package.json` in the dashboard module, causing the MCP server to crash silently on startup and expose zero tools through OpenClaw. Root cause: `src/principal-policy/dashboard.ts` used a separate `createRequire` with a path that resolved differently in the bundle vs source. Fix: import version from `config.ts` instead of duplicating the require.
- **sovereignty_audit permission gate** — The audit tool was documented as Tier 3 (auto-allow) but was never added to the `tier3_always_allow` list, causing it to default to Tier 1 (require approval) per SEC-011. Now correctly classified as Tier 3 alongside `shr_generate` and `monitor_health`.
- **Missing Tier 3 classifications** — `shr_gateway_export`, `bridge_commit`, `bridge_verify`, and `bridge_attest` were also missing from `tier3_always_allow`. All read-only or outbound-only tools now correctly auto-allow.

### Changed

- `SANCTUARY_VERSION` is now exported from `config.ts` for use by other modules, eliminating duplicate `createRequire` calls.

## [0.4.0] - 2026-04-01

### Added

- **Decommissioning Certificate** — Policy framework for decommission operations (Tier 1, requires approval). Tool implementation deferred to v0.5.0.
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
- Tool surface increased from 46 to 54 tools.

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
- MCP tool schema with 54 tools across all layers
- Comprehensive test suite (484 tests)
- Apache-2.0 license for code, CC-BY-4.0 for spec

---

## Release Versioning

- **0.2.x:** Initial foundation (L1–L4 core, identity, reputation)
- **0.3.x:** Audit, federation, integration (sovereignty audit, SHR spec, handshake, integrations)
- **0.4.x:** Lifecycle, hardening, composition (decommissioning, L2 hardening, gateway export, context gating)
- **0.5.x (planned):** Signed tool provenance, SIEM integration, delegation chain metadata

