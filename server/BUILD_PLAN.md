# Sanctuary MCP Server — Build Plan

**Specs:** `rfcs/RFC-0001-sanctuary-mcp-server.md`, `rfcs/RFC-0002-principal-policy-operational-approval.md`
**Target:** MVS v0.2.0
**Language:** TypeScript
**Test framework:** Vitest
**Build tool:** tsup
**Package:** `@sanctuary-framework/mcp-server`

---

## Phase 1a: Core + L1 (Sessions 1-2)

The foundation. Everything else depends on this.

### Step 1: Project scaffold
- `package.json` with all production deps (`@modelcontextprotocol/sdk`, `@noble/ciphers`, `@noble/hashes`, `@noble/ed25519`, `@noble/curves`, `hash-wasm`)
- `tsconfig.json` (ESM, strict)
- `tsup.config.ts` (CJS + ESM dual output)
- Directory structure per RFC Section 11.1
- Vitest config

### Step 2: Cryptographic core (`src/core/`)
- `encryption.ts` — AES-256-GCM encrypt/decrypt via `@noble/ciphers`
- `hashing.ts` — SHA-256, HMAC-SHA256, Merkle tree construction/verification
- `identity.ts` — Ed25519 keypair generation, signing, verification via `@noble/ed25519`
- `key-derivation.ts` — Argon2id (master key from passphrase) via `hash-wasm`, HKDF-SHA256 (namespace keys) via `@noble/hashes`
- `random.ts` — Secure random bytes via `crypto.getRandomValues`
- Unit tests for every function

### Step 3: Storage backend (`src/storage/`)
- `interface.ts` — Storage backend interface (read/write/list/delete raw bytes)
- `filesystem.ts` — Encrypted local filesystem backend (default)
- `memory.ts` — In-memory backend (for testing)

### Step 4: L1 StateStore (`src/l1-cognitive/state-store.ts`)
- `state_write` — Encrypt value, generate IV, sign ciphertext, write `.enc` file, update Merkle tree
- `state_read` — Read `.enc` file, verify signature, verify auth tag, decrypt, verify Merkle proof
- `state_list` — List keys in namespace (metadata only, no decryption)
- `state_delete` — Overwrite with random bytes, unlink, update Merkle tree
- `state_export` — Bundle all state as encrypted portable archive
- `state_import` — Import bundle with conflict resolution

### Step 5: L1 Identity (`src/l1-cognitive/identity-root.ts`)
- `identity_create` — Generate Ed25519 keypair, encrypt private key, store, return public info
- `identity_list` — List managed identities
- `identity_sign` — Load encrypted private key, decrypt, sign payload, return signature
- `identity_verify` — Verify Ed25519 signature against public key
- `identity_rotate` — Generate new keypair, sign rotation event with old key, update storage

### Step 6: MCP server wiring (`src/index.ts`, `src/router.ts`)
- MCP server initialization via `@modelcontextprotocol/sdk`
- Tool router dispatching `sanctuary/*` namespace
- Configuration loading (`src/config.ts`)
- All L1 tools registered and callable

### Step 7: Security tests (`test/security/`)
- `no-plaintext-leak.test.ts` — Scan storage path for plaintext after writes
- `key-never-in-response.test.ts` — Instrument tool handlers, verify no private key in output
- `iv-uniqueness.test.ts` — 10,000 writes, all IVs unique
- `rollback-detection.test.ts` — Replace .enc file with older version, verify read rejects
- `tamper-detection.test.ts` — Modify byte in .enc file, verify GCM auth fails
- `secure-deletion.test.ts` — After delete, verify file overwritten before unlink
- `signature-verification.test.ts` — Inject unsigned .enc file, verify read rejects

**STATUS: COMPLETE** — All steps delivered. 11 L1 tools, 4 security test suites. TypeScript compiles clean.

---

## Phase 1b: L2 + L3 + L4 (Sessions 3-4)

Builds on L1 foundation. Each layer is simpler than L1.

### Step 8: Audit log (`src/l2-operational/audit-log.ts`)
- Append-only log of all sovereignty-relevant operations
- Each entry: timestamp, layer, operation, identity_id, result
- Query with filters (time, layer, operation type)
- Stored encrypted under L1

### Step 9: L2 Attestation and monitoring
- `exec_attest` — Collect environment info (OS, runtime, TEE status, network exposure)
- `exec_resource_usage` — Report memory, storage, CPU, operation counts
- `monitor_health` — SHR generation (all four layers' status + degradations)
- `monitor_audit_log` — Query the audit log

### Step 10: L3 Commitment schemes
- `proof_commitment` — SHA-256(value || blinding_factor), return commitment + blinding factor
- `proof_reveal` — Verify commitment against revealed value + blinding factor
- `disclosure_set_policy` — Store disclosure policy rules (encrypted under L1)
- `disclosure_evaluate` — Evaluate disclosure request against active policy

### Step 11: L4 Reputation
- `reputation_record` — Create signed attestation of interaction outcome, store under L1
- `reputation_query` — Aggregate reputation data with filtering
- `reputation_export` — Bundle attestations as SANCTUARY_REP_V1
- `reputation_import` — Import bundle, verify signatures
- `bootstrap_create_escrow` — Create escrow record for trust bootstrapping
- `bootstrap_provide_guarantee` — Principal signs guarantee certificate for new agent

### Step 12: SIM manifest
- `sanctuary/manifest` — Generate full Sanctuary Interface Manifest from current config and capabilities

**STATUS: COMPLETE** — L2 (audit log, attestation, health), L3 (commitments, policies), L4 (reputation, export/import, escrow, guarantees), SIM manifest. 32 tests across 3 test files.

---

## Phase 1c: Integration + Hardening (Session 5)

### Step 13: Integration tests
- Full sovereignty flow: create identity → write state → attest → commit → record reputation → export → import into fresh instance
- Multi-identity isolation
- Reputation portability round-trip
- Harness compatibility (connect to Claude Code MCP config)

### Step 14: README and npm prep
- README.md with installation instructions, quick start, configuration reference
- npm package metadata
- CLI entry point (`npx @sanctuary-framework/mcp-server`)
- First-run initialization flow

**STATUS: COMPLETE** — Full sovereignty flow test (RFC 10.1 acceptance), multi-identity isolation, reputation portability round-trip, README with 26 tools documented. 7 integration tests.

---

## Phase 2: Principal Policy & Operational Approval (Session 6)

Prompt injection defense. Human-in-the-loop approval gating for high-risk operations.

**Spec:** `rfcs/RFC-0002-principal-policy-operational-approval.md`

### Step 15: Principal Policy types and loader
- `src/principal-policy/types.ts` — PrincipalPolicy, Tier2Config, ApprovalChannelConfig, ApprovalRequest, ApprovalResponse, GateResult, SessionProfile
- `src/principal-policy/loader.ts` — YAML/JSON policy parser, default policy generation, `loadPrincipalPolicy()` returns frozen (immutable) policy
- Default policy file generated at `{storage_path}/principal-policy.yaml` with 0o600 permissions

### Step 16: Behavioral baseline tracker
- `src/principal-policy/baseline.ts` — Sliding-window tracking for tool calls, namespace reads, signing frequency, counterparty interactions
- Encrypted cross-session persistence (learns over time)
- Internal namespaces (prefixed with "_") excluded from anomaly detection

### Step 17: Approval channels
- `src/principal-policy/approval-channel.ts` — StderrApprovalChannel (default, auto-deny after timeout), CallbackApprovalChannel (testing/API), AutoApproveChannel (testing)
- Stderr channel writes outside MCP stdin/stdout protocol — agent cannot intercept

### Step 18: Three-tier approval gate
- `src/principal-policy/gate.ts` — ApprovalGate with `evaluate()` method
- Tier 1: Always requires approval (state_export, identity_rotate, reputation_import, etc.)
- Tier 2: Behavioral anomaly detection (new namespace, new counterparty, sign frequency, bulk reads, frequency spikes)
- Tier 3: Always allowed with audit logging
- Denial responses deliberately omit policy details (prevents attacker learning)
- All decisions audit-logged

### Step 19: MCP tools and server integration
- `src/principal-policy/tools.ts` — `principal_policy_view` and `principal_baseline_view` (read-only)
- `src/router.ts` — Gate wraps every tool call; denied calls return generic "Operation not permitted"
- `src/index.ts` — Initializes policy → baseline → channel → gate; baseline saved on SIGINT/SIGTERM

### Step 20: Tests
- `test/principal-policy/policy-loader.test.ts` — 10 tests: YAML/JSON parsing, defaults, extractOperationName
- `test/principal-policy/baseline.test.ts` — 16 tests: first session, tracking, encryption, persistence
- `test/principal-policy/approval-gate.test.ts` — 12 tests: three tiers, anomaly detection, security properties

**STATUS: COMPLETE** — RFC-0002 written. 6 source files, 3 test files. 38 new tests. 88 total tests passing, 13 test files. Build clean. Pushed to GitHub 2026-03-26.

---

## Phase 3A: Adoption Infrastructure (Session 7)

Building the adoption surface: npm publish, machine-readable SHR, sovereignty handshake, Cowork plugin.

### Step 21: npm publish pipeline
- `prepublishOnly` script: typecheck → test → build
- Version alignment: `config.ts` → `package.json` both at `0.2.0`
- LICENSE file in `server/` (Apache-2.0, copied from root)
- `npm pack` produces clean tarball: dist/, README.md, LICENSE only
- `npx @sanctuary-framework/mcp-server` works end-to-end

### Step 22: Machine-readable SHR (Sovereignty Health Report)
- `src/shr/types.ts` — SHR type definitions, canonical serialization
- `src/shr/generator.ts` — Generate signed SHR from server state
- `src/shr/verifier.ts` — Verify counterparty SHR (signature, expiry, schema, sovereignty assessment)
- `src/shr/tools.ts` — `sanctuary/shr_generate`, `sanctuary/shr_verify` MCP tools
- `test/shr/shr.test.ts` — 11 tests: generation, layer completeness, degradations, validity window, error handling, verification, tamper detection, expiry detection, sovereignty assessment, canonical determinism

### Step 23: Sovereignty Handshake Protocol
- `src/handshake/types.ts` — Handshake type definitions (challenge, response, completion, result, session)
- `src/handshake/protocol.ts` — Core protocol: initiate, respond, complete, verify-completion
- `src/handshake/tools.ts` — `sanctuary/handshake_initiate`, `sanctuary/handshake_respond`, `sanctuary/handshake_complete`, `sanctuary/handshake_status` MCP tools
- `test/handshake/handshake.test.ts` — 8 tests: full round-trip, tampered SHR, tampered nonce signatures, tampered completion, protocol version rejection, missing identity, sovereignty assessment

### Step 24: Cowork Plugin Packaging
- `plugin/.claude-plugin/plugin.json` — Plugin manifest
- `plugin/.mcp.json` — MCP server configuration (npx launch)
- `plugin/skills/sanctuary/SKILL.md` — Skill definition with all 32 tools documented
- `plugin/README.md` — Plugin documentation

**STATUS: COMPLETE** — 6 new source files, 2 new test files. 19 new tests. 107 total tests passing, 15 test files. 32 MCP tools (6 new: shr_generate, shr_verify, handshake_initiate, handshake_respond, handshake_complete, handshake_status). Cowork plugin packaged.

---

## Phase 3B: Hardening & Advanced Cryptography (Session 8)

All four Phase 3B items shipped in a single session.

### Step 25: Sovereignty-gated reputation tiers
- `src/l4-reputation/tiers.ts` — SovereigntyTier type ("verified-sovereign" | "verified-degraded" | "self-attested" | "unverified"), TIER_WEIGHTS (1.0, 0.8, 0.5, 0.2), resolveTier(), computeWeightedScore(), tierDistribution()
- Automatic tier resolution from handshake results wired into reputation_record
- `sanctuary/reputation_query_weighted` MCP tool
- `test/l4/tiers.test.ts` — 15 tests

### Step 26: Gate integration test (prompt injection defense)
- `test/integration/gate-integration.test.ts` — 14 tests
- Tier 1 blocks (state_export, reputation_import, identity_rotate, bootstrap_provide_guarantee)
- Tier 2 anomaly catches (new namespace, new counterparty, signing frequency spike)
- Tier 3 allows (state_read, reputation_query, monitor_health, Phase 3A/3B tools)
- Full attack sequence simulation, approval flow test

### Step 27: MCP-to-MCP federation
- `src/federation/types.ts` — FederationPeer, PeerTrustEvaluation, etc.
- `src/federation/registry.ts` — FederationRegistry: handshake-gated peer entry, multi-factor trust evaluation (sovereignty tier + handshake currency + reputation + mutual attestation count), auto-deactivation of expired peers
- `src/federation/tools.ts` — `sanctuary/federation_peers`, `sanctuary/federation_trust_evaluate`, `sanctuary/federation_status`
- `test/federation/federation.test.ts` — 18 tests

### Step 28: ZK proof upgrade for L3
- `src/l3-disclosure/zk-proofs.ts` — Pedersen commitments on Ristretto255 (C = v*G + b*H), Schnorr proofs of knowledge via Fiat-Shamir, bit-decomposition range proofs with CDS OR-proofs
- `src/l3-disclosure/tools.ts` — 5 new MCP tools: `sanctuary/zk_commit`, `sanctuary/zk_prove`, `sanctuary/zk_verify`, `sanctuary/zk_range_prove`, `sanctuary/zk_range_verify`
- `test/l3/zk-proofs.test.ts` — 16 tests

**STATUS: COMPLETE** — 4 modules, 8 new source files, 4 new test files. 63 new tests. 170 total tests passing, 19 test files. 37 MCP tools (5 new ZK + 3 federation + 1 weighted reputation). Pushed to GitHub 2026-03-27. CI green.

---

## Phase 3C: Principal Dashboard (Session 9)

Human-facing web UI for the approval gate system. Replaces stderr-only auto-deny with an interactive browser-based dashboard.

### Step 29: Dashboard approval channel
- `src/principal-policy/dashboard.ts` — DashboardApprovalChannel (implements ApprovalChannel), local HTTP server (Node built-in `http` module, no external deps), SSE for real-time push, pending request queue with promise-based blocking
- `src/principal-policy/dashboard-html.ts` — Embedded single-page HTML/CSS/JS (dark theme, responsive, no build step, no CDN)

### Step 30: Dashboard HTTP routes
- `GET /` — Serves embedded dashboard HTML
- `GET /events` — SSE stream (init, pending-request, request-resolved, audit-entry, baseline-update)
- `GET /api/status` — Policy, baseline, pending count
- `GET /api/pending` — List pending approval requests
- `POST /api/approve/:id` — Approve a request (resolves blocking promise)
- `POST /api/deny/:id` — Deny a request (resolves blocking promise)
- `GET /api/audit-log` — Recent audit entries

### Step 31: Dashboard integration
- `src/config.ts` — `dashboard: { enabled, port, host }` with env var support
- `src/index.ts` — Conditional channel: DashboardApprovalChannel (when enabled) or StderrApprovalChannel (default)
- Localhost-only binding (127.0.0.1), no authentication needed (OS-level access)

### Step 32: Dashboard tests
- `test/principal-policy/dashboard.test.ts` — 14 tests: HTTP server, approval flow (approve, deny, timeout, concurrent requests), SSE, auto-approve mode, cleanup

### Step 33: Version bump and plugin update
- Version 0.3.0 across package.json, config.ts, router.ts
- Plugin SKILL.md updated with all 37 tools
- CI workflow: Node 22 + 24

**STATUS: COMPLETE** — 2 new source files, 1 new test file. 14 new tests. 184 total tests passing, 20 test files. 37 MCP tools.

---

## Phase 3D: Dashboard Authentication (Steps 34-36)

Adds bearer token authentication and TLS support to the Principal Dashboard, enabling secure non-localhost deployments.

### Step 34: Dashboard auth layer
- `src/principal-policy/dashboard.ts` — `checkAuth()` method: Bearer token via Authorization header or `?token=` query param fallback (needed for browser page load and EventSource). `DashboardConfig` extended with `auth_token?` and `tls?` fields.
- `src/principal-policy/dashboard-html.ts` — `authHeaders()` and `authQuery()` helpers embedded in JavaScript. All `fetch()` calls send Authorization header; EventSource connects via `?token=` query param.
- CORS `Access-Control-Allow-Headers` updated to include `Authorization`.

### Step 35: TLS and config wiring
- `src/principal-policy/dashboard.ts` — Conditional `node:https` server creation when TLS cert/key paths provided. Startup message shows `https://` URL and auth token.
- `src/config.ts` — `dashboard.auth_token?` and `dashboard.tls?` fields added. Env vars: `SANCTUARY_DASHBOARD_AUTH_TOKEN`, `SANCTUARY_DASHBOARD_TLS_CERT`, `SANCTUARY_DASHBOARD_TLS_KEY`.
- `src/index.ts` — `auth_token: "auto"` auto-generates a 32-byte hex token via `crypto.randomBytes()`.

### Step 36: Auth tests
- `test/principal-policy/dashboard.test.ts` — 10 new auth tests: reject without token, reject wrong token, accept correct Bearer header, accept correct query param, protect dashboard HTML, protect approve/deny endpoints, CORS preflight bypass, SSE auth, and no-auth backward compatibility.

**STATUS: COMPLETE** — 0 new files, 4 modified. 10 new tests. 194 total tests passing, 20 test files. 37 MCP tools.

---

## Validation Criteria (from RFC Section 10.1)

> An agent running in Claude Code can connect to the Sanctuary MCP Server, create an identity, write encrypted state, record interactions, export its reputation, and import it into a different harness — with zero plaintext leakage at any point.

All security tests MUST pass. All conformance tests for MVS-level claims MUST pass.

---

## Future Work

- **npm publish 0.3.0** — Ship Phases 3B-3D to npm registry
- **Webhook approval channel** — Approve/deny via external webhook (Slack, Discord, custom HTTP)
- **Concordia bridge** — Optional integration between Sanctuary (sovereignty) and Concordia (negotiation)
- **TEE support** — L2 isolation upgrade from process-level to hardware TEE
- **KERI identity** — L1 identity upgrade from Ed25519-only to KERI key management
