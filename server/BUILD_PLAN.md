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

## Phase 3B: Remaining Hardening (Not yet started)

### Option A: Gate integration test (hardening)
- End-to-end test: prompt injection scenario where agent tries state_export → gets blocked → tries unfamiliar namespace → baseline catches it
- Acceptance test for RFC-0002

### Option B: Sovereignty-gated reputation tiers
- Attestations from verified agents weighted higher
- Tier metadata in attestation schema
- Depends on sovereignty handshake (now complete)

### Option C: MCP-to-MCP federation
- Agent-to-agent sovereignty negotiation
- SIM exchange, mutual attestation, reputation trust evaluation
- Requires two Sanctuary instances communicating

### Option D: ZK proof upgrade for L3
- Replace commitment-only proofs with actual ZK proofs
- RISC Zero or SP1 integration
- Most technically complex; deferred in RFC-0001

---

## Validation Criteria (from RFC Section 10.1)

> An agent running in Claude Code can connect to the Sanctuary MCP Server, create an identity, write encrypted state, record interactions, export its reputation, and import it into a different harness — with zero plaintext leakage at any point.

All security tests MUST pass. All conformance tests for MVS-level claims MUST pass.
