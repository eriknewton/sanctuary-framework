# Sanctuary MCP Server — Build Plan

**Spec:** `rfcs/RFC-0001-sanctuary-mcp-server.md`
**Target:** MVS v0.1.0
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

---

## Validation Criteria (from RFC Section 10.1)

> An agent running in Claude Code can connect to the Sanctuary MCP Server, create an identity, write encrypted state, record interactions, export its reputation, and import it into a different harness — with zero plaintext leakage at any point.

All security tests MUST pass. All conformance tests for MVS-level claims MUST pass.
