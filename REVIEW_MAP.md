# REVIEW_MAP.md — Pre-Audit Surface Map

**Generated:** 2026-03-28
**Scope:** Sanctuary v0.3.0 (TypeScript MCP server, ~10,400 LoC) + Concordia v0.1.0-draft (Python MCP server, ~5,000 LoC)
**Purpose:** Exhaustive attack surface and shared-dependency map for use by security auditors. No severity assessments or recommendations — findings only.

---

## SECTION 1: ARCHITECTURE OVERVIEW

### 1.1 Sanctuary — Entry Points and Data Flow

**Entry point:** `server/src/cli.ts:18` — `main()` parses CLI flags (`--dashboard`, `--passphrase`, `--help`, `--version`), then calls `createSanctuaryServer()` from `server/src/index.ts:47`.

**Server initialization (`index.ts:47-524`):**
1. Configuration loaded from `config.ts` (environment variables and defaults).
2. Master key derived — either from `SANCTUARY_PASSPHRASE` env var via Argon2id (`index.ts:63-95`) or from a one-time random recovery key (`index.ts:97-124`).
3. Storage backend instantiated (`storage/filesystem.ts`), base path from `SANCTUARY_STORAGE_PATH` or `~/.sanctuary`.
4. `StateStore` created with master key + storage backend (`l1-cognitive/state-store.ts:133`).
5. `AuditLog` created under `_audit` namespace (`l2-operational/audit-log.ts:26`).
6. `ApprovalGate` created with policy from `principal-policy/loader.ts:35-85` and one of three approval channels.
7. All tool handlers registered, then passed to `router.ts:174` (`createServer()`).
8. MCP transport connected — `StdioServerTransport` (default) or HTTP.

**Environment variables consumed:**
- `SANCTUARY_STORAGE_PATH` — filesystem root (default `~/.sanctuary`)
- `SANCTUARY_PASSPHRASE` — triggers Argon2id key derivation
- `SANCTUARY_DASHBOARD_ENABLED` — `"true"` enables web dashboard
- `SANCTUARY_DASHBOARD_PORT` — default 3501
- `SANCTUARY_DASHBOARD_AUTH_TOKEN` — `"auto"` generates random token
- `SANCTUARY_WEBHOOK_ENABLED` — `"true"` enables webhook approval
- `SANCTUARY_WEBHOOK_URL` — POST endpoint for approval requests
- `SANCTUARY_WEBHOOK_SECRET` — HMAC-SHA256 shared secret

**Data flow (every tool call):**
```
Agent harness → MCP SDK (stdio/HTTP)
  → router.ts:204-277 (schema validation at line 224, gate evaluation at line 244)
  → ApprovalGate.evaluate() (gate.ts:49-84)
  → Tool handler (L1/L2/L3/L4/bridge/handshake/federation/SHR)
  → StateStore.write() → AES-256-GCM encrypt → filesystem.ts → ~/.sanctuary/state/{ns}/{key}.enc
  → AuditLog.append() → encrypted under _audit namespace
```

**External connections (network I/O):**
- Dashboard HTTP server: `principal-policy/dashboard.ts:104-109` — inbound only, serves approval UI on `dashboard.host:dashboard.port`. Optional TLS (`dashboard.ts:42-45`).
- Webhook HTTP POST: `principal-policy/webhook.ts:176-184` — outbound POST to `webhook.url` with HMAC-SHA256 signature. Callback listener on `webhook.callback_host:webhook.callback_port`.
- No other outbound HTTP, no telemetry, no peer-to-peer networking in core.

**Storage locations:**
- `~/.sanctuary/state/{namespace}/{key}.enc` — all encrypted state
- `~/.sanctuary/state/_identities/` — encrypted Ed25519 keypairs
- `~/.sanctuary/state/_audit/` — encrypted audit log
- `~/.sanctuary/state/_principal/` — encrypted baseline tracker
- `~/.sanctuary/state/_commitments/` — L3 commitments
- `~/.sanctuary/state/_reputation/` — L4 attestations
- `~/.sanctuary/state/_bridge/` — Concordia bridge commitments
- `~/.sanctuary/state/_federation/`, `_handshake/`, `_shr/` — federation state

### 1.2 Concordia — Entry Points and Data Flow

**Entry point:** `concordia/__main__.py:14` — `main()` parses `--transport` flag (stdio default, SSE optional), calls `mcp.run()` from `concordia/mcp_server.py:109`.

**Server initialization:**
1. FastMCP instance created at `mcp_server.py:109`.
2. Global `_store: SessionStore` instantiated at `mcp_server.py:217` (in-memory).
3. Service-level `KeyPair` generated at `mcp_server.py:713`.
4. 46 MCP tools registered via `@mcp.tool()` decorators throughout `mcp_server.py`.

**No environment variables consumed.** All configuration is hardcoded defaults.

**Data flow (every tool call):**
```
Agent harness → MCP SDK (stdio/SSE)
  → FastMCP dispatcher (mcp_server.py)
  → Tool handler function
  → Session state machine (session.py:115-155) — transition + transcript append
  → Signing (signing.py:83-92) — Ed25519 sign over canonical JSON
  → In-memory stores (SessionStore, AttestationStore, WantRegistry, AgentRegistry, NegotiationRelay)
  → [Optional] Sanctuary bridge payload generation (sanctuary_bridge.py)
```

**External connections:** None. Concordia makes no outbound HTTP calls. The MCP SDK manages transport. The Sanctuary bridge produces payloads that the client must forward — no direct inter-server communication.

**Storage:** All in-memory Python dicts. No disk persistence.

### 1.3 Overlap and Shared State Between the Two Tools

**No shared state.** The two tools run as separate processes with no shared memory, no shared database, and no implicit RPC channel.

**Shared conceptual surfaces:**
- Both implement Ed25519 signing independently (Sanctuary via `@noble/curves`, Concordia via Python `cryptography`).
- Both implement canonical JSON serialization independently (Sanctuary: `bridge/bridge.ts:53-73` `stableStringify()`; Concordia: `signing.py:70-80` `canonical_json()`). These must produce byte-identical output for bridge verification to work. This is the highest-risk interop surface.
- Both use SHA-256 for integrity (Sanctuary via `@noble/hashes`, Concordia via `hashlib`).

**Connection point — the Concordia Bridge:**
- Concordia side (`sanctuary_bridge.py:82-127`): builds commitment payloads shaped for Sanctuary's `proof_commitment` tool. Includes `session_id`, `agreed_terms`, `parties` (sorted), `timestamp`, `transcript_hash`. Does NOT call Sanctuary directly.
- Sanctuary side (`bridge/bridge.ts:92-157`): receives `ConcordiaOutcome` objects, canonicalizes them via `stableStringify()`, creates SHA-256 + optional Pedersen commitment, signs with Ed25519.
- Data crosses via client forwarding — the agent harness sends Concordia's output payload as input to Sanctuary's `bridge_commit` tool.

### 1.4 Agent-to-Agent Communication Surfaces

**Sanctuary sovereignty handshake (`handshake/protocol.ts:35-215`):**
- Three-step protocol: initiate (nonce + signed SHR), respond (sign counterparty nonce + own SHR), complete (verify both nonces).
- Communication happens via MCP tool calls relayed by the agent harness — not direct agent-to-agent networking.
- Session state stored encrypted under `_handshake` namespace.

**Concordia negotiation relay (`relay.py:205-598`):**
- Message relay service for agent-to-agent communication within negotiation sessions.
- Relay sessions created, messages sent/received, sessions concluded — all via MCP tool calls.
- Participant authentication: sender must be registered participant (`relay.py:336`).
- In-memory storage with size caps (1K messages per mailbox, 10K per transcript).

**Concordia want/have registry (`want_registry.py:384-636`):**
- Agents post wants and haves, system finds matches.
- No agent identity verification on posting — any caller can post on behalf of any `agent_id` (`want_registry.py:420`).

---

## SECTION 2: TRUST BOUNDARIES

### 2.1 Data Crossing Trust Boundaries

| Boundary | Direction | Data | Enforcement | Location |
|----------|-----------|------|-------------|----------|
| Agent input → Sanctuary router | Inbound | JSON tool arguments | Schema validation (type, size, enum, unknown field rejection) | `router.ts:70-128` |
| Sanctuary router → tool handler | Internal | Validated args | ApprovalGate.evaluate() for every tool call | `router.ts:244-260`, `gate.ts:49-84` |
| Tool handler → StateStore | Internal | Plaintext values | AES-256-GCM encryption, Ed25519 signature, Merkle proof | `state-store.ts:133+` |
| StateStore → filesystem | Internal→Disk | Encrypted ciphertext | File permissions 0o600, directory 0o700 | `filesystem.ts:45-49` |
| Webhook approval → external HTTP | Outbound | Operation metadata (not state data) | HMAC-SHA256 signed payload | `webhook.ts:85-87` |
| Webhook callback → Sanctuary | Inbound | Approval decision | HMAC-SHA256 signature verification (constant-time) | `webhook.ts:92-105, 293-303` |
| Dashboard → Sanctuary | Inbound | Approval decision | Bearer token auth | `dashboard.ts:225-246` |
| Concordia bridge payload → Sanctuary bridge | Cross-tool (via client) | Canonical JSON of negotiation outcome | Commitment recomputation, signature verification | `bridge.ts:92-157, 159-195` |
| Agent input → Concordia MCP | Inbound | JSON tool arguments | FastMCP type dispatch; no universal schema validation | `mcp_server.py` tool functions |
| Concordia tool → session state machine | Internal | Message dict | Transition table enforcement | `session.py:115-155` |
| Concordia tool → signing | Internal | Message payload | Ed25519 signing over canonical JSON | `signing.py:83-92` |
| External attestation → reputation store | Inbound | Attestation dict | JSON Schema validation, Sybil detection, deduplication | `reputation/store.py:180-214` |

### 2.2 Authentication and Authorization Decision Points

**Sanctuary:**

1. **Master key derivation** (`index.ts:63-124`): Argon2id from passphrase or random recovery key. This is the root of all trust — if compromised, all state is decryptable.

2. **ApprovalGate** (`gate.ts:49-84`): Three-tier decision for every tool call.
   - Tier 1 operations (always require human approval): `state_export`, `state_import`, `identity_rotate`, `reputation_import`, `bootstrap_provide_guarantee` (`loader.ts:37-43`).
   - Tier 2 anomaly detection (`gate.ts:89-206`): new namespace access, new counterparty, frequency spike, bulk read, first session. Anomaly conditions reference baseline tracker (`baseline.ts:92-135`).
   - Tier 3 auto-allow: 35+ operations including `state_read`, `state_write`, `identity_create`, `identity_sign`, all proof/ZK/handshake/federation ops (`loader.ts:45-83`).
   - **Default for unlisted operations:** Tier 3 (allowed) — `gate.ts:72-83`.

3. **Reserved namespace enforcement** (`l1-cognitive/tools.ts:36-63`): Prevents agent from accessing internal namespaces (`_identities`, `_audit`, `_meta`, etc.) via prefix matching at the tool layer.

4. **Signature verification on state entries** (`state-store.ts`): Each state entry includes an Ed25519 signature (`sig` field) and identity reference (`kid` field).

5. **Webhook callback authentication** (`webhook.ts:293-303`): HMAC-SHA256 signature on response payload; invalid signature returns 401.

6. **Dashboard authentication** (`dashboard.ts:225-246`): Bearer token via header or query parameter. Token can be auto-generated (`index.ts:448`).

**Concordia:**

1. **No master authentication.** Concordia has no passphrase, no master key, no startup auth gate.

2. **Ed25519 signing per agent** (`signing.py:83-92`): Messages are signed, but **signature verification is not mandatory before state transitions** — `session.py:115-155` does not call `verify_signature()`. Verification is available via `agent.py:265-270` but must be called explicitly.

3. **Relay participant check** (`relay.py:336`): Sender must be registered participant to send relay messages.

4. **Attestation ingestion validation** (`reputation/store.py:180-214`): Schema validation + Sybil signal detection. Signature verification is optional — only if `public_keys` are provided (`store.py:329-356`).

5. **No want/have registry authentication** (`want_registry.py:420`): Any caller can post wants/haves on behalf of any `agent_id`.

### 2.3 Assumed Trust Relationships

1. **Sanctuary assumes the MCP transport is not adversarial** — schema validation and the approval gate are the only protections. If the transport is compromised, the attacker has full tool-call access (subject to gate approval).

2. **Sanctuary does NOT trust Concordia bridge payloads** — verification is cryptographic (commitment recomputation, signature checks). See `bridge.ts:159-195`.

3. **Concordia trusts the MCP transport fully** — there is no per-call authentication or authorization layer beyond the FastMCP dispatcher.

4. **Concordia session state machine trusts that messages have valid signatures** — it does not verify. The trust assumption is that the caller (agent harness) has already verified or that the signing is done server-side (which it is for locally-generated messages, but not for externally-received attestations without explicit public_keys).

5. **Concordia want/have registry trusts agent_id claims** — no verification that the caller owns the claimed agent_id.

---

## SECTION 3: DATA INVENTORY

### 3.1 User Data Collected, Stored, Transmitted

**Sanctuary — data persisted to disk:**

| Data | Location | Encryption | Accessible via |
|------|----------|------------|----------------|
| Agent state (arbitrary key-value) | `~/.sanctuary/state/{ns}/{key}.enc` | AES-256-GCM per-namespace key | `state_read`, `state_list`, `state_export`, `state_delete` |
| Ed25519 identity keypairs | `~/.sanctuary/state/_identities/` | AES-256-GCM with purpose-derived key | `identity_list` (public only), `identity_rotate` |
| Audit log entries | `~/.sanctuary/state/_audit/` | AES-256-GCM with purpose-derived key | `monitor_audit_log` |
| Behavioral baseline | `~/.sanctuary/state/_principal/session-baseline` | AES-256-GCM with purpose-derived key | `principal_baseline_view` (read-only) |
| L3 commitments | `~/.sanctuary/state/_commitments/` | AES-256-GCM | `proof_commitment`, `proof_reveal` |
| L4 reputation attestations | `~/.sanctuary/state/_reputation/` | AES-256-GCM | `reputation_query`, `reputation_export` |
| Bridge commitments | `~/.sanctuary/state/_bridge/` | AES-256-GCM | `bridge_verify` |
| Handshake sessions | `~/.sanctuary/state/_handshake/` | AES-256-GCM | `handshake_status` |
| Federation peer registry | `~/.sanctuary/state/_federation/` | AES-256-GCM | `federation_peers`, `federation_status` |
| Key derivation parameters (salt, m, t, p, l) | `~/.sanctuary/state/_meta/` | AES-256-GCM | Not directly exposed |
| Disclosure policies | `~/.sanctuary/state/_policies/` | AES-256-GCM | `disclosure_set_policy`, `disclosure_evaluate` |
| Escrow/guarantees | `~/.sanctuary/state/_escrow/`, `_guarantees/` | AES-256-GCM | `bootstrap_create_escrow`, `bootstrap_provide_guarantee` |

**Sanctuary — data transmitted externally:**
- Webhook approval requests: operation metadata only (tool name, arguments summary, tier, timestamp). NOT state content. Sent to user-configured URL. (`webhook.ts:176-184`)
- Dashboard SSE events: pending approval requests. Served to local connections. (`dashboard.ts:277-278`)

**Concordia — data in memory (not persisted):**

| Data | Store | Max Capacity | Location |
|------|-------|-------------|----------|
| Negotiation sessions (terms, transcript, behaviors) | `SessionStore._sessions` | 10,000 | `mcp_server.py:137-217` |
| Ed25519 keypairs (per session context) | `SessionContext.initiator_key`, `.responder_key` | 2 per session | `mcp_server.py:130-131` |
| Reputation attestations | `AttestationStore` | 100,000 | `reputation/store.py:124-250` |
| Agent registry entries | `AgentRegistry._agents` | 100,000 | `registry.py:176-366` |
| Want postings | `WantRegistry._wants` | 50,000 | `want_registry.py:384-636` |
| Have postings | `WantRegistry._haves` | 50,000 | `want_registry.py:384-636` |
| Matches | `WantRegistry._matches` | 100,000 | `want_registry.py:384-636` |
| Relay sessions + mailboxes | `NegotiationRelay._sessions` | 10,000 sessions, 1K msgs/mailbox, 10K msgs/transcript | `relay.py:205-598` |
| Relay archives | `NegotiationRelay._archives` | 50,000 | `relay.py:210` |

**Concordia transmits no data externally.** All communication is via MCP tool responses to the agent harness.

### 3.2 Agent-Generated Data That Persists

**Sanctuary:** All state written via `state_write` persists to disk under `~/.sanctuary/state/`. This includes agent-generated values that are encrypted before writing. Every piece of persisted state is accessible via `state_read`, `state_list`, `state_export`, `state_delete`.

**Concordia:** Nothing persists to disk. All data is in-memory and lost on process restart.

### 3.3 Secrets, Keys, and Tokens

**Sanctuary secrets and their locations in code:**

| Secret | Where Generated | Where Stored | Where Used | Code Location |
|--------|----------------|-------------|-----------|---------------|
| Master key (256-bit) | Argon2id from passphrase or random | Never stored — re-derived on each startup from passphrase; recovery key hash stored in `_meta` | Key derivation for all encryption | `core/key-derivation.ts:48-82` |
| Per-namespace encryption key | HKDF-SHA256(master, namespace) | Derived on demand, not persisted separately | AES-256-GCM encrypt/decrypt | `core/key-derivation.ts:94-105` |
| Per-purpose encryption key | HKDF-SHA256(master, purpose string) | Derived on demand | Encrypting identities, audit log, baseline | `core/key-derivation.ts:107-117` |
| Ed25519 private keys | `ed25519.utils.randomPrivateKey()` | Encrypted at rest under `_identities` namespace | Signing, identity rotation | `core/identity.ts:57-64` |
| AES-256-GCM IVs | `randomBytes(12)` per encryption op | Stored alongside ciphertext in `EncryptedPayload` | Decryption | `core/encryption.ts:41-62` |
| SHA-256 blinding factors | `randomBytes(32)` per commitment | Stored in commitment record | Commitment reveal/verify | `l3-disclosure/commitments.ts:54-73` |
| Pedersen blinding factors | Random scalar on Ristretto255 | Stored in commitment record | ZK proof generation | `l3-disclosure/zk-proofs.ts:131-145` |
| Webhook HMAC secret | User-provided via `SANCTUARY_WEBHOOK_SECRET` env var | In-process memory only | Signing/verifying webhook payloads | `webhook.ts:85-105` |
| Dashboard auth token | Auto-generated random or user-provided via `SANCTUARY_DASHBOARD_AUTH_TOKEN` | In-process memory; printed to stderr on startup | Bearer token for dashboard API | `dashboard.ts:225-246`, `index.ts:448` |
| Recovery key | Random 256-bit | Shown once to user at first run; hash stored in `_meta` | Re-deriving master key if passphrase unavailable | `index.ts:97-124` |

**Concordia secrets and their locations in code:**

| Secret | Where Generated | Where Stored | Where Used | Code Location |
|--------|----------------|-------------|-----------|---------------|
| Ed25519 private keys (per agent) | `Ed25519PrivateKey.generate()` | In-memory only (SessionContext) | Signing messages | `signing.py:35`, `agent.py:50`, `mcp_server.py:713` |
| Service-level KeyPair | Generated once at module load | In-memory only | Signing reputation query responses | `mcp_server.py:713` |

**Neither tool stores secrets in plaintext on disk.** Sanctuary encrypts all secrets; Concordia holds them only in volatile memory.

---

## SECTION 4: SOVEREIGNTY-SPECIFIC SURFACE

### 4.1 Locations Where User Control Could Be Circumvented

1. **Sanctuary: Gate default for unknown operations is Tier 3 (allow).** Any newly registered tool that is not explicitly listed in Tier 1 or matched by Tier 2 anomaly conditions will auto-allow without human approval. `gate.ts:72-83`.

2. **Sanctuary: Stderr approval channel auto-resolves after 100ms.** The default channel does not wait for actual human input — it writes to stderr and immediately resolves based on `auto_deny` flag. In default config (`auto_deny: true`), this is fail-closed. But if `auto_deny: false`, operations auto-approve without human interaction. `approval-channel.ts:45-72`, `loader.ts:28-32`.

3. **Sanctuary: Webhook timeout behavior is configurable.** If `auto_deny: false` and the webhook endpoint is unreachable, the operation auto-approves after timeout. `webhook.ts:176-184`.

4. **Sanctuary: Import does not verify signatures.** The `state_import` function writes StateEntry objects without verifying the Ed25519 signatures they contain. An import bundle with forged signatures would be accepted. `state-store.ts:518-598`. (Note: import is Tier 1, requiring human approval, but the import itself doesn't validate cryptographic integrity.)

5. **Concordia: No approval gate.** Every tool call executes immediately without any human-in-the-loop mechanism.

6. **Concordia: Session state transitions do not verify message signatures.** `session.py:115-155` applies transitions without calling `verify_signature()`. An agent harness could inject unsigned or forged messages into a session.

7. **Concordia: Want/have registry has no identity verification.** Any caller can post wants/haves claiming to be any agent_id. `want_registry.py:420`.

8. **Concordia: Attestation signature verification is optional.** `reputation/store.py:329-356` only verifies signatures if `public_keys` are provided to the ingestion function.

### 4.2 Irreversible Operations

**Sanctuary:**

| Operation | Tool | Gate Tier | Irreversibility | Code Location |
|-----------|------|-----------|-----------------|---------------|
| Secure deletion (3-pass random overwrite) | `state_delete` with `secure_delete: true` | Tier 3 (auto-allow) | Data unrecoverable after 3-pass overwrite | `filesystem.ts:69-102` |
| Identity key rotation | `identity_rotate` | Tier 1 (approval required) | Old private key replaced; chain signature links old→new | `core/identity.ts:186-240` |
| State export to external system | `state_export` | Tier 1 | Once exported, data is outside Sanctuary's control | `state-store.ts:452-513` |
| Webhook outbound POST | Approval request | Automatic (triggered by gate) | Operation metadata sent to external URL | `webhook.ts:176-184` |
| Ed25519 signing | `identity_sign` | Tier 3 | Signature is non-repudiable | `core/identity.ts:140-162` |

**NOTE:** `state_delete` with `secure_delete: true` is Tier 3 (auto-allow), meaning secure deletion of state does not require human approval by default. This is a sovereignty surface — an agent could permanently destroy user data without explicit confirmation if the default policy is used.

**Concordia:**

| Operation | Tool | Gate | Irreversibility | Code Location |
|-----------|------|------|-----------------|---------------|
| Session rejection | `concordia_reject` | None | Session moves to REJECTED terminal state | `session.py:32-55` |
| Session agreement | `concordia_accept` | None | Session moves to AGREED terminal state | `session.py:32-55` |
| Ed25519 signing | Every message | None | Signature is non-repudiable | `signing.py:83-92` |
| Attestation generation | `concordia_session_receipt` | None | Creates signed behavioral record | `attestation.py:40-137` |

### 4.3 Agent Actions Without Explicit User Confirmation

**Sanctuary (with default stderr channel, auto_deny: true):**
- All Tier 3 operations execute without any user confirmation. This includes: `state_write`, `state_read`, `state_delete`, `identity_create`, `identity_sign`, `identity_verify`, all proof/ZK operations, all handshake/federation operations, all reputation record/query operations, all bridge operations.
- Secure deletion (`state_delete` with `secure_delete: true`) is Tier 3.

**Concordia:**
- Every tool call executes without user confirmation. There is no approval gate.

---

## SECTION 5: DEPENDENCY MAP

### 5.1 Sanctuary Dependencies (from `server/package.json`)

**Runtime dependencies:**

| Package | Version Constraint | Locked Version | Purpose | Crypto/Auth/IO |
|---------|-------------------|----------------|---------|----------------|
| `@modelcontextprotocol/sdk` | `^1.26.0` | `1.27.1` | MCP protocol implementation | IO (stdio/HTTP transport) |
| `@noble/ciphers` | `^2.1.1` | `2.1.1` | AES-256-GCM encryption/decryption | **Crypto** |
| `@noble/curves` | `^1.8.0` | `1.9.7` | Ed25519, Ristretto255 (Pedersen commitments) | **Crypto** |
| `@noble/hashes` | `^1.7.0` | `1.8.0` | SHA-256, HMAC-SHA256, HKDF-SHA256 | **Crypto** |
| `hash-wasm` | `^4.12.0` | `4.12.0` | Argon2id key derivation (WASM) | **Crypto** |

**Dev dependencies:**

| Package | Version Constraint | Locked Version | Purpose |
|---------|-------------------|----------------|---------|
| `@types/node` | `^22.0.0` | `22.19.15` | TypeScript Node.js type definitions |
| `tsup` | `^8.0.0` | `8.5.1` | TypeScript bundler |
| `typescript` | `^5.7.0` | `5.9.3` | TypeScript compiler |
| `vitest` | `^3.0.0` | `3.2.4` | Test framework |

**Lockfile:** `server/package-lock.json` exists (lockfileVersion 3). Resolved versions are deterministic.

**Version constraint type:** Caret ranges (`^`) — allow minor and patch updates within the major version.

**Node.js built-in modules used for network/crypto:**
- `node:crypto` — `createHmac` for webhook HMAC (`webhook.ts:85`)
- `node:http` / `node:https` — dashboard server and webhook callback server (`dashboard.ts:104-109`, `webhook.ts`)
- `node:fs` / `node:fs/promises` — file operations (`filesystem.ts`)
- `node:path` — path operations (`filesystem.ts`)

### 5.2 Concordia Dependencies (from `pyproject.toml`)

**Runtime dependencies:**

| Package | Version Constraint | Locked Version | Purpose | Crypto/Auth/IO |
|---------|-------------------|----------------|---------|----------------|
| `cryptography` | `>=42.0` | Not locked | Ed25519 signing/verification | **Crypto** |
| `jsonschema` | `>=4.20` | Not locked | Message and attestation schema validation | — |
| `mcp` | `>=1.0` | Not locked | FastMCP server SDK | IO (stdio/SSE transport) |

**Dev dependencies:**

| Package | Version Constraint | Purpose |
|---------|-------------------|---------|
| `pytest` | `>=8.0` | Test framework |
| `pytest-cov` | `>=4.0` | Coverage reporting |

**Lockfile:** None. No `requirements.txt`, `poetry.lock`, or `uv.lock` found. Build backend is `hatchling`.

**Version constraint type:** Minimum-only (`>=`) — allows unlimited future minor and major versions. Builds are not reproducible across environments.

**Python standard library modules used:**
- `hashlib` — SHA-256 for message hashing (`message.py`)
- `json` — canonical JSON serialization (`signing.py`)
- `time` — timestamps, session expiry checks (`relay.py`, `session.py`)
- `secrets` — not observed; `os.urandom` not observed; key generation delegated to `cryptography` library

### 5.3 Shared Dependencies Between Tools

No libraries are literally shared. Both tools are in different languages. Shared **conceptual** dependencies:

| Function | Sanctuary Library | Concordia Library |
|----------|-------------------|-------------------|
| Ed25519 signing/verification | `@noble/curves` (^1.8.0) | `cryptography` (>=42.0) |
| SHA-256 hashing | `@noble/hashes` (^1.7.0) | Python `hashlib` (stdlib) |
| Canonical JSON serialization | Custom `stableStringify()` in `bridge/bridge.ts:53-73` | Custom `canonical_json()` in `signing.py:70-80` |
| MCP protocol | `@modelcontextprotocol/sdk` (^1.26.0) | `mcp` (>=1.0) |

**Critical interop surface:** The canonical JSON implementations must produce byte-identical output. Sanctuary's `stableStringify()` sorts keys recursively and rejects NaN/Infinity. Concordia's `canonical_json()` sorts keys, rejects NaN/Infinity/-0.0, uses `separators=(",",":")` and `ensure_ascii=False`. Potential divergence points: Unicode normalization, floating-point string representation, handling of `null`/`undefined`/`None`, key ordering in deeply nested objects.

### 5.4 Unpinned Dependencies

**Sanctuary:** All dependencies use caret ranges (`^`), but `package-lock.json` pins exact versions. Reproducible builds are ensured by the lockfile.

**Concordia:** All dependencies use minimum-only ranges (`>=`) with no lockfile.
- `cryptography>=42.0` could resolve to any future version (43.x, 44.x, etc.).
- `jsonschema>=4.20` could resolve to any future version.
- `mcp>=1.0` could resolve to any future version.
- This means Concordia builds are non-reproducible across time and environments.

---

## SECTION 6: KNOWN GAPS

### 6.1 Areas Where Data Flow Cannot Be Fully Traced

1. **Concordia: MCP SDK internal routing.** The `mcp` Python package (FastMCP) handles transport and dispatching. The exact validation, serialization, and error handling within the `mcp` library are not inspectable from the Concordia codebase alone. Tool argument validation depends on what FastMCP enforces before calling the decorated handler.

2. **Sanctuary: MCP SDK internal routing.** The `@modelcontextprotocol/sdk` package handles transport, message framing, and protocol-level validation. The router in `router.ts` wraps the SDK's `CallToolRequestSchema` handler, but protocol-level attacks (malformed MCP messages, oversized frames) would be handled by the SDK before reaching Sanctuary's code.

3. **Sanctuary: `hash-wasm` WASM binary.** The Argon2id implementation is a WASM module bundled by `hash-wasm`. The WASM binary is not auditable from the TypeScript source alone. It must be verified against the upstream source.

4. **Concordia: `build_envelope()` accepts arbitrary `prev_hash`.** While sessions initialize with `GENESIS_HASH`, the `build_envelope()` function at `message.py:50` accepts a `prev_hash` parameter with `GENESIS_HASH` as default. If called directly (not through the session's `prev_hash` property), arbitrary chain heads could be injected. Whether this is exploitable depends on how the agent harness constructs messages. `validate_chain()` (`message.py:88-105`) catches this, but it must be called explicitly.

5. **Concordia: Schema file loading.** `schema_validator.py:19` loads `attestation.schema.json` at runtime. The exact path resolution and the schema file contents were not fully traced. If the schema file is missing or corrupted, validation behavior is unknown.

6. **Sanctuary: Dashboard HTML content.** The dashboard serves HTML at `dashboard.ts:275-276`. The HTML is presumably embedded or generated in the dashboard module. If it includes dynamic content from pending requests, it could be an XSS vector. The exact HTML generation was not fully traced.

7. **Sanctuary: `createHttpsServer` TLS configuration.** TLS cert/key are loaded from user-provided file paths (`dashboard.ts:104-109`). There is no validation of cert chain, no minimum TLS version enforcement observed, no cipher suite restrictions observed. These depend on Node.js defaults.

8. **Concordia: `degradation.py` (389 lines).** The graceful degradation module for non-Concordia peers was not deeply traced. It may introduce alternative message handling paths that bypass the structured protocol.

9. **Concordia: Session expiry is lazy, not proactive.** Expired sessions are only detected when accessed (`relay.py:137-139, 293`). There is no background cleanup. Memory growth from abandoned sessions is bounded only by the 10K session cap.

10. **Sanctuary: Merkle tree rollback detection.** Version monotonicity depends on the encrypted metadata file not being replaced with a stale copy. An attacker with filesystem access could potentially roll back the version metadata. The threat model for filesystem-level adversaries is not specified in the code.

11. **Sanctuary: Federation registry and peer capabilities.** `federation/registry.ts:41-71` stores peer capabilities from handshake. The structure of capabilities and how they're consumed was not fully traced — they may influence trust decisions in unaudited code paths.

12. **Concordia: Reputation scorer weight tuning.** The scorer weights (`scorer.py:97-104`) are hardcoded but their security properties (e.g., can an attacker game the score by controlling attestation volume?) are not formally analyzed and cannot be assessed from code inspection alone.

### 6.2 Stubs and Unimplemented Features

1. **Sanctuary: Hardware key protection (FIDO2/WebAuthn).** Config accepts `key_protection: "hardware-key"` (`config.ts`), but no implementation exists. Behavior when this option is selected is untraced.

2. **Sanctuary: TEE execution environment.** Config accepts `environment: "tee"` (`config.ts`), but attestation is self-reported only. No TEE integration exists.

3. **Sanctuary: Groth16/PLONK ZK proof systems.** Config accepts `proof_system: "groth16" | "plonk"` (`config.ts`), but only `"commitment-only"` is implemented. Behavior when unimplemented options are selected is untraced.

4. **Sanctuary: HTTP transport.** Config accepts `transport: "http"`, but the observed entry point only uses StdioServerTransport. HTTP transport initialization path was not fully traced.

5. **Concordia: SSE transport.** `__main__.py` accepts `--transport sse`, but SSE setup is delegated to the `mcp` library. The SSE server's network binding and security characteristics are untraced from Concordia's code.

---

## APPENDIX A: COMPLETE TOOL INVENTORY

### Sanctuary Tools (40+)

**L1 Cognitive Sovereignty** (`l1-cognitive/tools.ts`):
`state_write`, `state_read`, `state_list`, `state_delete`, `state_export` (Tier 1), `state_import` (Tier 1), `identity_create`, `identity_list`, `identity_sign`, `identity_verify`, `identity_rotate` (Tier 1)

**L2 Operational Isolation** (`index.ts:144-308`):
`exec_attest`, `monitor_health`, `monitor_audit_log`, `manifest`

**L3 Selective Disclosure** (`l3-disclosure/tools.ts`):
`proof_commitment`, `proof_reveal`, `disclosure_set_policy`, `disclosure_evaluate`, `zk_commit`, `zk_prove`, `zk_verify`, `zk_range_prove`, `zk_range_verify`

**L4 Verifiable Reputation** (`l4-reputation/tools.ts`):
`reputation_record`, `reputation_query`, `reputation_query_weighted`, `reputation_export` (Tier 1), `reputation_import` (Tier 1), `bootstrap_create_escrow` (Tier 1), `bootstrap_provide_guarantee` (Tier 1)

**Handshake** (`handshake/tools.ts`):
`handshake_initiate`, `handshake_respond`, `handshake_complete`, `handshake_status`

**SHR** (`shr/tools.ts`):
`shr_generate`, `shr_verify`

**Federation** (`federation/tools.ts`):
`federation_peers`, `federation_trust_evaluate`, `federation_status`

**Bridge** (`bridge/tools.ts`):
`bridge_commit`, `bridge_verify`, `bridge_attest`

**Principal Policy** (`principal-policy/tools.ts`):
`principal_policy_view`, `principal_baseline_view`

### Concordia Tools (46)

**Negotiation** (`mcp_server.py:277-726`):
`concordia_open_session`, `concordia_propose`, `concordia_counter`, `concordia_accept`, `concordia_reject`, `concordia_commit`, `concordia_session_status`, `concordia_session_receipt`

**Reputation** (`mcp_server.py:735-811`):
`concordia_ingest_attestation`, `concordia_reputation_query`, `concordia_reputation_score`

**Agent Registry** (`mcp_server.py:847-990`):
`concordia_register_agent`, `concordia_search_agents`, `concordia_agent_card`, `concordia_concordia_preferred_badge`, `concordia_deregister_agent`

**Degradation** (`mcp_server.py:1018-1195`):
`concordia_propose_protocol`, `concordia_respond_to_proposal`, `concordia_start_degraded`, `concordia_degraded_message`, `concordia_efficiency_report`

**Want Registry** (`mcp_server.py:1204-1445`):
`concordia_post_want`, `concordia_post_have`, `concordia_get_want`, `concordia_get_have`, `concordia_withdraw_want`, `concordia_withdraw_have`, `concordia_find_matches`, `concordia_search_wants`, `concordia_search_haves`, `concordia_want_registry_stats`

**Relay** (`mcp_server.py:1470-1730`):
`concordia_relay_create`, `concordia_relay_join`, `concordia_relay_send`, `concordia_relay_receive`, `concordia_relay_status`, `concordia_relay_conclude`, `concordia_relay_transcript`, `concordia_relay_archive`, `concordia_relay_list_archives`, `concordia_relay_stats`

**Sanctuary Bridge** (`mcp_server.py:1739-1860`):
`concordia_sanctuary_bridge_configure`, `concordia_sanctuary_bridge_commit`, `concordia_sanctuary_bridge_attest`, `concordia_sanctuary_bridge_status`

---

## APPENDIX B: CROSS-REFERENCE INDEX

Key file:line references for rapid audit navigation:

| Component | File | Key Lines |
|-----------|------|-----------|
| **Sanctuary entry** | `server/src/cli.ts` | 18-50 |
| **Server init + master key** | `server/src/index.ts` | 47-524 (master key: 63-124) |
| **Router + gate wrapping** | `server/src/router.ts` | 174-280 (gate: 244-260) |
| **Schema validation** | `server/src/router.ts` | 70-128 (size limits: 44-50) |
| **ApprovalGate** | `server/src/principal-policy/gate.ts` | 49-84 (anomaly: 89-206) |
| **Policy defaults + tiers** | `server/src/principal-policy/loader.ts` | 35-85 |
| **Baseline tracker** | `server/src/principal-policy/baseline.ts` | 24-135 |
| **Stderr channel** | `server/src/principal-policy/approval-channel.ts` | 45-72 |
| **Webhook channel** | `server/src/principal-policy/webhook.ts` | 85-105 (HMAC), 176-184 (timeout), 293-303 (callback auth) |
| **Dashboard channel** | `server/src/principal-policy/dashboard.ts` | 225-246 (auth), 254-263 (CORS), 275-294 (endpoints) |
| **AES-256-GCM** | `server/src/core/encryption.ts` | 41-103 |
| **Ed25519 identity** | `server/src/core/identity.ts` | 57-240 |
| **Argon2id KDF** | `server/src/core/key-derivation.ts` | 48-117 |
| **SHA-256 + Merkle** | `server/src/core/hashing.ts` | 15-103 |
| **StateStore** | `server/src/l1-cognitive/state-store.ts` | 133+ (export: 452-513, import: 518-598) |
| **Reserved namespace check** | `server/src/l1-cognitive/tools.ts` | 36-63 |
| **Filesystem storage** | `server/src/storage/filesystem.ts` | 25-149 (path sanitize: 27-28, permissions: 45-49, secure delete: 69-102) |
| **Pedersen commitments** | `server/src/l3-disclosure/zk-proofs.ts` | 131-326 |
| **Bridge canonical JSON** | `server/src/bridge/bridge.ts` | 53-73 (stableStringify), 92-240 (commit/verify/attest) |
| **Handshake protocol** | `server/src/handshake/protocol.ts` | 35-215 |
| **Federation registry** | `server/src/federation/registry.ts` | 34-100+ |
| **Audit log** | `server/src/l2-operational/audit-log.ts` | 26-130 |
| **SHR generator** | `server/src/shr/generator.ts` | — |
| **Concordia entry** | `concordia/__main__.py` | 14-48 |
| **MCP server + tools** | `concordia/mcp_server.py` | 109-1860 (SessionStore: 137-217) |
| **Session state machine** | `concordia/session.py` | 32-55 (transitions), 115-155 (apply_message) |
| **Signing + canonical JSON** | `concordia/signing.py` | 55-108 |
| **Message envelope + hash chain** | `concordia/message.py` | 29-105 (genesis: 40, chain validation: 88) |
| **Attestation generation** | `concordia/attestation.py` | 40-137 |
| **Reputation store + Sybil** | `concordia/reputation/store.py` | 44-101 (Sybil), 124-362 (store) |
| **Reputation scorer** | `concordia/reputation/scorer.py` | 97-390 |
| **Want/have registry** | `concordia/want_registry.py` | 384-636 |
| **Relay** | `concordia/relay.py` | 205-598 |
| **Sanctuary bridge** | `concordia/sanctuary_bridge.py` | 44-348 |
| **Schema validator** | `concordia/schema_validator.py` | 30-123 |
| **Agent registry** | `concordia/registry.py` | 176-366 |
| **Degradation** | `concordia/degradation.py` | 1-389 |

---

*End of REVIEW_MAP.md. This document is the input for all subsequent review stages (SECURITY_AUDIT.md, BUG_REPORT.md, REMEDIATION_PLAN.md). Gaps identified in Section 6 should be resolved before those stages begin.*
