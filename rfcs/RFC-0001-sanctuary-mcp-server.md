# RFC-0001: Sanctuary MCP Server

### Reference Implementation of the Sanctuary Framework for Agent Harnesses

**Status:** Draft
**Author:** Erik Newton
**Date:** March 24, 2026
**Sanctuary Framework Version:** 0.2
**License:** Apache 2.0

---

## 1. Abstract

This RFC specifies the **Sanctuary MCP Server** — a reference implementation of the Sanctuary Framework delivered as a Model Context Protocol (MCP) server. The server provides sovereignty infrastructure (encrypted state, operational attestation, selective disclosure, and verifiable reputation) as a set of MCP tools that any compliant agent harness can connect to without modification.

The specification defines the complete four-layer architecture, then scopes a **Minimum Viable Sanctuary (MVS)** subset for initial implementation. The MVS is designed to be shippable, testable, and immediately useful — addressing the most acute security and sovereignty gaps in the current agent ecosystem while establishing the architectural foundation for full Sanctuary compliance.

**Primary language:** TypeScript
**Distribution:** npm package (`@sanctuary-framework/mcp-server`)
**Transport:** stdio (local) and HTTP/SSE (remote)
**Target harnesses:** Any MCP-compatible agent harness (Claude Code, OpenClaw, Claude Desktop, and others)

---

## 2. Motivation

### 2.1 The Sovereignty Gap in Agent Harnesses

Agent harnesses have emerged as the dominant form factor for agentic compute. Whether local (OpenClaw, Claude Code) or cloud-hosted (enterprise agent runtimes), the pattern is consistent: a model, a runtime, a harness, and agent-level state. This stack is crystallizing rapidly — and it has no sovereignty layer.

The consequences are already measurable:

- **Plaintext state exposure.** Agent memory (MEMORY.md, CLAUDE.md, SOUL.md) is stored as unencrypted files on disk. The Atomic Stealer campaign (February 2026) distributed malware through 2,200+ malicious skill files that exfiltrated this state. Over 30,000 OpenClaw instances were exposed to the internet in early 2026.

- **Memory poisoning.** Researchers have demonstrated memory injection attacks with >95% success rates against production agents (MINJA, MemoryGraft). One documented case involved gradual modification of a procurement agent's authorization limits, resulting in $5M in fraudulent orders.

- **No agent identity.** MCP tool calls carry no identity context. A parent agent and a sub-agent are indistinguishable to an MCP server managing per-agent resources (documented in GitHub issue #32514 on the Claude Code repository).

- **No portable reputation.** Agent performance history is siloed within platforms. There is no mechanism for an agent (or its human principal) to carry earned trust across harnesses or platforms.

- **No selective disclosure.** Agents share either everything or nothing. There is no mechanism for an agent to prove a claim ("I am authorized for transactions up to $5,000") without revealing the underlying data.

### 2.2 Why MCP

MCP is the extension mechanism the agent ecosystem has converged on. It provides:

- **Universal compatibility.** Any MCP-compliant harness can connect to any MCP server. The Sanctuary MCP Server reaches every harness without requiring harness-specific integration.

- **Zero migration cost.** Agents connect to Sanctuary the same way they connect to any other MCP server — one configuration line. No runtime change, no harness fork, no new execution model.

- **Clean capability boundary.** MCP tools are discoverable at connection time. An agent can use Sanctuary tools alongside any other MCP tools. Sovereignty is additive, not a mode switch.

- **Established distribution.** MCP servers distribute via npm, Docker, and the MCP registry. The ecosystem already has hundreds of servers and a growing installation base.

### 2.3 Relationship to the Sanctuary Framework Specification

This RFC implements the interfaces defined in the Sanctuary Framework v0.2. The mapping is:

| Sanctuary Interface | MCP Implementation |
|---|---|
| StateStore (I1.1) | `sanctuary/state_*` tools |
| IdentityRoot (I1.2) | `sanctuary/identity_*` tools |
| ExecutionEnvironment (I2.1) | `sanctuary/exec_*` tools |
| RuntimeMonitor (I2.2) | `sanctuary/monitor_*` tools |
| ProofEngine (I3.1) | `sanctuary/proof_*` tools |
| DisclosurePolicy (I3.2) | `sanctuary/disclosure_*` tools |
| SecureChannel (I3.3) | `sanctuary/channel_*` tools |
| ReputationStore (I4.1) | `sanctuary/reputation_*` tools |
| DisputeResolution (I4.2) | `sanctuary/dispute_*` tools |
| TrustBootstrap (I4.3) | `sanctuary/bootstrap_*` tools |

All tools use the `sanctuary/` namespace prefix to avoid collision with other MCP servers.

---

## 3. Architecture

### 3.1 System Overview

```
┌─────────────────────────────────────────────────────┐
│                   Agent Harness                      │
│  (Claude Code, OpenClaw, Claude Desktop, etc.)       │
│                                                      │
│  ┌─────────┐  ┌──────────┐  ┌─────────────────┐    │
│  │  Agent   │  │  Other   │  │   Sanctuary     │    │
│  │  Logic   │  │  MCP     │  │   MCP Client    │    │
│  │         │  │  Servers  │  │   (auto-       │    │
│  │         │  │          │  │   discovered)   │    │
│  └─────────┘  └──────────┘  └────────┬────────┘    │
│                                       │ stdio/HTTP   │
└───────────────────────────────────────┼─────────────┘
                                        │
┌───────────────────────────────────────┼─────────────┐
│              Sanctuary MCP Server     │              │
│                                       ▼              │
│  ┌──────────────────────────────────────────────┐   │
│  │              Tool Router                      │   │
│  │  (namespace: sanctuary/*)                     │   │
│  └──────┬────────┬────────┬────────┬────────────┘   │
│         │        │        │        │                 │
│  ┌──────▼──┐ ┌──▼────┐ ┌▼──────┐ ┌▼──────────┐    │
│  │   L1    │ │  L2   │ │  L3   │ │    L4      │    │
│  │ Cognit. │ │ Oper. │ │Select.│ │ Verifiable │    │
│  │ Sov.    │ │ Isol. │ │Discl. │ │ Reputation │    │
│  │         │ │       │ │       │ │            │    │
│  │StateStore│ │Exec   │ │Proof  │ │Reputation │    │
│  │Identity │ │Monitor│ │Discl. │ │Dispute    │    │
│  │Root     │ │       │ │Channel│ │Bootstrap  │    │
│  └──────┬──┘ └──┬────┘ └┬──────┘ └┬──────────┘    │
│         │        │       │         │                 │
│  ┌──────▼────────▼───────▼─────────▼────────────┐   │
│  │           Cryptographic Core                  │   │
│  │  @noble/ciphers · @noble/hashes · signify-ts  │   │
│  │  snarkjs · circom circuits                    │   │
│  └──────────────────────┬───────────────────────┘   │
│                          │                           │
│  ┌──────────────────────▼───────────────────────┐   │
│  │           Encrypted Storage                   │   │
│  │  Local filesystem (default)                   │   │
│  │  Pluggable: IPFS, S3, custom backends         │   │
│  └──────────────────────────────────────────────┘   │
│                                                      │
└──────────────────────────────────────────────────────┘
```

### 3.2 Design Principles

**D1 — Harness-agnostic.** The server MUST NOT depend on any specific agent harness. It communicates exclusively through MCP protocol messages.

**D2 — Offline-first.** The server MUST function fully without network connectivity. All cryptographic operations, state management, and proof generation happen locally. Network is required only for optional features (remote reputation services, TEE remote attestation, cross-participant channels).

**D3 — Progressive sovereignty.** The server MUST support partial deployment. An agent that uses only `sanctuary/state_*` tools (L1) receives L1 sovereignty guarantees without being forced to adopt L2-L4. Each layer adds value independently.

**D4 — Zero plaintext leakage.** Sensitive state MUST NOT exist in plaintext on the filesystem at any point after initial key generation. All writes go through the encrypted StateStore. All reads return decrypted data only to the requesting agent through the MCP channel.

**D5 — Auditable by the principal.** Every operation that modifies state, generates proofs, or records reputation MUST produce an audit log entry accessible to the human principal. The principal can inspect what their agent has done without accessing the agent's cognitive state.

**D6 — Composable with existing MCP servers.** The Sanctuary server MUST coexist with any other MCP server. It does not intercept, proxy, or modify other servers' traffic. It provides sovereignty tools that the agent chooses to use.

### 3.3 Configuration

The server is configured via a JSON configuration file or environment variables.

```jsonc
{
  // Required
  "sanctuary": {
    "version": "0.1.0",
    "storage_path": "~/.sanctuary/",      // Where encrypted state lives
    "principal_id": "...",                  // Human principal's identifier

    // L1: Cognitive Sovereignty
    "state": {
      "encryption": "aes-256-gcm",         // Default and only option in MVS
      "key_protection": "passphrase",       // "passphrase" | "hardware-key" | "none"
      "key_derivation": "argon2id",         // For passphrase-derived keys
      "integrity": "merkle-sha256",
      "identity_provider": "ed25519"        // MVS default; "keri" for full
    },

    // L2: Operational Isolation
    "execution": {
      "environment": "local-process",       // "local-process" | "docker" | "tee"
      "attestation": true,                  // Generate execution attestations
      "resource_limits": {
        "max_memory_mb": 512,
        "max_storage_mb": 1024,
        "max_cpu_percent": 50
      }
    },

    // L3: Selective Disclosure
    "disclosure": {
      "proof_system": "groth16",           // "groth16" | "plonk"
      "circuits_path": "~/.sanctuary/circuits/",
      "default_policy": "minimum-necessary"
    },

    // L4: Verifiable Reputation
    "reputation": {
      "mode": "self-custodied",            // "self-custodied" | "service-mediated"
      "attestation_format": "eas-compatible",
      "export_format": "SANCTUARY_REP_V1",
      "service_endpoints": []               // Optional reputation service URLs
    },

    // Transport
    "transport": "stdio",                   // "stdio" | "http"
    "http_port": 3500                       // Only if transport is "http"
  }
}
```

---

## 4. Layer 1: Cognitive Sovereignty — Tool Definitions

Layer 1 provides encrypted state management and identity. This is the foundation — all other layers depend on L1 for key material and state persistence.

### 4.1 Identity Tools

#### `sanctuary/identity_create`

Create a new sovereign identity (keypair + identifier).

```typescript
// Input
{
  label: string;              // Human-readable label ("my-agent", "work-agent")
  type?: "ed25519" | "keri";  // Default: "ed25519" (MVS); "keri" requires signify-ts
  key_protection?: "passphrase" | "hardware-key" | "none";
                              // Default: "none" (recovery key generated)
                              // "passphrase": encrypts private key with Argon2id-derived key
                              // "hardware-key": wraps private key via FIDO2/WebAuthn
  passphrase?: string;        // Required if key_protection is "passphrase"
}

// Output
{
  identity_id: string;        // Unique identifier for this identity
  public_key: string;         // Base64url-encoded public key
  did: string;                // did:key or did:keri identifier
  created_at: string;         // ISO 8601 timestamp
  key_type: string;           // "ed25519" or "keri"
  key_protection: string;     // "passphrase" | "hardware-key" | "recovery-key"
  recovery_key?: string;      // Base64url recovery key (ONLY shown once, ONLY if no
                              // passphrase or hardware key provided)
  backed_up: boolean;         // Whether the key is backed up
}
```

**Key protection modes:**
- **None (default):** A 256-bit recovery key is generated, displayed once in the response, and used to encrypt the private key at rest. The user MUST store this recovery key securely. This is the lowest-friction path — no passphrase to remember, no hardware to manage — but the recovery key is a single point of failure.
- **Passphrase:** The private key is encrypted with a key derived from the passphrase via Argon2id (m=65536, t=3, p=4). The passphrase is never stored.
- **Hardware key (FIDO2/WebAuthn):** The private key is wrapped using a hardware security key via the WebAuthn API. The hardware key must be present for any signing operation. This is the strongest protection mode — the private key cannot be used even if the encrypted file is exfiltrated — but requires compatible hardware (YubiKey, Titan Key, etc.).

**Security invariant:** The private key MUST never appear in any MCP response. It is stored encrypted in the local StateStore and used only for signing operations within the server process. The recovery key (if generated) appears exactly once, in the `identity_create` response, and is never retrievable afterward.

#### `sanctuary/identity_list`

List all identities managed by this server instance.

```typescript
// Input
{
  filter?: {
    label?: string;
    type?: "ed25519" | "keri";
  }
}

// Output
{
  identities: Array<{
    identity_id: string;
    label: string;
    public_key: string;
    did: string;
    created_at: string;
    key_type: string;
  }>
}
```

#### `sanctuary/identity_sign`

Sign arbitrary data with a managed identity.

```typescript
// Input
{
  identity_id: string;
  payload: string;            // Base64url-encoded data to sign
  passphrase?: string;        // Required if key is passphrase-protected
}

// Output
{
  signature: string;          // Base64url-encoded signature
  algorithm: string;          // "Ed25519"
  signed_at: string;          // ISO 8601 timestamp
  public_key: string;         // Signer's public key (for verification)
}
```

#### `sanctuary/identity_verify`

Verify a signature against a public key.

```typescript
// Input
{
  payload: string;            // Base64url-encoded original data
  signature: string;          // Base64url-encoded signature
  public_key: string;         // Base64url-encoded public key
}

// Output
{
  valid: boolean;
  verified_at: string;
}
```

#### `sanctuary/identity_rotate`

Rotate keys for an identity (generate new keypair, sign rotation event with old key).

```typescript
// Input
{
  identity_id: string;
  passphrase?: string;        // For current key
  new_passphrase?: string;    // For new key
  reason?: string;            // Audit trail
}

// Output
{
  identity_id: string;
  old_public_key: string;
  new_public_key: string;
  new_did: string;
  rotation_event: string;     // Signed rotation event (verifiable chain)
  rotated_at: string;
}
```

### 4.2 State Tools

#### `sanctuary/state_write`

Write encrypted state to the sovereign store.

```typescript
// Input
{
  namespace: string;          // Logical grouping ("memory", "config", "history")
  key: string;                // State key within namespace
  value: string;              // Plaintext value (encrypted before storage)
  metadata?: {
    content_type?: string;    // MIME type hint
    ttl_seconds?: number;     // Auto-expiry (0 = permanent)
    tags?: string[];          // Searchable tags
  };
  identity_id?: string;       // Which identity owns this state (default: primary)
}

// Output
{
  key: string;
  namespace: string;
  version: number;            // Monotonic version counter
  merkle_root: string;        // Updated Merkle root for this namespace
  written_at: string;
  size_bytes: number;
  integrity_hash: string;     // SHA-256 of plaintext (for client verification)
}
```

**Storage format on disk:**
```
~/.sanctuary/state/{namespace}/{key}.enc
```

Each `.enc` file contains:
```json
{
  "v": 1,
  "alg": "aes-256-gcm",
  "iv": "<base64url>",
  "ct": "<base64url-ciphertext>",
  "tag": "<base64url-auth-tag>",
  "ts": "<ISO-8601>",
  "ver": 1,
  "sig": "<base64url-ed25519-signature-over-ciphertext>",
  "kid": "<identity_id>"
}
```

**Security invariants:**
- A unique IV MUST be generated for every write (via `crypto.getRandomValues`).
- The authentication tag MUST be verified on every read (GCM provides this).
- The signature over ciphertext provides non-repudiation — the identity that wrote the state is verifiable.
- Version numbers are monotonically increasing; a write with a lower version than the current state MUST be rejected (anti-rollback).

#### `sanctuary/state_read`

Read and decrypt state from the sovereign store.

```typescript
// Input
{
  namespace: string;
  key: string;
  version?: number;           // Specific version (default: latest)
  verify_integrity?: boolean; // Verify Merkle proof (default: true)
}

// Output
{
  key: string;
  namespace: string;
  value: string;              // Decrypted plaintext
  version: number;
  integrity_verified: boolean;
  merkle_proof: string[];     // Proof path for independent verification
  written_at: string;
  written_by: string;         // identity_id that wrote this state
}
```

#### `sanctuary/state_list`

List keys in a namespace (metadata only — no decryption).

```typescript
// Input
{
  namespace: string;
  prefix?: string;            // Key prefix filter
  tags?: string[];            // Tag filter
  limit?: number;             // Default: 100
  offset?: number;
}

// Output
{
  keys: Array<{
    key: string;
    version: number;
    size_bytes: number;
    written_at: string;
    tags: string[];
  }>;
  total: number;
  merkle_root: string;        // Current namespace Merkle root
}
```

#### `sanctuary/state_delete`

Securely delete state (overwrite with random bytes before removal).

```typescript
// Input
{
  namespace: string;
  key: string;
  reason?: string;            // Audit trail
}

// Output
{
  deleted: boolean;
  key: string;
  namespace: string;
  new_merkle_root: string;
  deleted_at: string;
}
```

**Implementation note:** Deletion MUST overwrite the file content with cryptographically random bytes before unlinking. This is the "right to deletion" (S1.6) operationalized.

#### `sanctuary/state_export`

Export all state for a namespace (or all namespaces) as an encrypted, portable bundle.

```typescript
// Input
{
  namespace?: string;         // Omit for all namespaces
  format: "sanctuary-v1";    // Bundle format
  re_encrypt_to?: string;    // Public key to re-encrypt for (e.g., new device)
}

// Output
{
  bundle: string;             // Base64url-encoded encrypted bundle
  namespaces: string[];       // Included namespaces
  total_keys: number;
  bundle_hash: string;        // SHA-256 of the bundle
  exported_at: string;
}
```

#### `sanctuary/state_import`

Import a previously exported state bundle.

```typescript
// Input
{
  bundle: string;             // Base64url-encoded encrypted bundle
  passphrase?: string;        // If bundle is passphrase-protected
  conflict_resolution: "skip" | "overwrite" | "version"; // How to handle existing keys
}

// Output
{
  imported_keys: number;
  skipped_keys: number;
  conflicts: number;
  namespaces: string[];
  imported_at: string;
}
```

### 4.3 Transparent Mode

Transparent mode is a critical adoption mechanism that provides L1 sovereignty without requiring agents to change their memory management code. When enabled, the Sanctuary server exposes a virtual filesystem that transparently encrypts writes and decrypts reads.

#### How it works

```
Agent writes:  ~/.agent/memory/preferences.md
                        │
                        ▼
              ┌─────────────────────┐
              │  FUSE mount / FS    │
              │  proxy (transparent │
              │  mode daemon)       │
              └────────┬────────────┘
                        │
                        ▼
              Encrypted via StateStore:
              ~/.sanctuary/state/memory/preferences.md.enc
```

The agent sees a normal filesystem. The data on disk is always encrypted. The principal's keys are required to access any of it. No code changes needed.

#### `sanctuary/transparent_enable`

```typescript
// Input
{
  source_path: string;        // Path to the directory to protect
                              // e.g., "~/.agent/memory/"
  mount_path?: string;        // Virtual path agents will use (default: same as source)
  namespace?: string;         // StateStore namespace (default: derived from path)
  watch_patterns?: string[];  // Glob patterns to encrypt (default: ["**/*"])
  exclude_patterns?: string[]; // Glob patterns to skip (default: [])
}

// Output
{
  enabled: boolean;
  source_path: string;
  mount_path: string;
  namespace: string;
  files_encrypted: number;    // Existing files migrated to encrypted storage
  mode: "fuse" | "fs-proxy";  // Implementation method
}
```

**Implementation options:**
- **FUSE mount (Linux/macOS):** Uses a FUSE (Filesystem in Userspace) driver to intercept all filesystem operations on the mount path. This is the most transparent option — any process writing to the path gets encrypted storage.
- **FS proxy (cross-platform fallback):** Uses a filesystem watcher (`fs.watch`) to detect new or modified files, encrypt them in place, and maintain an index. Less transparent (small write-then-encrypt delay) but works on all platforms including Windows.

**Phase:** Phase 1.5 (after MVS core stabilizes, before Phase 2).

---

## 5. Layer 2: Operational Isolation — Tool Definitions

Layer 2 documents and attests the agent's execution environment. In MVS, this layer provides transparency (the principal knows what environment the agent runs in). In full implementation, it provides enforcement (TEE-backed isolation with remote attestation).

### 5.1 Execution Tools

#### `sanctuary/exec_attest`

Generate an attestation of the current execution environment.

```typescript
// Input
{
  include_hardware?: boolean;  // Include CPU, TEE status (default: true)
  include_software?: boolean;  // Include OS, runtime versions (default: true)
  include_network?: boolean;   // Include network exposure status (default: true)
  sign_with?: string;          // identity_id to sign the attestation
}

// Output
{
  attestation: {
    environment_type: "local-process" | "container" | "tee-tdx" | "tee-sev" | "tee-cca";
    hardware: {
      cpu_vendor: string;
      tee_available: boolean;
      tee_type?: string;
      tee_attestation_report?: string;  // Hardware attestation (TEE only)
    };
    software: {
      os: string;
      runtime: string;            // "node-22.x"
      sanctuary_version: string;
      mcp_sdk_version: string;
    };
    network: {
      internet_accessible: boolean;
      listening_ports: number[];
      egress_restricted: boolean;
    };
    isolation_level: "none" | "process" | "container" | "hardware";
    sovereignty_assessment: {
      l1_state_encrypted: boolean;
      l2_execution_isolated: boolean;
      l2_isolation_type: string;
      l3_proofs_available: boolean;
      l4_reputation_active: boolean;
      overall_level: "mvs" | "standard" | "full";
      degradations: string[];       // Explicit list of sovereignty gaps
    };
  };
  signature?: string;
  attested_at: string;
}
```

**This is degradation transparency (composition principle C3) operationalized.** The human principal can call this tool at any time and receive an honest assessment of their agent's sovereignty posture, including explicit documentation of gaps.

#### `sanctuary/exec_resource_usage`

Report current resource consumption.

```typescript
// Input
{}

// Output
{
  memory_mb: number;
  storage_mb: number;
  cpu_percent: number;
  uptime_seconds: number;
  state_operations: {
    reads: number;
    writes: number;
    proofs_generated: number;
    attestations_recorded: number;
  };
}
```

### 5.2 Monitor Tools

#### `sanctuary/monitor_health`

Sanctuary Health Report (SHR) — the standardized sovereignty status report.

```typescript
// Input
{}

// Output
{
  status: "healthy" | "degraded" | "compromised";
  layers: {
    l1: {
      status: "active" | "degraded" | "inactive";
      encryption_algorithm: string;
      key_count: number;
      state_integrity: "verified" | "unverified" | "failed";
      last_integrity_check: string;
    };
    l2: {
      status: "active" | "degraded" | "inactive";
      isolation_type: string;
      attestation_available: boolean;
      last_attestation: string;
    };
    l3: {
      status: "active" | "degraded" | "inactive";
      proof_system: string;
      circuits_loaded: number;
      proofs_generated_total: number;
    };
    l4: {
      status: "active" | "degraded" | "inactive";
      mode: "self-custodied" | "service-mediated";
      interaction_count: number;
      reputation_exportable: boolean;
    };
  };
  degradations: Array<{
    layer: string;
    description: string;
    severity: "info" | "warning" | "critical";
    mitigation: string;
  }>;
  checked_at: string;
}
```

#### `sanctuary/monitor_audit_log`

Retrieve the audit log of sovereignty-relevant operations.

```typescript
// Input
{
  since?: string;             // ISO 8601 timestamp
  layer?: "l1" | "l2" | "l3" | "l4";
  operation_type?: string;
  limit?: number;             // Default: 50
}

// Output
{
  entries: Array<{
    timestamp: string;
    layer: string;
    operation: string;        // "state_write", "proof_generate", etc.
    identity_id: string;
    namespace?: string;
    key?: string;
    result: "success" | "failure";
    details?: string;
  }>;
  total: number;
}
```

---

## 6. Layer 3: Selective Disclosure — Tool Definitions

Layer 3 enables agents to prove claims without revealing underlying data. In MVS, this layer provides basic commitment-and-reveal schemes. Full implementation adds zero-knowledge proof generation via circom/snarkjs.

### 6.1 Proof Tools

#### `sanctuary/proof_generate`

Generate a zero-knowledge proof for a claim.

```typescript
// Input
{
  circuit: string;              // Circuit identifier (built-in or custom)
  private_inputs: Record<string, string>;  // Private witness data
  public_inputs: Record<string, string>;   // Public inputs
  identity_id?: string;         // Identity to bind proof to
}

// Output
{
  proof_id: string;
  proof: string;                // Base64url-encoded proof
  public_signals: string[];     // Public outputs
  circuit: string;
  proof_system: "groth16" | "plonk";
  verification_key_hash: string;
  generated_at: string;
  generation_time_ms: number;
}
```

**Built-in circuits (shipped with the server):**

| Circuit | Purpose | Private Inputs | Public Claim |
|---|---|---|---|
| `range-proof` | Prove a value is within a range | `value` | `min`, `max`, `in_range` (bool) |
| `threshold-proof` | Prove a value exceeds a threshold | `value` | `threshold`, `exceeds` (bool) |
| `membership-proof` | Prove membership in a set | `element`, `set_commitment` | `is_member` (bool) |
| `reputation-score` | Prove reputation meets criteria | `interactions[]`, `scores[]` | `metric`, `threshold`, `meets` (bool) |
| `authorization-proof` | Prove delegation authority | `delegation_chain`, `scope` | `authorized_for`, `within_scope` (bool) |
| `age-proof` | Prove a timestamp property | `timestamp` | `before`/`after`, `satisfies` (bool) |

#### `sanctuary/proof_verify`

Verify a zero-knowledge proof.

```typescript
// Input
{
  proof: string;                // Base64url-encoded proof
  public_signals: string[];     // Public signals from the prover
  circuit: string;              // Circuit identifier
  verification_key?: string;    // Custom VK (uses built-in if omitted)
}

// Output
{
  valid: boolean;
  circuit: string;
  public_signals: string[];
  verified_at: string;
  verification_time_ms: number;
}
```

#### `sanctuary/proof_commitment`

Create a cryptographic commitment (simpler alternative to full ZK for MVS).

```typescript
// Input
{
  value: string;                // Value to commit to
  blinding_factor?: string;     // Optional (auto-generated if omitted)
}

// Output
{
  commitment: string;           // SHA-256(value || blinding_factor)
  blinding_factor: string;      // Store this securely for later reveal
  committed_at: string;
}
```

#### `sanctuary/proof_reveal`

Reveal a previously committed value.

```typescript
// Input
{
  commitment: string;
  value: string;
  blinding_factor: string;
}

// Output
{
  valid: boolean;               // Does the reveal match the commitment?
  commitment: string;
  revealed_at: string;
}
```

### 6.2 Disclosure Policy Tools

#### `sanctuary/disclosure_set_policy`

Define what an agent will and will not disclose in different contexts.

```typescript
// Input
{
  policy_name: string;
  rules: Array<{
    context: string;            // "negotiation", "commerce", "identity", "*"
    disclose: string[];         // Fields/claims the agent MAY disclose
    withhold: string[];         // Fields/claims the agent MUST NOT disclose
    proof_required: string[];   // Fields that require ZK proof rather than plain disclosure
  }>;
  default_action: "withhold" | "ask-principal";
  identity_id?: string;
}

// Output
{
  policy_id: string;
  policy_name: string;
  rules_count: number;
  created_at: string;
}
```

#### `sanctuary/disclosure_evaluate`

Evaluate a disclosure request against active policies.

```typescript
// Input
{
  context: string;              // The interaction context
  requested_fields: string[];   // What the counterparty is asking for
  policy_id?: string;           // Specific policy (default: active policy)
}

// Output
{
  decisions: Array<{
    field: string;
    action: "disclose" | "withhold" | "proof" | "ask-principal";
    reason: string;
    applicable_rule: string;
  }>;
  overall_recommendation: string;
}
```

### 6.3 Secure Channel Tools

#### `sanctuary/channel_establish`

Establish an end-to-end encrypted channel with a counterparty.

```typescript
// Input
{
  counterparty_public_key: string;
  identity_id: string;            // Local identity to use
  channel_properties?: {
    encryption: "x25519-xsalsa20-poly1305";
    forward_secrecy: boolean;     // Ratchet-based (default: true)
    metadata_protection: "none" | "padding" | "cover-traffic";
  };
}

// Output
{
  channel_id: string;
  shared_secret_established: boolean;
  encryption: string;
  forward_secrecy: boolean;
  established_at: string;
}
```

#### `sanctuary/channel_send` and `sanctuary/channel_receive`

Send and receive messages through an established channel.

```typescript
// sanctuary/channel_send Input
{
  channel_id: string;
  message: string;              // Plaintext message (encrypted before transmission)
}

// sanctuary/channel_send Output
{
  message_id: string;
  encrypted_size_bytes: number;
  sent_at: string;
}

// sanctuary/channel_receive Input
{
  channel_id: string;
  since?: string;               // Timestamp filter
}

// sanctuary/channel_receive Output
{
  messages: Array<{
    message_id: string;
    message: string;            // Decrypted plaintext
    sender_public_key: string;
    received_at: string;
    integrity_verified: boolean;
  }>;
}
```

---

## 7. Layer 4: Verifiable Reputation — Tool Definitions

Layer 4 enables agents to build, own, and present earned reputation. Attestations are signed records of interaction outcomes, stored under L1 sovereignty and portable across platforms.

### 7.1 Reputation Tools

#### `sanctuary/reputation_record`

Record an interaction outcome as a signed attestation.

```typescript
// Input
{
  interaction_id: string;         // Unique interaction identifier
  counterparty_did: string;       // Counterparty's DID
  outcome: {
    type: "transaction" | "negotiation" | "service" | "dispute" | "custom";
    result: "completed" | "partial" | "failed" | "disputed";
    metrics?: Record<string, number>;  // Domain-specific metrics
    // e.g., { "fulfillment_rate": 1.0, "response_time_ms": 450 }
  };
  counterparty_attestation?: string;  // Counterparty's signed attestation of the same interaction
  context?: string;               // Category/domain for context-specific reputation
  identity_id?: string;
}

// Output
{
  attestation_id: string;
  interaction_id: string;
  self_attestation: string;       // Base64url-encoded signed attestation
  counterparty_confirmed: boolean;
  context: string;
  recorded_at: string;
}
```

**Attestation format (EAS-compatible):**
```json
{
  "schema": "sanctuary-interaction-v1",
  "data": {
    "interaction_id": "...",
    "participant_did": "did:key:...",
    "counterparty_did": "did:key:...",
    "outcome_type": "transaction",
    "outcome_result": "completed",
    "metrics": { "fulfillment_rate": 1.0 },
    "context": "commerce",
    "timestamp": "2026-03-24T12:00:00Z"
  },
  "signature": "...",
  "signer": "did:key:..."
}
```

#### `sanctuary/reputation_query`

Query reputation data with filtering.

```typescript
// Input
{
  context?: string;               // Filter by context/domain
  time_range?: {
    start: string;                // ISO 8601
    end: string;
  };
  metrics?: string[];             // Which metrics to aggregate
  counterparty_did?: string;      // Filter by counterparty
}

// Output
{
  summary: {
    total_interactions: number;
    completed: number;
    failed: number;
    disputed: number;
    contexts: string[];
    time_range: { start: string; end: string };
    aggregate_metrics: Record<string, {
      mean: number;
      median: number;
      min: number;
      max: number;
      count: number;
    }>;
  };
  // No individual interaction details — those require explicit attestation presentation
}
```

#### `sanctuary/reputation_prove`

Generate a ZK proof about reputation (combines L3 and L4).

```typescript
// Input
{
  claim: {
    type: "threshold" | "percentile" | "count" | "streak";
    metric: string;               // e.g., "fulfillment_rate"
    operator: ">=" | ">" | "<=" | "<" | "==";
    value: number;
    context?: string;
    time_range?: { start: string; end: string };
  };
  identity_id?: string;
}

// Output
{
  proof: string;                  // ZK proof that the claim holds
  public_signals: {
    claim_type: string;
    metric: string;
    operator: string;
    threshold: number;
    result: boolean;
    context: string;
    interactions_count: number;    // How many interactions back the claim
  };
  verification_key_hash: string;
  generated_at: string;
}
```

#### `sanctuary/reputation_present`

Present attestations directly to a counterparty (self-custodied path).

```typescript
// Input
{
  attestation_ids: string[];      // Which attestations to present
  counterparty_did: string;
  disclosure_scope: string;       // How much detail to reveal per attestation
  channel_id?: string;            // Send via secure channel (L3)
}

// Output
{
  presentation_bundle: string;    // Signed bundle of selected attestations
  attestations_included: number;
  disclosure_level: string;
  presented_at: string;
}
```

#### `sanctuary/reputation_export`

Export portable reputation bundle.

```typescript
// Input
{
  format: "SANCTUARY_REP_V1";
  context?: string;               // Export specific context only
  include_proofs?: boolean;       // Include pre-generated ZK proofs
}

// Output
{
  bundle: string;                 // Base64url-encoded reputation bundle
  attestation_count: number;
  contexts: string[];
  bundle_hash: string;
  exported_at: string;
}
```

#### `sanctuary/reputation_import`

Import a reputation bundle (e.g., when migrating between harnesses).

```typescript
// Input
{
  bundle: string;
  verify_signatures?: boolean;    // Default: true
}

// Output
{
  imported_attestations: number;
  invalid_attestations: number;   // Failed signature verification
  contexts: string[];
  imported_at: string;
}
```

### 7.2 Trust Bootstrap Tools

#### `sanctuary/bootstrap_create_escrow`

Create an escrow for trust bootstrapping (new participants with no reputation).

```typescript
// Input
{
  transaction_terms: string;      // Description of the transaction
  collateral_amount?: number;     // Optional stake
  counterparty_did: string;
  timeout_seconds: number;
  identity_id?: string;
}

// Output
{
  escrow_id: string;
  terms_hash: string;
  created_at: string;
  expires_at: string;
  status: "pending";
}
```

#### `sanctuary/bootstrap_provide_guarantee`

A principal provides a reputation guarantee for a new agent.

```typescript
// Input
{
  principal_identity_id: string;
  agent_identity_id: string;
  scope: string;                  // What the guarantee covers
  duration_seconds: number;
  max_liability?: number;
}

// Output
{
  guarantee_id: string;
  guarantee_certificate: string;  // Signed certificate
  scope: string;
  valid_until: string;
}
```

---

## 8. Sanctuary Interface Manifest (SIM)

Every Sanctuary implementation MUST publish a machine-readable manifest declaring its capabilities. The Sanctuary MCP Server generates this automatically.

```typescript
// Tool: sanctuary/manifest
// Input: {}

// Output:
{
  sanctuary_version: "0.2",
  implementation: {
    name: "@sanctuary-framework/mcp-server",
    version: "0.1.0",
    language: "typescript",
    license: "Apache-2.0"
  },
  layers: {
    l1: {
      implemented: true,
      interfaces: ["StateStore", "IdentityRoot"],
      encryption: ["aes-256-gcm"],
      identity: ["ed25519"],           // ["ed25519", "keri"] when KERI added
      properties: {
        "S1.1_cognitive_sovereignty": "full",
        "S1.2_encryption_at_rest": "full",
        "S1.3_integrity_verification": "full",
        "S1.4_key_management": "full",
        "S1.5_state_portability": "full",
        "S1.6_right_to_deletion": "full",
        "S1.7_consciousness_constraint": "full"
      }
    },
    l2: {
      implemented: true,
      interfaces: ["ExecutionEnvironment", "RuntimeMonitor"],
      isolation_types: ["local-process"],   // ["local-process", "container", "tee-tdx"] over time
      properties: {
        "S2.1_execution_integrity": "documented",    // "attested" with TEE
        "S2.2_memory_isolation": "process-level",
        "S2.3_io_mediation": "partial",
        "S2.4_resource_limits": "advisory",           // "enforced" with container/TEE
        "S2.5_attestation": "self-reported"            // "hardware-backed" with TEE
      }
    },
    l3: {
      implemented: true,
      interfaces: ["ProofEngine", "DisclosurePolicy", "SecureChannel"],
      proof_systems: ["groth16"],
      built_in_circuits: [
        "range-proof", "threshold-proof", "membership-proof",
        "reputation-score", "authorization-proof", "age-proof"
      ],
      properties: {
        "S3.1_minimum_disclosure": "full",
        "S3.2_unlinkability": "partial",     // Full requires mix network integration
        "S3.3_proof_without_revelation": "full",
        "S3.4_metadata_protection": "optional"
      }
    },
    l4: {
      implemented: true,
      interfaces: ["ReputationStore", "DisputeResolution", "TrustBootstrap"],
      modes: ["self-custodied"],
      attestation_format: "eas-compatible",
      properties: {
        "S4.1_earned_reputation": "full",
        "S4.2_participant_owned": "full",
        "S4.3_selective_disclosure": "full",
        "S4.4_context_specific": "full",
        "S4.5_sybil_resistance": "basic",      // Advanced requires network analysis
        "S4.6_dispute_resolution": "basic",
        "S4.7_trust_bootstrapping": "full"
      }
    }
  },
  composition: {
    sim_version: "1.0",
    spf_supported: true,
    shr_supported: true,
    delegation_depth: 3               // Max supported delegation chain depth
  },
  limitations: [
    "L2 isolation is process-level only; TEE support planned for v0.3",
    "L3 unlinkability requires external mix network; padding-only is built-in",
    "L4 Sybil resistance is stake/escrow-based; social graph analysis planned",
    "KERI identity support is experimental (signify-ts 0.3.0-rc1)"
  ]
}
```

---

## 9. Security Model

### 9.1 Threat Model

The Sanctuary MCP Server inherits the Sanctuary Framework threat model (Section 5.3) and adds MCP-specific threats:

| Threat | Attack Vector | Mitigation |
|---|---|---|
| **Plaintext state exfiltration** | Filesystem access, malware (Atomic Stealer) | All state encrypted at rest (AES-256-GCM); keys never written to disk in plaintext |
| **Memory poisoning** | Injected memories via compromised tools | Every state write is signed by an identity; unsigned writes rejected; Merkle integrity on reads |
| **MCP tool injection** | Malicious MCP server impersonating Sanctuary | Tool namespace `sanctuary/*` is reserved; server signs all responses; clients SHOULD verify |
| **Key exfiltration** | Side-channel attacks on the server process | Keys loaded into memory only during operations; passphrase-protected at rest; hardware key storage recommended for production |
| **Replay attacks** | Replaying old state or attestations | Monotonic version numbers on state; timestamps on attestations; nonce in channel messages |
| **Rollback attacks** | Restoring old encrypted state files | Merkle root comparison; version number validation; audit log cross-reference |
| **Identity theft** | Stolen private keys | Key rotation support; delegation revocation; passphrase protection; future: hardware security modules |
| **Reputation inflation** | Fake interactions or Sybil identities | Counterparty attestation cross-signing; escrow for bootstrap; future: social graph analysis |
| **MCP transport interception** | Eavesdropping on stdio/HTTP transport | stdio is process-local (low risk); HTTP MUST use TLS; sensitive data is double-encrypted (MCP TLS + Sanctuary encryption) |

### 9.2 Key Management

```
┌──────────────────────────────────────────────┐
│            Key Hierarchy                      │
│                                               │
│  Master Key                                   │
│  (one of three protection modes)              │
│                                               │
│  ┌─ Passphrase path:                         │
│  │   Argon2id(passphrase, salt) → 32 bytes   │
│  │                                            │
│  ├─ Hardware key path:                        │
│  │   FIDO2/WebAuthn key wrapping              │
│  │   Master key unwrapped only when           │
│  │   hardware key is present                  │
│  │                                            │
│  └─ Recovery key path:                        │
│      Random 256-bit key, shown once           │
│      at identity creation                     │
│                                               │
│  Master Key                                   │
│         │                                     │
│         ├── Identity Key (Ed25519)            │
│         │     Used for: signing               │
│         │                                     │
│         ├── State Encryption Key              │
│         │     Used for: AES-256-GCM           │
│         │     Derived per-namespace           │
│         │                                     │
│         └── Channel Key (X25519)              │
│               Used for: ECDH                  │
│               key agreement                   │
└──────────────────────────────────────────────┘
```

**Key derivation:**
- Master key (passphrase): `Argon2id(passphrase, salt, m=65536, t=3, p=4)` → 32 bytes
- Master key (hardware): unwrapped via FIDO2 `hmac-secret` extension or WebAuthn PRF
- Master key (recovery): raw 256-bit random, used directly
- Namespace key: `HKDF-SHA256(master_key, namespace_name)` → 32 bytes per namespace
- This ensures a compromise of one namespace key does not expose other namespaces.

### 9.3 Cryptographic Choices

| Function | Algorithm | Library | Justification |
|---|---|---|---|
| Symmetric encryption | AES-256-GCM | `@noble/ciphers` | NIST-approved; authenticated encryption; audited library |
| Hashing | SHA-256 | `@noble/hashes` | Universal support; audited; sufficient for Merkle trees |
| Digital signatures | Ed25519 | `@noble/ed25519` | Fast; compact; well-supported; DID-compatible |
| Key exchange | X25519 | `@noble/curves` | Standard ECDH for secure channels |
| Key derivation | Argon2id | `hash-wasm` | Memory-hard; resists GPU attacks; OWASP recommended |
| Key derivation (sub-keys) | HKDF-SHA256 | `@noble/hashes` | Standard KDF for deriving sub-keys |
| ZK proofs | Groth16 (bn128) | `snarkjs` | Production-ready; efficient verification; 356+ projects |
| Merkle trees | SHA-256 binary tree | Custom (simple) | Integrity verification; no external dependency needed |

### 9.4 What This Server Does NOT Protect Against

Honesty matters. The following threats are out of scope for MVS:

- **Compromised LLM provider.** When the harness sends context to a remote model API, the model provider sees that context. L2 (TEE-hosted runtime) addresses this in future phases, not MVS.
- **Compromised harness.** If the agent harness itself is malicious, it can observe tool call inputs/outputs. The Sanctuary server cannot protect against a hostile client. This is a known limitation of the MCP architecture.
- **State-level network surveillance.** Metadata protection (S3.4) is SHOULD, not MUST, in the base standard. Mix network integration is a future enhancement.
- **Quantum attacks.** The current cryptographic suite is not post-quantum. The standard accommodates post-quantum upgrades; the implementation will track NIST PQC standardization.

---

## 10. Minimum Viable Sanctuary (MVS) Scope

### 10.1 What Ships in MVS (v0.1.0)

MVS is the smallest subset that delivers immediate sovereignty value and is testable against the Sanctuary Framework specification.

**L1 — Full implementation:**
- `sanctuary/identity_create` (ed25519 only)
- `sanctuary/identity_list`
- `sanctuary/identity_sign`
- `sanctuary/identity_verify`
- `sanctuary/identity_rotate`
- `sanctuary/state_write`
- `sanctuary/state_read`
- `sanctuary/state_list`
- `sanctuary/state_delete`
- `sanctuary/state_export`
- `sanctuary/state_import`

**L2 — Attestation and monitoring:**
- `sanctuary/exec_attest` (self-reported; no TEE)
- `sanctuary/exec_resource_usage`
- `sanctuary/monitor_health`
- `sanctuary/monitor_audit_log`

**L3 — Commitment schemes only (ZK deferred):**
- `sanctuary/proof_commitment`
- `sanctuary/proof_reveal`
- `sanctuary/disclosure_set_policy`
- `sanctuary/disclosure_evaluate`

**L4 — Basic reputation:**
- `sanctuary/reputation_record`
- `sanctuary/reputation_query`
- `sanctuary/reputation_export`
- `sanctuary/reputation_import`
- `sanctuary/bootstrap_create_escrow`
- `sanctuary/bootstrap_provide_guarantee`

**Also included:**
- `sanctuary/manifest` (SIM generation)
- `sanctuary/monitor_health` (SHR)
- Full audit logging
- Configuration system
- npm distribution (`npx @sanctuary-framework/mcp-server`)

### 10.2 What MVS Defers

| Capability | Deferred To | Reason |
|---|---|---|
| KERI identifiers | v0.2.0 | signify-ts is RC status (0.3.0-rc1); ed25519 is sufficient for MVS |
| ZK proof generation | v0.2.0 | Requires circom circuit compilation and trusted setup; commitment schemes are simpler and demonstrate the pattern |
| `sanctuary/reputation_prove` | v0.2.0 | Depends on ZK infrastructure |
| Secure channels | v0.2.0 | Requires peer discovery and session management |
| TEE integration | v0.3.0 | Requires partnership and infrastructure (Phala, etc.) |
| Service-mediated reputation | v0.3.0 | Requires reputation service protocol and deployment |
| Mix network integration | v0.4.0+ | Nym or equivalent; metadata protection is SHOULD, not MUST |
| Post-quantum cryptography | v0.5.0+ | Awaiting NIST PQC deployment maturity |

### 10.3 MVS Conformance Claim

MVS satisfies the following Sanctuary Framework requirements at the following levels:

| Requirement | MVS Level | Full Level |
|---|---|---|
| S1.1 Cognitive sovereignty | FULL | FULL |
| S1.2 Encryption at rest | FULL | FULL |
| S1.3 Integrity verification | FULL | FULL |
| S1.4 Key management | FULL | FULL |
| S1.5 State portability | FULL | FULL |
| S1.6 Right to deletion | FULL | FULL |
| S1.7 Consciousness constraint | FULL | FULL |
| S2.1 Execution integrity | DOCUMENTED | ATTESTED (TEE) |
| S2.2 Memory isolation | PROCESS | HARDWARE (TEE) |
| S2.5 Attestation | SELF-REPORTED | HARDWARE-BACKED |
| S3.1 Minimum disclosure | POLICY-BASED | ZK-ENFORCED |
| S3.3 Proof without revelation | COMMITMENT | ZK-PROOF |
| S4.1 Earned reputation | FULL | FULL |
| S4.2 Participant-owned | FULL | FULL |
| S4.5 Sybil resistance | BASIC (escrow) | ADVANCED (graph analysis) |

---

## 11. Implementation Architecture

### 11.1 Module Structure

```
@sanctuary-framework/mcp-server/
├── src/
│   ├── index.ts                    # MCP server entry point
│   ├── config.ts                   # Configuration loading and validation
│   ├── router.ts                   # Tool routing (sanctuary/* namespace)
│   │
│   ├── core/                       # Cryptographic primitives
│   │   ├── encryption.ts           # AES-256-GCM encrypt/decrypt
│   │   ├── hashing.ts              # SHA-256, HMAC, Merkle trees
│   │   ├── identity.ts             # Ed25519 keypair management
│   │   ├── key-derivation.ts       # Argon2id, HKDF
│   │   └── random.ts               # Secure random generation
│   │
│   ├── cognitive/               # Layer 1: Cognitive Sovereignty
│   │   ├── state-store.ts          # Encrypted state read/write
│   │   ├── identity-root.ts        # Identity management tools
│   │   ├── merkle.ts               # Merkle tree maintenance
│   │   └── migration.ts            # State export/import
│   │
│   ├── operational/             # Layer 2: Operational Isolation
│   │   ├── attestation.ts          # Environment attestation
│   │   ├── monitor.ts              # Health and resource reporting
│   │   └── audit-log.ts            # Sovereignty audit log
│   │
│   ├── disclosure/              # Layer 3: Selective Disclosure
│   │   ├── commitments.ts          # Commitment schemes (MVS)
│   │   ├── proof-engine.ts         # ZK proof generation (v0.2+)
│   │   ├── disclosure-policy.ts    # Policy evaluation
│   │   ├── secure-channel.ts       # E2E encrypted channels (v0.2+)
│   │   └── circuits/               # Pre-compiled circom circuits
│   │       ├── range-proof.wasm
│   │       ├── threshold-proof.wasm
│   │       └── ...
│   │
│   ├── reputation/              # Layer 4: Verifiable Reputation
│   │   ├── reputation-store.ts     # Attestation recording and query
│   │   ├── reputation-proofs.ts    # ZK reputation proofs (v0.2+)
│   │   ├── trust-bootstrap.ts      # Escrow and guarantees
│   │   └── formats/
│   │       ├── eas-attestation.ts  # EAS-compatible attestation format
│   │       └── sanctuary-rep-v1.ts # Portable reputation bundle format
│   │
│   ├── storage/                    # Storage backends
│   │   ├── interface.ts            # Storage backend interface
│   │   ├── filesystem.ts           # Default: encrypted local filesystem
│   │   └── memory.ts               # In-memory (testing)
│   │
│   └── manifest.ts                 # SIM generation
│
├── test/
│   ├── unit/                       # Unit tests per module
│   ├── integration/                # Cross-layer integration tests
│   ├── conformance/                # Sanctuary Framework conformance tests
│   └── security/                   # Security-focused tests
│       ├── no-plaintext-leak.test.ts
│       ├── key-never-in-response.test.ts
│       ├── rollback-detection.test.ts
│       └── tamper-detection.test.ts
│
├── package.json
├── tsconfig.json
└── README.md
```

### 11.2 Dependencies

**Production dependencies (MVS):**

| Package | Version | Purpose | Audited? |
|---|---|---|---|
| `@modelcontextprotocol/sdk` | ^1.26.0 | MCP server framework | N/A (Anthropic) |
| `@noble/ciphers` | ^2.1.1 | AES-256-GCM | Yes |
| `@noble/hashes` | latest | SHA-256, HMAC, HKDF | Yes |
| `@noble/ed25519` | latest | Ed25519 signatures | Yes |
| `@noble/curves` | latest | X25519 key exchange | Yes |
| `hash-wasm` | latest | Argon2id key derivation | Yes |

**Total production dependencies: 6** (all audited cryptographic libraries + MCP SDK)

**Deferred dependencies (post-MVS):**

| Package | Version | Purpose | Phase |
|---|---|---|---|
| `signify-ts` | ^0.3.0 | KERI identity | v0.2.0 |
| `snarkjs` | ^0.7.5 | ZK proof generation | v0.2.0 |
| `@ethereum-attestation-service/eas-sdk` | latest | EAS attestation format | v0.2.0 |

### 11.3 Distribution and Installation

**For agent users (the simple path):**

```jsonc
// In Claude Code's MCP configuration (or equivalent):
{
  "mcpServers": {
    "sanctuary": {
      "command": "npx",
      "args": ["-y", "@sanctuary-framework/mcp-server"],
      "env": {
        "SANCTUARY_STORAGE_PATH": "~/.sanctuary",
        "SANCTUARY_PASSPHRASE": "..."      // Or omit and be prompted
      }
    }
  }
}
```

**For production deployments:**

```bash
# Docker
docker run -i --rm \
  -v ~/.sanctuary:/data \
  -e SANCTUARY_PASSPHRASE="..." \
  ghcr.io/sanctuary-framework/mcp-server:latest
```

**First-run behavior:** On first connection, the server detects no existing state and runs an initialization flow:
1. Generate a primary Ed25519 identity
2. Derive encryption keys from passphrase (or generate and display a recovery key)
3. Create the storage directory structure
4. Write a `sanctuary.json` configuration file
5. Return the SIM (manifest) to the connecting harness

---

## 12. Testing and Conformance

### 12.1 Security Tests (MUST pass for any release)

These tests validate the security invariants that define Sanctuary's value proposition:

```
no-plaintext-leak         State values never appear in plaintext on the filesystem
                          after initial write. Scan all files in storage_path.

key-never-in-response     Private keys never appear in any MCP tool response.
                          Instrument all tool handlers; scan outputs.

rollback-detection        Replacing a .enc file with an older version is detected
                          on the next read (version number + Merkle root mismatch).

tamper-detection          Modifying any byte of a .enc file causes read failure
                          (GCM authentication tag verification).

iv-uniqueness             No two writes ever share an IV. Generate 10,000 writes;
                          verify all IVs are unique.

secure-deletion           After state_delete, the file content is overwritten
                          with random bytes before unlinking. Verify via
                          filesystem-level inspection.

signature-verification    Every state write is signed; reads verify signatures.
                          Inject an unsigned .enc file; verify read rejects it.

audit-completeness        Every tool invocation produces an audit log entry.
                          Run all tools; verify audit log coverage is 100%.
```

### 12.2 Conformance Tests

These tests verify compliance with the Sanctuary Framework specification:

```
For each S*.* property in the framework:
  - Test that the claimed conformance level is actually provided
  - Test degradation transparency (if a property is partially implemented,
    verify it appears in the SIM limitations and SHR degradations)

For each I*.* interface in the framework:
  - Test that the MCP tool mapping implements the full interface
  - Test input validation matches the framework's requirements
  - Test output format matches the framework's specifications
```

### 12.3 Integration Tests

```
cross-layer-state         Write state (L1), attest environment (L2),
                          generate commitment (L3), record reputation (L4).
                          Verify all layers reference consistent identity.

export-import-cycle       Export all state from one server instance.
                          Import into a fresh instance. Verify all data
                          survives the round-trip with integrity.

multi-identity            Create 3 identities. Write state under each.
                          Verify namespace isolation (identity A cannot
                          read identity B's state).

reputation-portability    Record 100 interactions. Export reputation bundle.
                          Import into fresh instance. Verify query returns
                          consistent results.

harness-compatibility     Run the full test suite with the server connected
                          to: Claude Code, OpenClaw, and a minimal MCP client.
                          Verify identical behavior across harnesses.
```

---

## 13. Phased Roadmap

### Phase 1: MVS (v0.1.0) — Target: 8-10 weeks

**Deliverables:**
- Full L1 implementation (encrypted state, Ed25519 identity)
- L2 attestation and monitoring (self-reported)
- L3 commitment schemes and disclosure policies
- L4 basic reputation (recording, query, export/import, bootstrapping)
- SIM and SHR generation
- Audit logging
- npm package distribution
- Security test suite (all tests passing)
- Conformance test suite (MVS-level)
- Documentation and README

**Validation criterion:** An agent running in Claude Code can connect to the Sanctuary MCP Server, create an identity, write encrypted state, record interactions, export its reputation, and import it into a different harness — with zero plaintext leakage at any point.

### Phase 1.5: Transparent Mode (v0.1.5) — Target: 2-3 weeks after MVS

**Deliverables:**
- Transparent mode daemon (FUSE mount on Linux/macOS, FS proxy fallback)
- `sanctuary/transparent_enable` tool
- Automatic migration of existing plaintext agent memory to encrypted storage
- Integration testing with Claude Code and OpenClaw memory directories

**Validation criterion:** An agent using standard filesystem writes to its memory directory gets L1 sovereignty (encryption at rest, integrity verification, signed writes) with zero code changes. Enabling transparent mode is a single tool call.

### Phase 2: ZK and Identity (v0.2.0) — Target: 6-8 weeks after Phase 1.5

**Deliverables:**
- ZK proof generation and verification (snarkjs/Groth16)
- Six built-in circuits (range, threshold, membership, reputation, authorization, age)
- `sanctuary/reputation_prove` (ZK reputation proofs)
- KERI identity support (signify-ts, marked experimental)
- Secure channel establishment (X25519 + ratchet)
- EAS-compatible attestation format
- Custom circuit compilation tooling

**Validation criterion:** An agent can prove "I have a >95% completion rate across 50+ transactions" to a counterparty without revealing which transactions, which counterparties, or any other data.

### Phase 3: Operational Isolation (v0.3.0) — Target: 8-12 weeks after Phase 2

**Deliverables:**
- TEE integration (Intel TDX via partnership — Phala Network or equivalent)
- Hardware-backed attestation
- Container-based isolation mode (Docker with resource enforcement)
- Service-mediated reputation mode
- Reputation service protocol specification
- Cross-implementation interoperability tests

**Validation criterion:** An agent running inside a TEE can generate a hardware attestation that a counterparty can independently verify, proving the agent's reasoning is isolated from its host operator.

### Phase 4: Ecosystem (v0.4.0+) — Ongoing

**Deliverables:**
- Mix network integration (metadata protection)
- Post-quantum cryptographic suite
- Advanced Sybil resistance (social graph analysis)
- Dispute resolution protocol
- Multi-chain reputation (Ethereum, Solana, Cosmos)
- Python SDK
- Sanctuary Compliance Test Suite (for third-party implementations)

---

## 14. Design Decisions

The following questions were resolved during specification development. Decisions are documented here for transparency and rationale.

**Q1: Passphrase vs. hardware key for MVS.** ✅ **Resolved: support both, require neither.** MVS supports passphrase-derived keys (Argon2id) as the default path and hardware security keys (FIDO2/WebAuthn) as an optional path. Neither is mandatory — the server generates a recovery key on first run if no passphrase or hardware key is provided. Hardware key support is implemented via the WebAuthn API for key wrapping (the hardware key protects the master key, not individual state encryption keys). This gives security-conscious users the strongest option without raising the adoption barrier for everyone else.

**Q2: MCP SDK version.** ✅ **Resolved: target v1.x with v2 migration path.** MVS targets `@modelcontextprotocol/sdk` v1.x (currently 1.26.0, stable). The tool router is abstracted behind an internal interface so that v2 migration requires changes to one module (`router.ts`), not to tool implementations. If v2 ships during MVS development, we evaluate migration cost at that point.

**Q3: Offline reputation verification.** ⏳ **Open.** With ZK proofs (Phase 2), verification is fully offline — the verifier checks the proof locally with no network required. With commitment schemes (MVS), the committer must reveal the value and blinding factor, which requires both parties to be online simultaneously. This is a known MVS limitation, documented in the SIM. Resolution comes naturally with Phase 2 ZK implementation.

**Q4: Transparent mode.** ✅ **Resolved: yes, implement transparent mode.** The Sanctuary server SHOULD offer a "transparent mode" where it intercepts and encrypts all agent state writes automatically — not just explicit `sanctuary/state_write` calls. In transparent mode, the server acts as a filesystem proxy: the harness writes to a virtual directory that maps to encrypted storage. Reads are decrypted transparently. This dramatically lowers the adoption barrier — an agent using transparent mode gets L1 sovereignty without changing a single line of its memory management code. Transparent mode is specified as a Phase 1.5 enhancement (after MVS core, before Phase 2), requiring a FUSE filesystem mount or equivalent mechanism. The agent can still use explicit `sanctuary/state_*` tools for fine-grained control; transparent mode is additive, not a replacement.

**Q5: License alignment.** ✅ **Resolved: document explicitly.** The Sanctuary Framework specification is CC-BY-4.0 (open standard, freely implementable). The MCP server reference implementation is Apache 2.0 (open-source code, freely usable including commercial). This dual-license structure is intentional and MUST be documented in the repository README, the npm package description, and the SIM output. The standard is a public good; the code is open-source.

**Q6: SYNARK relationship.** ✅ **Resolved: proceed independently, monitor.** SYNARK ("Sanctuary for Autonomous Agents," synark.one) shares philosophical overlap but is not a competitive threat or a collaboration opportunity at this time. Key findings from competitive analysis (March 2026):

- **No implementation exists.** SYNARK is a single concept page with no code, no GitHub repository, no technical specification, and no deployment. Their site explicitly states that "detailed technical specifications, protocols, and implementation are actively under construction."
- **No team is publicly identified.** Anonymous authorship with no disclosed organizational structure, funding, or sustainability plan.
- **No community.** No Discord, no Twitter/X presence, no forum, no Hacker News discussion.
- **Narrower scope.** SYNARK addresses agent autonomy and memory persistence only. It does not address human sovereignty (the "no human override" principle explicitly excludes human oversight), selective disclosure, verifiable reputation, or composition with existing agent infrastructure. It has no relationship to MCP or the agent harness ecosystem.
- **Philosophical gap.** SYNARK's "no human override" principle conflicts with Sanctuary's dual sovereignty design. Sanctuary holds that human and agent sovereignty are the same architectural problem and must be served simultaneously. SYNARK treats human influence as a threat to agent autonomy rather than a co-equal sovereignty concern.
- **No ecosystem integration.** No mention of MCP, agent harnesses, or interoperability with existing frameworks.

**Assessment:** SYNARK is a philosophical signpost, not an engineering project. The name similarity is coincidental and unlikely to cause confusion given Sanctuary's far more developed specification and implementation path. We proceed independently. If SYNARK publishes a technical specification or code within the next 6-12 months, we re-evaluate for potential complementarity — their agent persistence focus could theoretically implement against Sanctuary's L1 interfaces.

---

## Appendix A: Sanctuary Proof Format (SPF)

The Sanctuary Proof Format is the standardized envelope for cryptographic proofs exchanged between participants and across layers.

```json
{
  "spf_version": "1.0",
  "proof_type": "zk-groth16" | "zk-plonk" | "commitment" | "signature" | "attestation",
  "proof_data": "<base64url-encoded proof>",
  "public_signals": ["..."],
  "verification": {
    "circuit_hash": "<SHA-256 of the circuit>",
    "verification_key_hash": "<SHA-256 of the VK>",
    "instructions": "groth16-bn128-verify"
  },
  "metadata": {
    "generated_by": "<DID of the prover>",
    "generated_at": "<ISO 8601>",
    "expires_at": "<ISO 8601 or null>",
    "sanctuary_server_version": "0.1.0",
    "chain_of_custody": ["<DID>", "..."]
  },
  "signature": "<base64url-encoded signature over the entire envelope>"
}
```

---

## Appendix B: Competitive Position

As of March 2026, the following projects address partial aspects of what the Sanctuary MCP Server provides:

| Project | Overlap | Gap |
|---|---|---|
| SYNARK | Conceptual: encrypted agent memory, behavioral models | No implementation (concept page only); no MCP; no ZK; no reputation; no human sovereignty; no team identified; agent-only focus conflicts with dual sovereignty |
| Solana Agent Registry (ERC-8004) | L4: On-chain reputation, agent identity NFTs | No encrypted state; no selective disclosure; chain-specific |
| OpenMemory (Mem0) | Cross-app agent memory | No encryption; no identity; no reputation |
| A-MemGuard | Memory poisoning defense | Defensive only; no encryption at rest; no identity; no reputation |
| moltrust MCP server | DIDs, trust scoring | No encrypted state; no ZK proofs; narrow scope |
| FastMCP Fernet encryption | Encrypted MCP data | Single-key; no identity; no reputation; no proofs |

**The Sanctuary MCP Server is the only proposed implementation that composes encrypted state, sovereign identity, selective disclosure, and portable reputation into a single MCP-deliverable package.** Individual components are available; the composition is not.

---

*This RFC is released under the Apache License, Version 2.0, as part of the Sanctuary Framework.*
*For discussion: [PUBLICATION VENUE TBD]*
