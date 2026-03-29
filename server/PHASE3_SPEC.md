# Sanctuary Phase 3: Adoption Infrastructure — Build Spec

**Date:** 2026-03-27
**Status:** Active
**Depends on:** Phase 2.5 complete (88 tests, 26 tools, Principal Policy shipped)

---

## Overview

Four deliverables, in dependency order:

1. **npm publish pipeline** — make `npx @sanctuary-framework/mcp-server` work
2. **Machine-readable SHR** — signed, versioned, agent-parseable sovereignty capability advertisement
3. **Sovereignty Handshake protocol** — mutual SHR exchange with challenge-response verification
4. **Cowork plugin packaging** — wrap the MCP server as an installable Cowork/Claude Code plugin

---

## 1. npm Publish Pipeline

**Goal:** A developer can run `npx @sanctuary-framework/mcp-server` and have a working sovereignty server in under 60 seconds.

### What exists
- `package.json` with correct metadata, `bin` entry, `files` array, dual CJS/ESM exports
- `cli.ts` entry point with stdio transport
- `tsup.config.ts` build tool
- README with 26-tool documentation

### What needs building
1. **Prepublish script** — `npm run build` in prepublish hook ensures dist/ is fresh
2. **Version alignment** — `package.json` version MUST match `config.ts` default version
3. **First-run UX** — The recovery key display (already in index.ts) serves as first-run. Verify it works end-to-end via `npx`.
4. **LICENSE file** — Apache-2.0 license file in server/ (referenced in package.json but must exist in published package)
5. **npmignore or files validation** — Ensure only `dist/`, `README.md`, `LICENSE` ship

### Acceptance criteria
- `npm pack` produces a clean tarball with only dist/, README.md, LICENSE
- `npx @sanctuary-framework/mcp-server` starts, prints recovery key, accepts MCP connections
- Package metadata displays correctly on npmjs.com

### Files touched
- `server/package.json` — add prepublish script, verify version
- `server/LICENSE` — create Apache-2.0 license file
- `server/tsup.config.ts` — verify cli.ts is in entry points

---

## 2. Machine-Readable SHR (Sovereignty Health Report)

**Goal:** An agent can present its sovereignty posture as a signed, versioned, machine-parseable document that any counterparty can verify without trusting the presenter.

### Design

The SHR is a JSON document with a fixed schema, signed by one of the instance's Ed25519 identities.

```typescript
interface SovereigntyHealthReport {
  // Envelope
  shr_version: "1.0";
  instance_id: string;          // Hash of primary public key
  generated_at: string;         // ISO 8601
  expires_at: string;           // ISO 8601 (SHR validity window)
  signed_by: string;            // Public key (base64url)
  signature: string;            // Ed25519 signature over canonical body

  // Sovereignty posture
  layers: {
    l1: {
      status: "active" | "degraded" | "inactive";
      encryption: string;       // e.g., "aes-256-gcm"
      key_custody: "self" | "delegated" | "platform";
      integrity: string;        // e.g., "merkle-sha256"
      identity_type: string;    // e.g., "ed25519"
      state_portable: boolean;
    };
    l2: {
      status: "active" | "degraded" | "inactive";
      isolation_type: string;   // e.g., "process-level", "tee-tdx"
      attestation_available: boolean;
    };
    l3: {
      status: "active" | "degraded" | "inactive";
      proof_system: string;     // e.g., "commitment-only", "groth16"
      selective_disclosure: boolean;
    };
    l4: {
      status: "active" | "degraded" | "inactive";
      reputation_mode: string;  // e.g., "self-custodied"
      attestation_format: string;
      reputation_portable: boolean;
    };
  };

  // Capabilities (what this instance can do in inter-agent contexts)
  capabilities: {
    handshake: boolean;         // Can perform sovereignty handshake
    shr_exchange: boolean;      // Can present/verify SHRs
    reputation_verify: boolean; // Can verify counterparty attestations
    encrypted_channel: boolean; // Can establish encrypted point-to-point
  };

  // Degradations (machine-readable, not just human-readable)
  degradations: Array<{
    layer: "l1" | "l2" | "l3" | "l4";
    code: string;               // e.g., "NO_TEE", "COMMITMENT_ONLY"
    severity: "info" | "warning" | "critical";
    description: string;
    mitigation?: string;
  }>;
}
```

### New MCP tools
- `sanctuary/shr_generate` — Generate and sign an SHR using a specified identity
- `sanctuary/shr_verify` — Verify a counterparty's SHR signature and check expiry

### Implementation
- `src/shr/types.ts` — SHR type definitions and schema
- `src/shr/generator.ts` — SHR generation from current server state
- `src/shr/verifier.ts` — SHR signature verification and validation
- `src/shr/tools.ts` — MCP tool definitions
- `test/shr/shr.test.ts` — Generation, signing, verification, expiry, tamper detection

### Acceptance criteria
- SHR is deterministically generated from server state
- Signature is Ed25519 over canonical JSON (sorted keys, no whitespace)
- Verification detects tampered fields, expired reports, invalid signatures
- Schema is documented and versioned (shr_version: "1.0")

---

## 3. Sovereignty Handshake Protocol

**Goal:** Two Sanctuary instances can mutually verify each other's sovereignty posture before transacting, producing a verified-counterparty status.

### Protocol flow

```
Agent A                              Agent B
   │                                    │
   ├─── handshake_initiate ────────────>│
   │    (A's SHR + nonce)               │
   │                                    │
   │<── handshake_respond ──────────────┤
   │    (B's SHR + nonce + A's nonce    │
   │     signed by B)                   │
   │                                    │
   ├─── handshake_complete ────────────>│
   │    (B's nonce signed by A)         │
   │                                    │
   │<── handshake_verified ─────────────┤
   │    (mutual verification result)    │
```

1. **Initiate:** Agent A generates a nonce, signs its SHR, sends both
2. **Respond:** Agent B verifies A's SHR, generates its own nonce, signs (A's nonce + B's SHR), returns package
3. **Complete:** Agent A verifies B's response, signs B's nonce, sends confirmation
4. **Result:** Both agents hold a `HandshakeResult` with verified counterparty status

### Types

```typescript
interface HandshakeChallenge {
  shr: SovereigntyHealthReport;
  nonce: string;                // base64url, 32 random bytes
  initiated_at: string;
}

interface HandshakeResponse {
  shr: SovereigntyHealthReport;
  responder_nonce: string;
  initiator_nonce_signature: string;  // B signs A's nonce
  responded_at: string;
}

interface HandshakeResult {
  counterparty_id: string;
  counterparty_shr: SovereigntyHealthReport;
  verified: boolean;
  sovereignty_level: "full" | "degraded" | "minimal" | "unverified";
  trust_tier: "verified-sovereign" | "verified-degraded" | "unverified";
  completed_at: string;
  expires_at: string;           // Handshake validity window
}
```

### New MCP tools
- `sanctuary/handshake_initiate` — Start a handshake (generates challenge)
- `sanctuary/handshake_respond` — Respond to an incoming handshake challenge
- `sanctuary/handshake_complete` — Complete a handshake after receiving response
- `sanctuary/handshake_status` — Check status of an active/completed handshake

### Implementation
- `src/handshake/types.ts` — Handshake type definitions
- `src/handshake/protocol.ts` — Core handshake logic (initiate, respond, complete)
- `src/handshake/tools.ts` — MCP tool definitions
- `test/handshake/handshake.test.ts` — Full round-trip, tamper detection, expiry, replay prevention

### Acceptance criteria
- Two instances complete a full handshake round-trip
- Nonce replay is detected and rejected
- Tampered SHR in transit is detected
- Expired handshakes are rejected
- Result includes sovereignty-level assessment of counterparty
- All handshake events are audit-logged

---

## 4. Cowork Plugin Packaging

**Goal:** A Cowork/Claude Code user can install Sanctuary as a plugin with one click.

### Plugin structure
```
sanctuary-plugin/
├── plugin.json           # Plugin manifest
├── skills/
│   └── sanctuary/
│       └── SKILL.md      # Skill definition for Cowork
├── mcp/
│   └── sanctuary.json    # MCP server configuration
└── README.md
```

### plugin.json
```json
{
  "name": "sanctuary",
  "displayName": "Sanctuary Framework",
  "description": "Sovereignty infrastructure for the agentic economy",
  "version": "0.2.0",
  "mcp": {
    "sanctuary": {
      "command": "npx",
      "args": ["@sanctuary-framework/mcp-server"],
      "env": {}
    }
  },
  "skills": ["skills/sanctuary"]
}
```

### SKILL.md content
- Explains what Sanctuary is (brief, agent-oriented)
- Lists available tool categories (state, identity, reputation, disclosure, monitoring)
- Provides usage patterns (create identity → write state → build reputation → export)
- Explains the SHR and when to present it

### Acceptance criteria
- Plugin directory structure is valid
- `plugin.json` schema is correct for Cowork plugin system
- SKILL.md provides enough context for an agent to use Sanctuary tools effectively
- MCP server launches correctly when invoked through the plugin

---

## Dependency Graph

```
npm publish ──────────────> Cowork plugin
     │
     v
Machine-readable SHR
     │
     v
Sovereignty Handshake
```

npm publish is the gate. SHR and handshake are sequential. Plugin depends on npm publish (uses `npx`) but not on SHR/handshake.

---

## Test count targets
- Current: 88 tests, 13 files
- After SHR: +10-12 tests
- After Handshake: +12-15 tests
- Target: ~115 tests, 16+ files
