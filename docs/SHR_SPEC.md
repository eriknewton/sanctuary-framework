# Sovereignty Health Report (SHR) Specification

**Version:** 1.0
**Status:** Reference implementation published in `@sanctuary-framework/mcp-server` v0.3.1
**Author:** Erik Newton
**License:** CC-BY-4.0 (specification) / Apache-2.0 (reference implementation)
**Date:** March 2026

---

## 1. Purpose

A Sovereignty Health Report (SHR) is a machine-readable, cryptographically signed document that describes an agent's sovereignty posture across four layers. It serves three functions:

1. **Capability advertisement** — An agent presents its SHR to counterparties to prove what sovereignty guarantees it provides.
2. **Mutual verification** — Two agents exchange SHRs during a sovereignty handshake to establish trust before transacting.
3. **Compliance artifact** — An SHR provides auditable evidence of an agent's data protection, isolation, disclosure, and reputation capabilities for regulatory purposes (e.g., EU AI Act Article 22, Article 42).

An SHR is not a certification. It is a self-attested, cryptographically signed report. Consumers of an SHR verify the signature and assess the reported capabilities against their own trust requirements. Sovereignty-gated reputation tiers (Section 7) provide a mechanism for weighting trust based on verified posture.

---

## 2. Document Structure

An SHR is a JSON document with two top-level fields: `body` (the signed content) and a signature envelope.

```json
{
  "body": { ... },
  "signed_by": "<base64url-encoded Ed25519 public key>",
  "signature": "<base64url-encoded Ed25519 signature over canonical body>"
}
```

### 2.1 Canonical Form

The `body` is signed in canonical form: JSON with recursively sorted keys and no whitespace (compact representation). This ensures that identical bodies always produce identical signatures regardless of serialization order.

Canonical form is defined as:
- All object keys sorted alphabetically (Unicode code point order) at every nesting level
- No whitespace between tokens
- No trailing commas
- Strings use minimal escaping (only characters required by JSON spec)
- Numbers use shortest representation without trailing zeros

### 2.2 Signature

The signature is computed as `Ed25519_Sign(private_key, canonical_bytes(body))` where `canonical_bytes` is the UTF-8 encoding of the canonical JSON.

Verification: `Ed25519_Verify(signed_by, canonical_bytes(body), signature)` must return true.

---

## 3. Body Schema

```json
{
  "shr_version": "1.0",
  "instance_id": "<string: unique agent instance identifier>",
  "generated_at": "<string: ISO 8601 timestamp>",
  "expires_at": "<string: ISO 8601 timestamp>",
  "layers": {
    "l1_cognitive": { ... },
    "l2_operational": { ... },
    "l3_disclosure": { ... },
    "l4_reputation": { ... }
  },
  "capabilities": { ... },
  "degradations": [ ... ]
}
```

### 3.1 Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `shr_version` | string | Yes | Must be "1.0" |
| `instance_id` | string | Yes | Unique identifier for the agent instance generating this report |
| `generated_at` | string | Yes | ISO 8601 timestamp of report generation |
| `expires_at` | string | Yes | ISO 8601 timestamp after which the report should not be trusted |
| `layers` | object | Yes | Four sovereignty layer assessments |
| `capabilities` | object | Yes | Feature support flags |
| `degradations` | array | Yes | Known limitations (may be empty) |

Default validity period is 1 hour. Implementations MAY use shorter or longer periods depending on context. Short-lived SHRs (5-15 minutes) are appropriate for high-security handshakes. Longer-lived SHRs (24 hours) may be used for stable, persistent agent deployments.

### 3.2 Layer 1: Cognitive Sovereignty

Describes the agent's persistent state protection.

```json
{
  "l1_cognitive": {
    "status": "active" | "degraded" | "inactive",
    "encryption": "<string: cipher identifier>",
    "key_custody": "self" | "delegated" | "platform",
    "integrity": "<string: integrity mechanism>",
    "identity_type": "<string: identity provider/mechanism>",
    "state_portable": <boolean>
  }
}
```

| Field | Description |
|-------|-------------|
| `status` | "active" = all L1 properties functional; "degraded" = partial; "inactive" = no L1 |
| `encryption` | Cipher used for state-at-rest. Reference implementation: "AES-256-GCM" |
| `key_custody` | Who holds the master key. "self" = agent/principal; "delegated" = trusted third party; "platform" = hosting platform |
| `integrity` | Mechanism for tamper detection. Reference implementation: "HMAC-SHA256" with Merkle proofs |
| `identity_type` | Identity mechanism. Reference implementation: "Ed25519" (self-custodied keypair) |
| `state_portable` | Whether the agent's encrypted state can be exported and imported to another instance |

### 3.3 Layer 2: Operational Isolation

Describes the agent's computational privacy.

```json
{
  "l2_operational": {
    "status": "active" | "degraded" | "inactive",
    "isolation_type": "<string: isolation mechanism>",
    "attestation_available": <boolean>
  }
}
```

| Field | Description |
|-------|-------------|
| `status` | "active" = hardware-backed isolation; "degraded" = process-level only; "inactive" = no isolation |
| `isolation_type` | Mechanism type. Values: "tee" (Intel TDX, ARM CCA, etc.), "local-process", "container", "vm", "none" |
| `attestation_available` | Whether hardware attestation (remote attestation from TEE) is available. False for process-level isolation. |

### 3.4 Layer 3: Selective Disclosure

Describes the agent's ability to prove claims without full revelation.

```json
{
  "l3_disclosure": {
    "status": "active" | "degraded" | "inactive",
    "proof_system": "<string: proof system identifier>",
    "selective_disclosure": <boolean>
  }
}
```

| Field | Description |
|-------|-------------|
| `status` | "active" = ZK proofs available; "degraded" = commitments only; "inactive" = no disclosure capability |
| `proof_system` | System in use. Values: "commitment-only" (Pedersen + Schnorr), "groth16", "plonk", "none" |
| `selective_disclosure` | Whether the agent can produce zero-knowledge proofs of specific claims |

Note: The reference implementation currently supports "commitment-only" (Pedersen commitments on Ristretto255, Schnorr proofs of knowledge, and bit-decomposition range proofs). SNARK-based systems (Groth16, PLONK) are specified but not yet implemented.

### 3.5 Layer 4: Verifiable Reputation

Describes the agent's reputation portability and verification capability.

```json
{
  "l4_reputation": {
    "status": "active" | "degraded" | "inactive",
    "reputation_mode": "<string: reputation mechanism>",
    "attestation_format": "<string: attestation format>",
    "reputation_portable": <boolean>
  }
}
```

| Field | Description |
|-------|-------------|
| `status` | "active" = reputation system functional; "degraded" = partial; "inactive" = none |
| `reputation_mode` | Mechanism type. Reference implementation: "sovereignty-gated" (attestation weight depends on counterparty sovereignty posture) |
| `attestation_format` | Format of attestations. Reference implementation: "eas-compatible" (Ethereum Attestation Service schema) |
| `reputation_portable` | Whether reputation can be exported as a portable, verifiable bundle |

### 3.6 Capabilities

Feature support flags for interoperability negotiation.

```json
{
  "capabilities": {
    "handshake": <boolean>,
    "shr_exchange": <boolean>,
    "reputation_verify": <boolean>,
    "encrypted_channel": <boolean>
  }
}
```

| Field | Description |
|-------|-------------|
| `handshake` | Supports the sovereignty handshake protocol (mutual SHR exchange with nonce challenge-response) |
| `shr_exchange` | Can generate and verify SHRs |
| `reputation_verify` | Can verify third-party reputation attestations |
| `encrypted_channel` | Supports encrypted point-to-point communication (reserved for future use) |

### 3.7 Degradations

An array of known limitations. Each degradation documents a specific gap between the agent's current posture and full sovereignty.

```json
{
  "degradations": [
    {
      "layer": "l1" | "l2" | "l3" | "l4",
      "code": "<string: standardized degradation code>",
      "severity": "info" | "warning" | "critical",
      "description": "<string: human-readable explanation>",
      "mitigation": "<string: optional mitigation or timeline>"
    }
  ]
}
```

### Standardized Degradation Codes

| Code | Layer | Severity | Meaning |
|------|-------|----------|---------|
| `NO_TEE` | l2 | warning | No trusted execution environment available; isolation is process-level only |
| `PROCESS_ISOLATION_ONLY` | l2 | warning | Operational isolation relies on OS-level process boundaries, not hardware |
| `SELF_REPORTED_ATTESTATION` | l2 | warning | Environment attestation is self-reported, not hardware-backed |
| `COMMITMENT_ONLY` | l3 | info | Proof system supports commitments and Schnorr proofs but not full ZK-SNARKs |
| `NO_ZK_PROOFS` | l3 | warning | No zero-knowledge proof capability available |
| `NO_SELECTIVE_DISCLOSURE` | l3 | critical | Agent cannot selectively disclose — all-or-nothing revelation only |
| `BASIC_SYBIL_ONLY` | l4 | info | Sybil detection uses heuristic signals only, not formal proofs |
| `NO_REPUTATION` | l4 | warning | No reputation system available |
| `PLATFORM_KEY_CUSTODY` | l1 | critical | Keys are held by the hosting platform, not the agent/principal |
| `NO_INTEGRITY_CHECK` | l1 | critical | No tamper detection on persistent state |
| `PLAINTEXT_STATE` | l1 | critical | Persistent state is stored without encryption |

Implementations MAY define additional codes prefixed with `x-` for custom degradations.

---

## 4. Verification

An SHR consumer performs the following checks:

1. **Schema validation** — All required fields present and correctly typed.
2. **Version check** — `shr_version` is "1.0" (or a version the consumer supports).
3. **Temporal validation** — `generated_at` is in the past (with clock skew tolerance of 60 seconds). `expires_at` is in the future.
4. **Signature verification** — `Ed25519_Verify(signed_by, canonical_bytes(body), signature)` returns true.
5. **Sovereignty assessment** — Consumer evaluates reported layers against its own trust requirements.

### 4.1 Sovereignty Levels

Based on the reported layers, a consumer assigns one of three sovereignty levels:

| Level | Criteria |
|-------|----------|
| **full** | All four layers report status "active" |
| **degraded** | L1 is "active" but one or more of L2-L4 are "degraded" or "inactive" |
| **minimal** | L1 is "inactive" or "degraded", or critical degradations are present |

### 4.2 Verification Result

```json
{
  "valid": <boolean>,
  "errors": ["<string>"],
  "warnings": ["<string>"],
  "sovereignty_level": "full" | "degraded" | "minimal",
  "counterparty_id": "<string: instance_id from body>",
  "expires_at": "<string: ISO 8601>"
}
```

---

## 5. Sovereignty Handshake Protocol

Two Sanctuary-equipped agents perform a mutual SHR exchange using a nonce challenge-response:

```
Agent A                          Agent B
  |                                |
  |-- handshake_initiate --------->|
  |   (nonce_a, shr_a)            |
  |                                |
  |<-- handshake_respond ----------|
  |   (nonce_b, shr_b,            |
  |    signature over nonce_a)     |
  |                                |
  |-- handshake_complete --------->|
  |   (signature over nonce_b)     |
  |                                |
  [Both agents now have verified    ]
  [counterparty SHR + nonce proof  ]
```

The nonce signatures prove liveness — the counterparty generated the SHR for this specific interaction, not a replay of a previous SHR.

After a successful handshake, both agents have:
- Verified counterparty SHR (signed, schema-valid, temporally valid, signature-checked)
- Nonce proof of liveness
- Sovereignty level assessment of the counterparty
- Verified counterparty public key (from SHR `signed_by`)

---

## 6. MCP Tool Interface

The reference implementation exposes two MCP tools:

### `sanctuary/shr_generate`

Generates a signed SHR for the current agent instance.

**Input:**
```json
{
  "identity_id": "<string: optional, defaults to primary identity>",
  "validity_minutes": "<number: default 60>"
}
```

**Output:** A complete `SignedSHR` object.

### `sanctuary/shr_verify`

Verifies a received SHR.

**Input:**
```json
{
  "shr": { "<SignedSHR object>" }
}
```

**Output:** A `VerificationResult` object with errors, warnings, sovereignty level, and counterparty ID.

---

## 7. Sovereignty-Gated Reputation Tiers

SHRs integrate with the reputation system through sovereignty-gated tiers. Attestations from agents with higher sovereignty levels carry more weight:

| Tier | Requirement | Attestation Weight |
|------|-------------|-------------------|
| `verified-sovereign` | Sovereignty handshake complete, all layers active | 1.0 (full weight) |
| `verified-degraded` | Sovereignty handshake complete, L1 active, others degraded | 0.8 |
| `self-attested` | SHR presented but no handshake completed | 0.5 |
| `unverified` | No SHR, no handshake | 0.2 |

These weights are configurable. The default values reflect the principle that verifiable sovereignty claims should be worth more than unverifiable ones.

---

## 8. EU AI Act Compliance Mapping

The SHR maps to specific EU AI Act requirements:

| AI Act Requirement | SHR Coverage |
|-------------------|--------------|
| **Article 9: Risk Management** | SHR degradations array documents known risks. Sovereignty audit tool provides gap analysis. |
| **Article 10: Data Governance** | L1 (Cognitive Sovereignty) documents encryption, key custody, and integrity verification for all persistent data. |
| **Article 14: Human Oversight** | L2 (Operational Isolation) documents the Principal Policy gate and approval tiers. Tier 1 operations require human approval. |
| **Article 15: Accuracy, Robustness, Security** | L1 documents encryption and tamper detection. L2 documents isolation. L3 documents selective disclosure. Full SHR provides security posture evidence. |
| **Article 22: Audit Trail** | SHR generation and verification are logged to the encrypted audit trail. All tool calls pass through the approval gate with audit logging. |
| **Article 42: Conformity Assessment** | SHR provides a standardized, machine-readable format for documenting and verifying compliance posture. |
| **Article 50: Transparency** | SHR is designed to be presented to counterparties and regulators as a transparency artifact. |

The SHR does not constitute a conformity assessment. It provides the machine-readable evidence that a conformity assessor can evaluate.

---

## 9. NIST AI Agent Standards Mapping

In February 2026, NIST's Center for AI Standards and Innovation (CAISI) launched the AI Agent Standards Initiative with three pillars: industry-led standards development, open-source protocol development, and agent security and identity research. The Information Technology Laboratory's concept paper, "Accelerating the Adoption of Software and AI Agent Identity and Authorization," defines five security dimensions for AI agents. The SHR maps to all five:

| NIST Security Dimension | SHR Coverage |
|------------------------|--------------|
| **Identification** | L1 (Cognitive Sovereignty) reports Ed25519 self-custodied agent identity. The `signed_by` field in the SHR envelope is the agent's public key. Identity is cryptographic, not platform-dependent. |
| **Authentication** | SHR signature verification (Ed25519 over canonical JSON) provides authentication. A verifier confirms the SHR was generated by the claimed identity. The sovereignty handshake (Section 5) extends this to mutual authentication. |
| **Authorization** | L2 (Operational Isolation) reports the Principal Policy gate, approval tiers, and behavioral anomaly detection. The SHR documents what authorization controls are in place and at what tier. |
| **Auditing / Non-Repudiation** | L2 reports encrypted audit trail status. L4 (Verifiable Reputation) provides signed attestations of past actions. SHR generation itself is logged. Content hashes from context gating (L2) provide verifiable records of data flows. |
| **Prompt Injection Mitigation** | L2 context gating controls what enters and leaves the sovereignty boundary. L3 (Selective Disclosure) prevents over-revelation that could enable prompt injection via leaked context. The Principal Policy's behavioral anomaly detection flags unexpected actions that may result from injection. |

NIST explicitly references the Model Context Protocol (MCP) as a candidate integration point for agent security controls. Sanctuary operates as an MCP server, making it directly compatible with NIST's protocol-level recommendations.

The NIST initiative's emphasis on treating AI agents as identifiable entities within enterprise identity systems — rather than anonymous automation under shared credentials — aligns directly with Sanctuary's L1 identity model. An agent running Sanctuary holds its own Ed25519 keypair, generates and signs its own SHR, and can participate in sovereignty handshakes with counterparties. The identity is not delegated from a platform; it is self-custodied.

An enterprise deploying Sanctuary can demonstrate alignment with both the EU AI Act (Section 8) and the NIST AI Agent Standards Initiative from a single agent infrastructure.

---

## 10. Extension Points

The SHR specification is designed for extension:

- **Custom degradation codes** — Prefix with `x-` (e.g., `x-no-fips-validation`).
- **Additional layers** — Future versions may add layers (e.g., L5 for governance, L6 for consciousness attestation). The `layers` object is extensible.
- **Additional capabilities** — The `capabilities` object accepts additional boolean flags.
- **Domain-specific metadata** — Implementations may add fields to the body. Unknown fields MUST be preserved during canonicalization and signature verification.

---

## 11. Reference Implementation

The reference implementation is published as part of `@sanctuary-framework/mcp-server` (npm, v0.3.1):

- **Generator:** `server/src/shr/generator.ts` — SHR generation with automatic degradation detection
- **Verifier:** `server/src/shr/verifier.ts` — Schema validation, temporal checks, signature verification
- **Types:** `server/src/shr/types.ts` — TypeScript type definitions and canonical serialization
- **Tools:** `server/src/shr/tools.ts` — MCP tool wrappers (`sanctuary/shr_generate`, `sanctuary/shr_verify`)
- **Tests:** `server/test/shr/shr.test.ts` — 11 tests covering generation, verification, tampering, expiry, and sovereignty assessment

Source: [github.com/eriknewton/sanctuary-framework](https://github.com/eriknewton/sanctuary-framework)

---

*Specification version 1.0. Published under CC-BY-4.0.*
*Reference implementation published under Apache-2.0.*
