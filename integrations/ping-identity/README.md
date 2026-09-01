# Ping Identity Agent Gateway Integration

This integration demonstrates how to use Sanctuary's Sovereignty Health Reports (SHRs) as authorization signals for Ping Identity's Agent Gateway.

## Overview

Ping Identity's "Identity for AI" (GA March 2026) includes an Agent Gateway that evaluates contextual authorization decisions for AI agents. This integration bridges Sanctuary's sovereignty framework with Ping's identity infrastructure by:

1. **Generating SHRs**: Sanctuary agents produce signed SHRs describing their sovereignty posture
2. **Transforming for the Gateway**: The adapter formats SHRs into a Ping-compatible authorization context
3. **Enabling Runtime Decisions**: The Gateway uses sovereignty signals to adjust authorization constraints

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Sanctuary Agent                                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  sanctuary/shr_generate                                 │ │
│  │  → generates signed SHR (Ed25519)                      │ │
│  └────────────────────────────────────────────────────────┘ │
│                           │                                  │
│  ┌────────────────────────▼────────────────────────────────┐ │
│  │  sanctuary/shr_gateway_export (format="ping")           │ │
│  │  → transforms SHR via gateway-adapter.ts               │ │
│  │  → produces PingAuthorizationContext                    │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────┐
│  Ping Identity Agent Gateway                                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Authorization Decision Engine                          │ │
│  │  • Overall sovereignty score (0-100)                   │ │
│  │  • Per-layer capability assessment                     │ │
│  │  • Recommended trust level (full/elevated/standard)    │ │
│  │  • Authorization constraints (read_only, approval, etc)│ │
│  └────────────────────────────────────────────────────────┘ │
│                           │                                  │
│  ┌────────────────────────▼────────────────────────────────┐ │
│  │  Access Control Enforcement                             │ │
│  │  • Apply constraints to agent's operations             │ │
│  │  • Log authorization decisions                         │ │
│  │  • Adapt in real-time based on sovereignty posture     │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Authorization Flow

### 1. Agent Presents Sovereignty Posture

The agent calls `sanctuary/shr_gateway_export`:

```typescript
const context = await agent.call('sanctuary/shr_gateway_export', {
  format: 'ping',          // Ping Identity format
  validity_minutes: 60,    // SHR valid for 1 hour
});
```

### 2. Ping Gateway Evaluates Sovereignty

The authorization context contains:

- **overall_score** (0-100): Weighted average of all four layer scores
- **recommended_trust_level**: "full", "elevated", "standard", or "restricted"
- **layer_scores**: Individual scores for the four layers: Cognitive, Operational, Disclosure (Charter), Reputation (Heralds)
- **authorization_signals**: Boolean flags for capability availability
- **recommended_constraints**: Suggested restrictions based on sovereignty gaps

### 3. Gateway Applies Authorization Constraints

Based on the context, the Gateway applies constraints:

| Sovereignty Posture | Recommended Constraint | Rationale |
|---|---|---|
| Score ≥ 80, all layers active | Full autonomous operation | Complete sovereignty across all layers |
| Score 60-79, some Operational Isolation degradation | Elevated (read-only writes) | Process isolation only, TEE unavailable |
| Score 40-59, Selective Disclosure degraded | Standard (no selective disclosure) | Cannot prove privacy-preserving predicates |
| Score < 40, multiple layers degraded | Restricted (identity verification required, human approval) | Multiple sovereignty gaps, high risk |

## Authorization Context Schema

The gateway export produces a `PingAuthorizationContext`:

```typescript
interface PingAuthorizationContext {
  shr_version: string;                    // "1.0"
  agent_identity: string;                 // Ed25519 public key (base64url)
  generated_at: string;                   // ISO 8601
  context_expires_at: string;             // ISO 8601 (SHR expires_at)

  overall_score: number;                  // 0-100
  recommended_trust_level: string;        // "full" | "elevated" | "standard" | "restricted"

  layer_scores: {
    l1_cognitive: number;
    l2_operational: number;
    l3_disclosure: number;
    l4_reputation: number;
  };

  layer_status: {
    l1_cognitive: string;                 // "active" | "degraded" | "inactive"
    l2_operational: string;
    l3_disclosure: string;
    l4_reputation: string;
  };

  authorization_signals: {
    approval_gate_active: boolean;        // Human approval required?
    context_gating_active: boolean;       // Data filtering enabled?
    encryption_at_rest: boolean;          // State encrypted?
    behavioral_baseline_active: boolean;  // Anomaly detection?
    identity_verified: boolean;           // Cryptographic identity?
    zero_knowledge_capable: boolean;      // ZK proofs available?
    selective_disclosure_active: boolean; // Selective redaction?
    reputation_portable: boolean;         // Portable reputation?
    handshake_capable: boolean;           // Sovereignty handshake?
  };

  degradations: Array<{
    layer: string;
    code: string;                         // e.g., "NO_TEE", "PROCESS_ISOLATION_ONLY"
    severity: string;                     // "info" | "warning" | "critical"
    authorization_impact: string;         // Human-readable impact on access
  }>;

  recommended_constraints: Array<{
    type: string;                         // "read_only", "requires_approval", etc.
    description: string;
    rationale: string;
    priority: "high" | "medium" | "low";
  }>;

  shr_signature: string;                  // Ed25519 signature (base64url)
  shr_signed_by: string;                  // Public key that signed (base64url)
}
```

## Usage

### Python Example

See `examples/gateway_flow.py`:

```bash
python examples/gateway_flow.py
```

This demonstrates:
- Generating an SHR via the MCP bridge
- Transforming it for the Ping Identity Gateway
- Simulating authorization decisions for different sovereignty profiles
- Showing both "sovereign agent" and "degraded agent" paths

### TypeScript Integration

In your Sanctuary-based agent:

```typescript
import { transformSHRForGateway } from '@sanctuary-framework/mcp-server';

// Generate SHR
const shr = await agent.call('sanctuary/shr_generate', {});

// Transform for Ping Identity
const authzContext = transformSHRForGateway(shr);

// Present to Ping Gateway
const gatewayResponse = await pingGateway.authorize(authzContext);

// Apply constraints
if (gatewayResponse.constraints.includes('read_only')) {
  // Only allow read operations
}
```

## Composition

This integration demonstrates Sanctuary's composition principle: sovereignty remains **identity-standard-agnostic**. The same SHR can be formatted for:

- **Ping Identity** (`format="ping"`): Ping-specific authorization context
- **Generic identity systems** (`format="generic"`): Standard capability advertisement
- **Future identity providers**: Add new transformers without modifying SHR

The SHR itself is immutable; only the presentation layer changes.

## Sovereignty Gaps and Authorization Constraints

The adapter maps real-world sovereignty gaps to authorization constraints:

| Gap | Constraint Type | Example |
|---|---|---|
| No TEE, process isolation only | `read_only` | "Restrict to read-only operations until TEE available" |
| Self-reported attestation only | `requires_approval` | "Human approval required for writes" |
| Commitment-only proofs, no ZK | `restricted_scope` | "Limit data sharing scope: cannot prove privacy-preserving predicates" |
| Non-portable reputation | `known_agents_only` | "Restrict to interactions with pre-approved agents" |
| Multiple degradations | `identity_verification_required` | "Additional identity verification required" |

## Testing

Run the test suite:

```bash
cd server
npm test -- gateway-adapter
```

Tests cover:
- SHR → authorization context transformation
- Trust level calculation (score-based)
- Authorization constraint generation for different sovereignty profiles
- Degradation impact on scores and constraints
- Generic vs. Ping-specific formatting

## Specification Reference

- **SHR Specification**: `docs/SHR_SPEC.md`, machine-readable sovereignty posture
- **Sanctuary Framework**: `server/src/shr/generator.ts`, SHR generation
- **Gateway Adapter**: `server/src/shr/gateway-adapter.ts`, transformation logic
- **Ping Identity Pathway**: Submitted via Nexus Technology Innovation pathway

## Next Steps

1. **Pre-meeting POC**: Deploy to test Sanctuary instance, demonstrate SHR → Gateway flow
2. **SHR→Agent Gateway Adapter**: Build lightweight format converter for other identity systems
3. **Non-TEE Operational Isolation Hardening**: Develop process-isolation + memory-protection path that moves Operational Isolation from "Degraded" to "Hardened" (most common constraint agents will encounter)
4. **Authorization Policy as-Code**: Enable agents to express authorization preferences alongside sovereignty posture

## Author

Erik Newton
