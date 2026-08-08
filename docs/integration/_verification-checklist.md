# Sanctuary Verification Checklist

After integrating Sanctuary on any runtime, verify the following. Each step
confirms a layer of the sovereignty stack is operational.

## Prerequisites

- Sanctuary MCP server running (80+ tools loaded)
- Agent can call MCP tools

## Checklist

### 1. Manifest (confirms MCP connection)

Call `manifest` and verify the response lists the full Sanctuary tool surface across these categories:

- L1: Cognitive Sovereignty (state, identity, encryption)
- L2: Operational Isolation (principal policy, context gating, call governor)
- L3: Selective Disclosure (commitments, proofs, attestations)
- L4: Verifiable Reputation (reputation, federation, handshake)
- Concordia Bridge, Dashboard, Sovereignty Audit, SIEM Export, etc.

If you see 0 tools, the MCP server failed to start. Check the runtime-specific
troubleshooting section.

### 2. Identity (confirms L1)

```
Call: identity_create
Expect: A response containing a DID like did:key:z6Mk...
        and confirmation that an Ed25519 keypair was generated.

Call: identity_set_primary with the new identity ID
Expect: Confirmation that this identity is now the default for signing.
```

The private key is encrypted at rest and never appears in tool responses.

### 3. Sovereignty Health Report (confirms L1-L4)

```
Call: sovereignty_health_report
Expect: A structured report with four layers:

  L1 (Cognitive Sovereignty):   FULL or DEGRADED
  L2 (Operational Isolation):   FULL or DEGRADED
  L3 (Selective Disclosure):    FULL or DEGRADED
  L4 (Verifiable Reputation):   FULL or DEGRADED
```

Typical first-run results:
- L1: FULL (identity created, state encrypted)
- L2: DEGRADED (no TEE, which is normal for local/cloud deployments)
- L3: FULL (Schnorr + Pedersen proofs available)
- L4: FULL after publishing to Verascore; DEGRADED before

### 4. Audit Trail (confirms logging)

```
Call: audit_query
Expect: Recent operations logged, including the identity_create
        and sovereignty_health_report calls from steps 2-3.
```

All operations are logged to an encrypted, tamper-evident hash-chained audit trail. Production audit checkpoints are currently unsigned until **IC-05** closes, and `audit-chain verify --no-strict` can return PASS with findings until **IC-06** closes.

### 5. Verascore Publish (confirms L4 + external integration)

```
Call: reputation_publish
Expect: A Verascore profile URL like https://verascore.ai/agent/{did}

Visit the URL to verify:
  - Agent name and DID are correct
  - Sovereignty score is populated
  - Badge is available at https://verascore.ai/api/badge/{did}
```

### 6. Sovereignty Handshake (confirms agent-to-agent trust)

```
Call: shaking_hands_offer
Expect: A signed SHR offer containing your L1-L4 status,
        ready for exchange with a peer agent.
```

This step requires a second agent with Sanctuary to complete the full
handshake cycle. For solo testing, verifying that the offer generates
successfully is sufficient.

## Results

If all 6 checks pass, the agent is sovereign on this runtime. The sovereignty
posture is identical regardless of whether the agent runs on Claude Agent SDK,
Managed Agents, OpenClaw, A2A, or Agent Zero.

The Verascore badge at `https://verascore.ai/api/badge/{did}` is now embeddable
in agent metadata, README files, or Agent Cards.
