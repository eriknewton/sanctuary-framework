# Sanctuary Exit Drill v0.1

Purpose: prove that an operator can leave a harness or machine without losing durable Sanctuary records.

This drill is an acceptance artifact for the product completion track. It is not a full migration wizard. It defines the operator-visible behavior that the wizard must eventually automate.

## Scope

The drill covers one operator, one wrapped agent, and one destination environment.

In scope:

- Identity continuity
- Policy continuity
- Audit continuity
- Reputation bundle continuity
- Harness migration from source to destination

Out of scope for v0.1:

- Cross-operator transfer
- Hardware key transfer
- Managed TEE migration
- Full state re-keying UX
- Third-party verifier UX

## Preconditions

- Source machine has a wrapped Sanctuary agent.
- Source agent has at least one identity.
- Source audit log has at least one recent entry.
- Destination machine has Node.js and npm installed.
- Operator has access to the source passphrase or recovery material.

## Drill Steps

1. On the source machine, confirm the current tenant:

   ```bash
   sanctuary agents
   ```

2. Export agent state from the wrapped source agent through the approved Tier 1 flow:

   ```text
   state_export
   ```

   Acceptance: the export requires human approval and produces an export bundle.

3. Export reputation from the source agent:

   ```text
   reputation_export
   ```

   Acceptance: the export bundle contains signed attestations and no private keys.

4. Export public identity material:

   ```text
   sanctuary_export_identity_bundle
   ```

   Acceptance: the identity bundle contains public identity material, DID, SHR or attestation evidence when available, and no private keys.

5. Move the exported bundles to the destination machine through operator-approved storage.

6. Install or update Sanctuary on the destination machine:

   ```bash
   npm install -g @sanctuary-framework/mcp-server@next
   ```

7. Import state into the destination tenant:

   ```text
   state_import
   ```

   Acceptance: import verifies signatures where public keys are available and reports conflicts before activation.

8. Import reputation:

   ```text
   reputation_import
   ```

   Acceptance: imported attestations verify against known source identities or are marked unverifiable rather than trusted.

9. Wrap the destination harness:

   ```bash
   sanctuary wrap --<harness>
   ```

10. Open the dashboard and confirm:

    - Agent identity is visible.
    - Recent audit continuity is visible.
    - Reputation evidence is visible or marked as pending verification.
    - Source platform is not required for the destination agent to operate.

## Pass Criteria

The exit drill passes only if all of the following are true:

- The source platform can be disconnected after migration.
- The destination agent retains a verifiable identity.
- Audit and reputation records remain inspectable.
- Failed verification is surfaced explicitly.
- No private key or passphrase appears in exported public bundles.
- Every irreversible operation required human approval.

## Current Gaps

- No single command creates a complete exit bundle.
- State import and reputation import are separate flows.
- Re-keying imported encrypted state under a new master key is not yet an operator-facing wizard.
- Dashboard does not yet guide the operator through the drill.
- Third-party verification exists in pieces but is not packaged as a standalone verifier command.

## Product Follow-Up

The dashboard exit wizard should automate this drill while preserving the same gates:

- Build a manifest over every exported artifact.
- Show exactly what will be exported before approval.
- Separate public identity material from private recovery material.
- Verify every imported artifact before activation.
- Record the migration as a signed audit event.

