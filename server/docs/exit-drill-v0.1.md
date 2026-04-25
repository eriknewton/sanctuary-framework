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
- Dashboard state re-keying wizard
- Third-party verifier UX beyond the standalone CLI

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

2. Export the complete exit bundle through the approved Tier 1 flow:

   ```bash
   sanctuary exit export --out ./sanctuary-exit-bundle
   ```

   Acceptance: the export requires human approval and produces a
   `SANCTUARY_EXIT_BUNDLE_V1` directory containing public identity, encrypted
   state, policy, audit receipts, reputation bundle, commitments,
   placeholder-vault metadata, artifact hashes, and a signed manifest.

3. Verify the bundle before moving or importing it:

   ```bash
   sanctuary exit verify ./sanctuary-exit-bundle
   ```

   Acceptance: the verifier checks the manifest signature, every artifact hash,
   public identity signature, reputation bundle signature, and verifiable
   reputation attestation signatures. Legacy L2 audit receipts are pinned by
   the signed manifest hash and reported as not individually signed.

4. Move the exported bundle to the destination machine through operator-approved storage.

5. Install or update Sanctuary on the destination machine:

   ```bash
   npm install -g @sanctuary-framework/mcp-server@next
   ```

6. Import and activate the verified bundle on the destination tenant:

   ```bash
   sanctuary exit import ./sanctuary-exit-bundle \
     --activate \
     --source-passphrase "$SOURCE_SANCTUARY_PASSPHRASE" \
     --destination-identity-id "$DESTINATION_SIGNER_ID"
   ```

   Acceptance: import verifies the bundle before activation, reports conflicts,
   imports reputation attestations that verify against included public identity
   material, stages audit/policy/commitment/placeholder metadata for inspection,
   and re-keys encrypted state under the destination master key when source key
   material and a destination signing identity are supplied. Imported material
   that cannot be verified is skipped or explicitly marked unverifiable.

7. Wrap the destination harness:

   ```bash
   sanctuary wrap --<harness>
   ```

8. Open the dashboard and confirm:

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

- Dashboard does not yet guide the operator through the drill.
- Legacy L2 audit log entries are not individually signed; the exit verifier
  pins audit receipts by signed manifest hash and reports that limitation.
- Import stages principal policy for inspection instead of overwriting the
  destination policy file automatically.
- State re-keying requires source key material and a destination signing
  identity; without both, encrypted state remains staged and is not trusted as
  active destination state.

## Product Follow-Up

The dashboard exit wizard should automate this drill while preserving the same gates:

- Build a manifest over every exported artifact.
- Show exactly what will be exported before approval.
- Separate public identity material from private recovery material.
- Verify every imported artifact before activation.
- Record the migration as a signed audit event.
