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
   sanctuary agents list
   ```

   Failure mode: the subcommand is required. Bare `sanctuary agents` prints the
   usage block and exits 0, which in a scripted drill scrolls past as a screenful
   of successful-looking output while confirming nothing. Expect a table with a
   `NAME` header and one row per tenant.

2. Export the complete exit bundle through the approved Tier 1 flow. Name every
   state namespace you intend to carry across:

   ```bash
   sanctuary exit export --out ./sanctuary-exit-bundle \
     --state-namespace <namespace> [--state-namespace <namespace> ...]
   ```

   Acceptance: the export requires human approval and produces a
   `SANCTUARY_EXIT_BUNDLE_V1` directory containing public identity, encrypted
   state, policy, audit receipts, reputation bundle, commitments,
   placeholder-vault metadata, artifact hashes, and a signed manifest. When
   state is exported it also prints a one-time **BUNDLE RE-KEY KEY** on the
   terminal. That key is the credential step 6 needs, it is never written into
   the bundle, and it is displayed exactly once. Capture it now.

   Failure mode: `--state-namespace` is not optional in practice. With the flag
   omitted the export still succeeds, still writes `artifacts/encrypted_state.json`,
   and still reports a signed manifest, but that artifact comes back
   `"namespaces": [], "total_keys": 0` and no re-key key is printed. Verified by
   differential run against one fortress holding one namespace: with the flag,
   `namespaces: ["memories"], total_keys: 1` plus a re-key key; without it, zero
   and silence. From the outside the two exports look alike, and the gap only
   surfaces at step 6 when there is nothing to import. Confirm `total_keys` in
   `artifacts/encrypted_state.json` before you move the bundle anywhere.

3. Verify the bundle before moving or importing it:

   ```bash
   sanctuary exit verify ./sanctuary-exit-bundle
   ```

   Acceptance: the verifier checks the manifest signature, every artifact hash,
   public identity signature, reputation bundle signature, and verifiable
   reputation attestation signatures. Legacy Operational audit receipts are pinned by
   the signed manifest hash and reported as not individually signed.

4. Move the exported bundle to the destination machine through operator-approved storage.

   Failure mode: the bundle's state entries are encrypted, but the bundle as a
   whole is a plaintext directory. Public identity material, the policy set,
   audit receipts, commitments, and namespace names all travel readable. Anything
   that touches the bundle in transit sees them: a cloud drive, a chat upload, an
   emailed archive, a shared `/tmp`, a backup agent watching the directory. The
   failure is silent by nature, since a successful copy and a copied-and-read
   copy look identical afterward. Move it over an encrypted channel to a path only
   the destination operator can read, and delete the intermediate copies once
   step 6 passes. Carry the re-key key from step 2 separately from the bundle;
   putting both in the same transfer defeats the reason it was never written into
   the bundle.

5. Install or update Sanctuary on the destination machine:

   ```bash
   npm install -g @sanctuary-framework/mcp-server@<exact-version>
   ```

   Failure mode: pin the version. `@next` and other floating tags resolve at the
   moment the command runs, so a drill run on Tuesday and a rerun on Thursday can
   install different builds, and the source and destination machines in the same
   drill can end up on different ones. Nothing in the run announces that: the
   command prints a successful install either way, and the drill's evidence then
   records a result that no one can reproduce, because "it passed on `@next`" does
   not name a build. Record the exact version on both machines as part of the drill
   evidence, and prefer the version that produced the bundle.

6. Import and activate the verified bundle on the destination tenant.

   The credential that re-keys the state is the **bundle re-key key** printed by
   the export in step 2, supplied as `--source-recovery-key`. Read it in with a
   silent prompt so it is never typed into the command line itself (a literal
   credential on the command line would be recorded in shell history):

   ```bash
   read -s BUNDLE_REKEY_KEY
   ```

   ```bash
   sanctuary exit import ./sanctuary-exit-bundle \
     --activate \
     --import-state \
     --source-recovery-key "$BUNDLE_REKEY_KEY" \
     --destination-identity-id "$DESTINATION_SIGNER_ID"
   ```

   `--source-passphrase` is the **legacy-bundle** path. A bundle exported from an
   envelope-custody fortress (any fortress a current Sanctuary creates from
   scratch) deliberately carries no passphrase-checkable material, so that there
   is no offline guessing oracle inside a bundle that travels. Supply a passphrase
   against such a bundle and the import fails closed with
   `SOURCE_PASSPHRASE_UNSUPPORTED`, pointing you at the re-key key.

   **Which path you need is decided by what you are holding, not by anything you
   have to inspect in the bundle.** The export mints the bundle re-key key and the
   bundle's re-key material together, in one step, so the two always travel as a
   pair:

   - **You have a re-key key from step 2.** Use `--source-recovery-key`, as above.
     Every bundle a current `sanctuary exit export` produces with state in it takes
     this path.
   - **The export never printed one**, because it came from a Sanctuary that
     predates the re-key key. That is a legacy pre-envelope bundle, and the
     passphrase form is its path:

     ```bash
     read -s SOURCE_SANCTUARY_PASSPHRASE
     ```

     ```bash
     sanctuary exit import ./sanctuary-exit-bundle \
       --activate \
       --import-state \
       --source-passphrase "$SOURCE_SANCTUARY_PASSPHRASE" \
       --destination-identity-id "$DESTINATION_SIGNER_ID"
     ```

   Start with `--source-recovery-key` whenever you have a key to supply, and let
   the possession rule above decide the rest. Do not expect the recovery-key path
   to announce a legacy bundle: when the bundle carries no re-key material, that
   path falls through to pre-envelope semantics and treats whatever you supplied
   AS the source master key, with no error and no warning. Your first signal is a
   downstream `SOURCE_KEY_MISMATCH` after every entry fails to decrypt, which
   names the symptom and never the cause. The loud message runs the other way:
   reach for `--source-passphrase` against an envelope bundle and the import
   refuses with `SOURCE_PASSPHRASE_UNSUPPORTED`, naming the flag you actually
   want. Do not try to decide this by reading fields out of
   `artifacts/encrypted_state.json`: the file has no field that reliably answers
   the question, and guessing wrong sends you down the passphrase path with the
   source host possibly already decommissioned.

   `--import-state` is required: the CLI rejects the source-credential flags
   without it (exit code 2), because the source credentials exist only to decrypt
   the exported state. If you omit it, the import fails closed with that message
   before touching anything.

   Known exposure, accepted for v0.1: the CLI takes the source credential only as
   a command-line flag, so the expanded value is visible in the process list
   (`ps`) for the duration of the import, to other processes on the same host.
   The `read -s` step keeps it out of shell history but cannot close the `ps`
   window. Run the import on a host with no untrusted local users or agent
   processes, which a fortress migration target should be anyway. (CLI
   follow-up filed: accept the source credential from an environment variable
   or stdin, as `SANCTUARY_PASSPHRASE` already is for the destination
   fortress.)

   Failure mode, and the one worth rehearsing: **a clean-looking import that moved
   no state.** The command's exit code and its `verdict:` line report whether the
   *bundle* verified, not whether state landed. The state outcome is a separate
   line, `state_status:`, and three of its four values mean nothing was imported:

   | `state_status` | What happened | Trigger |
   |---|---|---|
   | `rekeyed` | state was re-keyed under the destination master | the good case; check `state_imported_keys` |
   | `not_requested` | **the bundle itself carried no state entries**, so there was never anything to re-key | `--state-namespace` omitted at export (step 2). This is a defect in the bundle, and no import flag can repair it |
   | `staged_requires_source_key` | **entries arrived and stayed encrypted**, because no source master key was resolved | `--activate` run without `--import-state`, so no source credential reached the re-key step. The entries are on the destination and still locked to the source master |
   | `skipped_no_destination_signer` | **no decryption was attempted at all.** The signer is resolved before the entry loop starts, so the run stopped there and every entry was counted as skipped | `--destination-identity-id` omitted while the destination fortress has no default identity, **or** supplied with an id that does not exist on the destination |

   The first two are the pair that get confused, and they call for opposite
   responses. `not_requested` means go back to the source machine and re-export
   with `--state-namespace`; the bundle you are holding is not worth re-importing.
   `staged_requires_source_key` means the bundle is fine and the import command was
   incomplete; re-run it with `--import-state` and the source credential. Preserve
   the bundle in the first case and the import transcript in the second.

   The CLI will not let you reach `staged_requires_source_key` by supplying a
   credential wrongly. It rejects `--import-state` without `--activate`, a source
   credential without `--import-state`, and `--import-state` without a source
   credential, each at exit 2 before touching anything. The only route to that
   status is leaving `--import-state` off entirely.

   `skipped_no_destination_signer` carries a trap of its own for the drill record:
   because it returns before any decryption is attempted, **it tells you nothing
   about whether your source credential is good.** A run that ends here leaves the
   credential unproven. Fix the signer, re-run, and expect the credential to be
   tested for the first time on that second run. Do not record the first run as
   evidence that the source key worked.

   A credential that is present but wrong is the safe case: it fails closed and
   loudly, with `SOURCE_CREDENTIAL_INVALID` on the re-key-key path or
   `SOURCE_KEY_MISMATCH` on the legacy passphrase path. Only `not_requested`
   prints a loud multi-line warning. The other two appear as one line in a block
   of counters, under `verdict: PASS`, at exit code 0. Read `state_status` and
   `state_imported_keys` on every run and record both in the drill evidence.

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

   Read "recent audit continuity" strictly. The dashboard renders the destination
   fortress's own audit log, and imported receipts are staged under
   `_exit_audit_receipts` rather than replayed into `_audit`, so what you are
   looking at is the destination's short post-import history and not the source's
   record. A screen that fills up after the migration is evidence the destination
   is live, and it is not evidence that the source history came across. That
   archive-only boundary is a stated gap below, not a defect to chase.

   Failure mode after a successful import: the staged `_exit_*` namespaces are
   left in place on purpose, for inspection, and **master rotation refuses to run
   while any of them holds entries.** Rotation preflight rejects them by name
   (they are a named unsupported subsystem, not a silent skip), so the first
   symptom is a rotation attempt that aborts on a fortress the operator believes
   is finished migrating. Export or clear the staged namespaces, then rotate.

## Pass Criteria

The exit drill passes only if all of the following are true:

- The source platform can be disconnected after migration.
- The destination agent retains a verifiable identity.
- Audit receipts remain inspectable as an archive artifact. Imported audit
  receipts are not replayed into the destination `_audit/*.enc` namespace and
  are not returned by normal `AuditLog.query()` reads.
- Failed verification is surfaced explicitly.
- No private key or passphrase appears in exported public bundles.
- Every irreversible operation required human approval.

## Current Gaps

- Dashboard does not yet guide the operator through the drill.
- Legacy Operational audit log entries are not individually signed; the exit verifier
  pins audit receipts by signed manifest hash and reports that limitation.
- Audit receipt import is archive-only. The importer stages
  `artifacts/audit_receipts.json` under `_exit_audit_receipts` for inspection;
  it does not reconstruct per-entry encrypted `_audit/*.enc` continuity.
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
