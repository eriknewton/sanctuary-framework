---
title: Sanctuary Transparency Auditor Runbook
author: Erik Newton
---

# Sanctuary Transparency Auditor Runbook

This runbook covers PR-1 transparency auditor packs: an exported checkpoint
bundle, the operator's published signing key, and the standalone offline
verifier artifact. It does not add new cryptography, anchoring, or remote
attestation.

The claim is narrow: a verifier can prove that the operator's enforcement
history is real, signed by the operator's pinned key, append-only from genesis
by default, and not quietly rewritten inside the provided chain. It does not
prove packets were blocked on the wire.

## Operator Steps

1. Emit or wait for checkpoints on the fortress host:

   ```sh
   sanctuary transparency checkpoint
   ```

2. Export the auditor bundle:

   ```sh
   sanctuary transparency export --output transparency-bundle.json
   ```

   The command writes a `SANCTUARY_TRANSPARENCY_BUNDLE_V1` JSON document. It
   performs no network I/O. Publishing, emailing, committing, or otherwise
   sharing the bundle is an operator action.

3. Publish the verification key out-of-band.

   Production macOS installs pin the public key at:

   ```text
   /Library/Application Support/Sanctuary/castle-pinned-pubkey.bin
   ```

   Share the raw 32-byte public key file with the auditor and publish its
   fingerprint through a separate channel:

   ```sh
   shasum -a 256 "/Library/Application Support/Sanctuary/castle-pinned-pubkey.bin"
   ```

   The auditor should compare this fingerprint against the key file they
   received before verifying the bundle.

4. Provide the standalone verifier artifact.

   The build produces `server/dist/verify-transparency.js`, a bundled
   offline-only Node script. This PR packages the verifier as a single-file
   dist artifact instead of a second workspace package because the repo already
   publishes CLI artifacts from the server package with `tsup`, and the pure
   verifier already has a narrow dependency surface: Node builtins plus bundled
   `@noble` signature and hash code.

## Auditor Steps

1. Confirm prerequisites:

   ```sh
   node --version
   ```

   The artifact targets Node 22 or newer.

2. Verify the key fingerprint out-of-band:

   ```sh
   shasum -a 256 castle-pinned-pubkey.bin
   ```

   Compare the output to the fingerprint the operator published through a
   separate channel.

3. Run the offline verifier:

   ```sh
   node verify-transparency.js --input transparency-bundle.json --public-key-file castle-pinned-pubkey.bin
   ```

   Or, if the key was published as base64url text:

   ```sh
   node verify-transparency.js --input transparency-bundle.json --public-key <base64url-key>
   ```

4. Read the verdict and exit code:

   | Verdict | Exit | Meaning |
   |---------|------|---------|
   | `PASS` | `0` | Complete-from-genesis bundle verified under the pinned key with no findings |
   | `PARTIAL` | `10` | Suffix fragment verified internally under `--allow-partial`, but the genesis side was not verified |
   | `FAIL` | `1` | At least one verification finding exists |
   | Usage error | `2` | Missing or invalid CLI arguments |

   Exit `0` is reserved for a clean complete-from-genesis `PASS`.
   `PARTIAL` is deliberately non-zero so automation cannot mistake a suffix
   fragment for complete evidence.

5. Optional host check, only on the fortress host:

   ```sh
   sanctuary verify-transparency --input transparency-bundle.json --public-key-file castle-pinned-pubkey.bin --against-log --fortress ~/.sanctuary
   ```

   The standalone `verify-transparency.js` artifact is offline-only. Host-mode
   log recomputation needs Sanctuary storage and audit-log code, so it stays on
   the full `sanctuary verify-transparency` CLI.

## Drill Criteria

The PR-1 synthetic fixtures pre-declare the coordinator-run drill criteria:

1. Clean bundle verifies offline with only the exported bundle and the
   operator-published Ed25519 public key. Expected: `PASS`, exit `0`.
2. A truncated in-chain bundle fails with a specific reason code. Expected:
   `FAIL`, exit `1`, finding kind `counter_gap`.
3. Host-side audit-log tail truncation is caught by `--against-log`. Expected:
   `FAIL`, exit `1`, finding kind `log_head_behind_checkpoint`.

The fixture test is `server/test/transparency/auditor-pack-drill.test.ts`.
It uses synthetic local keys and logs, no network, no wall-clock soak, and no
production signer dependency.

## What a verifying party CAN conclude

From a chain of checkpoints that verifies offline under a pinned key:

1. **Authenticity.** Each checkpoint was signed by the holder of the pinned private key (on a production macOS install: the root signer helper).
2. **No rollback or reordering between checkpoints.** Counters step by exactly 1 and each checkpoint hash-links to its predecessor, so a replaced, reordered, or withheld-then-reinserted checkpoint breaks verification. The audit-log head sequence is also checked to never move backwards between consecutive checkpoints.
3. **Completeness from genesis (default).** A clean PASS / exit 0 means the chain was verified complete from the genesis checkpoint AND that genesis is authentic: the earliest record is counter 1 and its `previous_checkpoint_hash` is the genesis sentinel `"GENESIS"`. Three distinct origin attacks are caught and can never read as a clean PASS:
   - A bundle whose earliest record is counter N>1 is a withheld prefix and FAILS by default (`counter_prefix_missing`).
   - A counter-1 record whose `previous_checkpoint_hash` is a 64-hex value rather than `"GENESIS"` is asserting an undisclosed predecessor (a forged origin, or a withheld prefix wearing a genesis counter). It FAILS (`genesis_sentinel_mismatch`), and `--allow-partial` does NOT relax this: claiming counter 1 is claiming to be the genesis, and that claim must be true.
   - The genesis sentinel appearing on any non-earliest record (a spliced second origin) FAILS (`genesis_sentinel_misplaced`).

   To knowingly verify a suffix fragment, pass `--allow-partial`. The missing prefix is reported under `not_checked` and the result is the DISTINCT verdict `PARTIAL` with the dedicated exit code `10`, never `PASS` / exit 0. Automation gating on either the verdict string or the exit code therefore cannot mistake a suffix fragment for a complete-from-genesis verification. (Suffix withholding, an operator who stops publishing the NEWEST checkpoints, still cannot be detected from a single bundle; see CANNOT, below.)
4. **Audit-log commitment.** Each checkpoint commits to the entire surviving audit hash chain at its emission moment. Anyone who later runs `--against-log` on the host can detect tail truncation (live head behind a signed head), content alteration, and non-prefix in-window deletion relative to that commitment. Deletion of the LOWEST covered entry raises the live floor exactly as legitimate rotation does; `--against-log` distinguishes the two only by the master-key-MAC'd rotation anchor (the #437 audit rotation machinery), which requires the fortress passphrase. Without an authenticated anchor naming the live floor, the cut is treated as unauthenticated and the host check FAILS closed (`rotation_floor_unauthenticated`) rather than passing. A host run that prints `merkle root not recomputed` as a note is NOT a verification pass for the root.
5. **Policy stability or change.** Equal `policy.rules_sha256` values across checkpoints prove the policy input files did not change between them; a changed hash proves the policy changed. (What the policy says is deliberately not disclosed.)
6. **Enforcement activity counts.** The signed allowed/blocked totals and opaque per-rule counts for the covered window. On the host, with the fortress passphrase, these counts are recomputable from the decrypted log and the verifier compares them.
7. **Fork detection across observers.** Two checkpoints with the same counter but different contents, obtained by different observers, prove the operator presented divergent histories.

## What a verifying party CANNOT conclude

These limits are printed by the verifier on every run. Do not over-claim past them.

1. **That the wall was actually enforcing on the wire.** A checkpoint proves the recorded enforcement state and history. It is not a packet-level proof. Enforcement capability claims trace to drill evidence on the platform that matters, not to this format (see ASSURANCE_MATRIX.md).
2. **That the named binary was the running binary.** `daemon.binary_sha256` is self-reported by the emitting process. Comparing it against a published release hash detects a mismatched report; it cannot prove the process that emitted the checkpoint was not itself modified. Remote attestation is out of scope.
3. **Freshness / suffix completeness.** An operator who stops publishing the NEWEST checkpoints produces a shorter chain that is still genesis-rooted and still passes; one bundle cannot prove it is the latest. (Prefix withholding, dropping the genesis side, IS caught by default; see CAN, item 3.) Freshness comes from publication cadence and from cross-checking the highest counter across independently obtained bundles, not from any single bundle.
4. **Events between checkpoints.** The format commits to states at checkpoint moments. An entry appended and pruned between two checkpoints is not individually provable from checkpoints alone (the signed audit chain itself, exported via `sanctuary audit-chain export`, covers per-entry verification).
5. **Anything about audit-entry contents or policy contents.** By design.

## Explicit Non-Claims

- No wire-level proof: transparency checkpoints prove the recorded enforcement
  history, not packet filtering on the network.
- No binary attestation: `daemon.binary_sha256` is self-reported by the emitting
  process.
- No freshness guarantee without anchoring: a stale but genesis-rooted bundle can
  still pass if no newer checkpoint is provided to the verifier.
- No automatic publication: export is local, and sharing a bundle or key is the
  operator's action.
