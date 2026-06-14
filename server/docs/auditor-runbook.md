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

## Anchor Verification (PR-3, for fortresses with anchoring enabled)

When the operator opted into external anchoring (PR-2), each checkpoint's
salted commitment was published to a public Sigstore Rekor log. The auditor
can then close the freshness and fork gaps that a bundle alone cannot.

Operator steps (in addition to the bundle export above):

1. Export the anchor evidence file:

   ```sh
   sanctuary transparency anchor export --output anchors.json
   ```

   The file carries the local commitment salt, the derived anchoring public
   key, and every anchor receipt (including the Rekor entry bodies and
   inclusion proofs captured at anchor time). It is assembled entirely from
   local state and transmits nothing. The salt links the pseudonymous public
   anchors to this fortress's history for whoever holds the file; hand it to
   auditors deliberately, alongside the bundle.

Auditor steps:

1. Pin the Rekor log's public key OUT-OF-BAND (do not take it from the
   operator). For the public-good instance:

   ```sh
   curl -sS https://rekor.sigstore.dev/api/v1/log/publicKey -o rekor-key.pem
   ```

   Pin it the same way you pin the operator's signing-key fingerprint.

2. Verify offline (works on the standalone artifact too):

   ```sh
   node verify-transparency.js --input transparency-bundle.json \
     --public-key-file castle-pinned-pubkey.bin \
     --check-anchors anchors.json --rekor-public-key-file rekor-key.pem
   ```

   Per anchored checkpoint this recomputes the salted commitment against the
   bundle's actual checkpoint, rebinds the Rekor entry body (digest, the
   fortress anchoring key, its P-256 signature, the RFC 6962 leaf hash),
   requires the inclusion proof's leaf index to match the entry's signed log
   index and to lie inside the claimed tree, recomputes the Merkle inclusion
   proof, and verifies the signed entry timestamp and checkpoint-note
   signature under your pinned log key. The report states anchor coverage
   plainly; missing evidence is "unverified", never silently passed.

   The pinned log key is what makes verification log-attested. Without
   `--rekor-public-key-file` the tool checks internal consistency only:
   every input it has (salt, anchoring key, entry bodies, proofs, roots,
   notes, timestamps) comes from the operator-supplied files and could have
   been fabricated together. Such anchors are reported "consistent", never
   "verified", the log-signature checks are honestly listed under
   `not_checked`, the report says so on its trust-level line, and freshness
   cannot be asserted.

3. Apply the freshness policy you require:

   ```sh
   ... --check-anchors anchors.json --rekor-public-key-file rekor-key.pem --expect-fresh 36h
   ```

   `FAIL` with `anchor_freshness_stale` means the newest log-attested anchor
   is older than your window: you are being shown a stale view.

4. If you obtained a second bundle from another observer, check for split
   views:

   ```sh
   ... --compare other-observer-bundle.json
   ```

   `fork_detected` means the same counter exists in both bundles with
   different signed contents: divergent histories were presented.

5. Optionally refresh evidence directly from the log (full CLI only; the
   standalone artifact never performs network I/O):

   ```sh
   sanctuary verify-transparency --input transparency-bundle.json \
     --public-key-file castle-pinned-pubkey.bin \
     --check-anchors anchors.json --rekor-public-key-file rekor-key.pem --fetch-anchors
   ```

   A log that denies a claimed entry (`anchor_entry_not_found`) refutes the
   receipt; an unreachable log is reported and the run falls back to
   receipt-embedded material where present.

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

The PR-3 synthetic fixtures pre-declare the anchor-loop drill criteria
(fixture test: `server/test/transparency/anchor-verify-cli.test.ts`, scenarios
D1 to D4; same discipline: synthetic keys, a synthetic in-memory Rekor log,
no network, no soak):

1. **D1 clean loop:** bundle + anchors evidence + pinned operator key +
   pinned log key verify end-to-end, on the full CLI and on the standalone
   artifact. Expected: `PASS`, exit `0`, every anchor `verified`.
2. **D2 stale bundle caught:** the same evidence outside `--expect-fresh`.
   Expected: `FAIL`, exit `1`, finding kind `anchor_freshness_stale`.
3. **D3 forked history caught:** two bundles signed by the same key carrying
   the same counter with different contents, via `--compare`. Expected:
   `FAIL`, exit `1`, finding kind `fork_detected`.
4. **D4 withheld suffix caught:** a truncated bundle against the full anchors
   evidence. Expected: `FAIL`, exit `1`, finding kind `anchor_beyond_bundle`.

Per the drill-acceptance rule, these fixtures are the deterministic twins of
the coordinator-run drill; capability claims trace to captured drill evidence,
not to this runbook or to merged code.

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
3. **Freshness / suffix completeness, from a bundle alone.** An operator who stops publishing the NEWEST checkpoints produces a shorter chain that is still genesis-rooted and still passes; one bundle cannot prove it is the latest. (Prefix withholding, dropping the genesis side, IS caught by default; see CAN, item 3.) For fortresses with anchoring enabled, `--check-anchors` with `--expect-fresh` and a pinned Rekor log key bounds staleness against log-attested time, and an exported anchor receipt above the bundle's top counter is direct withheld-suffix evidence; an unanchored fortress retains only cadence and cross-bundle counter comparison.
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

## What the dashboard "armed" (green) light rests on

The Sovereignty Posture dashboard renders Castle Wall green ("armed") only from
fresh enforcement evidence in the tamper-evident audit log — never from a
daemon's self-reported belief. The cryptographic basis of that green light is
now surfaced honestly in the `producer_authenticity` field, and it differs by
platform:

- **Linux (per-producer authenticated).** When the daemon's pinned
  audit-producer public key is provisioned to the reader
  (`<storage_path>/policy/egress/audit-producer.pub`, the same anchor the
  daemon publishes), the dashboard RE-verifies each enforcement event's
  Ed25519 producer signature at read time, against that pinned key — the same
  kind of pinned anchor the transparency checkpoints verify against. The
  daemon's signing key is not reachable from the in-process Sanctuary server,
  so an in-process module that forges an audit entry (marker + claimed
  `producer_signed` basis, but no valid signature) fails this re-verification
  and can never render the wall green or inflate the kernel-block counts. The
  surface reports `producer_authenticity: "producer_signed"`.

- **macOS (channel-authenticated, NOT per-producer).** The macOS enforcing
  extension does not sign per-event verdicts today, so no pinned producer key
  is available to the reader. The dashboard then falls back to the legacy
  basis: the green light rests on the mutually-pinned IPC channel plus the
  tamper-evident audit chain. This is honestly labeled
  `producer_authenticity: "channel_authenticated"`. It is NOT a per-event,
  per-producer authenticity claim. Per-event authenticity on macOS is pending
  the extension-signing slice; do not over-claim it.

In both cases the `unknown`-is-never-green invariant holds: absence of fresh
evidence, a stale read, or an integrity finding renders amber, never green.
