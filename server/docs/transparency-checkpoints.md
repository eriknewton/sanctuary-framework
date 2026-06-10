# Sanctuary Verifiable Transparency Checkpoints

Version: 1 (`schema_version: 1`, domain `sanctuary.enforcement-checkpoint.v1`)
Produced by: `sanctuary transparency checkpoint` (on demand) and the Castle Wall daemon (periodic, default every 6 hours; `SANCTUARY_TRANSPARENCY_INTERVAL` configures or disables)
Exported by: `sanctuary transparency export`
Verified by: `sanctuary verify-transparency`

## What this is

An enforcement checkpoint is a compact, Ed25519-signed record that lets a third party verify, offline, that a Sanctuary fortress's enforcement surface was in a specific, non-rolled-back state at a specific moment. The signed payload contains:

| Field | Content |
|-------|---------|
| `counter` | Strictly monotonic checkpoint counter, starting at 1, incrementing by exactly 1 |
| `previous_checkpoint_hash` | SHA-256 of the previous checkpoint payload (hash chain), or `GENESIS` |
| `issued_at` | ISO 8601 emission time |
| `fortress_id` | Identifier of the emitting fortress |
| `audit.merkle_root` | Root over every surviving audit-chain entry hash at emission time |
| `audit.lowest_sequence` / `audit.highest_sequence` / `audit.head_hash` / `audit.entry_count` | The exact audit window the root covers |
| `policy.rules_sha256` / `policy.rules_count` / `policy.manifest_sha256` | Hashes and counts of the Castle Wall policy inputs. Never the rules themselves |
| `daemon.version` / `daemon.binary_sha256` | Version and SHA-256 of the emitting binary, self-reported |
| `enforcement.total_allowed` / `enforcement.total_blocked` | Counts of `egress_allowed` / `egress_blocked` events in the covered audit window |
| `enforcement.rules[]` | Per-rule counts keyed by an opaque label (domain-separated SHA-256 of the rule id, fortress-scoped). Never the rule id or contents |

A checkpoint is always signed. There is no unsigned variant: if the audit chain fails integrity verification, no Castle Wall policy exists, the emitting binary cannot be hashed, or no signer is reachable, emission refuses and persists nothing.

Privacy invariants: no state content, no rule details beyond counts, no key material. A published checkpoint does not disclose what the policy allows or blocks, and does not disclose audit-log contents (entry payloads stay encrypted; the checkpoint carries only hashes and counts).

## Key custody

Checkpoints are signed by the Castle Wall signing key. On macOS with the Castle Wall app installed, that key lives in the root signer helper (helper-as-signer custody): the emitting process hands opaque domain-separated bytes to a code-signed shim and receives only the signature. The private key never enters the emitting process. The verification key is the same trust anchor the wall pins: `/Library/Application Support/Sanctuary/castle-pinned-pubkey.bin` (root-owned). The dev/test path (`--local-sign`) uses the fortress-local pinned key instead and is not the production custody claim.

A verifying party should obtain the public key out-of-band (for example, from the operator's published key fingerprint), not from the bundle itself. The verifier refuses to silently fall back to the embedded key; `--trust-embedded` is an explicit opt-in and the report labels that basis as proving internal consistency only.

## Verifying

Offline, anywhere, with only the public key:

```
sanctuary verify-transparency --input bundle.json --public-key <base64url-key>
sanctuary verify-transparency --input bundle.json --public-key-file pinned-key.bin
```

On the fortress host, additionally cross-checking the live audit log:

```
sanctuary verify-transparency --input bundle.json --public-key-file pinned-key.bin \
  --against-log --fortress ~/.sanctuary
```

Exit codes: 0 PASS (complete from genesis with the authentic genesis sentinel), 10 PARTIAL (a suffix fragment accepted via `--allow-partial`: verified internally consistent but NOT rooted at genesis), 1 FAIL, 2 usage error. Exit 0 is reserved exclusively for a clean complete-from-genesis PASS. The report never says "best effort passed": every failed check is a specific finding, and everything the run could not check is listed under `not_checked`.

## What a verifying party CAN conclude

From a chain of checkpoints that verifies offline under a pinned key:

1. **Authenticity.** Each checkpoint was signed by the holder of the pinned private key (on a production macOS install: the root signer helper).
2. **No rollback or reordering between checkpoints.** Counters step by exactly 1 and each checkpoint hash-links to its predecessor, so a replaced, reordered, or withheld-then-reinserted checkpoint breaks verification. The audit-log head sequence is also checked to never move backwards between consecutive checkpoints.
3. **Completeness from genesis (default).** A clean PASS / exit 0 means the chain was verified complete from the genesis checkpoint AND that genesis is authentic: the earliest record is counter 1 and its `previous_checkpoint_hash` is the genesis sentinel `"GENESIS"`. Three distinct origin attacks are caught and can never read as a clean PASS:
   - A bundle whose earliest record is counter N>1 is a withheld prefix and FAILS by default (`counter_prefix_missing`).
   - A counter-1 record whose `previous_checkpoint_hash` is a 64-hex value rather than `"GENESIS"` is asserting an undisclosed predecessor (a forged origin, or a withheld prefix wearing a genesis counter). It FAILS (`genesis_sentinel_mismatch`), and `--allow-partial` does NOT relax this: claiming counter 1 is claiming to be the genesis, and that claim must be true.
   - The genesis sentinel appearing on any non-earliest record (a spliced second origin) FAILS (`genesis_sentinel_misplaced`).

   To knowingly verify a suffix fragment, pass `--allow-partial`. The missing prefix is reported under `not_checked` and the result is the DISTINCT verdict `PARTIAL` with the dedicated exit code `10` — never `PASS` / exit 0. Automation gating on either the verdict string or the exit code therefore cannot mistake a suffix fragment for a complete-from-genesis verification. (Suffix withholding — an operator who stops publishing the NEWEST checkpoints — still cannot be detected from a single bundle; see CANNOT, below.)
4. **Audit-log commitment.** Each checkpoint commits to the entire surviving audit hash chain at its emission moment. Anyone who later runs `--against-log` on the host can detect tail truncation (live head behind a signed head), content alteration, and non-prefix in-window deletion relative to that commitment. Deletion of the LOWEST covered entry raises the live floor exactly as legitimate rotation does; `--against-log` distinguishes the two only by the master-key-MAC'd rotation anchor (the #437 audit rotation machinery), which requires the fortress passphrase. Without an authenticated anchor naming the live floor, the cut is treated as unauthenticated and the host check FAILS closed (`rotation_floor_unauthenticated`) rather than passing. A host run that prints `merkle root not recomputed` as a note is NOT a verification pass for the root.
5. **Policy stability or change.** Equal `policy.rules_sha256` values across checkpoints prove the policy input files did not change between them; a changed hash proves the policy changed. (What the policy says is deliberately not disclosed.)
6. **Enforcement activity counts.** The signed allowed/blocked totals and opaque per-rule counts for the covered window. On the host, with the fortress passphrase, these counts are recomputable from the decrypted log and the verifier compares them.
7. **Fork detection across observers.** Two checkpoints with the same counter but different contents, obtained by different observers, prove the operator presented divergent histories.

## What a verifying party CANNOT conclude

These limits are printed by the verifier on every run. Do not over-claim past them.

1. **That the wall was actually enforcing on the wire.** A checkpoint proves the recorded enforcement state and history. It is not a packet-level proof. Enforcement capability claims trace to drill evidence on the platform that matters, not to this format (see ASSURANCE_MATRIX.md).
2. **That the named binary was the running binary.** `daemon.binary_sha256` is self-reported by the emitting process. Comparing it against a published release hash detects a mismatched report; it cannot prove the process that emitted the checkpoint was not itself modified. Remote attestation is out of scope.
3. **Freshness / suffix completeness.** An operator who stops publishing the NEWEST checkpoints produces a shorter chain that is still genesis-rooted and still passes; one bundle cannot prove it is the latest. (Prefix withholding — dropping the genesis side — IS caught by default; see CAN, item 3.) Freshness comes from publication cadence and from cross-checking the highest counter across independently obtained bundles, not from any single bundle.
4. **Events between checkpoints.** The format commits to states at checkpoint moments. An entry appended and pruned between two checkpoints is not individually provable from checkpoints alone (the signed audit chain itself, exported via `sanctuary audit-chain export`, covers per-entry verification).
5. **Anything about audit-entry contents or policy contents.** By design.

## Publishing

Publishing is an operator action. `sanctuary transparency export` writes a self-contained `SANCTUARY_TRANSPARENCY_BUNDLE_V1` JSON document; the operator may post it to a website, commit it to a repository, or hand it to an auditor. Nothing in this feature performs network I/O. Operators who publish should also publish their signing-key fingerprint through a separate channel so verifiers have an out-of-band key.

## Local anti-rollback

The emitter keeps a MAC-authenticated counter floor (keyed from the fortress master key) beside the checkpoint store. Deleting recent checkpoints or the floor itself causes the next emission to refuse rather than silently reissuing a counter. Residual: an adversary with full filesystem control who removes the newest checkpoint inside the narrow window before the floor is raised can hide that one checkpoint locally; any externally published copy of it still exposes the fork through duplicate counters.
