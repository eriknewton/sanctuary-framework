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
3. **Freshness / suffix completeness, from a bundle alone.** An operator who stops publishing the NEWEST checkpoints produces a shorter chain that is still genesis-rooted and still passes; one bundle cannot prove it is the latest. (Prefix withholding, dropping the genesis side, IS caught by default; see CAN, item 3.) When the operator enabled anchoring, this limit is addressable: `--check-anchors` with `--expect-fresh` and a pinned Rekor log key bounds how stale the presented view can be against log-attested time, and an exported receipt above the bundle's top counter is direct withheld-suffix evidence (`anchor_beyond_bundle`). An unanchored fortress retains only cadence and cross-bundle counter comparison.
4. **Events between checkpoints.** The format commits to states at checkpoint moments. An entry appended and pruned between two checkpoints is not individually provable from checkpoints alone (the signed audit chain itself, exported via `sanctuary audit-chain export`, covers per-entry verification).
5. **Anything about audit-entry contents or policy contents.** By design.

## Publishing

Publishing is an operator action. `sanctuary transparency export` writes a self-contained `SANCTUARY_TRANSPARENCY_BUNDLE_V1` JSON document; the operator may post it to a website, commit it to a repository, or hand it to an auditor. The only network I/O in this feature is opt-in anchoring (below), which is off by default; everything else is local. Operators who publish should also publish their signing-key fingerprint through a separate channel so verifiers have an out-of-band key.

## External anchoring (opt-in, off by default)

Two honest limits above, freshness and fork detection across observers, exist because checkpoints live only on the operator's own disk: an operator (or an attacker who owns the host) can withhold the newest checkpoints or present different histories to different people. Anchoring closes the publication half of that gap by writing a tiny commitment to each checkpoint into Sigstore Rekor, a public append-only transparency log that neither the operator nor Sanctuary's authors can rewrite.

Managed with `sanctuary transparency anchor enable|disable|status|now`, or opted into at setup with `sanctuary wrap --anchor-transparency`.

**Consent and privacy (hard constraint: nothing leaves the machine without explicit, confirmed intent):**

- Anchoring is OFF until the operator explicitly enables it. Enabling shows a plain-language consent statement; its hash and timestamp are recorded in the MAC-authenticated anchoring config and in the audit log.
- Anchors are HASH-ONLY. What is published per checkpoint: a salted SHA-256 commitment (the salt is a per-fortress random value that stays local), an ECDSA P-256 signature over the commitment preimage, and the signing public key. That key is a dedicated anchoring key derived from the master key for this single purpose; it is NOT the Ed25519 checkpoint custody key, so public anchors do not link to the published checkpoint-verification key.
- What is NEVER published: checkpoint contents, enforcement counts, policy or rule data, audit data, fortress identifiers, state content, or key material. An observer of the public log learns only that some pseudonymous party anchored at these times. (Anchor timing tracks the emission cadence, so uptime patterns are inferable from timing alone; an operator who finds that too revealing should not enable anchoring.)
- The anchoring config is MAC'd with a master-key-derived key. A tampered config refuses in BOTH directions: an attacker can neither silently switch transmission on nor silently switch evidence anchoring off.

**Rekor URL guard (SSRF):** the configured log URL is an outbound POST target, so it is validated fail-closed at enable time and re-checked before every anchor attempt. The default guard requires https and rejects hostnames that are IP literals in loopback, RFC1918-private, link-local, CGNAT, or reserved ranges, plus well-known metadata and local hostnames (169.254.169.254, `metadata.google.internal`, `*.internal`, `localhost`, `*.localhost`). A 409-duplicate `Location` header is followed only when it resolves to exactly the configured origin; anything else is a failure, not a request. For a local/dev Rekor instance, `--allow-unsafe-rekor-url` at enable time bypasses the address checks; the override must be re-passed at every enable (it is never inherited), and it is recorded in the MAC'd config, in the `transparency_anchoring_enabled` audit entry, and in `anchor status` output, so it can never be silently on.

  *Residual, stated honestly:* the guard checks literals and ranges only; it deliberately does NOT resolve DNS at validation time, because a resolve-then-check would be TOCTOU theater (the answer can change between the check and the POST). A hostile log operator whose hostname the fortress operator chose to configure can therefore still point that name at an internal address (DNS rebinding). Choosing a Rekor URL is choosing to send periodic salted-hash POSTs to that party; the guard stops misconfiguration and casual SSRF primitives, not a malicious log the operator explicitly trusted.

**Failure semantics (fail loud, never blocking):** checkpoint emission never depends on Rekor's uptime. If an anchor attempt fails, the failure is persisted as a receipt, written to the audit log as a critical entry (`transparency_anchor_failed`), and reported on the operator console; the local checkpoint stands. `sanctuary transparency anchor now` re-anchors every checkpoint that lacks a success receipt after an outage. Anchor coverage is therefore honest by construction: receipts state exactly which checkpoints are anchored and which are not, rather than pretending.

**What anchoring adds:** an anchored checkpoint must have existed near its anchor's log-integration time, so a withheld suffix is contradicted by newer public anchors, and two divergent histories anchored under the same pseudonym are publicly visible. The verifier consumes that evidence as follows.

**Verifier-side anchor checking (`--check-anchors`):** the auditor side of the loop. The operator exports the anchor evidence file with `sanctuary transparency anchor export` (the local commitment salt, the derived anchoring public key, and the receipts; the export performs no network I/O, and handing the file out is the operator's deliberate act of linking the pseudonymous anchors to this fortress's history for the recipient). The verifier, full CLI or standalone artifact, then checks per anchored checkpoint, offline: the commitment digest recomputes from the salt + counter + the hash of the checkpoint actually in the bundle; the Rekor entry body is a sha256 hashedrekord over exactly that digest, signed (P-256, verified) by the fortress's anchoring key; the entry UUID matches the RFC 6962 leaf hash of the body; the inclusion proof's leaf index equals the entry's signed log index and lies inside the claimed tree size (RFC 6962 trees allow duplicate leaves, so a proof for a different index with the same leaf must not satisfy an entry signed for this index); the Merkle inclusion proof recomputes to the proof's root; and the signed checkpoint note agrees with that root and tree size. Log-ATTESTED verification requires a pinned Rekor log public key (obtained out-of-band, `--rekor-public-key-file`): with it the verifier additionally checks the signed entry timestamp and the checkpoint-note signature under the log key plus the entry's logID, and only then can an anchor be reported `verified`. Without the pinned key the tool checks internal consistency only, since every remaining input (salt, anchoring key, entry body, proof, root, note, timestamp) comes from the operator-supplied evidence and could have been fabricated together: the skipped log-signature checks are listed under `not_checked`, anchors top out at the `consistent` state (never `verified`), and the report states the trust level explicitly. Anchor coverage is reported plainly (verified / consistent / unverified / invalid / failed-at-anchor-time / unanchored, per checkpoint); missing evidence is never counted as verified. An anchored receipt whose counter exceeds the bundle's newest checkpoint is a finding (`anchor_beyond_bundle`): the operator anchored a checkpoint they are not presenting. `sanctuary verify-transparency --fetch-anchors` fetches fresh entries and inclusion proofs from the log named in the anchors file (same SSRF guard as anchoring, with the same explicit `--allow-unsafe-rekor-url` escape hatch for local/dev logs); a log that answers 404 for a claimed entry is a finding (`anchor_entry_not_found`), and an unreachable log is an honest note, never a silent pass. The standalone artifact stays offline-only and refuses `--fetch-anchors`.

**Freshness (`--expect-fresh <window>`):** fails verification unless the newest log-attested anchor integration time is within the window. It deliberately requires the pinned Rekor log key: without it the timestamps are operator-suppliable and the check refuses (`anchor_freshness_unverifiable`) rather than passing on forgeable evidence.

**Fork detection (`--compare <other-bundle>`):** verifies a second, independently obtained bundle under the same key and cross-checks shared counters. The same counter carrying different signed contents is a `fork_detected` finding: the operator presented divergent histories to different observers. Consistent overlap where one bundle simply ends earlier is reported as a stale view, not a fork; non-overlapping ranges are an explicit inconclusive finding (`compare_no_overlap`), not a quiet pass.

**Honest limits of anchor verification:** anchor coverage speaks only about the receipts the operator exported; anchors published under the same pseudonym but omitted from the export are invisible offline (an auditor can enumerate the anchoring public key's entries on the public log independently to bound that). Anchoring evidence does not change the binary-identity or wire-enforcement limits above. Capability claims about this loop trace to drill evidence per the assurance-matrix discipline, not to this document; the pre-declared drill fixtures live in `server/test/transparency/anchor-verify-cli.test.ts`.

**Audit trail:** every anchoring state change and every anchor attempt is recorded: `transparency_anchoring_enabled` (with the consent text hash and whether `--allow-unsafe-rekor-url` was in effect), `transparency_anchoring_disabled`, `transparency_checkpoint_anchored` (with the Rekor log index and entry UUID), `transparency_anchor_failed` (with the error).

## Local anti-rollback

The emitter keeps a MAC-authenticated counter floor (keyed from the fortress master key) beside the checkpoint store. Deleting recent checkpoints or the floor itself causes the next emission to refuse rather than silently reissuing a counter. Residual: an adversary with full filesystem control who removes the newest checkpoint inside the narrow window before the floor is raised can hide that one checkpoint locally; any externally published copy of it still exposes the fork through duplicate counters.
