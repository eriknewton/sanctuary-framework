# Sanctuary Audit Chain Export Format

Version: 1.0
Produced by: `sanctuary audit-chain export`
Verified by: `sanctuary audit-chain verify`, with current bounds below.
Production checkpoints are unsigned today, and `--no-strict` can report PASS
even when findings are present. Open defect: **IC-05, IC-06**
(`docs/audit/inert-capability-register.md`).

## Overview

The audit chain export format is a JSONL (newline-delimited JSON) file where each line is one JSON object. The file is produced without requiring the master passphrase: it reads raw envelope bytes from storage and serializes the structural chain metadata. The `encrypted_payload_bytes` field within each entry record remains encrypted -- it is included because it is needed to recompute the `entry_hash`, not because it reveals audit content.

## Record Types

### `entry` -- Audit chain entry

Every append to the audit log produces one entry record.

```json
{
  "type": "entry",
  "seq": 1,
  "schema_version": 2,
  "prev_hash": "GENESIS",
  "entry_hash": "<64-char hex>",
  "timestamp": "2026-05-16T00:00:00.000Z",
  "encrypted_payload_bytes": "<base64url>"
}
```

| Field | Description |
|-------|-------------|
| `type` | Always `"entry"` |
| `seq` | Monotonically increasing sequence number starting at 1 (or after legacy anchor) |
| `schema_version` | Always `2` for v2 chain entries |
| `prev_hash` | `entry_hash` of the previous entry, or `"GENESIS"` for the first entry, or the legacy anchor `root_hash` after migration |
| `entry_hash` | SHA-256 of the canonical JSON of `{sequence, prev_hash, timestamp, encrypted_payload_bytes, schema_version}` (keys sorted, no spaces) |
| `timestamp` | ISO 8601 timestamp of when the entry was written |
| `encrypted_payload_bytes` | Base64url-encoded encrypted audit payload. Sufficient to recompute `entry_hash`; content remains confidential without the master key |

**Hash recomputation:** An external verifier recomputes `entry_hash` as:

```
entry_hash = SHA-256(canonical_json({
  "encrypted_payload_bytes": <value>,
  "prev_hash": <value>,
  "schema_version": 2,
  "sequence": <value>,
  "timestamp": <value>
}))
```

where `canonical_json` sorts object keys lexicographically at every level and uses no whitespace.

### `checkpoint` -- Periodic audit checkpoint

A checkpoint is written after every `checkpointInterval` critical appends (default: 100). It covers a span of consecutive entries and optionally carries an Ed25519 signature over the span root hash.

```json
{
  "type": "checkpoint",
  "checkpoint_kind": "audit-checkpoint",
  "checkpoint_sequence": 100,
  "from_sequence": 1,
  "root_hash": "<64-char hex>",
  "previous_checkpoint_sequence": 0,
  "signed_at": "2026-05-16T00:00:00.000Z",
  "signer_kid": "<identity-id or null>",
  "signature": "<base64url or null>",
  "public_key": "<base64url>",
  "unsigned": false
}
```

| Field | Description |
|-------|-------------|
| `type` | Always `"checkpoint"` |
| `checkpoint_kind` | Always `"audit-checkpoint"` |
| `checkpoint_sequence` | The `seq` of the last entry covered by this checkpoint |
| `from_sequence` | The `seq` of the first entry covered by this checkpoint |
| `root_hash` | SHA-256 of `canonical_json({"leaf_hashes": [entry_hash_N, ...]})` where the array covers `[from_sequence, checkpoint_sequence]` |
| `previous_checkpoint_sequence` | `checkpoint_sequence` of the preceding checkpoint, or `0` if this is the first |
| `signed_at` | ISO 8601 timestamp |
| `signer_kid` | Identity ID of the signing key, or `null` if unsigned |
| `signature` | Base64url-encoded Ed25519 signature, or `null` if unsigned |
| `public_key` | Base64url-encoded Ed25519 public key (embedded for verifier convenience), present when signed |
| `unsigned` | `true` if no signing identity was available at checkpoint time |

**Signature verification:** The signed bytes are:

```
message = "sanctuary.audit-checkpoint.v1\n" + canonical_json({
  "checkpoint_kind": "audit-checkpoint",
  "checkpoint_sequence": <value>,
  "from_sequence": <value>,
  "previous_checkpoint_sequence": <value>,
  "root_hash": <value>,
  "signed_at": <value>
})
```

The signature is an Ed25519 signature over `message` using the key identified by `signer_kid`. The `public_key` field in the export contains the signing public key in base64url format; a verifier may also supply a trusted key via `--public-key <base64url>` to override the embedded key.

### `legacy_anchor` -- Migration anchor for pre-v2 entries

If a fortress was originally created before v2 chain tracking was introduced, the pre-v2 entries are anchored into the chain at load time. The legacy anchor captures this anchor point.

```json
{
  "type": "legacy_anchor",
  "checkpoint_sequence": 5,
  "from_sequence": 1,
  "root_hash": "<64-char hex>",
  "previous_checkpoint_sequence": 0,
  "signed_at": "2026-05-16T00:00:00.000Z",
  "signer_kid": null,
  "signature": null,
  "unsigned": true
}
```

The `root_hash` is the SHA-256 of the canonical JSON of the legacy entry digests. V2 entries begin at `checkpoint_sequence + 1` and their `prev_hash` is this `root_hash`.

## File Layout

Records appear in this order:
1. All `entry` records, sorted by `seq` ascending
2. All `checkpoint` and `legacy_anchor` records, sorted by `checkpoint_sequence` ascending

An export file with no entries is valid (zero records). An export file with entries but no checkpoints is valid (checkpoints are written asynchronously; they may not yet exist for short-lived logs).

## Verification Algorithm

A verifier reading a JSONL export MUST:

1. **Parse** each line as JSON; reject any line that is not valid JSON.
2. **Sort** entries by `seq`, checkpoints/anchors by `checkpoint_sequence`.
3. **Sequence walk:** Starting from `seq = 1` (or `anchor.checkpoint_sequence + 1` if a legacy anchor is present), assert that each entry's `seq` equals the expected sequence and that there are no gaps.
4. **prev_hash walk:** Assert that each entry's `prev_hash` equals the `entry_hash` of the previous entry (or `"GENESIS"` for the first, or the legacy anchor `root_hash` after migration).
5. **Hash recomputation:** For each entry, recompute `entry_hash` from the envelope fields and compare to the stored value.
6. **Checkpoint root:** For each checkpoint, collect the `entry_hash` values for `[from_sequence, checkpoint_sequence]` and recompute the root hash; compare to `root_hash`.
7. **Checkpoint signature:** For each non-unsigned checkpoint, verify the Ed25519 signature over the domain-separated signing payload using the `public_key` field (or a supplied trusted key). Current bound: production checkpoints are unsigned because no production boot path supplies the checkpoint signer, so this leg is skipped on shipped installs. Open defect: **IC-05** (`docs/audit/inert-capability-register.md`).
8. **Legacy anchor:** Assert that `root_hash` is a valid 64-character hex string.

In strict mode (default), any single failure causes the verdict to be `FAIL`; that path is sound. Current bound, confined to `--no-strict`: non-strict mode reports `PASS` even when findings are present, so do not use `--no-strict` as audit evidence until **IC-06** is fixed (`docs/audit/inert-capability-register.md`).

## Verification Report Schema

```json
{
  "verdict": "PASS | FAIL",
  "entries_verified": 100,
  "checkpoints_verified": 1,
  "legacy_anchors_verified": 0,
  "findings": [
    {
      "kind": "entry_hash_mismatch | prev_hash_mismatch | sequence_gap | checkpoint_root_mismatch | checkpoint_signature_invalid | checkpoint_signature_missing_key | legacy_anchor_mismatch | schema_error",
      "seq": 5,
      "message": "Human-readable description",
      "expected": "<value>",
      "actual": "<value>"
    }
  ]
}
```

## Running the Verifier

```bash
# Export from a live fortress
sanctuary audit-chain export --output chain.jsonl

# Verify the export (strict mode, exits non-zero on any finding)
sanctuary audit-chain verify --input chain.jsonl

# Verify with an explicit trusted public key
sanctuary audit-chain verify --input chain.jsonl --public-key <base64url>

# Non-strict mode is diagnostic only until IC-06 is fixed; do not treat PASS as
# audit evidence. Open defect: IC-06
sanctuary audit-chain verify --input chain.jsonl --no-strict
```

## Standalone Use

The verifier (`server/src/cli/audit-chain-verify.ts`) imports only:
- `@noble/curves/ed25519` -- Ed25519 signature verification
- `@noble/hashes/sha256` -- SHA-256 hashing
- `node:fs` -- reading the JSONL file

It does not import from the Sanctuary server runtime (no storage backend, no encryption key, no audit log class). A security reviewer can copy `audit-chain-verify.ts`, install `@noble/curves` and `@noble/hashes`, and run it against an exported chain file without a Sanctuary installation. Current bound: unsigned production checkpoints and the `--no-strict` false-PASS path remain open defects: **IC-05, IC-06** (`docs/audit/inert-capability-register.md`).
