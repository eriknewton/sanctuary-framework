# Audit Log Architecture

## Storage and entry format

Each fortress owns its local `_audit` namespace. V2 records contain an encrypted
entry payload, sequence, previous hash, entry hash, and timestamp. The encrypted
payload uses AES-256-GCM and the master-derived `audit-log` purpose key. Legacy
records remain readable through the existing load path. Entry and anchor formats
are unchanged by names-only enumeration.

## Append and checkpoint work

The append queue serializes each instance's writes. Filesystem writers acquire
the shared audit write lock before discovering the durable tail and allocating
a sequence. Discovery takes one complete `listKeys("_audit")` snapshot, sorts it
with `localeCompare` and a code-unit tie break, and walks backward over entry keys. The sealed-region floor
and malformed-tail handling remain part of discovery. A backend without
`listKeys` uses its sized listing with the `entry-` prefix to preserve discovery's refusal boundary.

The entry is written before the head anchor. Filesystem persistence retains its
durable writes and readback checks. Callers must await critical appends or drain
pending writes with `flush()` before exiting. Exiting early can leave pending
writes unfinished. A first write also performs the existing once-per-instance
stale-lock-temp sweep; that startup directory read is additional to discovery.

An interval checkpoint reuses the append's key snapshot under the same lock.
It reads every entry body above the sealed tip and indexes accepted envelopes by
their sequence. A checkpoint is written only for a complete range with exactly
one accepted entry per sequence. An incomplete range keeps the pending hashes
and reports a diagnostic without signing a record. Shutdown checkpointing takes
its own lock and snapshot.

Checkpoint append listings of `_audit` are reduced from repeated listings to one.
Body reads are unchanged: one per entry above the sealed tip, amortized over
`checkpointInterval` critical appends. Filenames do not authenticate envelope
sequences, so reading only filenames in the requested range would not establish
complete coverage. A cheaper collector requires a later design for authenticated
key-to-envelope agreement.

The checkpoint tip lookup enumerates `_audit_checkpoints`, reads every record,
and takes the maximum parsed checkpoint sequence. An unsealed read fault still
refuses the append, including a fault in an older record. Names and body reads
are O(checkpoints) per checkpoint write, amortized over `checkpointInterval`.
Checkpoint records are never pruned; one
record per `checkpointInterval` critical appends accumulates for the fortress's
lifetime, with additional checkpoints possible at shutdown. Entry retention does
not bound this namespace.

## Retention accounting

The default limits are 100,000 entries and 100 MiB of entry bytes. A successful
prune targets `maxEntries - rotationHysteresis` entries and the byte cap less
the same one-percent proportion, subject to keeping one survivor. This deliberate
product behavior change must match `rotationDeleteCount` in
`server/src/operational/audit-log.ts`: the instance computes its configured margin
once as `max(1, floor(maxEntries * AUDIT_ROTATION_MARGIN_FRACTION))`.
The exported `AUDIT_ROTATION_HYSTERESIS` is the default-cap value, 1,000 entries.
A binding byte cap can retain fewer entries, and one oversized surviving entry
can exceed the byte target.
Sealed history is protected from pruning and lies outside these prunable totals.

The append snapshot feeds the rotation decision, including legacy keys when no
sealed boundary protects them, and including the append's own durable write
exactly once. The byte estimate is seeded from sized metadata. Unknown provenance
or a changed count, lowest key, or highest key requires an authoritative sized
listing before the decision. Pruning runs under the audit write lock and seeds
only confirmed survivors. Each step authenticates the next survivor before deleting
one entry. An episode uses a budget of `floor(configured hold / 3)`, 10 seconds at
the default hold, checked between steps. This does not guarantee that a contending
writer acquires within the five-second timeout. Rotation takes its own hold after
the append releases its lock; later over-cap appends continue toward the low target.
The budget starts when the rotation hold begins and includes recount time. The
recount and an in-flight step can overrun the budget. At least one step is attempted
when pruning is due. The next rotation hold of any writer deletes an entry left
below the authenticated rotation anchor when the entry the anchor names is present.
A partial failure leaves provenance
unknown. A load cannot publish an older seed across an own append or rotation.

On a backend without `listKeys`, legacy non-entry records make the entry-only
discovery signature differ from the full recount population on every append.
That arm pays one sized recount per append, with full-population accounting and
no pruning delay. A failed recount emits one raw-stderr diagnostic per fault
episode and one recovery line on the next successful recount. A raw empty recount
against a snapshot containing entry keys is rejected as inconsistent; a shorter
nonempty recount can be a cooperating writer's prune.

A foreign write after our append lock is released is reflected in rotation at
most one own append late. Same-key byte rewrites are outside writer accounting;
they belong to integrity verification. Failed pruning and large sealed regions
can increase enumeration work beyond the configured entry cap. Names-only work
still allocates and sorts the complete key set; it is not constant-time work.

## Verification and eager reads

Full loads retain their byte, chain, checkpoint, and anchor verification. An own
durable write makes the optional metadata fingerprint unknown, including when a
later anchor write fails. It does not constitute a completed verification pass.
The first eager read after the byte-pass interval still performs its byte pass,
independently of that fingerprint, with the smaller of the byte-pass and reverify
intervals controlling the backstop. A completed load refreshes the fingerprint.
Without reads there is no autonomous timed verification scan.

Append discovery and checkpoint enumeration no longer stat entry or checkpoint
files for listing metadata. Their exact-key body reads retain custody checks.
A metadata-only fault on a file the write does not read is observed by a later
sized load or recount. A strict verification read on the writing instance records
hard findings that refuse subsequent appends; a separate reader or a lenient
instance does not stop the writer. No availability claim follows from this change.

Entry persistence, anchoring, and interval checkpoint work share the existing
30-second hold deadline, with the existing 5-second contention timeout unchanged.
A rejected append can have a durable anchored entry and, if persistence was
already issued, a checkpoint that lands later. Pending state is kept for retry;
checkpoint flight ownership follows the hold and late cleanup cannot clear a
successor's flight.

The performance measurement uses synthetic pre-population followed by a strict
cold load and real durable filesystem appends. It does not establish a Darwin
capability-path latency bound; that requires a separate platform run.

## 6. Tamper Model

AES-GCM authenticates encrypted entry contents. The V2 hash chain, authenticated
head and rotation anchors, and checkpoint verification also report chain and
retention inconsistencies. Strict reads refuse hard findings; lenient reads
retain the findings for inspection. These mechanisms do not establish an
independent append-only proof against an actor holding the fortress master key.

Plain filenames expose timing metadata because entry keys include timestamps and sequences. Multi-fortress correlation from directory names and modification times is therefore outside the encryption boundary.

Castle Wall Phase 1 complements this model at the egress boundary. It is not an audit-log cryptographic proof system; it reduces the chance that encrypted audit blobs or unlocked data leave the machine without operator authorization. A master key from another fortress does not decrypt this fortress's audit entries unless the key material matches.

## 7. PQ Migration Implications

Local entries use symmetric encryption and a hash chain, rather than per-entry
asymmetric signatures. Signed checkpoints use Ed25519 and are a separate
asymmetric migration surface; they need explicit versioned migration guidance.

The entry-encryption path uses:

- Argon2id derives the 32-byte master key from the fortress passphrase.
- HKDF-SHA256 derives the `audit-log` purpose key.
- AES-256-GCM encrypts each entry.

HKDF-SHA256 and AES-256-GCM remain the relevant symmetric primitives in the post-quantum threat model. The more sensitive migration surfaces are passphrase strength and KDF parameters, envelope versioning for encrypted payloads, and any future asymmetric wrapping layer added around fortress-master material. If the mantle binding later introduces asymmetric master-key wrapping, that wrapping layer is where ML-KEM-768 belongs. It is not an audit-entry migration and should not be implemented as local audit-entry signatures.

Because the current encrypted payload schema has `v: 1` and `alg: "aes-256-gcm"` but no key-wrap metadata, a crypto-agility pass should design explicit envelope metadata before changing algorithms or adding KEM-wrapped key material.

## 8. Comparison To V1.x Federation Envelope Signing

The federation protocol is a separate audit surface. `server/docs/federation-protocol-v0.1-spec.md` section 5 defines canonical audit nodes, streamed audit batches, per-node signatures, HMAC chain proofs, and previous-batch hash continuity. In that path, wire events and audit batches are signed by per-node keys and verified against the fortress-master-anchored trust chain.

Local `AuditLog` does not use that federation envelope format. It writes encrypted local entries through the storage backend. The federation path has a signature-scheme and batch-chain migration problem; the local audit log has entry-encryption, checkpoint-signature, retention, and storage-integrity migration concerns.

## 9. Operator-Facing Implications

The audit log is unreadable while the fortress is locked because reads require the same master key used to derive the audit purpose key. Unlock through the normal passphrase path, recovery key path, or guardian recovery cascade restores access to the encrypted entries as long as the recovered master key matches the key used to write them.

Operators should inspect the log through `monitor_audit_log`, `audit_export_siem`, dashboard views that bind an unlocked `AuditLog`, or purpose-specific CLIs such as `secrets audit`. Direct `cat` or `grep` of `_audit/*.enc` shows envelopes containing encrypted payloads and chain metadata.

Retention is operator-policy-driven only through `AuditLogConfig` at construction today; defaults are 100 MiB and 100,000 entries. Existing multi-tenancy documentation states that cross-tenant or cross-fortress audit aggregation is not performed by the multi-agent dashboard. Each fortress storage path owns its own `_audit` namespace and master-key-derived audit key.

## 10. Open Questions And Future Work

- Explicit AAD binding: local audit entries currently pass no AES-GCM AAD. A future envelope could bind `fortress_id`, namespace, and key into authentication.
- Durability: filesystem entry and anchor writes use durable barriers. Platform drills remain necessary to establish interruption behavior on each supported filesystem.
- Cross-process contention: filesystem writers share an audit lock. Lockless backends retain their multi-writer coordination bound.
- Rollback evidence: chain and authenticated anchor checks cover retained-history consistency; independent evidence outside the fortress remains a separate design question.
- Memory hygiene: the audit purpose key is held in the `AuditLog` instance as `encryptionKey`; zeroization on fortress lock or shutdown is not implemented in this class.
- Corruption visibility: integrity findings accompany lenient reads, and strict reads refuse hard findings. Operator workflows must preserve those verdicts when exporting or aggregating results.
- Envelope agility: encrypted payloads expose algorithm and version, but no KDF parameters, key id, fortress id, or wrapping metadata for future PQ or rotation migrations.

## Source Verification

Primary implementation files inspected:

- `server/src/operational/audit-log.ts`
- `server/src/core/key-derivation.ts`
- `server/src/core/encryption.ts`
- `server/src/storage/interface.ts`
- `server/src/storage/filesystem.ts`
- `server/src/index.ts`
- `server/src/config.ts`
- `server/src/paths.ts`
- `server/src/wrap/passphrase.ts`
- `server/src/wrap/cli.ts`
- `server/src/disclosure/broker/open.ts`
- `server/src/cli/secrets.ts`
- `server/src/audit/siem-tools.ts`
- `server/src/dashboard/v1_1/wiring.ts`
- `server/src/dashboard/v1_1/dispatch.ts`
- `server/src/console/view-aggregator.ts`
- `server/docs/DEPLOYMENT.md`
- `server/docs/multi-tenancy.md`
- `server/docs/hkdf-info-string-registry.md`
- `server/docs/federation-protocol-v0.1-spec.md`

Discrepancy recorded: the dispatch framing described a whole-log master-key-wrapped encrypted blob. The source implements individually encrypted per-entry files under `_audit`, using the `audit-log` HKDF purpose key. The migration guidance above follows the implementation rather than the dispatch assumption.
