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
with `localeCompare`, and walks backward over entry keys. The sealed-region floor
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
only confirmed survivors. A partial failure leaves provenance unknown. A load
cannot publish an older seed across an own append or rotation.

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
