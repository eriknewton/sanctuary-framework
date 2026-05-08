# Audit Log Architecture

Sanctuary has two Castle Wall audit surfaces:

- The daemon-side WAL in `castle-wall-daemon` is a local plaintext NDJSON buffer used while Sanctuary main is unavailable or before main ACKs a drained event.
- The server-side audit log is the existing encrypted Sanctuary audit sink. Castle Wall critical events are folded into it by `AuditConsumer` after validation.

## Encryption Boundary

The daemon does not hold the fortress master key. Its WAL is owner-only (`0600`) and exists only as a durability bridge between enforcement and Sanctuary main. Sanctuary main remains responsible for encrypted audit persistence.

Server-side audit entries are appended through the normal audit sink, which is backed by master-key-derived encryption. The log is append-oriented, but individual entries are not daemon-signed.

## Integrity Model

The daemon WAL is hash-chained. Each WAL entry carries:

- `seq`: the daemon-assigned monotonic sequence number.
- `prior_sha256_hex`: the SHA-256 hash of the previous audit event's canonical JSON bytes, or `null` for the first event in a chain.
- `event_canonical_json`: the canonical audit event bytes Sanctuary main stores after drain.

On daemon startup, the WAL is replayed and checked for internal chain consistency. A truncated WAL may begin with an entry whose `prior_sha256_hex` points to an already-ACKed event no longer present on disk; subsequent entries must still link locally.

## Drain Validation Contract

The daemon injects `seq` and `prior_sha256_hex` into each event's `details` object before writing it to the WAL. `AuditConsumer.ingestCritical()` requires those fields before appending to the encrypted server-side audit log.

For each accepted critical event, Sanctuary main tracks the latest ACKed sequence and the SHA-256 hash of the accepted event's canonical JSON. The next event must have a greater `seq` and, after the first accepted event, a `prior_sha256_hex` matching that tracked hash.

Validation failures are recorded as `wal_chain_verification_failed` audit entries and the inbound event is rejected. Malformed event-shape failures still use the existing `audit_event_rejected` path and ACK behavior to avoid daemon redelivery loops for non-chain schema errors.

## Crypto Agility Notes

The v1.5+ crypto-agility sprint should treat the encrypted server-side audit log as the migration target. Expected migration work is key-wrap and cipher-suite agility around the encrypted log container, not per-entry daemon signing.

If the daemon WAL later gains at-rest encryption, it must preserve the same drain validation fields so Sanctuary main can continue proving sequence monotonicity and chain linkage independently of the daemon process.
