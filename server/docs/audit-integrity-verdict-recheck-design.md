# Audit Integrity Verdict Recheck Design

## Problem

Register C7 is an availability amplifier in `AuditLog`: once an instance records
an integrity finding, `ensureLoaded()` treats that in-memory finding as the
current verdict forever because it only reloads when `loaded === false`.

The fail-closed first refusal is correct. The bug is the next append after the
underlying transient has healed: a fresh `AuditLog` over the same bytes reads
clean, while the original instance still refuses using the stale cached finding.
On Mini2 this amplified one transient C6 verdict into hundreds of refused flow
audit writes.

## Constraints

- Do not weaken strict-mode tamper handling. If the store is still dirty, append
  must still fail closed with `AuditIntegrityError`.
- Do not run the expensive full-chain recheck while holding the cross-process
  append lock. On a large chain the full pass can exceed both the 30s lock-hold
  deadline and the 5s acquisition timeout for other appenders.
- Keep the fix scoped to cached dirty verdict recovery. The separate C9 exposure
  remains: a cold first append can still pay its initial load-and-verify inside
  the write lock.
- Preserve the existing append trust boundary after a clean load: the append
  lock still gates sequence allocation, tail freshening, entry persistence, head
  anchor publication, and optional durability verification.

## Design

Before `persistChainedEntry()` acquires the audit write lock, it checks for this
exact state:

```text
integrityMode === "strict"
loaded === true
integrityFindings.length > 0
```

Only in that state it runs `reloadPersistedEntries()` outside the append lock.

Outcomes:

- If the recheck is clean, `integrityFindings` is refreshed to `[]`; the append
  then acquires the write lock and continues through the existing
  `ensureLoaded()` and `freshenChainStateFromDisk()` path.
- If the recheck still finds corruption, `reloadPersistedEntries()` reports the
  finding and strict mode throws `AuditIntegrityError` before the append lock is
  acquired.
- If another process appends after the pre-lock recheck but before this append's
  lock acquisition, the existing locked `freshenChainStateFromDisk()` path
  advances to the newest persisted tail before allocating the next sequence.

This does not claim to make every append a full verifier. It removes the stale
cached refusal without changing the already documented loaded-clean append
boundary.

## Drill

The regression drill uses real `FilesystemStorage`:

1. Seed a valid chain and head anchor.
2. Delete a middle entry.
3. Use a fresh strict `AuditLog` to attempt an append. It fails closed and caches
   the finding.
4. Restore the deleted bytes.
5. Prove a fresh reader sees no findings.
6. Retry append through the original instance and assert the full recheck ran
   while `.audit-write.lock` was absent, then the append succeeds.

