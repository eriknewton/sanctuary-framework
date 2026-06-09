# Audit Log Tail Hardening Build Report

Date: 2026-06-09
Branch: `v1.x-audit-log-tail-hardening-2026-06-09`
Base observed: `65c05575`
Status: stopped before commit due S-1 reader-during-rotation tear

## Findings

### F-AUDIT-1: monotonic tail floor

Implemented a MAC-authenticated audit head anchor at `_audit_checkpoints/__head_anchor`.

The anchor stores:

- `highest_sequence`
- `head_hash`

It is MAC'd with a master-key-derived `audit-head-anchor` key and updated after append entry persistence. Load now verifies that the highest surviving chain sequence is not below the recorded floor and that the surviving head hash matches when the floor equals the surviving head.

Empty vs established distinction:

- A fresh empty audit store with no head anchor remains valid.
- Legacy-only audit data can TOFU-migrate once by writing the new head anchor.
- A v2 audit store with entries but no head anchor fails closed with `tail_anchor_missing`.
- A store whose audit entries and checkpoint namespace were deleted after establishment fails closed if the `_meta/audit-head-anchor-established-v1` marker remains.

Residual: if an attacker deletes `_audit`, `_audit_checkpoints`, and the `_meta/audit-head-anchor-established-v1` marker together, the current implementation cannot distinguish that from first boot. Avoiding that requires an anchor outside the same deletable storage trust boundary.

### F-AUDIT-2: audit search integrity surfacing

Implemented explicit integrity handling in `sanctuary audit search`.

- Strict-mode `AuditIntegrityError` now prints `AUDIT INTEGRITY WARNING`.
- `--json` includes `integrity_findings`.
- Findings return exit code 1.
- Master key bytes are cleared in `finally`.

### F-AUDIT-3: critical append routing

Switched the named security operations to awaited `appendCritical()`:

- `context_gate_set_policy`
- `context_gate_deny`
- `sanctuary_export_identity_bundle`

Added a source-level regression guard that prevents these operations from drifting back to best-effort `append()`.

### F-AUDIT-4: rotation anchor export

Export now includes a `rotation_anchor` JSONL record with:

- `base_sequence`
- `base_prev_hash`

The standalone verifier consumes that record to seed chain verification for rotated exports and skips checkpoint root recomputation for checkpoint spans whose leaves were legitimately pruned below the rotation floor. Signature verification still runs for those checkpoints.

### S-1: reader during rotation

Added a focused concurrent reader/rotation fuzz test in `server/test/l2/audit-log-concurrent-write.test.ts`.

Result: the test revealed real transient reader tears. Per the prompt, I stopped rather than guessing a locking change.

Observed failures included:

- `tail_anchor_missing` while the first append/head-anchor establishment was in flight.
- `entry_malformed` from a reader observing an entry file mid-write.
- `rotation_anchor_invalid` where the reader saw a newer rotation anchor before the corresponding prune completed, e.g. anchor `base_sequence 3` with lowest surviving sequence `2`.

This means the suspected race is confirmed enough to require a deliberate read consistency design, not a blind patch.

## Files Changed

- `server/src/l2-operational/audit-log.ts`
- `server/src/cli/audit.ts`
- `server/src/l2-operational/context-gate-tools.ts`
- `server/src/sanctuary-tools.ts`
- `server/src/cli/audit-chain-export.ts`
- `server/src/cli/audit-chain-verify.ts`
- `server/test/l2/audit-log-chain.test.ts`
- `server/test/cli/audit-search.test.ts`
- `server/test/cli/cli-audit-write-inventory.test.ts`
- `server/test/audit/external-verifier-drill.test.ts`
- `server/test/l2/audit-log-concurrent-write.test.ts`

## Tests And Gates

Passed:

```text
npm run typecheck
```

Passed:

```text
npm test -- test/l2/audit-log-chain.test.ts test/cli/audit-search.test.ts test/cli/cli-audit-write-inventory.test.ts test/audit/external-verifier-drill.test.ts
```

Result: 4 files passed, 36 tests passed.

Failed by design as blocker evidence:

```text
npm test -- test/l2/audit-log-concurrent-write.test.ts
```

Result: 1 failed, 1 passed. The new reader-during-rotation test failed with transient integrity findings, confirming S-1 needs a separate lock/read-consistency fix.

Not run:

- Full macOS suite.
- `.test-baseline` update. The build is stopped before commit because S-1 exposed a real tear.

## Deviations

- No commit was created. The prompt explicitly said to stop and report if the S-1 test revealed a real tear.
- No push, PR, or merge was performed.
