# Audit Log Tail Hardening Build Report

Date: 2026-06-09
Branch: `v1.x-audit-log-tail-hardening-2026-06-09`
Base observed: `65c05575`
Status: fixed locally, committed branch only, no push/PR/merge

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

### S-1: reader during rotation/read consistency

Implemented the read-consistency fix for the three confirmed concurrent-reader tears:

- `entry_malformed`: filesystem writes now publish through temp-file plus atomic `rename()`; durable writes fsync the temp file before publish and best-effort fsync the directory after publish.
- `rotation_anchor_invalid`: readers treat anchor-ahead/lowest-survivor mismatches as retryable only while the writer-owned `_audit/.audit-write.lock` marker is presently held.
- `tail_anchor_missing`: readers treat first-establishment anchor gaps as retryable only under the same live writer marker.

The retry design is attacker-safe:

- The reader does not retry just because sequence numbers look transient. It retries only when the observable writer marker exists.
- The retry budget is bounded to five 10 ms sleeps. If the store remains inconsistent after that ceiling, strict mode throws the integrity finding.
- If no writer marker is present, truncation findings fail immediately.
- If an attacker leaves truncation plus a fake/corrupt marker, the bounded ceiling expires and the tail-floor violation still fails closed.

Added regression coverage for that attacker-safety property in `server/test/l2/audit-log-chain.test.ts`.

Also hardened stale-lock recovery: if `os.uptime()` is unavailable in a sandboxed child process, boot-time staleness is not assumed; the code falls back to the PID-liveness proof and never breaks an unprovable lock.

## Files Changed

- `server/src/l2-operational/audit-log.ts`
- `server/src/storage/filesystem.ts`
- `server/src/cli/audit.ts`
- `server/src/l2-operational/context-gate-tools.ts`
- `server/src/sanctuary-tools.ts`
- `server/src/cli/audit-chain-export.ts`
- `server/src/cli/audit-chain-verify.ts`
- `server/test/l2/audit-log-chain.test.ts`
- `server/test/mcp/audit-integrity-gate-classification.test.ts`
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
npm test -- test/l2/audit-log-chain.test.ts test/l2/audit-log-concurrent-write.test.ts test/l2/audit-log-rotation-checkpoint.test.ts
```

Result: 3 files passed, 25 tests passed.

Passed:

```text
npm test -- test/l2/audit-log-*.test.ts test/cli/audit-search.test.ts test/audit/external-verifier-drill.test.ts
```

Result: 9 files passed, 59 tests passed.

Passed for S-1 flake confidence:

```text
for i in 1 2 3 4 5 6 7 8 9 10; do npx vitest run test/l2/audit-log-concurrent-write.test.ts >/tmp/audit-log-concurrent-$i.log || exit 1; done
```

Result: 10 consecutive green runs of the concurrent writer/reader rotation test.

Not run:

- Full macOS suite.
- `.test-baseline` update was not needed; the root `.test-baseline` remained unchanged.

## Deviations

- No push, PR, or merge was performed.
