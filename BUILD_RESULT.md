# Agent-Native Surface Phase 2 Build Result

Date: 2026-06-08
Branch: feat/agent-native-surface-phase2
Base confirmed: origin/main at `1ee1bd94 feat(agent-native): Phase 1 safety base (gate verify-mode, preflight, opaque-handle ownership) (#417)`
Remediation pass: `REVIEW_FINDINGS.md` P0-1 and P1-1/P1-2/P1-3 fixed locally. R2 follow-up closes `REVIEW_FINDINGS_R2.md` P1-1/P1-2/P2-1 locally. No push. No merge.

## What Changed

- Added the Phase 2 cooperative facade tools in `server/src/agent-native/cooperative-surface.ts`:
  - `sanctuary_remember` expands to `state_write`.
  - `sanctuary_recall` expands to `state_read` and returns compact `{ value, verified, audit_ref }` by default.
  - `sanctuary_hide` records version/content-hash-bound hidden markers behind the reserved `_facade/hidden` namespace contract.
  - `sanctuary_forget` expands to `state_delete` and is enrolled as Tier 1.
  - `sanctuary_help` uses a deterministic suppressive classifier for ordinary/sensitive/gated intents, including encoded and multi-intent probes.
  - `sanctuary_who_am_i` returns only disclosable identity fields.
  - `sanctuary_active_protections` returns positive-only coarse guarantees.
  - `sanctuary_events_open_cursor/read/close` implement local pull cursors with redacted, identity-bound reads and no callback/URL surface.
  - `sanctuary_audit_search` implements own-scope derived audit search with integrity fail-closed behavior.
  - `sanctuary_compound_execute` implements plan-hash construction and fail-closed pre-step denial when required approvals are not reserved.
- Extended router/preflight support so facade tools can declare `approvalTargetToolName`; the gate and approval preflight bind to the expanded primitive tool name and args instead of the friendly facade name.
- Registered the Phase 2 tools in server startup using the Phase 1 L1 namespace registry, preserving opaque-handle ownership state.
- Reserved `_facade` as an internal namespace prefix.
- Enrolled ordinary/read facade verbs in Tier 3 and secure/widening compound verbs in Tier 1.
- Remediated review findings:
  - Convenience verbs now default to the active opaque memory handle and reject non-opaque or non-owned explicit namespaces before primitive expansion.
  - Compound execution shares the router approval proof store, reserves and verifies every Tier 1 step approval against exact primitive args before step 1, consumes only attempted step approvals, and releases unattempted reservations on short-circuit.
  - Hide markers are durable `_facade/hidden` records, exported/imported with their target namespace bundles, reloaded across facade restart, and deny on stale version/content-hash mismatch.
  - Help intent classification now checks URL/base64 decoded and compacted variants, destructive paraphrases, and benign-pretext-plus-destructive-subgoal prompts before emitting ordinary runnable examples.
- Remediated R2 review findings:
  - Compound approval proof envelopes can now bind `plan_hash` and `step_id`; compound reservation verifies those fields plus the expanded primitive call before consumption, and ordinary gate proof verification rejects compound-bound proofs.
  - `sanctuary_help` suppresses runnable examples for multi-intent prompts when any clause is gated/destructive or ambiguous, including benign `remember` pretexts paired with `remove`.
  - `sanctuary_hide` TTL markers are enforced on recall: expired markers are garbage-collected, audited, and no longer hide the target.

## Tests Added

- `server/test/agent-native/phase2-cooperative-surface.test.ts`
  - Expanded primitive approval target binding.
  - Verification-preserving compact recall.
  - Hide-marker hidden recall and secure-forget marker removal/recreate behavior.
  - Help suppression for paraphrase, multi-intent, encoded, and callback-pretext gated intents.
  - Positive-only active protections.
  - Disclosable-only who-am-I response shape.
  - Pull-only event cursor denial for callbacks, redacted event reads, and coarse rate denial.
  - Own-scope audit search and widened-scope denial.
  - Compound plan short-circuit before step one when required approval is missing.
  - Cross-namespace convenience verb denial for another identity's opaque handle and legacy non-opaque namespaces.
  - Hide-marker lifecycle across facade restart, state export/import restore, and stale target overwrite.
  - Compound invalid later-step proof blocks step 1; valid future proof is released when an earlier step fails.
  - Help laundering suppression for wipe/purge/remove-permanently, encoded, multi-intent, and callback probes.
  - Compound approval proofs bound to `plan_hash`/`step_id`, accepted for the matching plan/step, and rejected across plans or steps.
  - Multi-intent help with a destructive `remove` clause suppresses runnable examples.
  - Expired hide markers are garbage-collected, audited, and do not hide default recall.

## Gate Results

- `cd server && npm run typecheck`: passed.
- `cd server && npm test`: passed.
  - Test files: 446 passed, 1 skipped.
  - Tests: 5,482 passed, 8 skipped.
  - Baseline: `.test-baseline` is 5,423, so the run is above baseline.
  - No transform or collection errors.

## Design Semantics Interpreted

- The facade uses the Phase 1 router/gate binding path by declaring expanded primitive approval targets; handlers then execute the matching primitive tool with the same server-expanded args.
- Explicit facade namespaces are intentionally narrower than legacy L1 state namespaces: they must be opaque `mem_...` handles owned by the active session, otherwise the facade fails closed.
- Hide markers are implemented as server-owned facade metadata and are not exposed through agent-facing state primitives. The marker binding uses target version plus a content hash derived from the verified read value because the primitive read result does not expose the internal state envelope integrity hash. State export/import carries matching marker records only for exported target namespaces so hidden state remains hidden after round-trip restore.
- Audit search is implemented as a derived own-history view over `AuditLog.query`, with integrity findings returning the fixed denial schema. The explicit Tier-1 widening placeholder is policy-enrolled but no widening tool is exposed in this phase.
- Compound execution implements the ratified fail-closed pre-step reservation behavior for missing, invalid, expired, mismatched, or already-reserved approvals; it does not claim rollback semantics.

## Stop Point

Committed locally only. No push. No merge.
