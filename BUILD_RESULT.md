# Agent-Native Cooperative Surface Phase 1 Build Result

Date: 2026-06-08

## Scope Implemented

Phase 1 safety base only.

### Step 1: Approval/Denial Safety Base

- Added `server/src/agent-native/safety-base.ts` with:
  - fixed coarse denial schema `{ denied, message, remediation_class, retry_after, audit_ref }`
  - canonical JSON and `sha256:<hex>` normalized-args hashing
  - `CanonicalApprovalEnvelope`
  - in-memory single-use `ApprovalProofStore`
  - active session identity binding helpers
  - side-effect-free `classifyApprovalRequest(...)`
  - opaque namespace registry primitives used by Step 2
- Extended `ApprovalGate.evaluate(toolName, args, approval?)`.
  - Existing no-proof Tier 1 behavior still requests approval through the configured approval channel.
  - Proof mode rebuilds the canonical envelope from the actual primitive tool name, validated primitive args, active session requester fingerprint, target resource, risk tier, and stored expiry/nonce/audit ID.
  - Proof mode verifies envelope hash, approved decision, expiry, requester, nonce, target, and tool.
  - Proof mode atomically consumes the record before returning allowed.
  - Proof mismatch and replay deny without prompting.
- Factored tier classification into a shared `classifyRiskTier(...)` path used by both live gate evaluation and preflight classification.
- Updated `router.ts` denial behavior to return the fixed coarse denial payload. `approval_ref` is treated as approval metadata and stripped before primitive handler execution, so it is not included in primitive args or handler behavior.

### Step 2: Session Identity and Opaque Namespace Ownership

- Added explicit session identity binding support via `SessionBinding`.
- Wired server startup to expose an active binding only when `SANCTUARY_SESSION_IDENTITY_ID` is set; absent binding remains fail-closed for agent-native proof/opaque-handle paths.
- Added `OpaqueNamespaceRegistry`.
  - Opaque memory handles are non-guessable `mem_<random>` handles.
  - Handles map server-side to an identity ID.
  - The raw identity fingerprint is not used as a namespace handle.
- Enforced opaque memory-handle ownership below the facade in primitive state handlers:
  - `state_write`
  - `state_read`
  - `state_list`
  - `state_delete`
  - scoped `state_export`
- Made absent/unowned opaque namespace read denials share the same fixed message, remediation class, and coarse retry behavior.

## Tests Added

Added `server/test/agent-native/phase1-safety-base.test.ts`.

Coverage includes:

- approval proof mismatch denial
- atomic single-use approval proof reuse denial
- no approval prompt on proof mismatch/replay
- non-executing preflight classification
- preflight does not call the approval channel
- primitive-level opaque handle isolation
- replayed/guessed handle failure through primitive state tools
- unbound session failure for opaque handles
- indistinguishable absent/unowned denial fields
- coarse `retry_after` values

## Gates

- `cd server && npm run typecheck`: passed.
- `cd server && npm test`: passed.
  - Test result: 5,460 passed, 8 skipped.
  - `.test-baseline`: 5,423.
  - No transform or collection errors.

Note: the first focused Vitest run hit sandbox `EPERM` writing Vite temp config under `server/node_modules/.vite-temp`; reruns used the approved test execution path. One full-suite run exposed a misplaced namespace check inside `identity_sign`; that was fixed, the affected tests passed, and the final full suite passed cleanly.

## Semantic Interpretations

- Phase 1 implements the non-executing preflight as an exported server-side classifier, not yet as a new agent-facing `sanctuary_request_approval` tool. This keeps the build inside the requested safety-base scope and avoids shipping catalog/help/facade surface before the coordinator-owned later phases.
- The approval proof store is in-memory for Phase 1. The canonical record shape and atomic consume interface are in place for a later persistent approval-record table or signed-token backend.
- Opaque namespace mapping is in-memory for Phase 1. The primitive/gate-layer ownership enforcement point is established; a later encrypted persistence table can back the same interface.
- Existing ordinary namespaces keep their legacy behavior. The new fail-closed active-session requirement applies to opaque agent-memory handles and approval-proof verification, which are the new agent-native safety surfaces.

## Explicitly Not Built

Per Phase 1 scope, this build did not implement:

- `sanctuary_remember`
- `sanctuary_recall`
- `sanctuary_hide`
- `sanctuary_forget`
- `sanctuary_help`
- `sanctuary_who_am_i`
- `sanctuary_active_protections`
- pull event cursors
- audit semantic search
- compound operation plans or plan-level approval reservation
- hide-marker lifecycle
