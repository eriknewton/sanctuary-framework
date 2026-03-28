# SPRINT_CONTRACT.md — SEC-011: Gate Default for Unlisted Operations Is Tier 3 (Allow)

**Sprint Date:** 2026-03-28
**Finding:** SEC-011 (reclassified Medium → High)
**Branch:** `security-review`
**Remediation Plan Reference:** HP-12

---

## Architecture Decision

### a) Root Cause — Not the Symptom

In `server/src/principal-policy/gate.ts:72-83`, the `evaluate()` method has a three-step evaluation:

1. Check if operation is in `tier1_always_approve` → request approval
2. Check if operation triggers a Tier 2 anomaly → request approval
3. **Fall through unconditionally to Tier 3 (allow with audit logging)**

Step 3 is the bug. It does not verify that the operation is actually in the `tier3_always_allow` list. Any operation that is not in `tier1_always_approve` and does not trigger a Tier 2 anomaly is auto-allowed — **even if it appears in no tier list at all**.

This means a newly registered MCP tool that is not classified in any policy tier will silently auto-allow without human approval. This is a bypass vector for the entire approval architecture: the SEC-002 fix hardened timeout behavior, but SEC-011 lets unlisted operations bypass the gate entirely.

### b) Smallest Change That Closes the Vulnerability

Add a conditional check at gate.ts line 72: before the Tier 3 allow block, verify that the operation is in the `tier3_always_allow` list. If the operation is NOT in any tier list, default to **Tier 1 (require approval)** and log an audit entry indicating the operation is unclassified.

This is a ~10-line change to the conditional logic in `evaluate()`.

### c) Interaction with Other Findings

- **SEC-002 (Critical, PASS):** SEC-002 hardened the approval gate so timeouts always deny. SEC-011's fix routes unlisted operations through the same approval gate, so unlisted operations will now be properly denied on timeout. The two fixes are complementary — SEC-002 ensures the gate denies safely, SEC-011 ensures unlisted operations actually reach the gate.
- **No other finding dependencies.**

### d) New Risk Introduced

A tool added to the MCP server without a corresponding entry in the Principal Policy will now require Tier 1 approval instead of auto-allowing. This is a **correct fail-safe** — the disruption (unexpected approval prompt) is vastly preferable to the alternative (unguarded sensitive operation). Developers must update the policy file when adding tools. The audit log entry for unlisted operations makes this easy to diagnose.

---

## Fix Specification

### Exact Fix

In `server/src/principal-policy/gate.ts`, in the `evaluate()` method, replace the unconditional Tier 3 fall-through (lines 72-83) with:

1. Check if the operation is in `this.policy.tier3_always_allow`
2. If YES → current Tier 3 behavior (allow with audit logging)
3. If NO → treat as unlisted/unclassified: default to Tier 1 (request approval), with a reason indicating the operation is not classified in any policy tier

### Files to Modify

| File | Lines | Change |
|------|-------|--------|
| `server/src/principal-policy/gate.ts` | 72-83 | Add `tier3_always_allow.includes(operation)` check; add else-branch for unlisted operations that defaults to Tier 1 |
| `server/test/principal-policy/approval-gate.test.ts` | new tests | Add regression test: unlisted operation defaults to Tier 1 |

### Behavior Before and After

| Scenario | Before | After |
|----------|--------|-------|
| Operation in `tier1_always_approve` | Tier 1 (require approval) | Tier 1 (require approval) — **unchanged** |
| Operation triggers Tier 2 anomaly | Tier 2 (require approval) | Tier 2 (require approval) — **unchanged** |
| Operation in `tier3_always_allow` | Tier 3 (allow) | Tier 3 (allow) — **unchanged** |
| Operation NOT in any tier list | Tier 3 (allow) ← **BUG** | Tier 1 (require approval) ← **FIXED** |

### Regression Test

Tests added to `server/test/principal-policy/approval-gate.test.ts`:

1. **Unlisted operation defaults to Tier 1 (require approval).** Create a policy with explicit tier lists. Evaluate an operation name NOT in any list (e.g., `"totally_new_tool"`). Assert: `result.tier === 1`, `result.approval_required === true`.

2. **Unlisted operation is denied when channel denies.** Same setup with a deny channel. Assert: `result.allowed === false`.

3. **Unlisted operation generates audit log entry.** Verify the audit log records the unclassified operation event.

4. **Existing Tier 3 operations still auto-allow.** Verify that operations in `tier3_always_allow` are unaffected by the change.

### Definition of Done (Evaluator Criteria)

1. **Root cause addressed:** The gate no longer falls through to Tier 3 for operations not in `tier3_always_allow`
2. **Correct default:** Unlisted operations require Tier 1 approval
3. **No regression:** All existing Tier 1, Tier 2, and Tier 3 operations behave identically to before
4. **Test coverage:** New tests specifically verify unlisted operation → Tier 1 default
5. **Audit trail:** Unlisted operations generate an audit log entry indicating the operation is unclassified
6. **Test suite passes:** 243+ tests pass (baseline: 243), no test count decrease

### Prompt Injection Surface

This fix does not touch any input/output path that handles user-controlled text. The operation name is derived from the MCP tool registration (developer-controlled, not agent-controlled). The `extractOperationName()` function strips the `sanctuary/` prefix — this is a static string operation, not a user-input surface. No prompt injection concern.
