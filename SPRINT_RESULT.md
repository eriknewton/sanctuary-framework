# SPRINT_RESULT.md — SEC-011: Gate Default for Unlisted Operations Is Tier 3 (Allow)

**Sprint Date:** 2026-03-28
**Finding:** SEC-011 (reclassified Medium → High)
**Branch:** `security-review`

---

## What Was Changed and Why

### Source Change: `server/src/principal-policy/gate.ts`

**The problem:** The `evaluate()` method's Tier 3 block (lines 72-83) was unconditional. After checking Tier 1 and Tier 2, it fell through to Tier 3 (allow with audit logging) for ALL remaining operations — regardless of whether the operation was in `tier3_always_allow`.

**The fix:** Added a conditional check: `if (this.policy.tier3_always_allow.includes(operation))` before the Tier 3 allow block. Added an else-branch that:

1. Logs an audit entry with `gate_unclassified:{operation}` action, warning that the operation is not classified
2. Routes the operation to `requestApproval()` at Tier 1, requiring human approval
3. Includes `unclassified: true` in the approval context so the human can see why the approval was triggered

The change is ~15 lines of new code replacing what was an unconditional block.

### Test Changes: `server/test/principal-policy/approval-gate.test.ts`

Added 4 new tests under a `"SEC-011 — unlisted operations default to Tier 1"` describe block:

1. **"requires approval for operations not in any tier list"** — Evaluates `totally_new_tool` (not in any tier list), asserts Tier 1 + approval_required
2. **"denies unlisted operations when channel denies"** — Same with a deny channel, asserts `allowed: false`
3. **"logs unclassified operation to audit log"** — Verifies audit entries are created for unclassified operations
4. **"still allows explicitly listed Tier 3 operations"** — Verifies `state_read` (in tier3_always_allow) is unaffected

---

## Full Test Suite Output

```
Test Files  24 passed (24)
     Tests  247 passed (247)
  Start at  15:12:53
  Duration  20.09s
```

**Baseline:** 243 tests
**After fix:** 247 tests (+4 new regression tests)
**Failures:** 0

---

## New Risk Introduced

A tool registered in the MCP server without a corresponding entry in any policy tier will now require Tier 1 human approval instead of auto-allowing. This could cause unexpected approval prompts for developers who add tools without updating `principal-policy.yaml`. This is the **intended safe default** — the audit log entry (`gate_unclassified:{operation}`) makes it easy to diagnose and add the tool to the appropriate tier.

---

## Adjacent Findings Noticed (Do Not Fix)

None. This fix is tightly scoped to the gate evaluation logic and does not interact with any other finding beyond SEC-002 (which is already PASS).

---

## Sprint Contract Criteria Assessment

| Criterion | Met? |
|-----------|------|
| Root cause addressed: gate no longer falls through to Tier 3 for unlisted operations | ✅ |
| Correct default: unlisted operations require Tier 1 approval | ✅ |
| No regression: existing Tier 1/2/3 operations unchanged | ✅ (all 243 existing tests pass) |
| Test coverage: new tests verify unlisted → Tier 1 | ✅ (4 new tests) |
| Audit trail: unclassified operations logged | ✅ (`gate_unclassified` audit entry) |
| Test suite passes: 243+ tests, no decrease | ✅ (247 tests, 0 failures) |

**Honest assessment:** All sprint contract criteria are met. The fix is minimal, targeted, and introduces no new attack surface.
