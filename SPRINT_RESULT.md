# SPRINT RESULT — SEC-016: Stderr Approval Channel Auto-Resolves in 100ms

**Sprint Date:** 2026-03-28
**Finding:** SEC-016 (High)
**Branch:** `security-review`

---

## What Changed and Why

### 1. Removed 100ms setTimeout from StderrApprovalChannel (approval-channel.ts)

**Root cause:** The stderr channel used `await new Promise((resolve) => setTimeout(resolve, 100))` to create a 100ms async delay before returning its denial. This delay served no purpose — the channel has no input mechanism (stdin is consumed by MCP protocol). The delay created a timing window that was a latent risk for future code that might race against the Promise.

**Fix:** Removed the setTimeout entirely. The channel now returns `{ decision: "deny" }` synchronously after writing the informational prompt to stderr. Changed `decided_by` from `"timeout"` to `"stderr:non-interactive"` to distinguish from legitimate timeouts in the webhook/dashboard channels.

### 2. Updated prompt text (approval-channel.ts)

The prompt header changed from "Approval Required" to "Operation Denied (non-interactive channel)" and the footer now reads "Denied: stderr channel cannot accept input (SEC-016)" with guidance to use dashboard or webhook for interactive approval.

### 3. Updated ApprovalResponse type (types.ts)

Added `"stderr:non-interactive"` to the `decided_by` union type.

### 4. Updated SEC-002 regression tests (sec-002-auto-deny-hardcoded.test.ts)

The two StderrApprovalChannel tests now assert `decided_by === "stderr:non-interactive"` instead of `"timeout"`. Test names and comments updated to reflect SEC-016 invariant.

### 5. Updated SEC-001 integration test (sec-001-state-delete-requires-approval.test.ts)

Updated comment and test name to reference SEC-016. Removed the `timeout_seconds: 0.1` hack (no longer needed since there's no timeout).

### 6. New regression test file (sec-016-stderr-always-denies.test.ts)

4 new tests:
- `always denies Tier 1 operations with decided_by stderr:non-interactive`
- `denies immediately with no timing window (< 10ms, not 100ms)`
- `ignores auto_deny: false config (SEC-002 interaction)`
- `denies Tier 2 operations identically`

---

## Test Suite Output

```
Test Files  27 passed (27)
     Tests  265 passed (265)
  Start at  17:43:39
  Duration  19.89s
```

Test count: 261 → 265 (+4 new SEC-016 regression tests)

---

## SEC-002 Interaction Analysis

SEC-002 established the invariant: "timeout on any approval channel ALWAYS results in denial." This sprint strengthens that invariant for the stderr channel specifically:

- **Before SEC-016:** The stderr channel honored SEC-002 by returning `deny` after a 100ms timeout. The timing window existed but the outcome was safe.
- **After SEC-016:** The stderr channel has no timeout at all. It denies synchronously. This is strictly stronger — there is no async gap to exploit, no timeout to race against, no timing window whatsoever.

The webhook and dashboard channels are unchanged — they still use legitimate timeouts (configurable via `timeout_seconds`) because they wait for real human input. Only the stderr channel's fake timeout was removed.

---

## New Risk Introduced

None identified. The behavioral change (deny after 100ms → deny immediately) is strictly more restrictive. No code in the codebase depends on the 100ms delay.

---

## Adjacent Findings Noticed

None. The stderr channel implementation is self-contained. The fix touches only the approval-channel.ts source file, the types.ts type definition, and existing/new test files.

---

## Self-Assessment

All sprint contract criteria are met:

1. ✅ The `setTimeout` / 100ms delay is completely removed
2. ✅ The channel returns deny synchronously with no async gap
3. ✅ `decided_by` is `"stderr:non-interactive"` (not `"timeout"`)
4. ✅ SEC-002 invariant preserved: no config can cause approval
5. ✅ All 4 regression tests pass
6. ✅ Test count 265 ≥ 261 (no decrease, +4 net new)
