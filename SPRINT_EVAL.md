# SPRINT_EVAL.md — SEC-002: Independent QA Evaluation

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-002 — Webhook Auto-Approve on Timeout Is Configurable and Inverts the Security Model
**Commit:** `7f68d5a`
**Branch:** `security-review`

---

## 1. ROOT CAUSE

**Question:** Does the fix address the root cause — the default behavior when no decision is reached — or does it only patch one channel while leaving others open?

**Verdict: PASS.**

I traced all three approval channels in the post-fix source code:

**StderrApprovalChannel** (`approval-channel.ts:59-65`): After the 100ms pause, the function unconditionally returns `{ decision: "deny", decided_by: "timeout" }`. There is no conditional branch. The `config.auto_deny` field is never read. The old `if (this.config.auto_deny) / else` branch is gone — replaced by a straight-line return.

**WebhookApprovalChannel** (`webhook.ts:176-184`): The `setTimeout` callback unconditionally sets `decision: "deny"`. The old ternary `this.config.auto_deny ? "deny" : "approve"` is replaced with a hardcoded `"deny"`. The `WebhookConfig` interface retains `auto_deny?: boolean` as optional but no code reads it.

**DashboardApprovalChannel** (`dashboard.ts:182-195`): Same pattern — the `setTimeout` callback unconditionally sets `decision: "deny"`. The old ternary is gone. The `DashboardConfig` interface retains `auto_deny?: boolean` as optional but no code reads it.

All three channels are fixed. No channel retains a code path that can return `"approve"` on timeout.

**Additional channels noted:** `CallbackApprovalChannel` (programmatic callback, lines 102-114) and `AutoApproveChannel` (test-only, lines 119-127) exist but are not reachable from the policy-driven server startup path (`index.ts:443-475` only instantiates Stderr, Dashboard, or Webhook based on config). The SPRINT_RESULT correctly discloses these as out-of-scope. They do not undermine the fix for policy-configured deployments.

---

## 2. REGRESSION TEST

**File:** `server/test/security/sec-002-auto-deny-hardcoded.test.ts` (215 lines, 9 tests)

**Verdict: PASS.**

The test covers the specific failure mode:

- Tests 1-2 (Stderr): Construct `StderrApprovalChannel` with default config, and with `auto_deny: false` explicitly. Both assert `decision: "deny"` and `decided_by: "timeout"`. Test 2 would have returned `"approve"` against the pre-fix code (the old `else` branch).
- Tests 3-4 (Webhook): Construct `WebhookApprovalChannel` with `auto_deny: false` and without the field. Use a silent mock receiver that never responds, forcing timeout. Both assert `decision: "deny"`. Test 3 would have returned `"approve"` against the pre-fix code (the old ternary).
- Tests 5-6 (Dashboard): Same pattern — construct with `auto_deny: false` and without. Both assert `decision: "deny"`. Test 5 would have returned `"approve"` against the pre-fix code.
- Tests 7-9 (Policy parser): Verify `parsePolicy()` strips `auto_deny: false` from YAML and JSON inputs, and that `DEFAULT_POLICY` does not set `auto_deny`.

**Would these tests fail against pre-fix code?** Yes. Tests 2, 3, and 5 explicitly pass `auto_deny: false` to the channel constructors. Before the fix, the timeout handlers contained `this.config.auto_deny ? "deny" : "approve"` — with `auto_deny: false`, the result would be `"approve"`, failing the `expect(response.decision).toBe("deny")` assertion. Tests 7-8 would also fail because `validatePolicy()` did not strip `auto_deny` before the fix.

**Test suite run (independent):**

```
 Test Files  23 passed (23)
      Tests  236 passed (236)
   Duration  20.11s
```

236 tests = 227 original + 9 new. Zero failures. Confirmed independently.

---

## 3. NEW RISK

### 3a. Silent stripping does not cause YAML parse failure

**Verdict: PASS.**

The `validatePolicy()` function in `loader.ts:195-204` merges user-supplied `approval_channel` with defaults, then executes `delete merged.auto_deny`. This runs after successful parsing — it does not interfere with the YAML or JSON parsing step. A policy file containing `auto_deny: false` parses normally; the field is removed after parsing. Regression tests 7-8 confirm this by parsing YAML and JSON containing `auto_deny: false` without errors.

### 3b. No other code path re-introduces permissive timeout

**Verdict: PASS with observation.**

Full codebase search for `auto_deny` in `server/src/` found:

| File | Lines | Nature |
|------|-------|--------|
| `types.ts:33-38` | Interface field declaration (`auto_deny?: boolean`) | Optional, never read |
| `webhook.ts:44-45` | Interface field declaration (`auto_deny?: boolean`) | Optional, never read |
| `dashboard.ts:38-39` | Interface field declaration (`auto_deny?: boolean`) | Optional, never read |
| `loader.ts:31,200-202` | Comment + `delete merged.auto_deny` | Active stripping |
| `tools.ts:51` | Reports `auto_deny: true` hardcoded | Cosmetic |
| `dashboard.ts:334,379` | Reports `auto_deny: true` hardcoded | Cosmetic |
| `index.ts:455,469` | Comments documenting removal | No code effect |
| `approval-channel.ts:35` | Stale comment in docstring | See observation below |

No remaining code path reads `auto_deny` from config to make a branching decision. The field is inert across the entire codebase.

Search for `"approve"` near `timeout` patterns in `server/src/` found only the `AutoApproveChannel` (test-only class) and the callback handler's HMAC-verified approval path (legitimate human-initiated approve via webhook callback or dashboard POST). Neither represents a timeout auto-approve path.

**Observation (non-blocking):** Two stale comments remain:
- `webhook.ts:12`: "Timeout fallback: auto-deny (or auto-approve) if no callback received" — the "(or auto-approve)" is no longer accurate.
- `dashboard.ts:12`: "Timeout fallback: auto-deny (or auto-approve) if no response" — same.
- `approval-channel.ts:35`: "For MVS, the channel auto-resolves based on the auto_deny setting" — no longer true; it always denies.

These are comment-only issues, not code defects. They should be cleaned up in a follow-up but do not affect security behavior.

---

## 4. SCOPE

**Verdict: PASS.**

The sprint contract committed to modifying 7 source files and 4 existing test files, plus writing 1 new regression test file. The commit `7f68d5a` changes exactly:

**Source files (7):**
1. `server/src/principal-policy/types.ts`
2. `server/src/principal-policy/approval-channel.ts`
3. `server/src/principal-policy/webhook.ts`
4. `server/src/principal-policy/dashboard.ts`
5. `server/src/principal-policy/loader.ts`
6. `server/src/principal-policy/tools.ts`
7. `server/src/index.ts`

**Test files (3 modified + 1 new):**
8. `server/test/principal-policy/webhook.test.ts`
9. `server/test/principal-policy/dashboard.test.ts`
10. `server/test/principal-policy/policy-loader.test.ts`
11. `server/test/security/sec-002-auto-deny-hardcoded.test.ts` (new)

**Review artifacts (2):**
12. `SPRINT_CONTRACT.md`
13. `SPRINT_RESULT.md`

Total: 13 files. This matches the `git show --stat` output exactly. No files were changed outside the sprint contract scope.

Note: The sprint contract listed 4 existing test files to modify (items 9-11 plus item 12 for the new file), but `approval-gate.test.ts` was not modified — it was listed in the contract numbering but ultimately did not need changes (its tests already pass `auto_deny: true`). This is acceptable; modifying fewer files than planned is safe.

---

## 5. PROMPT INJECTION SURFACE

**Verdict: PASS.**

The sprint contract states: "This fix does not expand the prompt injection surface." I verified this independently.

The `ApprovalGate.evaluate()` method in `gate.ts:49-52` receives `toolName` (string) and `args` (Record<string, unknown>) from the MCP router, which are agent-controlled. These flow into the `ApprovalRequest` as `operation` and `context` (via `summarizeArgs`). The approval channels receive this `ApprovalRequest` and use it for display/logging purposes only.

The SEC-002 fix changes only what happens when the timeout fires. It removes a conditional branch (`auto_deny ? "deny" : "approve"`) and replaces it with unconditional `"deny"`. No new data parsing, no new fields read from the request, no new trust boundary crossed. The agent-controlled content (`operation`, `context`) was already flowing through these channels before the fix and continues to flow through them after — but the fix does not introduce any new processing of that content.

The `CallbackApprovalChannel` and `AutoApproveChannel` classes are pre-existing and unchanged by this commit. They are not policy-reachable.

---

## GRADE: PASS

All five evaluation criteria are satisfied:

1. **Root cause addressed:** All three user-facing channels unconditionally deny on timeout.
2. **Regression test valid:** 9 tests, all covering the specific pre-fix failure mode, all passing. Tests would genuinely fail against pre-fix code.
3. **No re-introduction risk:** `auto_deny` field is inert across the entire codebase. Parser strips it. No code reads it.
4. **Scope matched:** 13 files changed, all within sprint contract scope.
5. **No new injection surface:** Fix removes a branch, adds no new data flow.

**Non-blocking observations for follow-up cleanup:**
- Three stale comments referencing "(or auto-approve)" behavior in `webhook.ts:12`, `dashboard.ts:12`, and `approval-channel.ts:35`.
- `auto_deny` field retained as optional in three TypeScript interfaces (`types.ts`, `webhook.ts`, `dashboard.ts`). Fully removing the field would reduce confusion but is cosmetic.
- `AutoApproveChannel` exists as an exported class for testing. Not reachable from policy config, but its existence could confuse future reviewers.
