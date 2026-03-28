# SPRINT_CONTRACT.md — SEC-002: Flip Approval Gate Default to Deny

**Date:** 2026-03-28
**Finding:** SEC-002 — Webhook Auto-Approve on Timeout Is Configurable and Inverts the Security Model
**Branch:** `security-review`
**Severity:** Critical

---

## FILES TO MODIFY

### Source Files

1. **`server/src/principal-policy/types.ts` line 32** — Remove `auto_deny: boolean` from `ApprovalChannelConfig` interface.
2. **`server/src/principal-policy/loader.ts` line 31** — Remove `auto_deny: true` from `DEFAULT_CHANNEL`. Remove `auto_deny: true` from generated YAML (line 279).
3. **`server/src/principal-policy/loader.ts` lines 194-197** — In `validatePolicy()`, strip any user-supplied `auto_deny` from parsed policy so it cannot override the hardcoded behavior.
4. **`server/src/principal-policy/approval-channel.ts` lines 59-71** — Remove the `if (this.config.auto_deny)` branch. Hardcode timeout resolution to `"deny"`. Update format prompt (lines 98-100) to remove mention of configurable `auto_deny`.
5. **`server/src/principal-policy/webhook.ts` line 45** — Remove `auto_deny: boolean` from `WebhookConfig`. Line 179: hardcode timeout decision to `"deny"`.
6. **`server/src/principal-policy/dashboard.ts` line 38** — Remove `auto_deny: boolean` from `DashboardConfig`. Line 184: hardcode timeout decision to `"deny"`. Lines 332, 377: remove `auto_deny` from SSE init and status responses (or report it as always-true).
7. **`server/src/principal-policy/tools.ts` line 51** — Remove `auto_deny` from policy view response (or report it as hardcoded `true`).
8. **`server/src/index.ts` lines 455, 469** — Remove `auto_deny: policy.approval_channel.auto_deny` from channel constructor calls.

### Test Files

9. **`server/test/principal-policy/webhook.test.ts` line 393** — Remove or rewrite the `auto_deny: false` test. The test at line 403 ("auto-approves on timeout when auto_deny is false") must be replaced with a test asserting that timeout ALWAYS denies.
10. **`server/test/principal-policy/dashboard.test.ts` line 179** — Same: remove `auto_deny: false` test block. Replace with test asserting timeout always denies.
11. **`server/test/principal-policy/policy-loader.test.ts` lines 40, 54, 99, 110** — Tests that parse `auto_deny: false` from YAML/JSON must be updated. The parser should either ignore the field or reject it. Tests must reflect that `auto_deny` is always effectively `true`.
12. **New file: `server/test/security/sec-002-auto-deny-hardcoded.test.ts`** — Regression test (see below).

---

## BEHAVIOR BEFORE THE FIX

When `auto_deny: false` is set in the Principal Policy YAML (or passed programmatically), all three approval channels — stderr, webhook, and dashboard — resolve timed-out approval requests with `decision: "approve"`. This means:

- **Tier 1 operations** (state_export, state_import, identity_rotate, reputation_import) that require human approval are **auto-approved** if the human does not respond within the timeout window.
- **Tier 2 operations** flagged as anomalous are **auto-approved** on timeout.
- An attacker who makes the approval channel unreachable (DoS on webhook endpoint, network partition to dashboard) causes **all gated operations to auto-approve**.
- The stderr channel auto-resolves after 100ms with no human interaction possible — with `auto_deny: false`, every Tier 1 operation silently auto-approves in 100ms.

The vulnerable code paths are:

- `approval-channel.ts:65-70`: `else { return { decision: "approve" ... } }`
- `webhook.ts:179`: `decision: this.config.auto_deny ? "deny" : "approve"`
- `dashboard.ts:184`: `decision: this.config.auto_deny ? "deny" : "approve"`

---

## BEHAVIOR AFTER THE FIX

All three approval channels **always deny on timeout**, regardless of configuration. The `auto_deny` field is removed from the config interfaces and the policy schema. If a user's existing policy YAML contains `auto_deny: false`, the parser silently ignores it (the field has no effect). No configuration option exists to make timeout resolve to "approve."

Specifically:

- `approval-channel.ts`: Timeout always returns `{ decision: "deny", decided_by: "timeout" }`.
- `webhook.ts`: Timeout always returns `{ decision: "deny", decided_by: "timeout" }`.
- `dashboard.ts`: Timeout always returns `{ decision: "deny", decided_by: "timeout" }`.
- `types.ts`: `auto_deny` removed from `ApprovalChannelConfig`.
- `loader.ts`: `auto_deny` removed from defaults, generated YAML, and `validatePolicy` output.
- Policy view tools and dashboard SSE/status endpoints report `auto_deny: true` (hardcoded) or omit the field.

If a deployment genuinely requires auto-approve behavior (which should be extraordinary and dangerous), this sprint does NOT provide that escape hatch. Per the REMEDIATION_PLAN, a future sprint could add a `SANCTUARY_DANGEROUSLY_AUTO_APPROVE=true` environment variable with a startup warning. That is out of scope for this fix.

---

## REGRESSION TEST

**File:** `server/test/security/sec-002-auto-deny-hardcoded.test.ts`

**What input triggers the vulnerable path:**
Constructing each of the three channel types (StderrApprovalChannel, WebhookApprovalChannel, DashboardApprovalChannel) and submitting a Tier 1 approval request with a short timeout. Before the fix, if `auto_deny: false` was passed, the timeout would resolve to "approve."

**What the test asserts (post-fix):**

1. StderrApprovalChannel always returns `decision: "deny"` on timeout — no `auto_deny` config option exists.
2. WebhookApprovalChannel always returns `decision: "deny"` on timeout — no `auto_deny` config option exists.
3. DashboardApprovalChannel always returns `decision: "deny"` on timeout — no `auto_deny` config option exists.
4. `parsePolicy()` with `auto_deny: false` in input produces a policy where timeout behavior is still deny (the field is ignored/stripped).
5. The `DEFAULT_POLICY` does not contain an `auto_deny` field (or if it does for backward compat, it is always `true`).

---

## CALLERS THAT RELY ON CURRENT PERMISSIVE DEFAULT

### Test code (will be updated in this sprint):

- `webhook.test.ts` line 393: Creates a WebhookApprovalChannel with `auto_deny: false` and asserts `decision: "approve"` on timeout. **This test will be removed and replaced.**
- `dashboard.test.ts` line 179: Same pattern. **Will be removed and replaced.**
- `policy-loader.test.ts` lines 40, 54, 99, 110: Parse policies with `auto_deny: false` and assert it is preserved. **Will be updated to assert the field is ignored.**

### Production code:

- `index.ts` lines 455, 469: Pass `policy.approval_channel.auto_deny` to channel constructors. Since the default is `true`, this already produces deny behavior in default deployments. After the fix, this line is removed because the config interfaces no longer accept `auto_deny`.
- `tools.ts` line 51: Reports `auto_deny` in the policy view. Will be updated to report hardcoded `true` or omit.
- `dashboard.ts` lines 332, 377: Reports `auto_deny` in SSE init and status API. Will be updated similarly.

### No production caller relies on `auto_deny: false` for correct operation.

The default policy has always been `auto_deny: true`. The `false` option existed as a configurable escape hatch. No internal code path sets it to `false` — it could only be set by a user editing their policy YAML. Removing the option does not break any default deployment.

---

## PROMPT INJECTION SURFACE

This fix touches the approval gate — a security-critical path that processes the `operation` name and `context` object from tool calls. The fix does NOT change what data flows through the gate; it only changes the timeout resolution. The `operation` and `context` fields in `ApprovalRequest` are populated by `router.ts` from the MCP tool call, which is agent-controlled input.

However, this fix does not introduce any new agent input processing. The change is strictly: remove a conditional branch (`auto_deny ? "deny" : "approve"`) and replace it with an unconditional `"deny"`. No new string parsing, no new data flow, no new trust boundary crossed.

**Assessment: This fix does not expand the prompt injection surface.**

---

## DEFINITION OF DONE

The evaluator will grade this sprint PASS if and only if ALL of the following hold:

1. **No channel can auto-approve on timeout.** Constructing any approval channel (stderr, webhook, dashboard) and letting a request time out MUST produce `decision: "deny"`. There must be no configuration option, environment variable, or code path that produces `decision: "approve"` on timeout.

2. **The `auto_deny` config option is inert or removed.** Parsing a policy YAML/JSON with `auto_deny: false` must NOT cause any channel to auto-approve. The field is either stripped by the parser or the config interfaces no longer accept it.

3. **Regression test exists and passes.** `server/test/security/sec-002-auto-deny-hardcoded.test.ts` contains tests for all three channels and the policy parser, asserting deny-on-timeout is unconditional.

4. **Full test suite passes.** 227 tests were passing before this sprint. After the fix, the count must be >= 227 (may increase due to new regression tests). Zero failures.

5. **No silent caller breakage.** Every caller of `auto_deny` in source and test files has been audited and updated. No test passes by accident due to the field being silently ignored.

6. **Backward compatibility for existing policy files.** A policy YAML containing `auto_deny: false` does not cause a parse error or crash. The field is silently ignored (safe default wins).
