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

---
---

# SPRINT_EVAL.md — SEC-001: Independent QA Evaluation

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-001 — Secure Deletion Is Tier 3 (Auto-Allow): Agent Can Irreversibly Destroy All User State Without Confirmation
**Commit:** `4f2274a`
**Branch:** `security-review`

---

## 1. ROOT CAUSE

**Question:** Does the fix address the root cause — the tier classification of `state_delete` — or does it patch a symptom (e.g., adding a guard inside the handler)?

**Verdict: PASS.**

The root cause was that `state_delete` appeared in `DEFAULT_POLICY.tier3_always_allow` (loader.ts, formerly line 50), which caused `ApprovalGate.evaluate()` to reach the Tier 3 fallthrough at gate.ts:72-83 and auto-allow the operation with only audit logging.

The fix moves `state_delete` from `tier3_always_allow` to `tier1_always_approve` in two places within loader.ts:

1. **The `DEFAULT_POLICY` constant (lines 38-45, 47-84):** `"state_delete"` is now at line 41 inside `tier1_always_approve`. It is absent from `tier3_always_allow`. I verified by reading lines 35-84 of the post-fix loader.ts.
2. **The `generateDefaultPolicyYaml()` output (lines 222-244):** The YAML string template mirrors the constant — `state_delete` appears under `tier1_always_approve:` and is absent from `tier3_always_allow:`.

I independently traced the gate evaluation path in gate.ts:58-64: `this.policy.tier1_always_approve.includes(operation)` is checked at line 59 before any Tier 2 or Tier 3 logic. With `state_delete` in the Tier 1 array, it hits line 60 and calls `this.requestApproval(operation, 1, ...)`, which routes through the configured approval channel. The handler never executes unless the channel returns `decision: "approve"`.

This is a root-cause fix. The tier classification — the actual source of the vulnerability — was changed. No symptom-level workaround was used.

---

## 2. REGRESSION TEST

**File:** `server/test/security/sec-001-state-delete-requires-approval.test.ts` (158 lines, 7 tests)

**Verdict: PASS.**

I read every test in the file and independently ran both the full test suite and the SEC-001 tests in isolation.

**Full test suite run (independent):**

```
 Test Files  24 passed (24)
      Tests  243 passed (243)
   Duration  19.83s
```

243 = 236 pre-sprint + 7 new SEC-001 tests. Zero failures.

**SEC-001 tests in isolation:**

```
 Test Files  1 passed (1)
      Tests  7 passed (7)
   Duration  279ms
```

**Analysis of whether each test would fail against pre-fix code:**

- **Test 1** (`DEFAULT_POLICY includes state_delete in tier1_always_approve`): Pre-fix, `state_delete` was NOT in `tier1_always_approve`. `expect(...).toContain("state_delete")` would fail. **Would fail against pre-fix: YES.**

- **Test 2** (`DEFAULT_POLICY does NOT include state_delete in tier3_always_allow`): Pre-fix, `state_delete` WAS in `tier3_always_allow`. `expect(...).not.toContain("state_delete")` would fail. **Would fail against pre-fix: YES.**

- **Test 3** (gate classifies as Tier 1, denies on channel denial): Pre-fix, the gate would classify `state_delete` as Tier 3 (auto-allow). `expect(result.tier).toBe(1)` would fail (result.tier would be 3). `expect(result.approval_required).toBe(true)` would fail (Tier 3 sets `approval_required: false`). The `CallbackApprovalChannel` would never be invoked. **Would fail against pre-fix: YES.**

- **Test 4** (gate allows when human approves): Pre-fix, `result.tier` would be 3, not 1. **Would fail against pre-fix: YES.**

- **Test 5** (gate denies on stderr timeout — SEC-002 integration): This is the critical SEC-002 interaction test. It constructs a `StderrApprovalChannel` with `timeout_seconds: 0.1` and calls `gate.evaluate("sanctuary/state_delete", ...)`. Pre-fix, the gate would classify `state_delete` as Tier 3 and never invoke the channel, returning `allowed: true`. The assertion `expect(result.allowed).toBe(false)` would fail. **Would fail against pre-fix: YES.** Post-SEC-002, the `StderrApprovalChannel` unconditionally returns `decision: "deny"` on timeout (lines 59-65 of approval-channel.ts, hardcoded — no `auto_deny` check). This test confirms that the SEC-001 + SEC-002 combination produces the correct denied result.

- **Test 6** (generated YAML places state_delete in tier1): Parses `DEFAULT_POLICY` through `parsePolicy()` and verifies the round-tripped result. Pre-fix, `tier1_always_approve` would not contain `state_delete`. **Would fail against pre-fix: YES.**

- **Test 7** (tier1 wins when state_delete appears in both tier1 and tier3): Tests gate evaluation order — constructs a custom policy with `state_delete` in both tiers. Asserts `result.tier === 1`. This test would actually pass against pre-fix code IF you manually added `state_delete` to tier1 in the custom policy — but it tests the gate's evaluation order correctness, not the DEFAULT_POLICY contents. It's a defensive test for the scenario where a user has a stale policy file. **Edge case coverage test, not a pre-fix regression test.** Acceptable.

**Specific verification of Test 5 and SEC-002 interaction:** I confirmed by reading approval-channel.ts:59-64 that `StderrApprovalChannel.requestApproval()` unconditionally returns `{ decision: "deny", decided_by: "timeout" }` after the 100ms pause. There is no `auto_deny` conditional. The SEC-002 hardening is intact and Test 5 exercises it end-to-end through the gate for `state_delete` specifically.

---

## 3. NEW RISK

### 3a. Other irreversible operations remaining in tier3_always_allow

**Verdict: PASS.**

I reviewed every operation in the post-fix `tier3_always_allow` array (loader.ts lines 47-84):

`state_read`, `state_write`, `state_list` — read/write/enumerate operations. `state_write` overwrites existing values but is not a destructive delete; the old value is replaced but the operation is a normal data mutation, not a 3-pass secure wipe. Reversible by writing again.

`identity_create`, `identity_list`, `identity_sign`, `identity_verify` — create and query operations. Not destructive.

`proof_commitment`, `proof_reveal` — cryptographic proof operations. Create commitments or reveal values. Not destructive.

`disclosure_set_policy`, `disclosure_evaluate` — policy setting and evaluation. Overwritable, not irreversible.

`reputation_record`, `reputation_query`, `reputation_export` — create/query/export reputation data. `reputation_export` is a read operation that exports a bundle; it does not delete or modify anything.

`bootstrap_create_escrow` — creates an escrow record. Not destructive.

`exec_attest`, `monitor_health`, `monitor_audit_log`, `manifest`, `principal_policy_view`, `principal_baseline_view` — monitoring and attestation. Read-only or additive.

`shr_generate`, `shr_verify`, `handshake_initiate`, `handshake_respond`, `handshake_complete`, `handshake_status` — sovereignty handshake protocol. Session-based, not destructive.

`reputation_query_weighted`, `federation_peers`, `federation_trust_evaluate`, `federation_status` — query/status operations.

`zk_commit`, `zk_prove`, `zk_verify`, `zk_range_prove`, `zk_range_verify` — zero-knowledge proof operations. Create proofs, do not destroy data.

**No irreversible destruction operations remain in `tier3_always_allow`.** The only operations that perform irreversible destruction are `state_delete` (now Tier 1) and potentially `identity_rotate` (which is already Tier 1 — it replaces the identity key, which is irreversible in the sense that the old key is gone). `state_export` and `state_import` are already Tier 1. `bootstrap_provide_guarantee` is already Tier 1.

### 3b. Callers that assumed state_delete was auto-allowed

**Verdict: PASS.**

The `state_delete` handler in `tools.ts:537-572` does not interact with the gate directly — the gate wrapping is in the MCP router (router.ts), which intercepts all tool calls before they reach handlers. The handler has no awareness of its tier classification.

No production code calls `state_delete` programmatically — it is only invoked by external MCP tool calls from agent harnesses, which must go through the router and therefore through the gate.

The only test code that needed adjustment was `createTestPolicy()` in `approval-gate.test.ts`, which was updated. I verified the diff: `state_delete` was removed from `tier3_always_allow` and added to `tier1_always_approve` in the test helper (lines 27 and 37 of the diff). All existing tests in that file continue to pass — none specifically tested `state_delete` as a Tier 3 operation.

---

## 4. SCOPE

**Verdict: PASS.**

The sprint contract committed to modifying exactly these files:

1. `server/src/principal-policy/loader.ts` (source change)
2. `server/test/principal-policy/approval-gate.test.ts` (test helper update)
3. `server/test/security/sec-001-state-delete-requires-approval.test.ts` (new file)

Plus the review artifacts: `SPRINT_CONTRACT.md` and `SPRINT_RESULT.md`.

The commit `4f2274a` (`git show --stat`) touches exactly 5 files:

```
SPRINT_CONTRACT.md                                  | 125
SPRINT_RESULT.md                                    | 118
server/src/principal-policy/loader.ts               |   4
server/test/principal-policy/approval-gate.test.ts  |   4
server/test/security/sec-001-...test.ts             | 158
```

This matches the contract exactly. Three code files + two review artifacts. No out-of-scope files were touched. The `loader.ts` diff is +2/-2 lines (add to tier1 array, remove from tier3 array, in both the constant and the YAML template). The `approval-gate.test.ts` diff is +2/-2 lines (same move in the test helper). Minimal, surgical changes.

---

## 5. SEC-002 INTERACTION

**Verdict: PASS.**

Test 5 (`gate denies state_delete on stderr channel timeout (SEC-002 integration)`) at lines 93-110 of the regression test file:

1. Constructs a `StderrApprovalChannel` with `timeout_seconds: 0.1`.
2. Constructs an `ApprovalGate` with `DEFAULT_POLICY` (which now has `state_delete` in Tier 1).
3. Calls `gate.evaluate("sanctuary/state_delete", ...)`.
4. Asserts `result.allowed === false`, `result.approval_required === true`, `result.tier === 1`.

I independently verified that `StderrApprovalChannel.requestApproval()` (approval-channel.ts:45-66) unconditionally returns `{ decision: "deny", decided_by: "timeout" }` after the 100ms pause. Lines 59-60 contain the SEC-002 comment: "SEC-002: Timeout ALWAYS denies. No configuration can change this." The return on lines 61-65 is unconditional — no branch, no config read.

The test exercises the full chain: gate receives `state_delete` -> matches Tier 1 -> calls `requestApproval` on the stderr channel -> channel times out and returns deny -> gate returns `allowed: false`. This confirms that the SEC-001 reclassification + SEC-002 hardened timeout work together correctly.

This test explicitly tests the **post-SEC-002 hardened gate behavior**, not the pre-fix permissive behavior. There is no `auto_deny` configuration in the test. The channel simply denies unconditionally on timeout, which is exactly the SEC-002 invariant.

---

## GRADE: PASS

All five evaluation criteria are satisfied:

1. **Root cause addressed:** `state_delete` moved from `tier3_always_allow` to `tier1_always_approve` in both the `DEFAULT_POLICY` constant and the generated default YAML. The tier classification — the actual vulnerability — is fixed.
2. **Regression test valid:** 7 tests, all covering the specific failure mode. Tests 1-6 would genuinely fail against pre-fix code. Test 7 is a defensive edge-case test. All 7 pass. Full suite: 243/243 pass.
3. **No new risk:** No irreversible operations remain in `tier3_always_allow`. No callers assumed `state_delete` was auto-allowed.
4. **Scope matched:** 5 files changed, exactly matching the sprint contract — 3 code files + 2 review artifacts.
5. **SEC-002 interaction confirmed:** Test 5 exercises the full Tier 1 -> stderr timeout -> deny chain with the post-SEC-002 hardened channel.

**Non-blocking observations for follow-up:**

- `reputation_export` is in Tier 3. It is a read-only export and does not destroy data, so Tier 3 is defensible. However, `state_export` (also a read-only export) is Tier 1. This asymmetry may deserve review — if the concern is data exfiltration rather than destruction, both exports should arguably be at the same tier. This is outside the scope of SEC-001 but worth noting.
- The SPRINT_RESULT correctly identifies that existing policy YAML files from pre-fix deployments will still have `state_delete` in Tier 3. Users must manually update or regenerate their policy file. There is no migration mechanism. This is acceptable for a security fix but should be documented in release notes.
- SEC-011 (unlisted operations default to Tier 3) remains open and is the inverse of SEC-001. The safe default should be deny, not allow.

---
---

# SPRINT_EVAL.md — SEC-011: Independent QA Evaluation

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-011 — Sanctuary Gate Default for Unlisted Operations Is Tier 3 (Allow)
**Commit:** `4a72000`
**Branch:** `security-review`

---

## 1. ROOT CAUSE

**Question:** Does the fix address the root cause — the missing tier membership check that allows unlisted operations to fall through to Tier 3 auto-allow — or does it patch a symptom?

**Verdict: PASS.**

I read `gate.ts` and traced the execution path for an operation that exists in no tier list (e.g., `totally_new_tool`).

**Pre-fix code** (from `git diff 4a72000^..4a72000`): After Tier 1 (line 59) and Tier 2 (line 68) checks, the code fell through unconditionally to a Tier 3 block that called `this.auditLog.append("l2", "gate_allow:${operation}", ...)` and returned `{ allowed: true, tier: 3, approval_required: false }`. There was no `if (this.policy.tier3_always_allow.includes(operation))` guard. Any operation not matched by Tier 1 or Tier 2 was auto-allowed.

**Post-fix code** (gate.ts:72-101): The evaluation now has four explicit branches:

1. **Line 59:** `if (this.policy.tier1_always_approve.includes(operation))` → Tier 1 approval. Unchanged.
2. **Line 67-70:** Tier 2 anomaly detection → approval. Unchanged.
3. **Line 73:** `if (this.policy.tier3_always_allow.includes(operation))` → Tier 3 allow with audit log. **New guard added.**
4. **Lines 87-101:** Else branch — unlisted/unclassified → audit log `gate_unclassified:{operation}`, then `requestApproval(operation, 1, ...)` routing to **Tier 1**.

I confirmed the `includes()` check at line 73 uses `Array.prototype.includes()`, which performs strict equality (`===`) comparison. An operation name like `totally_new_tool` that does not appear in the `tier3_always_allow` array will fail this check and fall through to the else branch at line 87.

The else branch at line 96 calls `this.requestApproval(operation, 1, ...)` — the second argument `1` is the tier parameter (typed as `1 | 2` per the method signature at line 231). This routes to the configured approval channel at Tier 1.

**This is a root-cause fix.** The vulnerability was the missing membership check; the fix adds the membership check. No symptom-level workaround.

---

## 2. AUDIT LOG

**Question:** Is the `gate_unclassified` log entry written before the Tier 1 routing — not after, not conditionally? Can an attacker suppress it by manipulating the operation name?

**Verdict: PASS.**

Lines 90-94 of gate.ts:

```typescript
this.auditLog.append("l2", `gate_unclassified:${operation}`, "system", {
  tier: 1,
  operation,
  warning: "Operation is not classified in any policy tier — defaulting to Tier 1 (require approval)",
});
```

Lines 96-101:

```typescript
return this.requestApproval(
  operation,
  1,
  `"${operation}" is not classified in any policy tier — requires approval (SEC-011 safe default)`,
  { operation, unclassified: true }
);
```

The `auditLog.append()` call at line 90 executes **before** the `requestApproval()` call at line 96. There is no conditional between them — no `if`, no `try/catch` that could skip the log, no early return. The audit entry is written unconditionally for every unclassified operation before the approval request is dispatched.

**Can an attacker suppress the log by manipulating the operation name?** The operation name is derived from `extractOperationName(toolName)` at line 53 (called at the top of `evaluate()`). I read `loader.ts:92-96`: `extractOperationName` strips the `sanctuary/` prefix via `toolName.slice("sanctuary/".length)` or returns the raw `toolName`. This is a deterministic string operation. The operation name flows from the MCP router's tool registration — it is developer-controlled at registration time, not agent-controlled at call time. An agent calls `sanctuary/foo`; the operation name becomes `foo`. There is no path for the agent to inject a different operation name that would skip the audit log.

**Edge case:** If the operation name contained special characters or was extremely long, the audit log would still be written — `auditLog.append()` takes the string as-is. There is no validation that could reject it before logging. The log entry is unconditional.

---

## 3. REGRESSION TESTS

**Question:** Are 4 new tests present? Does at least one explicitly test an unlisted operation → Tier 1? Would these tests fail against the pre-fix code?

**Verdict: PASS.**

Four tests exist in the `"SEC-011 — unlisted operations default to Tier 1"` describe block (lines 224-295 of `approval-gate.test.ts`):

**Test 1** (line 225): `"requires approval for operations not in any tier list"` — Evaluates `sanctuary/totally_new_tool` with a non-first-session baseline. Asserts `result.tier === 1` and `result.approval_required === true`. **Pre-fix:** `totally_new_tool` would fall through to the unconditional Tier 3 block, returning `tier: 3, approval_required: false`. Both assertions would fail. **Would fail against pre-fix: YES.**

**Test 2** (line 243): `"denies unlisted operations when channel denies"` — Same operation with a `CallbackApprovalChannel` that returns `decision: "deny"`. Asserts `result.tier === 1`, `result.approval_required === true`, `result.allowed === false`. **Pre-fix:** The operation would auto-allow at Tier 3 without ever reaching the channel. `result.allowed` would be `true`, `result.tier` would be `3`. All three assertions would fail. **Would fail against pre-fix: YES.**

**Test 3** (line 264): `"logs unclassified operation to audit log"` — Evaluates `sanctuary/unregistered_dangerous_op`. Asserts `auditLog.size >= 2` (one for the `gate_unclassified` entry, one for the `gate_approve` from `requestApproval`). **Pre-fix:** The operation would hit the Tier 3 block, which writes only one audit entry (`gate_allow`). There would be no `gate_unclassified` entry. The audit log would have size 1, failing the `>= 2` assertion. **Would fail against pre-fix: YES** (marginal — depends on baseline audit entries, but the pre-fix Tier 3 block writes exactly 1 entry vs. the post-fix unclassified path which writes 2).

**Test 4** (line 279): `"still allows explicitly listed Tier 3 operations"` — Evaluates `sanctuary/state_read` (in `tier3_always_allow`). Asserts `result.tier === 3`, `result.allowed === true`, `result.approval_required === false`. **Pre-fix:** This test would PASS against pre-fix code too — `state_read` was always in `tier3_always_allow`. This is a non-regression test, confirming the fix doesn't break existing Tier 3 behavior. **Would fail against pre-fix: NO (this is intentional — it's a stability test).**

**Summary:** 3 of 4 tests would genuinely fail against pre-fix code. Test 4 is a stability/non-regression test. This is adequate coverage.

---

## 4. SEC-002 INTERACTION

**Question:** Does an unclassified operation that times out result in denial, not approval?

**Verdict: PASS.**

The unclassified operation path (gate.ts:96-101) calls `this.requestApproval(operation, 1, ...)`. The `requestApproval` method (gate.ts:229-261) delegates to `this.channel.requestApproval(request)` at line 243.

I verified all three production channels:

- **StderrApprovalChannel** (approval-channel.ts:59-65): Unconditionally returns `{ decision: "deny", decided_by: "timeout" }`. SEC-002 hardened — no `auto_deny` conditional. Comment at line 59: "SEC-002: Timeout ALWAYS denies. No configuration can change this."

- **WebhookApprovalChannel** (confirmed in SEC-002 eval above): Timeout callback unconditionally sets `decision: "deny"`.

- **DashboardApprovalChannel** (confirmed in SEC-002 eval above): Timeout callback unconditionally sets `decision: "deny"`.

After the channel returns a deny, `requestApproval` at line 253 evaluates `response.decision === "approve"` → `false`, returning `{ allowed: false, ... }`.

The test policy in `approval-gate.test.ts` line 44 sets `auto_deny: true` in the approval channel config, and the SEC-011 test 2 explicitly uses a deny channel to confirm the end-to-end denial. While no SEC-011 test uses `StderrApprovalChannel` directly (which would be the production timeout path), the SEC-002 regression tests already cover that all channels deny on timeout. The combination is sound: SEC-011 routes unclassified → `requestApproval(tier 1)` → SEC-002 ensures timeout → deny.

**The two fixes are complementary.** SEC-002 ensures the gate denies on timeout. SEC-011 ensures unclassified operations reach the gate. Together, an unclassified operation that times out is denied.

---

## 5. SCOPE

**Question:** Does commit `4a72000` touch exactly 4 files?

**Verdict: PASS.**

`git show --stat 4a72000` output:

```
 SPRINT_CONTRACT.md                                 | 138
 SPRINT_RESULT.md                                   | 124
 server/src/principal-policy/gate.ts                |  36
 server/test/principal-policy/approval-gate.test.ts |  73
 4 files changed, 193 insertions(+), 178 deletions(-)
```

Exactly 4 files: `gate.ts`, `approval-gate.test.ts`, `SPRINT_CONTRACT.md`, `SPRINT_RESULT.md`. No other files touched.

---

## 6. NEW RISK

### 6a. Can `tier3_always_allow.includes()` be bypassed by a partial match?

**Verdict: PASS — no bypass possible.**

`Array.prototype.includes()` in JavaScript/TypeScript uses the SameValueZero algorithm, which for strings is equivalent to strict equality (`===`). It does not perform substring matching, prefix matching, or regex matching. An operation name like `state_rea` (partial match of `state_read`) would not match `"state_read"` in the array. An operation name like `state_read_all` would not match either. Only the exact string `"state_read"` matches the entry `"state_read"`.

The `extractOperationName` function (loader.ts:92-96) strips only the `sanctuary/` prefix. It does not normalize, lowercase, trim, or otherwise transform the operation name. The MCP SDK routes tool calls by exact tool name match, so the operation name reaching the gate is always the exact registered tool name minus the prefix.

**No partial match bypass is possible.**

### 6b. Does the `gate_unclassified` audit log entry expose sensitive classification logic?

**Verdict: PASS with minor observation.**

The audit log entry (gate.ts:90-94) contains:

```typescript
{
  tier: 1,
  operation,
  warning: "Operation is not classified in any policy tier — defaulting to Tier 1 (require approval)",
}
```

The `operation` field reveals the name of the unclassified operation — this is the tool name the agent already knows (it called it). The `warning` message reveals that the operation is "not classified in any policy tier." This confirms to an observer that the operation is unlisted, but this information is already implicit in the fact that the operation triggered a Tier 1 approval prompt with the reason string `"is not classified in any policy tier"` (gate.ts:99).

**What this does NOT reveal:** The audit log entry does not list the contents of `tier1_always_approve`, `tier3_always_allow`, or any other tier list. It does not reveal which operations ARE classified. It does not reveal the Tier 2 anomaly detection thresholds. An attacker reading this log entry learns only that their specific operation is unlisted — not what IS listed.

**CLAUDE.md §"WHAT THESE TOOLS MUST NEVER DO" #7** states: "Denial responses never reveal policy rules." The denial reason in the `GateResult` (gate.ts:99) says the operation "is not classified in any policy tier" — this reveals the operation's classification status (unlisted) but does not reveal any policy rules (which operations are in which tier, what the anomaly thresholds are). This is consistent with the existing Tier 1 and Tier 2 reason strings, which also name the triggering operation without revealing the full policy.

**Minor observation (non-blocking):** The audit log `warning` field and the `requestApproval` reason string both include the phrase "SEC-011 safe default" (gate.ts:99). This is an internal reference that could be visible to an agent if the approval prompt is reflected back through the MCP response. However, the `requestApproval` method (gate.ts:229-261) returns a `GateResult` with the reason field, and the MCP router wraps denied operations in a generic denial message that does not include the reason (per CLAUDE.md §12: "Denial messages are generic"). The SEC-011 reference in the reason string would only appear in the audit log and the approval channel prompt (stderr/dashboard/webhook), not in the MCP response to the agent.

---

## 7. FULL TEST SUITE

**Independent run:**

```
 Test Files  24 passed (24)
      Tests  247 passed (247)
   Duration  20.10s
```

247/247 pass. Zero failures. Baseline was 243 (post-SEC-001/SEC-002). +4 new SEC-011 tests = 247. Confirmed.

---

## GRADE: PASS

All six evaluation criteria are satisfied:

1. **Root cause addressed:** The unconditional Tier 3 fall-through is replaced with an explicit `tier3_always_allow.includes()` guard. Unlisted operations now route to Tier 1 approval. Verified by reading the diff and tracing the execution path.
2. **Audit log correct:** `gate_unclassified` entry is written unconditionally before `requestApproval()` — no conditional, no try/catch, no way to suppress. Operation name is developer-controlled, not agent-controlled.
3. **Regression tests valid:** 4 tests added, 3 would genuinely fail against pre-fix code, 1 is a stability test. At least one test (Test 1) explicitly sends `totally_new_tool` and asserts Tier 1 routing.
4. **SEC-002 interaction sound:** Unclassified operations route through `requestApproval(tier 1)`, which delegates to the approval channel. All three production channels unconditionally deny on timeout (SEC-002 hardening). An unclassified operation that times out is denied.
5. **Scope exact:** 4 files changed — `gate.ts`, `approval-gate.test.ts`, `SPRINT_CONTRACT.md`, `SPRINT_RESULT.md`. No other files.
6. **No new bypass risk:** `Array.prototype.includes()` uses strict equality — no partial match bypass. Audit log entry reveals only that the specific operation is unlisted, not the contents of any tier list.

**Non-blocking observations for follow-up:**

- The reason string at gate.ts:99 includes `"(SEC-011 safe default)"` — this internal finding reference is fine in audit logs and approval prompts but should not leak into MCP responses. Verified that the MCP router uses generic denial messages, so this is not currently exposed to the agent. However, if future changes reflect `GateResult.reason` to the agent, this string would need sanitizing.
- Test 3 (`"logs unclassified operation to audit log"`) asserts `auditLog.size >= 2` rather than checking the specific `gate_unclassified` action string in the audit entries. A stronger test would verify the specific action string exists. The current assertion is sufficient but could pass even if the log format changed.
- The gate.ts file header comment (line 10) still reads "Tier 3 / default: Allow with audit logging" — this is now inaccurate since the default for unlisted operations is Tier 1 deny. Should be updated to reflect the four-branch evaluation.

---

## SEC-005 — Import Does Not Verify Ed25519 Signatures on Imported State Entries

**Sprint Date:** 2026-03-28
**Evaluator Date:** 2026-03-28
**Fix Commit:** `d2fd381`
**Grade: CONDITIONAL PASS**

### 1. Root Cause Verification

The `import()` method in `state-store.ts:518-630` now contains a signature verification block (lines 556-581) that runs before any entry is written to storage. For each entry:

- The `kid` is resolved via `publicKeyResolver`. If the resolver returns `null`, the entry is rejected (`skippedUnknownKid++`, `continue`).
- The `sig` is verified against `entry.payload.ct` using the resolved public key via the same `verify()` function from `core/identity.ts` that `read()` uses. If verification fails or throws, the entry is rejected (`skippedInvalidSig++`, `continue`).
- Only entries passing both checks reach the write path at line 613.

**Issue found:** The `publicKeyResolver` parameter is declared **optional** (`publicKeyResolver?: (kid: string) => Uint8Array | null` at line 521). Line 556 guards the entire verification block with `if (publicKeyResolver)`. If no resolver is provided, all entries bypass verification entirely — identical to the pre-fix behavior. The sprint contract states: "Signature verification is **mandatory, not optional**." The sprint result acknowledges this: "The resolver parameter is optional to maintain backward API compatibility for internal callers, but the tool handler always provides it."

The single production caller (`tools.ts:622`) does always provide the resolver, so the MCP-facing attack vector described in SEC-005 is closed. However, the `StateStore` API itself does not enforce mandatory verification — any future direct caller of `import()` that omits the resolver silently bypasses the fix.

**Verdict:** The production path is secure. The API contract is not. This is the basis for CONDITIONAL PASS.

### 2. Resolver Pattern

- **(a) Required parameter?** No. The parameter is optional (`?`). The tool handler always provides it, but the type signature does not enforce it. **Condition for PASS: remove the `?` from `publicKeyResolver` to make it a required parameter.**
- **(b) Null return → rejection?** Yes. Line 559-563: `if (!signerPublicKey)` → `skippedUnknownKid++; skippedKeys++; continue;`. This is a hard rejection, not a warning.
- **(c) Decoupling from IdentityManager?** Yes. `state-store.ts` has zero imports from or references to `IdentityManager`. The resolver is a pure function `(kid: string) => Uint8Array | null` — the coupling lives entirely in the tool handler's wiring at `tools.ts:616-620`. This is genuine decoupling.

### 3. Rejection Counts

The rejection paths are mutually exclusive:

- If `kid` resolution returns `null` → `skippedUnknownKid++`, `skippedKeys++`, `continue` (line 560-562). The `skippedInvalidSig` counter is never reached.
- If `sig` verification fails → `skippedInvalidSig++`, `skippedKeys++`, `continue` (lines 570-574 or 577-579). The `skippedUnknownKid` counter is not touched.
- If verification passes → neither counter is incremented.

Every rejected entry increments exactly one specific counter. No entry can increment both. No rejected entry can increment neither. `skippedKeys` is incremented for every rejection, serving as a total. Correct.

**Oracle attack surface:** The `skipped_unknown_kid` and `skipped_invalid_sig` counts do distinguish between "identity not found" and "identity found but signature invalid." An attacker could craft bundles with entries referencing different `kid` values and observe which get `skipped_unknown_kid` vs `skipped_invalid_sig` to probe which identities exist on the instance. However, import is a Tier 1 operation requiring out-of-band human approval for every invocation. A human approver would need to approve each probing attempt. The attack is theoretically possible but practically infeasible under the existing approval gate. **No action required**, but the observation is noted.

### 4. Regression Tests

`server/test/security/import-verifies-signatures.test.ts` — 5 tests, 222 lines:

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | Valid import with correct signatures | 2 entries imported, 0 skipped — valid signatures accepted |
| 2 | Forged signature rejected | 1 accepted, 1 rejected (`skipped_invalid_sig: 1`) — mixed batch with correct counts |
| 3 | Unknown kid rejected | 0 imported, `skipped_unknown_kid: 1` — unknown identity rejected |
| 4 | All entries invalid (bad signatures) | 0 imported, 3 skipped — full batch rejection |
| 5 | Reserved namespace still skipped | Existing behavior preserved regardless of signature status |

Coverage assessment:
- **(a) Valid signature accepted:** Test 1. ✓
- **(b) Invalid signature rejected:** Tests 2, 4. ✓
- **(c) Unknown kid rejected:** Test 3. ✓
- **(d) Mixed batch with correct counts:** Test 2 (1 good + 1 tampered). ✓

All 5 tests pass. Full suite: 252/252. No regressions. Previous count was 247, net +5.

### 5. Cluster Contract

The sprint contract (SPRINT_CONTRACT.md) defines the verification pattern for SEC-010 and SEC-014:

- Callback signature: `(identifier: string) => PublicKey | null`
- Verification is mandatory, not optional.
- Null return from resolver → rejection, not warning.
- Response includes structured rejection counts.

This is self-contained and clear. A future implementer working on SEC-010 or SEC-014 can follow this pattern without reading the SEC-005 implementation. The sprint result reinforces this in the "Adjacent Findings Noticed" section, explicitly naming the Concordia-side equivalent (`signing.py` has `verify_signature()` but never calls it).

### 6. Scope

Commit `d2fd381` touches exactly 5 files:

1. `server/src/l1-cognitive/state-store.ts` — verification logic added to `import()`
2. `server/src/l1-cognitive/tools.ts` — resolver callback wired in handler
3. `server/test/security/import-verifies-signatures.test.ts` — new test file (5 tests)
4. `SPRINT_CONTRACT.md` — contract for this sprint
5. `SPRINT_RESULT.md` — result documentation

No other files touched. ✓

### Condition for Upgrade to PASS

**One condition:** Make `publicKeyResolver` a required parameter in `StateStore.import()`. Remove the `?` from line 521 and remove the `if (publicKeyResolver)` guard at line 556. If backward compatibility is needed for test helpers or internal use, callers that intentionally skip verification should pass an explicit no-op resolver (e.g., `() => null`) — making the bypass visible and intentional rather than silent. This aligns the API with the sprint contract's "mandatory, not optional" requirement and with CLAUDE.md constraint 5 ("Never silently degrade to a less-secure behavior on error").
