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

### Follow-Up: Condition Resolved — Upgraded to PASS

**Re-check Date:** 2026-03-28
**Condition Fix Commit:** `94a8567`

All four sub-conditions verified:

1. **(a) `?` removed from parameter declaration:** `state-store.ts:521` declares `publicKeyResolver: (kid: string) => Uint8Array | null` — no optional marker. TypeScript will reject any caller that omits the argument at compile time. ✓
2. **(b) `if (publicKeyResolver)` guard removed:** Line 557 calls `publicKeyResolver(entry.kid)` unconditionally — no existence check wrapping the verification block. Verification executes for every entry on every import. ✓
3. **(c) All callers pass the resolver:** The single production caller (`tools.ts:622-626`) passes `publicKeyResolver`. All 5 test callers in `import-verifies-signatures.test.ts` pass a resolver. No caller omits it. ✓
4. **(d) No code path where import succeeds without verification:** Every entry in the `for` loop at line 554 must pass both `publicKeyResolver` resolution (line 557) and `verify()` (line 568) before reaching the write path at line 581. Entries failing either check are rejected via `continue`. The reserved-namespace skip (line 546) rejects entries — it does not import them. There is no path from entry to storage that bypasses signature verification. ✓

Full test suite: **252/252 pass** (25 files, 19.90s). No regressions.

**Grade: PASS** — condition fully closed. SEC-005 upgraded from CONDITIONAL PASS to PASS.

---
---

# SPRINT_EVAL.md — SEC-012: Independent QA Evaluation

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-012 — Dashboard Authentication Token Passed in Query String
**Commit:** `91b2740`
**Branch:** `security-review`

---

## 1. ROOT CAUSE

**Question:** Does the fix eliminate the long-lived auth token from all URL surfaces — not just the primary entry point but every endpoint, redirect, and client-side navigation path?

**Verdict: PASS.**

I read `dashboard.ts` end-to-end (636 lines). The `checkAuth()` method (lines 257–282) has exactly three auth paths:

1. `Authorization: Bearer <TOKEN>` header — accepts the long-lived token. ✓ (header-only, never in URL)
2. `?session=<SESSION_ID>` query parameter — accepts short-lived session IDs only. ✓ (not the long-lived token)
3. Everything else → 401 rejection.

There is no remaining code path that reads `?token=` from the URL. I searched all files under `server/src/` for `?token=`, `token=.*URL`, and `query.*token` patterns — every match is a comment referencing the old behavior or the SEC-012 fix. No functional code reads a token from query parameters.

On the client side (`dashboard-html.ts`), the `authHeaders()` function puts the token in the `Authorization` header for API calls (approve/deny, status). The `sessionQuery()` function appends only the session ID to URLs. The `exchangeSession()` function POSTs to `/auth/session` with the token in the header. The SSE `EventSource` connection at line 364 uses `sessionQuery('/events')` — session ID only. The init block (lines 553–565) strips any legacy `?token=` from the browser URL bar via `history.replaceState`.

No code path puts the long-lived token in a URL.

---

## 2. SESSION EXCHANGE SECURITY

**(a) Cryptographic randomness of session ID:**

**PASS.** `createSession()` at line 303: `randomBytes(32).toString("hex")` — 256 bits from Node's CSPRNG. The session ID is not derived from or predictable from the auth token. The `DashboardSession` interface (lines 64–68) stores only `id`, `created_at`, `expires_at` — no reference to the original token.

**(b) 5-minute TTL enforced server-side:**

**PASS.** `SESSION_TTL_MS = 5 * 60 * 1000` at line 70. `createSession()` sets `expires_at: now + SESSION_TTL_MS` (line 308). `validateSession()` at line 319 checks `Date.now() > session.expires_at` — this is a server-side wall-clock check. The client-side refresh at 80% TTL (line 342 of dashboard-html.ts) is a convenience optimization, not a security enforcement point.

**(c) Expired sessions are rejected, not extended:**

**PASS.** `validateSession()` lines 319–322: when `Date.now() > session.expires_at`, the session is deleted from the map and the method returns `false`. There is no renewal, extension, or grace period. The `cleanupSessions()` timer (every 60s, line 98) also sweeps expired entries, but the primary enforcement is at validation time.

**(d) Exchange endpoint probing protection:**

**OBSERVATION (not blocking).** There is no explicit rate limiting on `POST /auth/session`. However, this endpoint does not introduce a new probing vector: every endpoint on the dashboard server already returns 401 for invalid Bearer tokens via `checkAuth()`. The exchange endpoint's 401 response reveals no additional information beyond what a GET to `/` would reveal. Rate limiting on the dashboard server is a pre-existing gap, not introduced by this fix.

---

## 3. LONG-LIVED TOKEN REJECTION

**Question:** Is sending `?token=<AUTH_TOKEN>` an active rejection (explicit error) or a silent failure?

**Verdict: PASS.**

Sending `GET /?token=<AUTH_TOKEN>` (without an Authorization header) causes `checkAuth()` to:
1. Check Authorization header — absent → skip.
2. Check `?session=` — absent → skip.
3. Return 401 with body `{"error":"Unauthorized — use Authorization: Bearer header or a valid session"}`.

The attacker receives an explicit 401 status code and a descriptive error message. This is not a silent failure. The test at line 48–57 of `dashboard-no-query-token.test.ts` confirms this: `expect(res.status).toBe(401)` and `expect(body.error).toBeDefined()`.

Note: the rejection is generic (same 401 as any unauthenticated request) rather than a targeted "token-in-URL is forbidden" message. This is acceptable — a targeted message would actually leak information about the auth mechanism to an attacker.

---

## 4. REGRESSION TESTS

**File:** `server/test/security/dashboard-no-query-token.test.ts` (172 lines, 8 tests)

| Required test | Covered by | Verified |
|--------------|-----------|----------|
| Token in URL query parameter is actively rejected | Test 1 (lines 48–57): `GET /?token=TOKEN` → 401 | ✅ |
| Valid session exchange via Bearer header succeeds | Test 3 (lines 73–87): `POST /auth/session` → 200, session_id is 64 hex chars | ✅ |
| Expired session ID is rejected | Test 5 (lines 111–138): white-box expiry via `sessions.get().expires_at = past` → 401 | ✅ |
| Session ID cannot be reused after expiry | Test 5: after expiry, `validateSession` deletes the session (line 320–321 of dashboard.ts) and returns 401 — session is gone, not just expired-but-present | ✅ |

Additional coverage: Test 2 (header auth works), Test 4 (session in URL works), Test 6 (invalid session rejected), Test 7 (wrong token on exchange rejected), Test 8 (missing header on exchange rejected).

**Full suite: 261/261 pass** (26 files, 19.85s). No regressions.

---

## 5. SCOPE

**Commit `91b2740` touches exactly 6 files:**

1. `server/src/principal-policy/dashboard.ts` — core auth changes ✓
2. `server/src/principal-policy/dashboard-html.ts` — client-side session flow ✓
3. `server/test/principal-policy/dashboard.test.ts` — updated existing tests ✓
4. `server/test/security/dashboard-no-query-token.test.ts` — new regression tests ✓
5. `SPRINT_CONTRACT.md` ✓
6. `SPRINT_RESULT.md` ✓

Confirmed via `git show --stat 91b2740`: 6 files changed, 492 insertions, 126 deletions. No unexpected files touched.

---

## 6. NEW RISK ASSESSMENT

**(a) Auth token not logged in success or error paths:**

**PASS.** I searched `dashboard.ts` for `console.log`, `console.error`, and `process.stderr.write.*token` patterns. Zero matches. The only stderr output mentioning the token is the startup hint (lines 136–144) which prints only the first and last 4 characters — this is pre-existing behavior, not introduced by this fix. The `handleSessionExchange` method (lines 408–437) returns only the session ID and expiry on success, and generic error messages on failure. The auth token is never included in any response body or log output.

**(b) Session store does not persist beyond TTL:**

**PASS.** Sessions are stored in an in-memory `Map` (line 85). `cleanupSessions()` runs every 60 seconds (line 98) and deletes expired entries. `validateSession()` deletes expired entries at access time (line 320–321). `stop()` calls `this.sessions.clear()` (line 179). No disk persistence, no serialization, no external storage.

**(c) Session ID cannot recover the original token:**

**PASS.** The `DashboardSession` interface (lines 64–68) has three fields: `id`, `created_at`, `expires_at`. The original auth token is not stored in the session record. There is no API endpoint that returns the auth token. The `createSession()` method generates a fresh random ID — it is a one-way exchange with no back-reference.

---

## EVALUATOR PARKING LOT

- **No rate limiting on dashboard endpoints (pre-existing).** The dashboard server has no rate limiting on any endpoint, including `POST /auth/session`. While this is not introduced by SEC-012, it means an attacker with network access to the dashboard could attempt brute-force token discovery. The 127.0.0.1 default bind mitigates this for most deployments. Not blocking for this evaluation — logged as a pre-existing observation.

---

## Grade: PASS

All six verification criteria met. The fix correctly eliminates the long-lived auth token from all URL surfaces, introduces a sound session exchange mechanism with server-side TTL enforcement, and includes comprehensive regression tests. The session store introduces minimal new attack surface with appropriate bounds (1000-entry cap, 5-minute TTL, periodic cleanup). No regressions in the full test suite (261/261).

---
---

# SPRINT_EVAL.md — SEC-016: Independent QA Evaluation

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-016 — Stderr Approval Channel Auto-Resolves After 100ms Without Human Input
**Commit:** `6c0516e`
**Branch:** `security-review`

---

## 1. ROOT CAUSE

**Question:** Does the fix eliminate the 100ms timing window entirely, or just shorten it?

**Verdict: PASS.**

Inspected `StderrApprovalChannel.requestApproval()` in `approval-channel.ts:49-64`. The method is:

1. Write informational prompt to stderr via `process.stderr.write()` (synchronous in Node.js)
2. Return `{ decision: "deny", decided_at: ..., decided_by: "stderr:non-interactive" }` immediately

There is no `setTimeout`. There is no `await`. There is no `new Promise`. The 100ms delay is not reduced or moved — it is deleted. The channel denies synchronously after the stderr write. The timing window is eliminated, not shortened.

---

## 2. SEC-002 INTERACTION

**Question:** Does SEC-016 weaken SEC-002's invariant ("timeout on any approval channel always results in denial") in any edge case?

**Verdict: PASS.**

The commit does not modify `webhook.ts` or `dashboard.ts` — confirmed via `git show --stat 6c0516e` which lists exactly 7 files, neither of which is a webhook or dashboard source file. Additionally, `git show 6c0516e -- server/src/principal-policy/webhook.ts server/src/principal-policy/dashboard.ts` returned empty output.

The SEC-002 regression tests for webhook and dashboard channels are unchanged in behavior. Webhook tests still assert `decided_by: "timeout"` and `decision: "deny"` on timeout. Dashboard tests same. The stderr-specific SEC-002 tests were updated to assert `decided_by: "stderr:non-interactive"` instead of `"timeout"` — this is correct because the channel no longer times out; it denies immediately. The invariant "denial is unconditional regardless of config" is preserved and strengthened.

The two changes are strictly additive: SEC-002 guarantees timeout = deny across all channels; SEC-016 eliminates the timeout entirely for the one channel that never needed it.

---

## 3. DECIDED_BY SEMANTICS

**Question:** Is `"stderr:non-interactive"` a valid value, and does downstream code handle it correctly?

**Verdict: PASS.**

(a) **Type validity:** `types.ts:69` defines `decided_by: "human" | "timeout" | "auto" | "stderr:non-interactive"`. The value is explicitly in the union. TypeScript will enforce this at compile time.

(b) **Downstream handling:** Searched all `decided_by` references in `server/src/`. Two downstream consumers:

- `gate.ts:249` — passes `decided_by` through to the audit log as a metadata field. No pattern matching, no conditional. Any string value works.
- `gate.ts:256` — uses `decided_by` in a template literal: `Approved by ${response.decided_by}`. This only executes when `decision === "approve"`, which never happens for the stderr channel. Even if it did, the string interpolation handles any value.

No code performs `if (decided_by === "timeout")` or switches on the value. The new value cannot cause a silent failure or default-to-allow.

---

## 4. EXISTING TEST UPDATES

**Question:** Were the 2 updated tests weakened to match new output, or do they still test the same invariants?

**Verdict: PASS.**

**SEC-002 tests (`sec-002-auto-deny-hardcoded.test.ts`):**
- Test "denies immediately with default config": Still creates a `StderrApprovalChannel`, calls `requestApproval`, asserts `decision === "deny"`. Changed assertion from `decided_by === "timeout"` to `decided_by === "stderr:non-interactive"`. The denial invariant is preserved. The `decided_by` change is correct — the channel no longer times out.
- Test "denies immediately even if auto_deny is explicitly set to false": Same structure. Still passes `auto_deny: false`, still asserts denial. The SEC-002 invariant (no config can cause approval) holds.

**SEC-001 tests (`sec-001-state-delete-requires-approval.test.ts`):**
- Test "gate denies state_delete on stderr channel": Updated comment to reference SEC-016. Removed `timeout_seconds: 0.1` (unnecessary since there's no timeout). Still asserts `allowed === false`, `approval_required === true`, `tier === 1`. The invariant (state_delete requires Tier 1 approval and is denied on stderr) is unchanged.

No assertion was weakened. No invariant was relaxed.

---

## 5. REGRESSION TESTS

**Question:** Does `sec-016-stderr-always-denies.test.ts` test the required behaviors?

**Verdict: PASS.**

4 tests in the file:

1. **"always denies Tier 1 operations with decided_by stderr:non-interactive"** — Creates channel, calls `requestApproval` with Tier 1 request, asserts `decision === "deny"` and `decided_by === "stderr:non-interactive"`. ✅ Tests unconditional denial.

2. **"denies immediately with no timing window (< 10ms, not 100ms)"** — Measures `performance.now()` before and after `requestApproval`, asserts elapsed < 10ms. ✅ Tests synchronous denial (the old 100ms setTimeout would fail this).

3. **"ignores auto_deny: false config (SEC-002 interaction)"** — Creates channel with `auto_deny: false`, asserts denial. ✅ Tests SEC-002 interaction.

4. **"denies Tier 2 operations identically"** — Same as test 1 but with Tier 2 request. ✅ Tests operation-type independence.

All three required properties are covered: (a) synchronous with no delay, (b) `decided_by` is `"stderr:non-interactive"`, (c) unconditional regardless of operation type (Tier 1 and Tier 2 both tested) and config (`auto_deny: false` tested).

**Full suite:** 265/265 pass. Confirmed independently by running `npx vitest run`.

---

## 6. SCOPE

**Question:** Does commit `6c0516e` touch only the expected files?

**Verdict: PASS.**

`git show --stat 6c0516e` lists exactly 7 files:

| File | Expected? | Change |
|------|-----------|--------|
| `server/src/principal-policy/approval-channel.ts` | ✅ Yes | StderrApprovalChannel source — core fix |
| `server/src/principal-policy/types.ts` | ✅ Yes | ApprovalResponse type union |
| `server/test/security/sec-016-stderr-always-denies.test.ts` | ✅ Yes | New regression tests |
| `server/test/security/sec-002-auto-deny-hardcoded.test.ts` | ✅ Yes | Updated existing tests |
| `server/test/security/sec-001-state-delete-requires-approval.test.ts` | ✅ Yes | Updated existing tests |
| `SPRINT_CONTRACT.md` | ✅ Yes | Sprint documentation |
| `SPRINT_RESULT.md` | ✅ Yes | Sprint documentation |

No unexpected files. No changes to webhook, dashboard, gate, loader, or any other module.

---

## Observations (Non-Blocking)

None. The fix is clean, minimal, and precisely scoped. No new concerns raised.

---

## Grade: PASS

All six verification criteria met. The `setTimeout` is deleted (not reduced or moved). The channel denies synchronously with zero async gap. `decided_by` uses a valid, well-typed value that downstream code handles correctly. The SEC-002 invariant is preserved and strictly strengthened. Webhook and dashboard channels are completely untouched. The 4 new regression tests cover all required properties. The 2 updated existing tests preserve their original invariants. The commit scope is exactly as expected with no unexpected files. Full suite 265/265.

---
---

# SPRINT_EVAL.md — SEC-019: Independent QA Evaluation

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-019 — Config Silently Accepts Unimplemented Security Features
**Commit:** `0633836`
**Branch:** `security-review`

---

## 1. ROOT CAUSE

**Question:** Does the fix reject unimplemented config values at load time — before any component initializes with a false assumption — or does it warn after initialization?

**Verdict: PASS.**

In `config.ts`, `loadConfig()` follows this sequence:

1. `deepMerge(config, fileConfig)` at line 182 produces the merged config.
2. `validateConfig(merged)` at line 183 runs validation.
3. `return merged` at line 184 only executes if validation passes.

The `validateConfig()` function (lines 212-253) throws an `Error` if any unimplemented value is found. This throw happens before the config object is returned to any caller. No component can initialize with a config containing unimplemented values because `loadConfig()` never returns one.

In the catch block (lines 185-192), validation errors are re-thrown: the check `err.message.includes("unimplemented features")` at line 187 ensures validation errors propagate while file-not-found errors fall back to defaults. This means a caller wrapping `loadConfig()` in try/catch cannot silently swallow a validation error unless they explicitly ignore errors containing "unimplemented features" — which would require deliberate intent.

The default config path (line 191) returns defaults without calling `validateConfig()`. This is safe because `defaultConfig()` returns `key_protection: "none"`, `environment: "local-process"`, and `proof_system: "commitment-only"` — all implemented values. Confirmed by the test "validateConfig passes for default config" (test line 157-159).

---

## 2. WHITELIST COMPLETENESS

**Question:** Are the rejected values genuinely unimplemented, and are there other config fields with unimplemented values not covered?

**Verdict: PASS, with one non-blocking observation.**

**(a) Are the rejected values genuinely unimplemented?**

- `"hardware-key"`: Searched `server/src/` for any implementation. Found only type annotations in `identity.ts:27`, `identity.ts:102`, `tools.ts:145`, and `index.ts:65` — all declaring the union type. No FIDO2, WebAuthn, or hardware security module code exists anywhere in the codebase. CLAUDE.md §"Intended but unverified" #19 confirms: "planned for v0.3.0, config option exists, implementation not yet present." Correctly rejected.

- `"tee"`: Searched `server/src/`. All references are diagnostic: `shr/generator.ts:65` says "Process-level isolation only (no TEE)", `shr/generator.ts:66` says "TEE support planned for v0.3.0", `index.ts:164` echoes the same. No TEE integration, remote attestation, or enclave code exists. CLAUDE.md §"Intended but unverified" #20 confirms. Correctly rejected.

- `"groth16"` and `"plonk"`: Searched `server/src/`. Zero results outside `config.ts`. No SNARK circuit definitions, no trusted setup, no proof generation or verification code. CLAUDE.md §"Intended but unverified" #21 confirms: "Config accepts these as proof_system options, but only commitment-only is implemented." Correctly rejected.

**(b) Are there other config fields with unimplemented values?**

I examined the full `SanctuaryConfig` interface. Two fields warrant mention:

- `disclosure.default_policy` accepts `"withhold-all"` in addition to `"minimum-necessary"`. Searching the codebase for `withhold-all`, `default_policy`, or `minimum-necessary` outside config.ts returns zero results. Neither value is read by any code. This means neither policy is enforced — but unlike the three validated fields, neither claims to provide a specific cryptographic capability. The security impact is lower: a user setting `"withhold-all"` gets the same behavior as `"minimum-necessary"` (neither is enforced), rather than believing they have hardware key protection they don't have.

- `reputation.mode` accepts `"service-mediated"`. References in `shr/generator.ts:118` and `index.ts:272,364` pass the value through as a label, but no code branches on it to implement service-mediated reputation differently from self-custodied.

These are not security-critical misrepresentations in the way groth16/plonk/hardware-key/tee are, so their omission from the SEC-019 fix is defensible. Logged as a non-blocking observation for future consideration.

---

## 3. ERROR COLLECTION

**Question:** Does the fix collect all violations into a single error, and is the error descriptive and non-swallowable?

**Verdict: PASS.**

**(a) All three fields are always checked regardless of earlier failures.**

The `validateConfig()` function (lines 212-253) uses three independent `if` blocks at lines 218, 229, and 240. Each pushes to the `errors` array without returning early. If all three fields are invalid, all three are checked and all three error messages are collected.

**(b) Error messages are descriptive enough for a user to understand what to change.**

Each error message includes: the full config path (e.g., `state.key_protection`), the invalid value in quotes, the list of implemented alternatives, and an explanation of why the unimplemented value is dangerous ("would silently degrade security"). The outer error message prefixes with "Sanctuary configuration references unimplemented features:" followed by all violations joined by newlines.

**(c) The error cannot be silently swallowed.**

The catch block in `loadConfig()` (lines 186-189) re-throws any error whose message includes "unimplemented features". Only file-not-found errors are swallowed. A caller that wraps `loadConfig()` in try/catch would receive the validation error as a thrown exception — standard error propagation.

One minor note: the re-throw mechanism relies on string matching (`err.message.includes("unimplemented features")`). A future refactor that changes the error message wording could break this. A custom error class would be more robust, but this is a code quality concern, not a security gap.

---

## 4. DEFAULT CONFIG

**Question:** Does default config (no file) continue to work?

**Verdict: PASS.**

`defaultConfig()` returns:
- `state.key_protection: "none"` — in whitelist `["passphrase", "none"]`
- `execution.environment: "local-process"` — in whitelist `["local-process", "docker"]`
- `disclosure.proof_system: "commitment-only"` — in whitelist `["commitment-only"]`

All three pass validation. When no config file exists, `loadConfig()` catches the file-not-found error and returns the default config at line 191, bypassing validation entirely (safe because defaults are hardcoded and always valid).

Test coverage: "accepts default config (no overrides)" (test line 149-153) loads from a non-existent path and confirms no throw. "validateConfig passes for default config" (test line 157-159) directly validates the default config object.

---

## 5. REGRESSION TESTS

**Question:** Does `reject-unimplemented-features.test.ts` adequately test the fix?

**Verdict: PASS.**

The test file contains 13 tests in one describe block:

**(a) Each unimplemented value individually rejected:**
- `"groth16"` (line 42-52): verifies throw matches `/unimplemented/i`, `/disclosure\.proof_system/`, `/groth16/`
- `"plonk"` (line 54-61): verifies throw matches `/unimplemented/i`, `/plonk/`
- `"hardware-key"` (line 65-75): verifies throw matches `/unimplemented/i`, `/state\.key_protection/`, `/hardware-key/`
- `"tee"` (line 79-89): verifies throw matches `/unimplemented/i`, `/execution\.environment/`, `/tee/`

**(b) Multiple violations produce a single combined error:**
- Test at line 93-115: sets all three fields to unimplemented values, verifies the single thrown error contains all three values (`/hardware-key/`, `/tee/`, `/groth16/`).

**(c) Valid/default values pass:**
- `"commitment-only"` (line 119-123)
- `"passphrase"` (line 125-129)
- `"none"` (line 131-135)
- `"local-process"` (line 137-141)
- `"docker"` (line 143-147)
- Default config with no overrides (line 149-153)
- `validateConfig` direct unit tests (lines 157-165)

**Full suite: 278/278 passed.** Confirmed by running `npx vitest run` — output shows "Test Files 28 passed (28), Tests 278 passed (278)". Count increased from 265 to 278 (+13 new tests).

---

## 6. SCOPE

**Question:** Does commit `0633836` touch exactly 4 files?

**Verdict: PASS.**

`git show --stat 0633836` confirms exactly 4 files changed:

1. `server/src/config.ts` — added `validateConfig()` function and call from `loadConfig()`
2. `server/test/security/reject-unimplemented-features.test.ts` — new file, 166 lines
3. `SPRINT_CONTRACT.md` — sprint contract for SEC-019
4. `SPRINT_RESULT.md` — sprint result for SEC-019

No unexpected files. No changes to router, gate, storage, or any other subsystem.

---

## Observations (Non-Blocking)

1. **Unimplemented-but-unchecked config values:** `disclosure.default_policy: "withhold-all"` is accepted by the type system but never read by any code. `reputation.mode: "service-mediated"` is passed through as a label but triggers no behavioral change. Neither represents a false security promise at the level of groth16/hardware-key/tee, but they are dead config options. Consider adding validation or removing from the union type in a future cleanup sprint.

2. **Error re-throw uses string matching:** The catch block in `loadConfig()` detects validation errors by checking `err.message.includes("unimplemented features")`. A custom error class (e.g., `ConfigValidationError`) would be more robust against message wording changes. Non-blocking because the current implementation works correctly.

---

## Grade: PASS

All six verification criteria met. `validateConfig()` is called before the config is returned to any caller, preventing initialization with unimplemented features. The three validated fields are genuinely unimplemented — confirmed by codebase search. Error collection checks all fields independently and produces descriptive, combined error messages. Default config passes validation. 13 regression tests cover all unimplemented values, all implemented values, combined errors, and default config. Commit scope is exactly 4 files. Full suite 278/278.

---
---

# SPRINT_EVAL.md — SEC-020: Independent QA Evaluation

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-020 — Recovery Key Path Regenerates Master Key on Every Restart
**Commit:** `d44997d`
**Branch:** `security-review`

---

## 1. ROOT CAUSE

**Question:** Does the fix eliminate the `generateRandomKey()` call from the recovery path entirely? Is there any remaining code path where a new random key is generated when existing encrypted data is present?

**Verdict: PASS.**

I read `server/src/index.ts` lines 98-182 directly. The `else` branch (no passphrase) now has two sub-branches:

**When `_meta/recovery-key-hash` exists (lines 109-158):** The code reads `SANCTUARY_RECOVERY_KEY` from `process.env`, decodes from base64url, validates length (32 bytes), hashes via `hashToString()`, compares against the stored hash using `constantTimeEqual()`, and sets `masterKey = recoveryKeyBytes`. There is no call to `generateRandomKey()` anywhere in this path. Three `throw new Error()` gates prevent fallthrough: missing env var (line 113), format/length failures (lines 129, 135), and hash mismatch (line 148).

**When `_meta/recovery-key-hash` does not exist (lines 159-181):** Before calling `generateRandomKey()`, the code checks for orphaned `key-params` in `_meta` (line 162). If found, it throws — refusing to start. Only if no `key-params` exist (genuine first run) does `generateRandomKey()` execute at line 172.

The `generateRandomKey()` call at line 172 is the only one in the entire `else` branch, and it is guarded by the absence of both `recovery-key-hash` and `key-params`. No code path generates a new key when existing encrypted data is present.

---

## 2. KEY VERIFICATION

**Question:** Is the comparison genuinely constant-time? Does a wrong key cause server refusal? Does the hash comparison use the same algorithm as the original hash?

**Verdict: PASS.**

**(a) Constant-time comparison:** `constantTimeEqual()` in `server/src/core/encoding.ts:62-68` uses the standard XOR-accumulate pattern: `diff |= a[i] ^ b[i]` in a loop over all bytes, returning `diff === 0`. The `===` comparison is on an integer (the accumulated diff), not on the hash strings — this is correct. The early return on `a.length !== b.length` is acceptable because both inputs are always SHA-256 hashes encoded to base64url string bytes — they are always the same length. This is not `===` or `==` on the hash strings themselves.

**(b) Wrong key causes refusal:** Line 148-153 throws `"Recovery key does not match the stored key hash"` on mismatch. This is an unhandled throw that propagates up to `createSanctuaryServer()` and prevents the server from starting. There is no catch block, no fallback, no silent key generation.

**(c) Same algorithm:** Both the original hash (line 175, first run: `hashToString(masterKey)`) and the verification hash (line 142, recovery: `hashToString(recoveryKeyBytes)`) use the same `hashToString()` function from `server/src/core/hashing.ts`, which computes SHA-256 and encodes as base64url. Same function, same parameters, same algorithm.

---

## 3. ENVIRONMENT VARIABLE SECURITY

**Question:** Is the key logged? Is the env var cleared after use? Do error messages reveal hash or key material?

**Verdict: PASS (with minor observation).**

**(a) No logging of key material:** I searched for `console.log`, `console.warn`, `console.error`, and `console.info` combined with `recovery` or `SANCTUARY_RECOVERY` in `index.ts`. Zero matches. The `envRecoveryKey` variable is read, decoded, hashed, and compared — it never appears in any log statement or error message string. Error messages reference the env var *name* (`SANCTUARY_RECOVERY_KEY`) but never its *value*.

**(b) Env var not cleared after use:** `process.env.SANCTUARY_RECOVERY_KEY` is not deleted after the key is extracted. This is consistent with the existing treatment of `SANCTUARY_PASSPHRASE` (also not cleared). The SPRINT_CONTRACT acknowledged this as an accepted risk: "This is the same risk class as `SANCTUARY_PASSPHRASE`." Non-blocking — parity with existing behavior.

**(c) No hash or key material in error messages:** All four error paths (missing env var at line 113, invalid base64url at line 129, wrong length at line 135, hash mismatch at line 148) contain only instructional text. None include `storedHash`, `existingHash`, `keyHash`, `providedHash`, `recoveryKeyBytes`, or `envRecoveryKey` in the error strings. Verified by searching all `throw new Error` strings in lines 98-182.

---

## 4. ORPHANED METADATA

**Question:** Does the corrupted-metadata path also refuse to start rather than generating a new key?

**Verdict: PASS.**

Lines 160-169: When `_meta/recovery-key-hash` is absent (first-run branch), the code lists `_meta` entries and checks for `key-params`. If `key-params` exists without a `recovery-key-hash`, line 164 throws: `"Found existing key derivation parameters but no recovery key hash. This indicates a corrupted or incomplete installation."` This is a hard throw — no fallback, no key generation. The `generateRandomKey()` call at line 172 is only reachable if the `hasKeyParams` check passes (no orphaned metadata).

No code path silently overwrites existing key material.

---

## 5. REGRESSION TESTS

**Question:** Do the 9 tests cover the required scenarios? Does the full suite pass at 287/287?

**Verdict: PASS.**

Located at `server/test/security/sec-020-recovery-key-restart.test.ts` (242 lines, 9 `it()` blocks). Coverage:

| # | Test | Required Scenario |
|---|------|-------------------|
| 1 | first run generates a recovery key and stores its hash | Fresh start |
| 2 | subsequent run with correct recovery key succeeds and preserves key material | (a) correct key restores access |
| 3 | subsequent run without credentials fails with descriptive error | (c) missing key refuses start |
| 4 | subsequent run with incorrect recovery key fails | (b) wrong key refuses start |
| 5 | rejects recovery key with invalid base64url encoding | Input validation |
| 6 | rejects recovery key with incorrect length | Input validation |
| 7 | first run with orphaned key-params fails | Orphaned metadata safety net |
| 8 | passphrase path is not affected | Non-regression |
| 9 | recovery key verification uses constant-time hash comparison | Crypto mechanism unit test |

All four required scenarios (a-d from the task) are covered: test 2 covers (a), test 4 covers (b), test 3 covers (c), test 1 covers (d). Additional tests for input validation and non-regression round out the suite.

**Full suite result:** 287/287 passed, 29 test files, 20.00s duration. Confirmed by running `npx vitest run` directly.

---

## 6. SCOPE

**Question:** Does commit `d44997d` touch only the expected files?

**Verdict: PASS.**

`git show --stat d44997d` reports exactly 4 files:

- `SPRINT_CONTRACT.md` — expected
- `SPRINT_RESULT.md` — expected
- `server/src/index.ts` — expected (the fix)
- `server/test/security/sec-020-recovery-key-restart.test.ts` — expected (new test file)

No unexpected files. 400 insertions, 79 deletions.

---

## Observations (Non-Blocking)

1. **Environment variable not cleared from memory:** `process.env.SANCTUARY_RECOVERY_KEY` persists in the Node.js process after use. This is the same pattern as `SANCTUARY_PASSPHRASE` and is accepted risk per the sprint contract. A future hardening sprint could zero both env vars after extraction — but this is defense-in-depth, not a blocking issue.

2. **`constantTimeEqual` early return on length mismatch:** The function returns `false` immediately when `a.length !== b.length`. In this usage, both inputs are always the same length (base64url-encoded SHA-256 hash → string bytes), so the early return is unreachable during normal operation. Not a vulnerability in this context, but worth noting for any future reuse of the function with variable-length inputs.

---

## Grade: PASS

All six verification criteria met. The `generateRandomKey()` call is eliminated from all code paths where existing encrypted data is present. Recovery key verification uses genuine constant-time comparison via XOR-accumulate, not `===` on hash strings. Wrong or missing credentials cause hard startup failure with descriptive errors that reveal no key material. The orphaned-metadata safety net catches corrupted installations and refuses to start. 9 regression tests cover all required scenarios plus input validation and non-regression. Commit scope is exactly 4 expected files. Full suite 287/287.

---

# SPRINT_EVAL.md — SEC-003: Cross-Repo Canonical JSON Divergence

**Date:** 2026-03-28
**Evaluator posture:** Skeptical QA — did not write this code, does not trust self-assessment.
**Finding:** SEC-003 — Canonical JSON Serialization Divergence Between TypeScript and Python
**Sanctuary commit:** `82f3321`
**Concordia commit:** `bc615ad`
**Branch:** `security-review` (both repos)

---

## 1. DIVERGENCE COVERAGE

**Question:** Are all five identified divergence points addressed?

**(a) Number formatting — `1.0` vs `"1"`:** PASS. Python's `_format_number_ecmascript()` (signing.py:70-162) implements ECMAScript Number::toString rules. Integer-valued floats drop the decimal (`1.0` → `"1"`). Scientific notation thresholds match V8 (decimal up to 10^21, exponential beyond). TypeScript side already followed ECMAScript natively via `JSON.stringify(value)` at bridge.ts:69. Test vectors in both repos verify `{"v":1}` not `{"v":1.0}`.

**(b) Unicode escaping — `\uXXXX` vs raw UTF-8:** PASS. The vanilla `json.dumps()` call in `sanctuary_bridge.py:113` (which defaulted to `ensure_ascii=True`, escaping non-ASCII as `\uXXXX`) has been replaced with `canonical_json(agreement).decode("utf-8")` at sanctuary_bridge.py:115. Python's `_stable_stringify` uses `json.dumps(value, ensure_ascii=False)` for strings (signing.py:190), matching V8's raw UTF-8 output. Test vectors cover `café` and `你好世界` in both repos.

**(c) Negative zero — asymmetric validation:** PASS. TypeScript now rejects `-0` with `Object.is(value, -0)` check at bridge.ts:63-67, throwing an error. Python already rejected it via `_check_no_special_floats` (signing.py:60-61). Both repos now reject symmetrically. Both test suites have explicit `-0` rejection tests.

**(d) Unsorted key bypass in `bridge.ts` and `sanctuary_bridge.py`:** PASS. The commitment signing payload at bridge.ts:139 now uses `stableStringify(commitmentPayload)` instead of `JSON.stringify`. The verification payload at bridge.ts:199 also uses `stableStringify(commitmentPayload)`. The Python bridge at sanctuary_bridge.py:115 now uses `canonical_json(agreement).decode("utf-8")` instead of `json.dumps(agreement, sort_keys=True, separators=(",",":"))`. Comments at bridge.ts:137-138 and bridge.ts:188-189 explicitly reference SEC-003. Comments at sanctuary_bridge.py:113-114 do the same.

**(e) undefined vs None structural gap:** PASS (acknowledged as non-practical). TypeScript's `stableStringify` maps `undefined` → `"null"` (bridge.ts:55). Python has no `undefined` concept; `None` maps to `"null"` (signing.py:179). No cross-repo divergence is possible because Python never produces `undefined` and TypeScript serializes it to the same output as `null`. The sprint contract correctly identified this as "not a practical cross-repo divergence, but a spec gap." No fix needed. Accepted.

---

## 2. CANONICAL FORMAT CORRECTNESS

**(a) Python `_format_number_ecmascript()` implementation:**

I inspected signing.py:70-162 line by line.

- Integer-valued floats: `value.is_integer()` → formats as `str(int(value))` with decimal notation up to 21 digits (matching V8's threshold). Correct.
- Zero: explicitly returns `"0"` (line 88). Correct.
- Bool rejection: `isinstance(value, bool)` raises TypeError (line 82). Necessary because Python's `bool` subclasses `int`. Correct.
- Negative handling: extracts sign, operates on absolute value (lines 91-93). Correct.
- Non-integer floats: uses `repr(value)` to get shortest representation, then reformats per ECMA-262 §6.1.6.1.20 rules (lines 113-161). The thresholds match V8: `k <= n <= 21` for trailing zeros, `0 < n <= 21` for decimal within digits, `-6 < n <= 0` for small decimals, else exponential. Correct.
- Exponential format uses `"e+"` or `"e-"` (line 156). Matches V8. Correct.
- `-0.0` is pre-rejected by `_check_no_special_floats` before reaching this function. Correct.

**(b) TypeScript `stableStringify` key sorting vs Python `_stable_stringify`:**

TypeScript (bridge.ts:76): `Object.keys(obj).sort()` — default lexicographic sort by code point.
Python (signing.py:194): `sorted(value.keys())` — default lexicographic sort by code point.
Both use `JSON.stringify(k)` / `json.dumps(k, ensure_ascii=False)` for key strings.
Both recurse identically on values. Both handle arrays, null, booleans, strings, and numbers consistently.

Key sort order: identical. Nested object handling: identical. Separator handling: both use compact `","` and `":"` with no whitespace. Confirmed consistent.

---

## 3. CALL SITE COVERAGE

**Original vulnerable call sites:**

- `bridge.ts` line 131 (now 139): WAS `JSON.stringify(commitmentPayload)` → NOW `stableStringify(commitmentPayload)`. FIXED. ✓
- `bridge.ts` line 189 (now 199): WAS `JSON.stringify(commitmentPayload)` → NOW `stableStringify(commitmentPayload)`. FIXED. ✓
- `sanctuary_bridge.py` line 113 (now 115): WAS `json.dumps(agreement, sort_keys=True, separators=(",",":"))` → NOW `canonical_json(agreement).decode("utf-8")`. FIXED. ✓

**Residual `JSON.stringify` in Sanctuary `server/src/`:** I grepped the entire source tree. 56 remaining `JSON.stringify` calls exist — all are in non-signature contexts: config file serialization, audit log encryption, dashboard HTTP responses, storage serialization, webhook payloads, router error formatting, and HTML template embedding. None of these are on commitment signing, verification, or hash computation paths. The `JSON.stringify` calls within `stableStringify` itself (lines 69, 71, 77) are intentional — they format individual primitives and keys, not full objects. CLEAN.

**Residual `json.dumps` in Concordia `concordia/`:** 80+ remaining `json.dumps` calls — all in `mcp_server.py` for MCP tool response formatting (human-readable output to the agent harness). These are display-layer serialization, not signing or commitment computation. The only `json.dumps` in `signing.py` is within `_stable_stringify` (lines 190, 196) for individual string values with `ensure_ascii=False`. CLEAN.

---

## 4. CROSS-LANGUAGE TEST VECTORS

**Sanctuary:** 16 new tests in `bridge.test.ts` within `cross-language canonical JSON vectors (SEC-003)` describe block. Includes 14 shared vectors in a single test (`matches shared cross-language test vectors`) that assert exact string equality (`expect(ss(input)).toBe(expected)`). Additional individual tests cover key sorting, nesting, compact separators, integers, booleans/null, empty structures, string escaping, Unicode preservation, deep nesting, mixed-type arrays, negative zero rejection, NaN rejection, and Infinity rejection.

**Concordia:** 16 test methods in `TestCrossLanguageCanonicalJSON` class + 2 tests in `test_sanctuary_bridge.py` (unicode preservation and integer formatting) + 1 additional `test_ecmascript_number_formatting` = 19 total. The class includes 13 shared vectors that assert exact byte equality (`assert canonical_json(data) == expected` where expected is a byte literal).

**Divergence point coverage:**
- Number formatting: Covered (integer, float, negative, zero)
- Unicode: Covered (café, 你好世界, emoji ☺)
- Negative zero: Covered (rejection tests)
- Sorted keys: Covered (alphabetical, nested)
- undefined/None: Not directly tested cross-language (accepted — no practical divergence exists)

**Byte-identical assertions:** Both repos assert exact string/byte equality against hardcoded expected values. The shared vectors use identical expected strings in both repos. Confirmed.

**Edge cases:**
- Empty objects/arrays: Covered ✓
- Nested structures: Covered (3+ levels) ✓
- Unicode: Covered (Latin, CJK, emoji) ✓
- Floats/integers: Covered ✓
- Negative zero rejection: Covered ✓
- NaN/Infinity rejection: Covered ✓
- Control characters: Covered (newline, quote, backslash) ✓
- Mixed-type arrays: Covered ✓

**Minor discrepancy:** Shared vector count differs — Sanctuary has 14 vectors in the batch test, Concordia has 13 vectors. The SPRINT_RESULT claims "14 vectors in both repos." I verified the Sanctuary batch has 14 entries and the Concordia batch has 13. The extra vector in Sanctuary is `{ mix: [null, true, "a", 1, {k: "v"}] }` which is covered by a separate individual test in Concordia. Coverage is equivalent but not structurally identical. Non-blocking.

---

## 5. MIGRATION IMPACT

**Claim:** Zero migration impact because no production signatures exist.

**Verification:**
- Sanctuary `security-review` is NOT merged to `main`. Confirmed: `git merge-base --is-ancestor security-review main` returns false.
- Concordia `security-review` is NOT merged to `main`. Confirmed: same check returns false.
- Concordia stores all data in-memory (Python dicts). No persistent database exists. No signatures survive process restart.
- Sanctuary's bridge commitment tests create fresh commitments each run — no stored fixtures with pre-computed signatures.
- No `.enc` files or serialized signature fixtures in either repo's test directories that would be invalidated by the format change.

Claim verified. Zero migration impact is accurate.

---

## 6. COMMIT SCOPE

**Sanctuary commit `82f3321`:**

Expected (per sprint contract): `bridge.ts`, new test file, `SPRINT_CONTRACT.md`, `SPRINT_RESULT.md` — 4 files.

Actual: 8 files.
- `server/src/bridge/bridge.ts` ✓ (expected)
- `server/test/bridge/bridge.test.ts` ✓ (expected)
- `SPRINT_CONTRACT.md` ✓ (expected)
- `SPRINT_RESULT.md` ✓ (expected)
- `server/src/bridge/tools.ts` ⚠️ UNEXPECTED — adds `_content_trust: "external"` tag (SEC-ADD-03)
- `server/src/handshake/tools.ts` ⚠️ UNEXPECTED — adds `_content_trust: "external"` tags
- `server/src/l4-reputation/tools.ts` ⚠️ UNEXPECTED — adds `_content_trust: "external"` tag
- `server/test/security/prompt-injection-tagging.test.ts` ⚠️ UNEXPECTED — new test file for SEC-ADD-03

**Finding: 4 extra files from a different finding (SEC-ADD-03 / prompt injection output tagging) were bundled into this commit.** The changes are small (3 one-line metadata additions + 1 new test file), non-destructive, and don't interact with the SEC-003 fix. However, this violates the sprint discipline rule: "Do not bundle two findings into one sprint." The SEC-ADD-03 changes should have been in a separate commit.

**Concordia commit `bc615ad`:**

Expected (per user's list): `signing.py`, `sanctuary_bridge.py`, new test file, `SPRINT_CONTRACT.md`, `SPRINT_RESULT.md` — 5 files.

Actual: 6 files.
- `concordia/signing.py` ✓
- `concordia/sanctuary_bridge.py` ✓
- `tests/test_signing.py` ✓ (new test file)
- `SPRINT_CONTRACT.md` ✓
- `SPRINT_RESULT.md` ✓
- `tests/test_sanctuary_bridge.py` — additional file, but listed in the sprint contract as a file to modify. Contains 2 regression tests for the SEC-003 fix. This is within scope.

**Concordia scope: CLEAN.** All 6 files are within the sprint contract's declared scope.

---

## 7. TEST SUITE RESULTS

**Sanctuary:** 303 passed, 0 failed. Baseline was 287, +16 new. ✓
**Concordia:** 517 passed, 0 failed. Baseline was 483, +34 new. ✓

---

## Observations (Non-Blocking)

1. **Sanctuary commit bundles SEC-ADD-03 changes.** The 4 extra files add `_content_trust: "external"` metadata to bridge, handshake, and reputation tool responses. These are small, non-destructive additions from a different finding. The SEC-003 fix itself is correct and complete. However, the bundled changes should be noted for audit trail integrity. Recommend: if SEC-ADD-03 gets its own sprint evaluation, the evaluator should note the fix commit is `82f3321` (shared with SEC-003).

2. **Test helper `stableStringify` in bridge.test.ts is a simplified copy.** It lacks the `-0` rejection and `NaN`/`Infinity` rejection present in the production `stableStringify`. The SPRINT_RESULT correctly notes this as a cleanup item. Not a security issue — tests that need rejection behavior call `canonicalize()` directly.

3. **Shared vector count mismatch.** Sanctuary has 14 batch vectors, Concordia has 13. The SPRINT_RESULT claims "14 vectors in both repos." The missing vector in Concordia's batch (`mix` array) is covered by a separate test. Coverage is equivalent but the claim is slightly inaccurate.

---

## Grade: CONDITIONAL PASS

**Condition:** The SEC-ADD-03 changes bundled in Sanctuary commit `82f3321` are out of scope for the SEC-003 sprint. This is a process violation (bundling two findings), not a correctness issue. The SEC-003 fix itself is complete and correct across both repos.

**To reach unconditional PASS:** Acknowledge that SEC-ADD-03's fix commit is `82f3321` and log it in COWORK_CONTEXT.md as sharing a commit with SEC-003. No code changes required — the fix is functionally correct. This is a bookkeeping condition only.

All five divergence points are addressed. Canonical format implementation is correct. All three vulnerable call sites are fixed with no residual vanilla serialization on signature paths. Test vectors cover the identified divergence points with byte-identical assertions. Migration impact is zero (verified). Test suites pass at 303/303 and 517/517.

---

## Condition Closure

Condition resolved: SEC-ADD-03 prompt injection tagging changes are bundled in fix commit `82f3321`. Changes are non-destructive and do not affect SEC-003 correctness. SEC-ADD-03 fix commit is logged as `82f3321` (shared). Sprint discipline violation noted in RETROSPECTIVES.md.
