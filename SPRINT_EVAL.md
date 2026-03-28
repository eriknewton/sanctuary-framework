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
