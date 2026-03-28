# SPRINT_RESULT.md — SEC-002: Flip Approval Gate Default to Deny

**Date:** 2026-03-28
**Finding:** SEC-002 — Webhook Auto-Approve on Timeout Is Configurable and Inverts the Security Model
**Branch:** `security-review`

---

## WHAT WAS CHANGED AND WHY

### The vulnerability

All three approval channels (stderr, webhook, dashboard) accepted an `auto_deny` boolean config option. When set to `false`, any timed-out approval request — including Tier 1 operations like `state_export`, `state_import`, `identity_rotate`, and `reputation_import` — was auto-approved instead of denied. This inverted the entire security model: an unreachable approval endpoint caused the gate to open rather than close.

### The fix

Seven source files and four test files were modified. The `auto_deny` configuration option is now inert — all three channels unconditionally return `decision: "deny"` on timeout, regardless of any configuration value.

### Files modified

**Source files:**

| File | Change |
|------|--------|
| `server/src/principal-policy/types.ts` | Made `auto_deny` optional (`auto_deny?: boolean`) with a SEC-002 doc comment explaining it is ignored. |
| `server/src/principal-policy/approval-channel.ts` | Removed the `if (this.config.auto_deny)` / `else` branch (lines 59-71). Replaced with unconditional `decision: "deny"`. Updated format prompt to say "Auto-denying on timeout (hardcoded — not configurable)". |
| `server/src/principal-policy/webhook.ts` | Made `auto_deny` optional in `WebhookConfig`. Replaced `this.config.auto_deny ? "deny" : "approve"` with unconditional `"deny"` (line 179). |
| `server/src/principal-policy/dashboard.ts` | Made `auto_deny` optional in `DashboardConfig`. Replaced `this.config.auto_deny ? "deny" : "approve"` with unconditional `"deny"` (line 184). Changed SSE init and status API responses to report `auto_deny: true` (hardcoded). |
| `server/src/principal-policy/loader.ts` | Removed `auto_deny: true` from `DEFAULT_CHANNEL`. Added `delete merged.auto_deny` in `validatePolicy()` so user-supplied `auto_deny: false` is stripped from parsed policies. Removed `auto_deny: true` from generated default YAML, added comment explaining timeout always denies. |
| `server/src/principal-policy/tools.ts` | Changed policy view response to report `auto_deny: true` (hardcoded) instead of reading from policy object. |
| `server/src/index.ts` | Removed `auto_deny: policy.approval_channel.auto_deny` from both DashboardApprovalChannel and WebhookApprovalChannel constructor calls (lines 455, 469). |

**Test files:**

| File | Change |
|------|--------|
| `server/test/principal-policy/webhook.test.ts` | Replaced "auto-approves on timeout when auto_deny is false" test with "denies on timeout even when auto_deny is false (SEC-002)" — now asserts `decision: "deny"`. |
| `server/test/principal-policy/dashboard.test.ts` | Same replacement pattern — auto-approve test replaced with deny assertion. |
| `server/test/principal-policy/policy-loader.test.ts` | Four assertions updated: tests that checked `auto_deny` is preserved from YAML/JSON now assert `auto_deny` is `undefined` (stripped). DEFAULT_POLICY test updated to assert `auto_deny` is `undefined`. |
| `server/test/security/sec-002-auto-deny-hardcoded.test.ts` | **New file.** 9 regression tests covering all three channels and the policy parser. |

---

## FULL TEST SUITE OUTPUT

```
 Test Files  23 passed (23)
      Tests  236 passed (236)
   Start at  11:09:46
   Duration  20.13s
```

- **Before sprint:** 227 tests passing.
- **After sprint:** 236 tests passing (227 original + 9 new regression tests).
- **Zero failures.**

All 9 new tests in `sec-002-auto-deny-hardcoded.test.ts` pass:

1. StderrApprovalChannel denies on timeout with default config ✓
2. StderrApprovalChannel denies on timeout even if auto_deny explicitly set to false ✓
3. WebhookApprovalChannel denies on timeout even when auto_deny was historically false ✓
4. WebhookApprovalChannel denies on timeout with no auto_deny field ✓
5. DashboardApprovalChannel denies on timeout even when auto_deny was historically false ✓
6. DashboardApprovalChannel denies on timeout with no auto_deny field ✓
7. Policy parser ignores auto_deny: false in YAML policy ✓
8. Policy parser ignores auto_deny: false in JSON policy ✓
9. DEFAULT_POLICY does not set auto_deny ✓

---

## CALLERS THAT REQUIRED ADJUSTMENT

### Test callers (3 files, updated in this sprint):

- `webhook.test.ts`: Test "auto-approves on timeout when auto_deny is false" asserted `decision: "approve"`. **Updated** to assert `decision: "deny"`.
- `dashboard.test.ts`: Same pattern. **Updated** to assert `decision: "deny"`.
- `policy-loader.test.ts`: Four assertions checked that `auto_deny: false` was preserved in parsed policy. **Updated** to assert `auto_deny` is `undefined` (stripped by parser).

### Production callers (no behavioral change required):

- `index.ts` lines 455, 469: Passed `policy.approval_channel.auto_deny` to constructors. **Removed** the property from constructor calls. Since the field is now optional and ignored, the constructors work without it.
- `tools.ts` line 51: Reported `auto_deny` from policy. **Changed** to report hardcoded `true`.
- `dashboard.ts` lines 332, 377: Reported `auto_deny` in SSE/status. **Changed** to report hardcoded `true`.

### No production code relied on `auto_deny: false` for correct operation.

The default policy has always been `auto_deny: true`. The `false` option was a configurable escape hatch that no internal code path ever used. Only a user editing their policy YAML could set it.

---

## NEW RISK INTRODUCED BY THE FIX

### Minimal new risk:

1. **Backward compatibility:** Existing policy YAML files with `auto_deny: false` will silently have the field stripped. The field is not rejected with an error — it is quietly ignored. This is intentional: the safe default wins, and a validation error could prevent a server from starting.

2. **No auto-approve escape hatch exists.** The REMEDIATION_PLAN suggests a future `SANCTUARY_DANGEROUSLY_AUTO_APPROVE=true` environment variable for extraordinary cases. This sprint does not implement that. If a deployment genuinely needs auto-approve (which should be near-zero), there is currently no supported way to get it. This is the correct trade-off for a security fix.

3. **The `auto_deny` field still exists in the TypeScript interfaces** (as optional). It is not fully removed because: (a) removing it would require touching every test and constructor that currently passes it, even as `true`, and (b) existing policy files may contain it. The field is inert — its value is never read. A follow-up cleanup sprint could remove it entirely.

---

## ADJACENT CODE NOTICED — SEPARATE FINDINGS

The following issues were observed during this sprint but are **out of scope and not fixed here**:

1. **SEC-016 (already filed):** The stderr approval channel auto-resolves after 100ms (line 57 of `approval-channel.ts`). Even with the SEC-002 fix, the stderr channel never actually reads human input — it always auto-denies after 100ms. This means the stderr channel is not a real interactive gate in any configuration. The fix here makes it safe (deny on timeout), but it is still not interactive.

2. **`ProgrammaticApprovalChannel` (approval-channel.ts:107-124):** This channel accepts a callback function that can return any decision, bypassing the hardcoded deny. This is by design (it's for testing and API integration), but it means the "all channels always deny on timeout" invariant technically only applies to the three user-facing channels. The programmatic channel is not exposed to end users.

3. **Dashboard and webhook still accept `auto_deny` in their config interfaces** as an optional field. A thorough cleanup would remove the field entirely from all interfaces, constructors, and test sites. This sprint retains it as optional+ignored for minimal diff and backward compat.

---

## SPRINT CONTRACT CRITERIA ASSESSMENT

| Criterion | Status | Evidence |
|-----------|--------|----------|
| No channel can auto-approve on timeout | **PASS** | All three channels hardcode `decision: "deny"`. The conditional branch is removed. 9 regression tests confirm. |
| `auto_deny` config option is inert | **PASS** | `validatePolicy()` deletes `auto_deny` from parsed policies. Channel timeout logic does not read the field. |
| Regression test exists and passes | **PASS** | `sec-002-auto-deny-hardcoded.test.ts`: 9 tests, all passing. |
| Full test suite passes (≥227) | **PASS** | 236 tests passing (227 + 9 new). Zero failures. |
| No silent caller breakage | **PASS** | All callers audited and updated. Updated tests explicitly assert the new behavior. |
| Backward compatibility for existing policy files | **PASS** | `auto_deny: false` in YAML/JSON is silently stripped (no parse error, no crash). |

**Overall assessment: All sprint contract criteria are met. PASS.**
