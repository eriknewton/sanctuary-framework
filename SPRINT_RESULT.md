# SPRINT_RESULT.md — SEC-001: Require Explicit Approval for state_delete

**Date:** 2026-03-28
**Finding:** SEC-001 — Secure Deletion Is Tier 3 (Auto-Allow): Agent Can Irreversibly Destroy All User State Without Confirmation
**Branch:** `security-review`

---

## WHAT WAS CHANGED AND WHY

### The vulnerability

`state_delete` was classified as Tier 3 (auto-allow) in the default Principal Policy (`loader.ts:50`). The `state_delete` tool performs a 3-pass random overwrite before unlinking — an irreversible secure deletion. Because it was Tier 3, no human approval was required. A compromised or prompt-injected agent could enumerate all namespaces via `state_list` (also Tier 3) and then call `state_delete` on every entry, irreversibly destroying all encrypted state, identities, commitments, reputation, and audit history with zero confirmation.

This directly violated CLAUDE.md §"WHAT THESE TOOLS MUST NEVER DO" #3: "Never execute an irreversible operation without a confirmation gate."

### The fix

`state_delete` was moved from `tier3_always_allow` to `tier1_always_approve` in the default Principal Policy. This is a tier reclassification — the smallest possible change that ensures every `state_delete` call requires explicit human approval before execution.

### Files modified

| File | Change |
|------|--------|
| `server/src/principal-policy/loader.ts` | Added `"state_delete"` to `tier1_always_approve` array in `DEFAULT_POLICY` (line 40). Removed `"state_delete"` from `tier3_always_allow` array (formerly line 50). Same changes mirrored in the generated default YAML string (`generateDefaultPolicyYaml()`). |
| `server/test/principal-policy/approval-gate.test.ts` | Updated `createTestPolicy()` helper: added `"state_delete"` to `tier1_always_approve`, removed it from `tier3_always_allow`. Prevents test/production policy divergence. |
| `server/test/security/sec-001-state-delete-requires-approval.test.ts` | **New file.** 7 regression tests verifying state_delete is Tier 1, requires approval, and integrates correctly with the SEC-002 hardened timeout behavior. |

---

## FULL TEST SUITE OUTPUT

```
 Test Files  24 passed (24)
      Tests  243 passed (243)
   Start at  11:26:39
   Duration  19.84s
```

- **Before sprint:** 236 tests passing (24 test files including SEC-002 regression tests).
- **After sprint:** 243 tests passing (236 original + 7 new SEC-001 regression tests).
- **Zero failures.**

All 7 new tests in `sec-001-state-delete-requires-approval.test.ts` pass:

1. DEFAULT_POLICY includes state_delete in tier1_always_approve ✓
2. DEFAULT_POLICY does NOT include state_delete in tier3_always_allow ✓
3. Gate classifies state_delete as Tier 1 and denies when channel denies ✓
4. Gate allows state_delete when human explicitly approves ✓
5. Gate denies state_delete on stderr channel timeout (SEC-002 integration) ✓
6. Generated default YAML places state_delete in tier1_always_approve ✓
7. User policy YAML with state_delete in both tier1 and tier3 — tier1 wins ✓

---

## SEC-002 INTEGRATION VERIFICATION

The SEC-001 fix was verified to work correctly with the SEC-002 hardened approval gate (commit `7f68d5a`):

- **Test 5** constructs a `StderrApprovalChannel` and calls `gate.evaluate("sanctuary/state_delete", ...)`. The stderr channel auto-denies after 100ms (SEC-002 hardcoded behavior). The test confirms `result.allowed === false` and `result.tier === 1`.
- The SEC-002 regression tests (9 tests in `sec-002-auto-deny-hardcoded.test.ts`) continue to pass unchanged — the SEC-001 fix does not interfere with any SEC-002 behavior.
- All three approval channels (stderr, webhook, dashboard) unconditionally deny on timeout. Since `state_delete` is now Tier 1, it is covered by this unconditional denial.

---

## CALLERS THAT REQUIRED ADJUSTMENT

### Test callers (1 file updated):

- `approval-gate.test.ts`: The `createTestPolicy()` helper had `state_delete` in `tier3_always_allow`. Updated to move it to `tier1_always_approve`. All existing tests in this file continue to pass — none of them specifically tested `state_delete` as a Tier 3 operation.

### Production callers (no changes needed):

- `server/src/l1-cognitive/tools.ts:537-572`: The `state_delete` tool handler is unchanged. The handler itself does not know or care about its tier classification — tier gating is applied by the router/gate wrapper before the handler executes.
- `server/src/principal-policy/gate.ts`: No changes. The gate's `evaluate()` method checks `tier1_always_approve` first (line 59), which now catches `state_delete` before it can reach the Tier 3 fallthrough.
- `server/src/storage/filesystem.ts:69-102`: The 3-pass secure overwrite implementation is unchanged.

---

## NEW RISK INTRODUCED BY THE FIX

### Minimal new risk:

1. **Existing policy YAML files.** Users who have already generated a `principal-policy.yaml` from a pre-fix version of Sanctuary will have `state_delete` listed under `tier3_always_allow` and NOT under `tier1_always_approve`. The DEFAULT_POLICY constant is only used when no policy file exists. For existing deployments, the user must manually move `state_delete` from Tier 3 to Tier 1 in their policy YAML, or delete their policy file to regenerate from the new defaults. This is documented behavior — the policy file is user-owned.

2. **Agent workflows that rely on unattended deletion.** Any agent workflow that calls `state_delete` as part of a cleanup or garbage collection routine will now be blocked by the approval gate. This is the intended behavior change — the whole point of SEC-001 is that deletion should not be unattended. If a deployment needs automated deletion (which is a security-sensitive decision), the operator must configure an approval channel that can respond programmatically (e.g., the webhook channel with an automated approval endpoint).

3. **No behavioral change for other tools.** Only `state_delete` was moved. All other tools remain in their existing tiers. The `tier3_always_allow` list still contains 32 operations (down from 33).

---

## ADJACENT FINDINGS NOTICED — NOT FIXED IN THIS SESSION

1. **SEC-011 (already filed, Medium → reclassified High in REMEDIATION_PLAN):** The gate default for unlisted operations is Tier 3 (allow). If a new tool is registered without being added to any tier list, it auto-allows. This is the inverse of SEC-001: SEC-001 was a known tool in the wrong tier; SEC-011 is about unknown tools getting the permissive default. The safe default should be deny (Tier 1 or Tier 2), not allow (Tier 3).

2. **The `state_delete` tool description says "Securely delete state" but the input schema does not expose a `secure_delete` boolean parameter.** The SECURITY_AUDIT.md (SEC-001) references `secure_delete: true` as a parameter, but the actual tool schema (`tools.ts:541-548`) only has `namespace`, `key`, and `reason`. The handler at `tools.ts:560` always calls `stateStore.delete()` which always performs the 3-pass overwrite. There is no non-secure deletion mode. This is a documentation/audit discrepancy, not a code bug — the tool is actually more secure than the audit assumed (every deletion is secure), but the audit text is misleading.

3. **The `state_delete` handler does not check `gate.allowed` — the gate wrapping is in the router.** Verified in `router.ts` that the gate wraps all handlers uniformly. This is correct architecture, but worth noting: the handler itself has no self-protection. If a future refactor bypasses the router, the handler would execute without approval.

---

## SPRINT CONTRACT CRITERIA ASSESSMENT

| Criterion | Status | Evidence |
|-----------|--------|----------|
| `state_delete` in `tier1_always_approve` | **PASS** | `loader.ts` line 40: `"state_delete"` is in the array. Regression test 1 confirms. |
| `state_delete` NOT in `tier3_always_allow` | **PASS** | `loader.ts`: `"state_delete"` removed from Tier 3 array. Regression test 2 confirms. |
| Generated default YAML reflects change | **PASS** | `generateDefaultPolicyYaml()` lists `state_delete` in Tier 1 section, not Tier 3. Regression test 6 confirms. |
| Gate classifies as Tier 1 | **PASS** | Regression tests 3-5 confirm `result.tier === 1` and `result.approval_required === true`. |
| Denial on timeout confirmed | **PASS** | Regression test 5 uses StderrApprovalChannel (SEC-002 hardened) and confirms `result.allowed === false`. |
| Regression test exists and passes | **PASS** | `sec-001-state-delete-requires-approval.test.ts`: 7 tests, all passing. |
| No other tool's tier changed | **PASS** | Only `state_delete` was moved. Diff shows exactly two array modifications in `DEFAULT_POLICY` and two in the YAML string. |
| Full test suite passes (≥236) | **PASS** | 243 tests passing (236 + 7 new). Zero failures. |
| `createTestPolicy()` updated | **PASS** | `approval-gate.test.ts` helper now has `state_delete` in Tier 1, not Tier 3. |

**Overall assessment: All sprint contract criteria are met. PASS.**
