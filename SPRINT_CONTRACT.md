# SPRINT_CONTRACT.md — SEC-001: Require Explicit Approval for state_delete

**Date:** 2026-03-28
**Finding:** SEC-001 — Secure Deletion Is Tier 3 (Auto-Allow): Agent Can Irreversibly Destroy All User State Without Confirmation
**Branch:** `security-review`
**Severity:** Critical
**Predecessor:** SEC-002 (already fixed in commit `7f68d5a`; approval gate now unconditionally denies on timeout)

---

## FILES TO MODIFY

### Source Files

1. **`server/src/principal-policy/loader.ts` line 50** — Remove `"state_delete"` from the `tier3_always_allow` array (line 50 of `DEFAULT_POLICY`).
2. **`server/src/principal-policy/loader.ts` line 38-44** — Add `"state_delete"` to the `tier1_always_approve` array in `DEFAULT_POLICY`.
3. **`server/src/principal-policy/loader.ts` line 246** — Remove `state_delete` from the Tier 3 section of the generated default YAML, and add it to the Tier 1 section.

### Test Files

4. **`server/test/principal-policy/approval-gate.test.ts` line 37** — Remove `"state_delete"` from the `tier3_always_allow` array in the `createTestPolicy()` helper. The test policy must reflect the production policy change to avoid test/production divergence.
5. **New file: `server/test/security/sec-001-state-delete-requires-approval.test.ts`** — Regression test (see below).

---

## BEHAVIOR BEFORE THE FIX

When an agent calls `state_delete` (registered as `sanctuary/state_delete` in `server/src/l1-cognitive/tools.ts:537`):

1. The MCP router passes the call to `ApprovalGate.evaluate()`.
2. The gate checks `tier1_always_approve` — `state_delete` is NOT listed. Skips Tier 1.
3. The gate checks Tier 2 anomaly detection — `state_delete` IS in `tier3_always_allow` (line 50 of `loader.ts`), so the first-session check at `gate.ts:98` passes it through.
4. The gate falls through to Tier 3 (line 72-83 of `gate.ts`): **auto-allow with audit logging only**.
5. The handler in `tools.ts:550-572` executes the deletion immediately. The `stateStore.delete()` call at `tools.ts:560` performs a 3-pass random overwrite (via `filesystem.ts:69-102`) before unlinking the file. This is irreversible.

**Result:** A compromised or prompt-injected agent can call `state_list` to enumerate all namespaces/keys, then call `state_delete` on every entry. All encrypted state — identities, commitments, reputation, audit history — is irreversibly destroyed with zero human confirmation.

The Tier 2 frequency spike detector might eventually fire after multiple rapid calls, but: (a) by that time significant data is already destroyed, and (b) on the first session (where no baseline exists), the frequency spike check has no reference point for `state_delete` because it is in the Tier 3 list and bypasses the first-session gate at `gate.ts:96-98`.

---

## BEHAVIOR AFTER THE FIX

When an agent calls `state_delete`:

1. The MCP router passes the call to `ApprovalGate.evaluate()`.
2. The gate checks `tier1_always_approve` — `state_delete` IS listed. **Tier 1 match.**
3. The gate calls `this.requestApproval(operation, 1, ...)` which sends an approval request through the configured approval channel (stderr, webhook, or dashboard).
4. **If the human approves:** The gate returns `{ allowed: true, tier: 1, approval_required: true }` and the deletion proceeds.
5. **If the human denies or the channel times out:** The gate returns `{ allowed: false, tier: 1 }`. The deletion does NOT execute. Per SEC-002 (already fixed), timeout **always** results in denial — there is no `auto_deny: false` escape hatch.

**Result:** Every `state_delete` call — whether normal unlink or 3-pass secure overwrite — requires explicit human approval before execution. A compromised agent cannot destroy any state without the human principal authorizing each deletion.

---

## WHY TIER 1 (NOT JUST REMOVING AUTO_ALLOW)

The REMEDIATION_PLAN (CP-01) suggests either moving `state_delete` to Tier 1 or splitting into `state_delete` (Tier 3) and `state_secure_delete` (Tier 1). This sprint chooses **moving the entire `state_delete` operation to Tier 1** for the following reasons:

1. **Even non-secure deletion is destructive.** The current `state_delete` handler in `tools.ts:550-572` always calls `stateStore.delete()`, which always performs the 3-pass secure overwrite (per `filesystem.ts:77-87`). There is no "soft delete" mode — every deletion is irreversible. Moving only a `secure_delete: true` variant to Tier 1 would be meaningless because the tool always does secure deletion.

2. **Splitting the tool is a larger change.** Creating a new `state_secure_delete` tool would require: a new MCP tool registration, new handler, schema changes, router changes, and updates to the tool manifest. That is out of scope for a minimal security fix.

3. **Consistency with the security model.** CLAUDE.md states: "Never execute an irreversible operation without a confirmation gate." Deletion of encrypted state is irreversible. Tier 1 is the correct classification.

4. **The `state_delete` tool description already says "Securely delete"** (tools.ts:538-540). The tool was always intended to perform secure deletion.

---

## INTERACTION WITH SEC-002 FIX

The SEC-002 fix (commit `7f68d5a`) hardcoded all approval channels to deny on timeout. This means:

- **Stderr channel:** Auto-denies after 100ms. `state_delete` will be denied unless a real interactive channel is configured.
- **Webhook channel:** Denies on timeout. If the webhook endpoint is unreachable, `state_delete` is denied.
- **Dashboard channel:** Denies on timeout. If the human doesn't respond, `state_delete` is denied.

The SEC-001 fix is fully consistent with SEC-002: moving `state_delete` to Tier 1 means the SEC-002 hardened timeout behavior protects it. There is no configuration that can cause `state_delete` to auto-approve on timeout.

---

## REGRESSION TEST

**File:** `server/test/security/sec-001-state-delete-requires-approval.test.ts`

**What the test asserts:**

1. **state_delete is classified as Tier 1 in DEFAULT_POLICY.** `DEFAULT_POLICY.tier1_always_approve` includes `"state_delete"`. `DEFAULT_POLICY.tier3_always_allow` does NOT include `"state_delete"`.

2. **state_delete requires approval through the gate.** Construct an `ApprovalGate` with a `CallbackApprovalChannel` that records requests and denies. Call `gate.evaluate("sanctuary/state_delete", { namespace: "test", key: "test" })`. Assert: `result.tier === 1`, `result.approval_required === true`, `result.allowed === false`.

3. **state_delete is allowed when the human approves.** Construct an `ApprovalGate` with an `AutoApproveChannel`. Call `gate.evaluate("sanctuary/state_delete", ...)`. Assert: `result.tier === 1`, `result.approval_required === true`, `result.allowed === true`.

4. **state_delete is denied on channel timeout.** Construct an `ApprovalGate` with a `StderrApprovalChannel` (which auto-denies after 100ms). Call `gate.evaluate("sanctuary/state_delete", ...)`. Assert: `result.allowed === false`, `result.approval_required === true`.

5. **state_delete is not in tier3_always_allow.** Verify that the parsed default policy YAML does not list `state_delete` in the Tier 3 array.

6. **Generated default YAML lists state_delete in Tier 1.** Parse the generated default YAML and verify `state_delete` appears in `tier1_always_approve`.

---

## DEFINITION OF DONE

The evaluator will grade this sprint PASS if and only if ALL of the following hold:

1. **`state_delete` is in `tier1_always_approve` in `DEFAULT_POLICY`.** The constant in `loader.ts` must include `"state_delete"` in the Tier 1 array.

2. **`state_delete` is NOT in `tier3_always_allow` in `DEFAULT_POLICY`.** The constant in `loader.ts` must not include `"state_delete"` in the Tier 3 array.

3. **The generated default YAML reflects the change.** `state_delete` appears in the Tier 1 section, not the Tier 3 section.

4. **The approval gate classifies `state_delete` as Tier 1.** When `gate.evaluate("sanctuary/state_delete", ...)` is called, the result has `tier: 1` and `approval_required: true`.

5. **Denial on timeout is confirmed.** With the SEC-002 hardened channels, a timed-out `state_delete` approval request results in `allowed: false`.

6. **Regression test exists and passes.** `server/test/security/sec-001-state-delete-requires-approval.test.ts` contains tests covering criteria 1-5.

7. **No other tool's tier classification is changed.** Only `state_delete` moves. All other tools remain in their current tier.

8. **Full test suite passes.** 236 tests were passing before this sprint. After the fix, the count must be >= 236 (may increase due to new regression tests). Zero failures.

9. **The approval-gate test helper `createTestPolicy()` is updated.** `state_delete` must not appear in `tier3_always_allow` in the test helper, preventing test/production divergence.
