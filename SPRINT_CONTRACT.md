# SPRINT CONTRACT — SEC-016: Stderr Approval Channel Auto-Resolves in 100ms

**Sprint Date:** 2026-03-28
**Finding:** SEC-016 (High)
**Branch:** `security-review`
**Implementer:** Claude (sprint session)

---

## Step 2 — Architecture Decision

### a) Root Cause

The `StderrApprovalChannel.requestApproval()` method (approval-channel.ts:45-66) uses a 100ms `setTimeout` before returning its response. This creates two problems:

1. **The 100ms delay serves no purpose.** The channel never reads any input — the setTimeout is cosmetic. It creates the illusion of waiting for a response that can never arrive. In the MCP stdio transport model, stdin is consumed by the MCP JSON-RPC protocol and is not available for interactive human input.

2. **The timing window is a latent risk.** While SEC-002 hardened the return value to always be `"deny"`, the 100ms async gap between the stderr write and the resolution is unnecessary attack surface. Any future code that races against this Promise (e.g., a concurrent channel fallback, a middleware that interprets "no response yet" as approval) has a 100ms window to exploit. The webhook and dashboard channels have legitimate timeout windows because they are waiting for real human input. The stderr channel is waiting for nothing.

The root cause is: **the stderr channel was implemented as a timeout-based channel mimicking the webhook/dashboard pattern, but it has no input mechanism to justify a timeout.**

### b) Smallest Change That Closes the Vulnerability

Remove the `setTimeout` entirely. The stderr channel should:
- Write the informational prompt to stderr (preserved — the human still sees what's happening)
- Return `decision: "deny"` immediately and synchronously (no async gap)
- Document clearly in the prompt text and code comments that this is a non-interactive channel

This is Option B from REMEDIATION_PLAN.md HP-11: remove the fake timeout, always deny, document the limitation. Option A (reading stdin) is infeasible because stdin is consumed by MCP protocol.

### c) Interaction with Other Findings

**SEC-002 (Critical, PASS):** SEC-002 hardened all three approval channels so that timeout always results in denial. The SEC-002 fix for the stderr channel changed the return value from `this.config.auto_deny ? "deny" : "approve"` to a hardcoded `"deny"`. This sprint completes the hardening by eliminating the timing window itself. After this fix, the stderr channel has zero async gap — it denies synchronously. This is strictly stronger than SEC-002's invariant ("timeout always denies") because there is no timeout to exploit at all.

**SEC-019 (pending):** No interaction. Config validation is a separate concern.

**SEC-012 (PASS):** No interaction. Dashboard auth token is a separate channel.

### d) New Risk Introduced

Minimal. The behavioral change is:
- Before: deny after 100ms async delay
- After: deny immediately (synchronous)

Any code depending on the 100ms delay for stderr flushing would be affected, but `process.stderr.write()` is synchronous in Node.js — it does not need an async flush window. The prompt is displayed before the denial is returned regardless.

---

## Step 3 — Sprint Contract

### Fix Chosen

Remove the 100ms `setTimeout` from `StderrApprovalChannel.requestApproval()`. Replace with synchronous deny-on-call. Update the prompt text to explicitly state this is a non-interactive channel. Update code comments to document the SEC-002 and SEC-016 invariants. Change `decided_by` from `"timeout"` to `"stderr:non-interactive"` to distinguish from legitimate timeouts in webhook/dashboard channels.

### Files Modified

| File | Change |
|------|--------|
| `server/src/principal-policy/approval-channel.ts:45-66` | Remove setTimeout, return deny synchronously, update prompt text, update decided_by |
| `server/test/security/sec-016-stderr-always-denies.test.ts` | New: regression tests for SEC-016 |

### Behavior Before and After

**Before:**
- `requestApproval()` writes prompt to stderr
- Waits 100ms via `setTimeout`
- Returns `{ decision: "deny", decided_by: "timeout" }` after 100ms

**After:**
- `requestApproval()` writes prompt to stderr
- Returns `{ decision: "deny", decided_by: "stderr:non-interactive" }` immediately (no async delay)
- Prompt text includes: "Non-interactive channel — operation denied automatically"

### Regression Tests

1. **stderr channel always denies Tier 1 operations** — create a StderrApprovalChannel, call requestApproval with a Tier 1 operation, assert decision is "deny" and decided_by is "stderr:non-interactive".
2. **stderr channel denies immediately (no timing window)** — measure the wall-clock time of requestApproval, assert it completes in <10ms (no 100ms delay).
3. **stderr channel ignores auto_deny config** — create a channel with `auto_deny: false`, confirm it still denies (SEC-002 interaction).
4. **stderr channel denies Tier 2 operations identically** — same as test 1 but with tier 2.

### Definition of Done

The evaluator will verify:
1. The `setTimeout` / `100ms` delay is completely removed from the stderr channel
2. The channel returns deny synchronously with no async gap
3. `decided_by` clearly identifies the decision as a non-interactive channel denial (not a "timeout")
4. The SEC-002 invariant is preserved: no configuration can cause the stderr channel to approve
5. All 4 regression tests pass
6. Full test suite count >= 261 (no decrease)

### Prompt Injection Assessment

This fix does not touch any input/output path that processes user-controlled or agent-controlled text. The stderr channel writes a formatted prompt string constructed from system-internal `ApprovalRequest` fields (operation name, tier, reason). These fields originate from the gate evaluation logic, not from external input. No prompt injection surface is introduced or modified.
