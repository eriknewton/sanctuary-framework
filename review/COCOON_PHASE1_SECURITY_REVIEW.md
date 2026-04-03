# Cocoon Phase 1 — Delta Security Review

**Reviewer:** Claude Opus 4.6 (1M context)
**Date:** 2026-04-03
**Scope:** Cocoon Phase 1 merge (commit 0e979ba) — 6 new files, 5 modified files
**Base audit:** SEC-001 through SEC-040 (v0.5.13, commit 346873f)
**Finding IDs:** SEC-041 through SEC-043

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 1 |
| Medium | 1 |
| Low | 1 |
| Info | 0 |
| **Total** | **3** |

**Verdict:** PASS — All 3 findings fixed in commit ff28d12. 722 tests passing (61 sovereignty profile + 661 baseline; 1 pre-existing compile failure in context-gate-enforcer.test.ts is unrelated).

---

## Prior Fix Cross-Reference

| Prior Finding | Status | Notes |
|---------------|--------|-------|
| SEC-002 (auto-deny default) | PASS | New code introduces no new approval channels or timeout behavior |
| SEC-005 (dashboard auth) | PASS | Both new routes (`GET /api/sovereignty-profile`, `POST /api/sovereignty-profile`) execute after `checkAuth()` at line 577 of dashboard.ts |
| SEC-013 (audit logging) | PASS | MCP tools log all 3 operations. Dashboard POST logs with operation `sovereignty_profile_update_dashboard`. Dashboard GET does not log (consistent with other read-only GET endpoints) |
| SEC-036 (dashboard token in HTML) | PASS | New panel uses static HTML elements only. No auth token embedded. JavaScript uses `sessionStorage` for auth via existing `fetchAPI()` pattern |

---

## Findings

### SEC-041 — Reserved namespace `_sovereignty_profile` not in L1 namespace firewall

**Severity:** High
**File:** `server/src/l1-cognitive/tools.ts` (line 36–50), `server/src/l1-cognitive/state-store.ts` (line 44–58)
**Category:** Authorization bypass

**Description:**
The `SovereigntyProfileStore` stores profile data in the `_sovereignty_profile` namespace, which is underscore-prefixed (following the reserved namespace convention). However, this namespace is NOT listed in the `RESERVED_NAMESPACE_PREFIXES` array in either `tools.ts` or `state-store.ts`.

The L1 state tools (`state_read`, `state_write`, `state_list`, `state_delete`) check namespaces against this list. Since `_sovereignty_profile` is absent, an agent can:
1. **Read** the encrypted profile blob via `state_read("_sovereignty_profile", "active")`
2. **Overwrite** the profile with arbitrary data via `state_write("_sovereignty_profile", "active", ...)`
3. **Delete** the profile via `state_delete("_sovereignty_profile", "active")`

While the data is encrypted (AES-256-GCM with a different HKDF domain key than L1 state), overwriting or deleting the profile would force a reset to defaults on next load, and a crafted encrypted payload could potentially be used in a downgrade attack if the attacker also controls the master key (e.g., via export).

**Note:** This same gap exists for `_context_gate_policies` (pre-existing, not introduced by this delta). This finding addresses only the new namespace.

**Impact:** Agent can tamper with or delete the sovereignty profile without Tier 1 approval.

**Remediation:**
Add `"_sovereignty_profile"` to `RESERVED_NAMESPACE_PREFIXES` in both:
- `server/src/l1-cognitive/tools.ts` (line 36)
- `server/src/l1-cognitive/state-store.ts` (line 44)

Also add `"_context_gate_policies"` while we're here (pre-existing gap).

---

### SEC-042 — Dashboard POST `/api/sovereignty-profile` lacks input validation

**Severity:** Medium
**File:** `server/src/principal-policy/dashboard.ts` (line 994)
**Category:** Input validation

**Description:**
The `handleSovereigntyProfileUpdate` handler parses the request body as JSON and passes it directly to `profileStore.update()` without validating the shape or types:

```typescript
const updates: SovereigntyProfileUpdate = JSON.parse(body);
const updated = await this.profileStore!.update(updates);
```

The TypeScript type cast provides no runtime protection. An authenticated dashboard user could send:
- `{ "audit_logging": { "enabled": "yes" } }` — stores a string where a boolean is expected
- `{ "injection_detection": { "sensitivity": "INVALID_VALUE" } }` — stores an invalid sensitivity level
- `{ "context_gating": { "policy_id": "<very long string>" } }` — stores an unbounded string that appears in the generated system prompt

The MCP tool path (`sovereignty_profile_update`) has schema validation via the MCP router's `inputSchema`, but the dashboard path bypasses this entirely.

**Impact:** Type confusion in stored profile. The `policy_id` value is interpolated into the system prompt text without length limits, which could be used to inject content into agent instructions (though the dashboard is auth-gated, limiting the attack surface).

**Remediation:**
Add runtime validation in `SovereigntyProfileStore.update()`:
- Validate `enabled` fields are booleans
- Validate `sensitivity` is one of `"low" | "medium" | "high"`
- Validate `policy_id` length (max 256 characters)

---

### SEC-043 — Body size limit race in dashboard POST handler

**Severity:** Low
**File:** `server/src/principal-policy/dashboard.ts` (line 982–990)
**Category:** Error handling

**Description:**
When the body exceeds 16KB, the handler sends a 413 response and calls `req.destroy()`. However, the `end` event listener is already registered and may still fire with the accumulated (oversized) body, causing `JSON.parse` and `res.writeHead` to execute on an already-ended response. While this would be caught by the outer `try/catch` and would not cause data corruption, it produces an unhandled "write after end" scenario.

**Impact:** Minimal — a caught exception in an edge case. No data corruption or security bypass.

**Remediation:**
Add a `destroyed` flag to prevent the `end` handler from processing after 413.

---

## Trust Boundary Audit

| # | Boundary | Enforcement | Verdict |
|---|----------|-------------|---------|
| 1 | Agent → `sovereignty_profile_update` | Tier 1 in `loader.ts` line 48. Gate evaluated before handler. | PASS |
| 2 | Agent → `sovereignty_profile_get` / `generate_prompt` | Tier 3 in `loader.ts` lines 102–103. No sensitive data leaked (profile contains feature toggles only, no keys/secrets). | PASS |
| 3 | Dashboard POST → profile store | Auth checked (line 577). Rate-limited (line 580). Audit-logged (line 1000). Size-limited (line 986). | PASS (with SEC-042 caveat) |
| 4 | SSE broadcast of profile changes | Broadcast via `broadcastSSE` (line 1009). SSE connections are auth-gated. Payload contains feature toggles and system prompt text only — no keys, secrets, or tokens. | PASS |
| 5 | Profile store encryption | HKDF domain `"sovereignty-profile"` (unique, no collision with other stores). AES-256-GCM via `encrypt()`/`decrypt()`. Reserved namespace `_sovereignty_profile` (but see SEC-041). | PASS (with SEC-041 caveat) |

---

## Files Reviewed

| File | Verdict | Notes |
|------|---------|-------|
| `server/src/sovereignty-profile.ts` | PASS | Correct encryption pattern. HKDF domain separation. No plaintext leak. |
| `server/src/sovereignty-profile-tools.ts` | PASS | All 3 tools audit-logged. Correct tier assignments. No sensitive data in responses. |
| `server/src/system-prompt-generator.ts` | PASS | Pure function. No side effects. No external calls. Policy_id interpolation is text-only (no HTML). |
| `server/src/index.ts` | PASS | Profile store init + tool registration follows existing patterns. |
| `server/src/dashboard-standalone.ts` | PASS | Profile store init follows existing patterns. |
| `server/src/principal-policy/dashboard-html.ts` | PASS | All DOM updates use `.textContent` (XSS-safe). No auth token in HTML. |
| `server/src/principal-policy/dashboard.ts` | See SEC-042, SEC-043 | New routes auth-gated. Rate-limited. Audit-logged. |
| `server/src/principal-policy/loader.ts` | PASS | `sovereignty_profile_update` correctly Tier 1. Get/generate correctly Tier 3. |
| `server/test/sovereignty-profile.test.ts` | PASS | Covers encryption, persistence, defaults, restart survival. |
| `server/test/sovereignty-profile-tools.test.ts` | PASS | Covers all 3 tools, response format, state persistence. |
| `server/test/system-prompt-generator.test.ts` | PASS | Covers all toggle combinations, token budget. |

---

## CLAUDE.md Invariant Check

| Invariant | Status |
|-----------|--------|
| 1. Never transmit user data to external endpoint | PASS — no external calls |
| 2. Never persist data user cannot inspect/export/delete | PASS — profile readable via `sovereignty_profile_get` |
| 3. Never execute irreversible operation without confirmation gate | PASS — `sovereignty_profile_update` is Tier 1 |
| 4. Never assume trust across Sanctuary-Concordia boundary | N/A — no bridge interaction |
| 5. Never silently degrade to less-secure behavior on error | PASS — corrupted profile falls back to secure defaults (audit + injection ON) |
| 6. Never expose private keys in any response | PASS — profile contains only feature toggles |
| 7. Never allow agent to read/modify Principal Policy at runtime | PASS — profile is a separate store; policy is unchanged |
| 8. Never allow attestations to include raw deal terms | N/A — no attestation interaction |
