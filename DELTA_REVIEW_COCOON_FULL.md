# Delta Security Review — Cocoon Full Build (v0.5.15)

**Date:** 2026-04-03
**Scope:** 5,504 new/modified lines across Parts A–D (dashboard UX, MCP proxy, injection hardening, runtime governance)
**Baseline:** v0.5.14 (867 tests passing)
**Verdict:** PASS (after remediation)

---

## Files Reviewed

### Part A — Dashboard UX & System Prompt Generator
- `server/src/principal-policy/dashboard-html.ts` (825 lines changed)
- `server/src/principal-policy/dashboard.ts` (106 lines changed)
- `server/src/principal-policy/gate.ts` (50 lines added)
- `server/src/principal-policy/loader.ts` (8 lines added)
- `server/src/sovereignty-profile.ts` (61 lines changed)
- `server/src/system-prompt-generator.ts` (132 lines changed)
- `server/src/index.ts` (118 lines changed)

### Part B — MCP Proxy
- `server/src/proxy/client-manager.ts` (368 lines, new file)
- `server/src/proxy/proxy-router.ts` (309 lines, new file)

### Part C — Injection Hardening
- `server/src/security/injection-detector.ts` (742 lines changed)

### Part D — Runtime Governance
- `server/src/l2-operational/call-governor.ts` (365 lines, new file)
- `server/src/l2-operational/governor-tools.ts` (172 lines, new file)

---

## Findings Summary

| ID | Severity | Subsystem | Title | Status |
|----|----------|-----------|-------|--------|
| SEC-044 | **CRITICAL** | Proxy | Command injection via stdio args | **FIXED** |
| SEC-045 | **CRITICAL** | Proxy | Environment variable injection | **FIXED** |
| SEC-046 | **CRITICAL** | Proxy | No validation of upstream response schema | **FIXED** |
| SEC-047 | HIGH | Proxy | Server name collision / namespace squatting | **FIXED** |
| SEC-048 | HIGH | Proxy | Tool discovery failure silent degradation | ACCEPTED (defense-in-depth: tools=[]) |
| SEC-049 | HIGH | Proxy | No rate limiting per upstream server | DEFERRED (v0.6.0 — CallGovernor integration) |
| SEC-050a | HIGH | Proxy | Upstream errors passed unfiltered | **FIXED** |
| SEC-050b | HIGH | Injection | Homoglyph coverage gaps (confusable normalization) | **FIXED** |
| SEC-051 | HIGH | Injection | Incomplete invisible character detection | **FIXED** |
| SEC-052 | MEDIUM | Injection | HTML entity decoding ReDoS potential | ACCEPTED (input size capped) |
| SEC-053 | MEDIUM | Injection | Secret pattern regex global flag state pollution | **FIXED** |
| SEC-054 | MEDIUM | Injection | Token budget analysis encoding heuristic | ACCEPTED (defense-in-depth only) |
| SEC-055 | LOW | Injection | Token accumulation overflow risk | **FIXED** (1MB cap) |
| SEC-056 | HIGH | Governor | Governor reset missing internal Tier 1 gate | ACCEPTED (router enforces T1) |
| SEC-057 | **CRITICAL** | Profile | Approval gate exposed as toggleable feature | **FIXED** |
| SEC-058 | HIGH | Loader | Missing Tier 3 classification for generate_prompt | **FIXED** |
| SEC-059 | MEDIUM | Loader | Governor status Tier classification | ACCEPTED (status is read-only) |
| SEC-060 | HIGH | Profile | Upstream server tool_overrides design risk | DEFERRED (v0.6.0) |
| SEC-061 | HIGH | Dashboard | XSS via insertAdjacentHTML | NOT VULNERABLE (esc() already applied) |
| SEC-062 | MEDIUM | Profile | Unbounded upstream server config | DEFERRED (v0.6.0) |

---

## Critical Fixes Applied

### SEC-044: Command Injection via stdio Transport Args
**File:** `client-manager.ts`
**Fix:** Added `SAFE_ARG_PATTERN` validation (`/^[a-zA-Z0-9._\-\/=:@]+$/`) before spawning stdio transports. Unsafe args are rejected with an error.

### SEC-045: Environment Variable Injection
**File:** `client-manager.ts`
**Fix:** Added `ENV_BLOCKLIST` (13 dangerous vars: PATH, HOME, NODE_OPTIONS, LD_PRELOAD, DYLD_INSERT_LIBRARIES, proxy vars, etc.). Blocked vars are silently filtered from the env merge.

### SEC-046: Upstream Response Validation
**File:** `proxy-router.ts`
**Fix:** Added `MAX_RESPONSE_SIZE` (1MB) and `MAX_TEXT_BLOCK_SIZE` (100KB) limits. Oversized responses return errors; text blocks are truncated with `[response truncated]` indicator.

### SEC-057: Approval Gate as Toggleable Feature
**File:** `sovereignty-profile.ts`
**Fix:** Changed `approval_gate` type from `{ enabled: boolean }` to `{ enabled: true }` (literal type). Default profile now sets `approval_gate: { enabled: true }`. Update method rejects `enabled: false`. This is a core enforcement feature, not a user-toggleable option.

---

## High Fixes Applied

### SEC-047: Server Name Validation
**File:** `client-manager.ts`
**Fix:** Added `SAFE_SERVER_NAME` regex validation in `configure()`. Only alphanumeric, underscore, and dash characters are allowed.

### SEC-050a: Upstream Error Sanitization
**File:** `proxy-router.ts`
**Fix:** Added `sanitizeError()` function: truncates to 200 chars, redacts file paths (`[path-redacted]`) and connection strings (`[connection-redacted]`).

### SEC-050b: Homoglyph Coverage Expansion
**File:** `injection-detector.ts`
**Fix:** Added Georgian letters (ვ→v, დ→d, ლ→l), Latin dotless i (ı→i), and documented NFKC dependency for mathematical alphanumerics.

### SEC-051: Invisible Character Detection Expansion
**File:** `injection-detector.ts`
**Fix:** Added 9 format control characters to INVISIBLE_CHARS: U+202A–U+202E (directional overrides) and U+2066–U+2069 (directional isolates).

### SEC-053: Secret Pattern Regex Fix
**File:** `injection-detector.ts`
**Fix:** Removed `/g` global flag from all 20 SECRET_PATTERNS. Removed now-unnecessary `lastIndex = 0` reset.

### SEC-058: Missing Tier Classification
**File:** `loader.ts`
**Fix:** Added `sovereignty_profile_generate_prompt` to Tier 3 explicit allow list.

---

## Accepted Risks

### SEC-048: Tool Discovery Silent Degradation
The empty tools array on failure is the correct safe default. Adding operator notification is a UX improvement, not a security fix.

### SEC-049: Per-Upstream Rate Limiting
The CallGovernor provides global rate limiting. Per-upstream quotas are a v0.6.0 feature that requires proxy ↔ governor integration design.

### SEC-052: HTML Entity Decoding ReDoS
The 1MB input cap (SEC-055) bounds the worst case. The regex patterns are sufficiently constrained.

### SEC-054: Token Budget Heuristic
This is defense-in-depth signaling, not a security gate. False positives on emoji are acceptable for the signal value provided.

### SEC-056: Governor Reset Tier 1 Gate
The ApprovalGate at the router level enforces Tier 1 before the handler runs. Belt-and-suspenders internal gate is a nice-to-have but not required for security.

---

## Deferred to v0.6.0

- SEC-049: Per-upstream rate limiting and quota integration with CallGovernor
- SEC-060: Remove tool_overrides from UpstreamServer (tier assignment should come from Principal Policy only)
- SEC-062: Add MAX_UPSTREAM_SERVERS and MAX_TOOL_OVERRIDES validation

---

## Test Results

867 tests passing (56 test files). All pre-existing tests pass. 3 tests updated to reflect SEC-057 fix (approval_gate always enabled).

**Prior findings (SEC-001→043): Verified intact.** No regressions introduced.
