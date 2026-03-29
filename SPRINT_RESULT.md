# SPRINT RESULT — SEC-012: Dashboard Auth Token in URL Query Strings

**Sprint Date:** 2026-03-28
**Finding:** SEC-012 (reclassified Medium → High)
**Branch:** `security-review`

---

## What Changed and Why

### Root cause addressed

The `checkAuth()` method in `dashboard.ts` accepted the long-lived dashboard auth token via `?token=<TOKEN>` URL query parameter. This token — the highest-privilege credential in the system (it can approve/deny Tier 1 operations like state export and identity rotation) — was exposed in server logs, browser history, proxy logs, and HTTP Referer headers. The `EventSource` SSE API's inability to set custom headers was the original justification, but the correct solution is a session exchange, not raw token exposure.

### Changes made

**`server/src/principal-policy/dashboard.ts`:**
- Added `DashboardSession` interface and server-side session store (`Map<string, DashboardSession>`) with 5-minute TTL and 1000-entry cap
- Added `POST /auth/session` endpoint: authenticates via `Authorization: Bearer` header only, returns a short-lived session ID (32 random bytes, hex-encoded)
- Modified `checkAuth()`: removed `?token=` query parameter acceptance; added `?session=` query parameter acceptance for short-lived sessions
- Added `createSession()`, `validateSession()`, and `cleanupSessions()` methods
- Added periodic session cleanup timer (60s interval)
- Updated `stop()` to clean up session state and timer
- Updated startup message to no longer suggest `?token=` usage

**`server/src/principal-policy/dashboard-html.ts`:**
- Replaced `authQuery()` (which put token in URLs) with `sessionQuery()` (uses session ID)
- Added `exchangeSession()` function: POSTs to `/auth/session` with Authorization header, stores session ID
- SSE connection now uses `?session=SESSION_ID` instead of `?token=TOKEN`
- Added session auto-refresh at 80% of TTL
- Added URL cleanup to strip legacy `?token=` from browser URL bar

**`server/test/principal-policy/dashboard.test.ts`:**
- Updated 3 existing tests to verify the new behavior:
  - "accepts requests with correct token in query parameter" → now verifies token-in-URL is **rejected** (401) and session-in-URL is accepted
  - "serves dashboard HTML with correct query token" → now uses Authorization header
  - "SSE requires auth via query param" → now verifies token-in-URL is rejected and session-in-URL works

**`server/test/security/dashboard-no-query-token.test.ts`** (new file, 8 tests):
1. Long-lived token in `?token=` query string is rejected (401)
2. Long-lived token in Authorization header is accepted (200)
3. Session exchange via `POST /auth/session` works
4. Session token in `?session=` query string is accepted
5. Expired session is rejected (401)
6. Invalid/random session is rejected (401)
7. Session exchange with wrong auth token is rejected (401)
8. Session exchange without Authorization header is rejected (401)

---

## Test Suite Output

```
Test Files  26 passed (26)
     Tests  261 passed (261)
```

Test count: 252 → 261 (net +9: 8 new SEC-012 regression tests + 1 additional assertion in updated existing test)

---

## New Risk Introduced

- **Server-side session state**: sessions are stored in an in-memory `Map` with 5-minute TTL and 1000-entry cap. Periodic cleanup runs every 60 seconds. The session store is cleared on server stop. Risk is minimal — sessions are ephemeral and bounded.
- **Session token in URLs**: the session token does appear in URLs (via `?session=`), but it is short-lived (5 minutes) and cryptographically random (32 bytes). Even if logged, the window for exploitation is small and each session is bound to the server instance.

---

## Adjacent Findings Noticed

None. The dashboard auth flow is self-contained and does not interact with other security-relevant code paths.

---

## Sprint Contract Criteria Assessment

| Criterion | Met? |
|-----------|------|
| `checkAuth()` no longer accepts `?token=` for long-lived auth token | ✅ Yes |
| `/auth/session` endpoint exists and returns short-lived session IDs | ✅ Yes |
| SSE and page loads work via session tokens only | ✅ Yes |
| All 8 regression tests pass (contract specified 6, delivered 8) | ✅ Yes |
| Full test suite count ≥ 252 | ✅ Yes (261) |
| No prompt injection surface introduced | ✅ Yes |

**Self-assessment: All sprint contract criteria are met.**
