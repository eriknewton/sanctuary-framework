# SPRINT CONTRACT — SEC-012: Dashboard Auth Token in URL Query Strings

**Sprint Date:** 2026-03-28
**Finding:** SEC-012 (reclassified Medium → High)
**Branch:** `security-review`

---

## Architecture Decision

### a) Root cause — not the symptom

The `checkAuth()` method in `server/src/principal-policy/dashboard.ts` (lines 227–248) accepts the bearer auth token via `?token=<TOKEN>` query parameter. This exists because the browser's SSE `EventSource` API does not support custom headers — the only way to authenticate the SSE connection was to pass the token in the URL.

The root cause is **using the long-lived auth token directly in URLs** rather than exchanging it for a short-lived session credential via a header-authenticated endpoint.

### b) Smallest change that closes the vulnerability

1. **Add a session exchange endpoint** (`POST /auth/session`): accepts `Authorization: Bearer <TOKEN>` header, validates it, returns a short-lived (5-minute) random session ID.
2. **Replace query-string token acceptance** in `checkAuth()`: remove `?token=` support for the long-lived auth token. Instead, accept `?session=<SESSION_ID>` for page loads and SSE connections, validated against the server-side session store.
3. **Update dashboard HTML**: on page load, exchange the token (passed via JS, never in URL) for a session via `POST /auth/session`, then use the session ID for SSE connections and API calls that need URL-based auth.
4. **Update startup message**: no longer suggest `?token=` — instead guide user to use Authorization header or the dashboard session flow.

### c) Interaction with other findings

None. SEC-002 (auto_deny hardcoded) is orthogonal — it addresses timeout behavior, not token transport. No other finding touches the dashboard auth flow.

### d) New risk introduced

- **Server-side session state**: sessions are stored in a `Map` with automatic TTL expiry (5 minutes). Map is bounded to 1000 entries. Risk is minimal — sessions are ephemeral, in-memory only, and cleaned up on expiry or server stop.
- **Session fixation**: mitigated by generating cryptographically random 32-byte session IDs and binding them to creation time with strict TTL.

---

## Fix Specification

### Files to modify

1. `server/src/principal-policy/dashboard.ts` — core auth changes: add session store, session exchange endpoint, modify checkAuth
2. `server/src/principal-policy/dashboard-html.ts` — client-side session exchange flow

### Behavior before

- `checkAuth()` accepts long-lived auth token via `?token=<TOKEN>` query parameter
- SSE connections use `EventSource(url + '?token=TOKEN')`
- Dashboard page loads with `?token=TOKEN` in browser URL bar
- Token appears in: server logs, browser history, proxy logs, Referer headers

### Behavior after

- `checkAuth()` rejects long-lived tokens in query strings
- New `POST /auth/session` endpoint: header-authenticated, returns `{ session_id }` (random 32 bytes hex, 5-min TTL)
- `checkAuth()` accepts `?session=<SESSION_ID>` for routes that need URL-based auth (SSE `/events` and initial page load)
- SSE connections use `EventSource('/events?session=SESSION_ID')`
- API calls (approve/deny, status) use `Authorization: Bearer <TOKEN>` header — no URL tokens
- Long-lived token never appears in any URL
- Session tokens are short-lived, rotate on each exchange, and auto-expire

### Regression test

File: `server/test/security/dashboard-no-query-token.test.ts`

Tests:
1. **Long-lived token in query string is rejected (401)** — `GET /?token=<AUTH_TOKEN>` returns 401
2. **Long-lived token in Authorization header is accepted** — `GET /` with `Authorization: Bearer <TOKEN>` returns 200
3. **Session exchange works** — `POST /auth/session` with bearer token returns session_id
4. **Session token in query string is accepted** — `GET /events?session=<SESSION_ID>` returns 200
5. **Expired session is rejected** — after TTL, session_id returns 401
6. **Invalid session is rejected** — random session_id returns 401

### Definition of Done

1. `checkAuth()` no longer accepts `?token=` query parameter for the long-lived auth token
2. `/auth/session` endpoint exists and returns short-lived session IDs
3. SSE and page loads work via session tokens only
4. All 6 regression tests pass
5. Full test suite count ≥ 252 (current baseline)
6. No prompt injection surface introduced (this fix does not modify any input/output path that reaches a model prompt)

### Prompt injection assessment

This fix does not touch any input/output path that reaches a model prompt. The dashboard is a human-facing web UI that communicates only with the approval gate. No user-controlled text from the dashboard reaches any AI model context.
