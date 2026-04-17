# Delta Security Review — Sanctuary v0.9.0-rc.1

**Date:** 2026-04-16 (coordinator review, post-ship)
**Baseline:** v0.8.0 (commit prior to `9aaa0b7`)
**Delta:** 5 commits, ~2,200 src lines + ~1,073 test lines across the dashboard module, `sanctuary wrap` CLI, macOS Keychain integration, and CLI wiring
**Release tag:** `v0.9.0-rc.1` on `53ae2d1` (+ `af3fd31` screenshots)
**Test baseline:** 1,328 passing
**Methodology:** Two parallel Explore subagents reviewed the dashboard and wrap CLI independently; coordinator verified CRITICAL and HIGH findings against ground-truth source before inclusion.
**Verdict:** **Ship after fixing 1 CRITICAL + 1 HIGH before promoting to v0.9.0 final.** MEDIUMs addressable during soak. LOWs can roll into v0.9.1.

---

## Files Reviewed

### Sovereignty Dashboard (new module)
- `server/src/dashboard/aggregator.ts` (383 lines, new) — L1/L2/L3/L4 snapshot assembly
- `server/src/dashboard/api.ts` (193 lines, new) — HTTP + SSE endpoints
- `server/src/dashboard/html.ts` (712 lines, new) — single-page HTML render
- `server/src/dashboard/server.ts` (124 lines, new) — HTTP server lifecycle
- `server/src/dashboard/index.ts` (116 lines, new) — module composition / public API

### `sanctuary wrap` CLI
- `server/src/cocoon/cli.ts` (556 net-changed lines) — rewritten `wrap` flow
- `server/src/cocoon/passphrase.ts` (257 lines, new) — macOS Keychain + fallback file
- `server/src/cocoon/fortress-view.ts` (10 lines changed)

### CLI wiring
- `server/src/cli.ts` (89 lines net) — `wrap` + `export-passphrase` subcommands
- `server/src/index.ts` (25 lines net) — dashboard re-exports only
- `server/package.json` — version bump + `sanctuary` bin alias

### Tests
- `server/test/dashboard/{aggregator,api,html}.test.ts` (621 lines)
- `server/test/wrap/{passphrase,wrap-cli,readme}.test.ts` (452 lines)

---

## Findings Summary

| ID | Severity | Subsystem | Title | Status |
|----|----------|-----------|-------|--------|
| SEC-061 | **CRITICAL** | Wrap | Passphrase written plaintext into rewritten agent config when `--passphrase` flag is used | **OPEN** |
| SEC-062 | HIGH | Wrap | Fallback passphrase file silently regenerated on decrypt failure → state becomes undecryptable | **OPEN** |
| SEC-063 | MEDIUM | Wrap | Non-macOS fallback uses weaker machine-local encryption with no user warning | **OPEN** |
| SEC-064 | MEDIUM | Wrap | Keychain write failure on macOS silently falls back to file with no warning | **OPEN** |
| SEC-065 | MEDIUM | Dashboard | No security headers (CSP, X-Frame-Options, X-Content-Type-Options) on HTTP responses | **OPEN** |
| SEC-066 | MEDIUM | Dashboard | Approval POST endpoints protected only by bearer token; no Origin / SameSite defense | **OPEN** |
| SEC-067 | MEDIUM | Dashboard | Upstream server error strings surfaced to UI unredacted | **OPEN** |
| BUG-041 | MEDIUM | Dashboard | Per-layer aggregation calls (`buildL1`/`buildL2`/`buildL3`/`buildL4`) not individually error-boxed | **OPEN** |
| BUG-042 | MEDIUM | Dashboard | SSE write errors swallowed silently — no debug log, no operator visibility | **OPEN** |
| BUG-043 | MEDIUM | Dashboard | `startDashboard` accepts unbounded `initialActivity` / `initialApprovals` arrays | **OPEN** |
| BUG-044 | MEDIUM | Dashboard | Activity/approval buffer mutation not serialized (`unshift` + length-trim race) | **OPEN** |
| SEC-068 | LOW | Wrap | Re-wrap prints a warning but does not require confirmation; irreversible config rewrite | **OPEN** |
| SEC-069 | LOW | Wrap | Keychain service/account names are fixed; multiple installs on same machine share one passphrase | **OPEN** |
| SEC-070 | LOW | Dashboard | Auth enabled/disabled is distinguishable via 401-vs-200 response timing | ACCEPTED (localhost threat model) |
| BUG-045 | LOW | Wrap | Browser-open failures swallowed with no user-visible warning | **OPEN** |
| BUG-046 | LOW | Wrap | Upstream tool count printed in success message is a placeholder, not a real count | **OPEN** |
| BUG-047 | LOW | Dashboard | `publish()` does not runtime-validate `event.type` is in the allowed set | **OPEN** |
| CLEAN-011 | LOW | Wrap | Pause-Agent button in fortress-view has `TODO: POST to /api/cocoon/pause` but ships interactive | **OPEN** |
| CLEAN-012 | LOW | Wrap | Backup metadata file still named `cocoon-meta.json` despite `wrap` rename | **OPEN** |
| CLEAN-013 | LOW | Wrap | `cocoon` deprecated alias not mentioned in `sanctuary --help` | **OPEN** |
| CLEAN-014 | LOW | Wrap | Server-name sanitization silently transforms illegal chars; collisions possible | **OPEN** |
| CLEAN-015 | LOW | Wrap | `generatePassphrase()` uses base64 (with `=` padding) while `generateAuthToken()` uses base64url | **OPEN** |
| CLEAN-016 | LOW | Dashboard | "Cocoon proxy" reference in `server.ts` comment (internal; not user-visible) | **OPEN** |
| CLEAN-017 | LOW | Dashboard | Test coverage gap: no auth edge-case tests (malformed header, empty token, very long token) | **OPEN** |
| CLEAN-018 | LOW | Wrap | Test coverage gap: no end-to-end test exercises the `--passphrase flag → rewrite config` path (which is why SEC-061 wasn't caught) | **OPEN** |
| CLEAN-019 | Dashboard | Hero copy "Erik picks on merge" comment still present above `HERO_COPY` constant | INFO (choice is made; delete the options comment) |

**Score card:** 1 CRITICAL, 1 HIGH, 7 MEDIUM, 15 LOW, 1 accepted, 1 info.

---

## CRITICAL

### SEC-061 — Passphrase written plaintext into rewritten agent config when `--passphrase` flag is used

**Severity:** CRITICAL
**File:** `server/src/cocoon/cli.ts:225-232`
**Also relevant:** `server/src/cli.ts:70` (initial argv parse)

**What happens.** When a user runs `sanctuary wrap --passphrase XYZ`, the code path at `cli.ts:184` sets `passphraseSource = "flag"`. The rewrite call at `cli.ts:225-232` then spreads `["--passphrase", passphraseValue]` into the new agent-launcher command:

```typescript
await rewriteConfigForCocoon(
  agentConfig, "npx",
  [
    "@sanctuary-framework/mcp-server",
    ...(passphraseSource === "flag" ? ["--passphrase", passphraseValue] : []),
  ]
);
```

Net effect: the user's passphrase is persisted in plaintext into the agent config file (e.g. `~/.openclaw/openclaw.json`) and re-appears in `ps aux` / `/proc/*/cmdline` every time the agent launcher spawns the MCP server.

**Why it matters.** The passphrase derives every encryption key in `~/.sanctuary/state/` (master key → HKDF per namespace → AES-256-GCM). Any process running as the same user can read it from argv or from the config file. This defeats the L1 Cognitive Sovereignty guarantee in CLAUDE.md invariant 1 (no plaintext state to disk without explicit intent) and undermines the Argon2id KDF entirely — the derived keys no longer require brute-forcing a passphrase, because the passphrase itself is readable at rest.

**Who is exposed.** Only users who explicitly pass `--passphrase` on the command line. The default happy path (auto-generated + Keychain or fallback file) is **not** affected — those code paths set `passphraseSource = "keychain"` / `"fallback-file"` / `"generated"`, and the spread at `cli.ts:230` produces no `--passphrase` argument. But any user who follows a typical "pass the passphrase on the command line" instinct is silently downgraded to plaintext-at-rest.

**Remediation.** Remove the `passphraseSource === "flag"` branch from the config rewrite. Instead, when the user supplies `--passphrase` at wrap time, persist that value into the Keychain (macOS) or fallback file and rewrite the config without any `--passphrase` argument. The launcher then re-resolves the passphrase at runtime via the same `getOrCreatePassphrase()` path everyone else uses. This collapses `--passphrase` into a one-time setter for the first wrap and eliminates the plaintext-at-rest footgun. Add a regression test that runs `wrap --passphrase FOO` end-to-end and asserts neither the rewritten config nor any process argv contains the passphrase literal.

---

## HIGH

### SEC-062 — Fallback passphrase file silently regenerated on decrypt failure

**Severity:** HIGH
**File:** `server/src/cocoon/passphrase.ts:184-205` (read path), `63-100` (generate-and-overwrite path)

**What happens.** `readFromFallbackFile()` catches any decryption failure and returns `null` (line 202-204). The caller `getOrCreatePassphrase()` treats `null` as "no stored passphrase" and proceeds to line 90 — `const value = generatePassphrase()` — writing a fresh random passphrase on top of the failed-to-decrypt file (line 98: `writeToFallbackFile(fallback, value, home)`).

**Trigger conditions.**
- The fallback file exists but the machine-local key can no longer re-derive it (hostname changed, `uid` / `username` changed, `$HOME` moved).
- The file is corrupted, truncated, or has been partially overwritten.
- A migration / clone moved `~/.sanctuary/` to a new machine.

**Why it matters.** The old passphrase is now destroyed and a new random one takes its place. All encrypted state at `~/.sanctuary/state/` — every namespace, identity key, audit log entry, reputation attestation — was encrypted under the old passphrase and is now permanently unrecoverable. This is silent, irreversible data loss on a failure mode that is visible only as "your state mysteriously disappeared."

The repo invariant at CLAUDE.md line 71 is explicit: "If encryption fails, the operation must fail — not fall back to plaintext storage." The spirit of that rule applies here: if *decryption of the user's master passphrase* fails, the operation must fail loudly, not silently overwrite the only key material.

**On macOS this path fires only if Keychain is also empty** (line 72-75 returns early when Keychain has a value), so the common macOS upgrade path is protected. But users who rely on the fallback file, plus any user who restores from a backup onto a new machine, hit this.

**Remediation.** Distinguish three read outcomes in `readFromFallbackFile()`: `NOT_FOUND` (proceed to generate), `UNREADABLE` (fail loudly with instructions to restore from backup or re-import), and `OK`. Never auto-regenerate on `UNREADABLE`. Add a test that writes a fallback file, mutates the machine-key input, and asserts the next `getOrCreatePassphrase()` throws rather than silently regenerating.

---

## MEDIUM

### SEC-063 — Non-macOS fallback uses weaker machine-local encryption with no user warning

**Severity:** MEDIUM
**File:** `server/src/cocoon/passphrase.ts:70-99, 222-235`

**What happens.** On Linux / Windows / any non-`darwin` platform, the wrap flow skips Keychain entirely and uses `writeToFallbackFile()`, which encrypts the passphrase with a key derived via `hkdf(sha256, hostname + uid + username + home, …)` (line 228-235). The file comment acknowledges the trade-off plainly: "This is NOT cryptographically strong authentication — it only ensures that the encrypted file cannot be read off a different machine. If an attacker already has local access, they can trivially re-derive this." (line 222-227)

**Why it matters.** The user receives a success message like "passphrase stored at `~/.sanctuary/passphrase.enc`" with no indication that the protection is *functionally* equivalent to chmod-0600 (since any same-user process can re-derive the key). On macOS they would get Keychain, which is unlocked per-login and can carry ACLs. The platform-dependent security posture is never surfaced.

In practice Keychain on default settings is also accessible to any process running as the same user, so the gap is narrower than it looks. But the discrepancy is real and undocumented at run-time.

**Remediation.** On non-`darwin`, emit a one-time warning at wrap-time describing the fallback store and linking to documentation that explains the trade-off. Consider requiring `--accept-fallback-storage` or `SANCTUARY_ACCEPT_FALLBACK=1` for non-interactive confirmation. Long-term: integrate with `libsecret` (Linux) / DPAPI (Windows) behind the same `PassphraseSource` abstraction.

---

### SEC-064 — Keychain write failure on macOS silently falls back to file with no warning

**Severity:** MEDIUM
**File:** `server/src/cocoon/passphrase.ts:89-99`

**What happens.** After generating a fresh passphrase, the flow calls `writeToKeychain(value, exec)` (line 92). If that returns `false` — Keychain locked, user denied the prompt, `security` binary missing — the code silently falls through to `writeToFallbackFile()` on line 98 and returns `source: "generated", location: fallback` without any log line mentioning that Keychain was attempted and failed.

The user sees the success notice (`cli.ts:198-200`) reading `Generated and stored passphrase (/Users/…/.sanctuary/passphrase.enc)`. The fallback *location* is reported correctly (so the subagent's initial framing that "the message wrongly claims Keychain" was off). But the user still has no idea that Keychain was the intended store and that it failed.

**Why it matters.** Users on managed Macs where Keychain access is centrally restricted will silently end up on the weaker storage path. Operators debugging a "why isn't my passphrase in Keychain" report have no breadcrumbs in logs.

**Remediation.** When `writeToKeychain` returns `false` on darwin, emit a stderr warning naming the Keychain failure and the fallback location. Optionally capture the `security` binary's stderr for diagnostics instead of discarding it at `passphrase.ts:173`.

---

### SEC-065 — No security headers on dashboard HTTP responses

**Severity:** MEDIUM
**File:** `server/src/dashboard/api.ts:68-82` (response builder)

**What happens.** The dashboard HTTP server sets `Content-Type` and `Cache-Control` but does not set `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, or `Referrer-Policy`.

**Why it matters.** On a strictly localhost service the miss is defensible (CSRF requires luring the user to `http://127.0.0.1:<port>` in the same browser profile, and clickjacking requires the user having the dashboard loaded under a chosen port). But since `html.ts` emits inline `<script>` tags with JSON payloads, a missing CSP means an XSS bypass of the `escHtml` defenses would be unbounded. And since the release goal is "make the user feel protected," shipping a dashboard with no CSP on the same release that carries SSE + approval POSTs is a bad look if a third party audits it.

**Remediation.** Emit at minimum:
- `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`

Document the `'unsafe-inline'` as required for the single-page inline render; a follow-up can move to nonce-based CSP.

---

### SEC-066 — Approval POST endpoints protected only by bearer token; no Origin / SameSite defense

**Severity:** MEDIUM
**File:** `server/src/dashboard/api.ts:126-142`

**What happens.** The POST endpoints `/api/approvals/:id/allow` and `/api/approvals/:id/deny` require the bearer token (via header or `?token=` query string). Any page loaded in the user's browser that can read the token (e.g. a page the user was tricked into opening with the `?token=…` URL pasted in) can POST allow/deny on behalf of the user. There is no `Origin` or `Referer` check on state-changing endpoints, and no SameSite-strict cookie layer.

**Why it matters.** The auto-opened browser URL is `${dashboard.url}?token=${authToken}` — the token is in the URL bar, browser history, and any referer leakage. On localhost the attack surface is narrow, but the "defense in depth" story for an approval gate (which is the L2 invariant backbone) should not rest on a single bearer token in a query string.

**Remediation.** On state-changing POSTs, require an `Origin` (or `Referer`) header whose host matches the dashboard's bound host. Reject otherwise. Optionally issue a SameSite=Strict, HttpOnly session cookie on first authenticated page load and use *that* for subsequent POSTs, keeping the bearer token only for initial bootstrap.

---

### SEC-067 — Upstream server error strings surfaced to UI unredacted

**Severity:** MEDIUM
**File:** `server/src/dashboard/aggregator.ts:325-338` (`buildUpstreamServers`)

**What happens.** `UpstreamServerStatus` includes an optional `error` field populated from whatever string the upstream connection threw. These strings can include internal service hostnames, file paths, credential prefixes, or stack-trace excerpts that leak environment detail.

**Why it matters.** The dashboard is low-trust ("any local process on this user" per SEC-066), so treating any surfaced string as potentially-observed data is the right posture. Leaking an upstream's hostname from a stack trace is not catastrophic but is exactly the kind of small information leak that shows up in bug bounties.

**Remediation.** Map known error classes to enum-style categories (`"connection-refused"`, `"timeout"`, `"auth-denied"`, `"unknown"`) and render those. Keep the raw error in the encrypted audit log for operator diagnosis, not on the dashboard.

---

### BUG-041 — Per-layer aggregation calls not individually error-boxed

**Severity:** MEDIUM
**File:** `server/src/dashboard/aggregator.ts:348-383`

**What happens.** `getProtectionSnapshot()` wraps only `sources.auditLog.query()` in try/catch (degrades to empty array). `buildAgent`, `buildL1`, `buildL2`, `buildL3`, `buildL4`, `buildUpstreamServers` are called without guards. If the L1 store is mid-rotation or the L2 policy reload is in flight when the snapshot is requested, one throw takes down the entire render and the API returns 500 — even though the user still wants to see the other layers.

**Remediation.** Wrap each `build*` call in try/catch; on failure return a `status: "unavailable", reason?: string` stub for that layer and mark the snapshot `degraded: true`.

---

### BUG-042 — SSE write errors swallowed silently

**Severity:** MEDIUM
**File:** `server/src/dashboard/api.ts:166-180`

**What happens.** The SSE listener body and keep-alive interval both catch exceptions with empty `catch {}` blocks. When a client socket half-closes or a write races with a close, there is no breadcrumb in logs. An operator watching the dashboard never stop listening to an event has no signal to follow.

**Remediation.** Accept a `logger?: (level, msg, err?) => void` option in `startDashboard()` (or thread through the server's existing logger). Log at `debug` level on expected errors (client-closed), `warn` on unexpected ones.

---

### BUG-043 — `startDashboard` accepts unbounded `initialActivity` / `initialApprovals`

**Severity:** MEDIUM
**File:** `server/src/dashboard/index.ts:104-112`

**What happens.** `startDashboard(options)` accepts `options.initialActivity` and `options.initialApprovals` as plain arrays. The wrapper helpers trim to `MAX_ACTIVITY = 50` on subsequent `unshift`, but the initial array is stored as-is. A caller that passes a 100k-entry audit query will sit 100k entries in the buffer and only start trimming after the 50,001st new entry.

**Remediation.** Cap at initial-write time: `activity = (options.initialActivity ?? []).slice(0, MAX_ACTIVITY)`.

---

### BUG-044 — Activity/approval buffer mutation not serialized

**Severity:** MEDIUM
**File:** `server/src/dashboard/index.ts:104-112`

**What happens.** `publishActivity()` and `publishApproval()` do `array.unshift(entry); if (array.length > 50) array.length = 50` without a lock. If two async callers fire concurrently, the unshift + length-trim can interleave and briefly leave an 51-entry array or double-trim. Not destructive (aggregator re-reads on snapshot), but the in-memory buffer and what SSE clients see can desync.

**Remediation.** Either document that callers must serialize, or use a simple sequential queue (a single-entry `Promise` chain) to make mutations linear.

---

## LOW

### SEC-068 — Re-wrap prints a warning but does not require confirmation

**Severity:** LOW
**File:** `server/src/cocoon/cli.ts:154-162`

**What happens.** If `sanctuary wrap` detects an existing Sanctuary entry in the target config, it prints `Warning: This agent already has a Sanctuary server configured. Re-wrapping will update the existing Sanctuary entry.` and proceeds without any prompt or `--force` flag.

**In practice the operation is idempotent in the common case** — the passphrase is *read* from Keychain (not regenerated), the state directory is reused, the backup file is rewritten. So the "silently overwrite and lose state" framing the initial review raised is not quite right. The realistic failure is a user-triggered misdetection (wrong platform hint) that rewrites a config they didn't mean to touch.

**Remediation.** Add `--force` / interactive `[y/N]` prompt. The backup is already being saved, so rollback is possible; surfacing that in the confirmation text closes the loop.

---

### SEC-069 — Keychain service/account names are fixed; multi-install share one passphrase

**Severity:** LOW
**File:** `server/src/cocoon/passphrase.ts:25-26`

**What happens.** `KEYCHAIN_ACCOUNT = "sanctuary"` and `KEYCHAIN_SERVICE = "sanctuary-passphrase"` are constants. Multiple `sanctuary wrap` runs on the same Mac (e.g. wrapping OpenClaw and Claude Code for the same user) will share one passphrase.

**This is consistent with `~/.sanctuary/` being per-user, not per-install**, so for the current design it is fine. It's worth flagging for the future if Sanctuary ever supports multiple isolated state directories per user.

**Remediation.** When / if Sanctuary supports `--state-dir` or multi-tenant layouts, derive the Keychain service name from the state-dir path (e.g. `sanctuary-passphrase-<hash-of-path>`).

---

### SEC-070 — Auth enabled/disabled distinguishable via 401-vs-200 timing

**Severity:** LOW (ACCEPTED)
**File:** `server/src/dashboard/api.ts:61-66`

**What happens.** When the auth token is configured, valid-vs-invalid comparison uses `constantTimeEquals`, but the presence/absence of auth is visible from whether the endpoint 401s in ~1ms.

**Why accepted.** The dashboard is localhost-bound and the threat model for timing side channels over loopback is thin. Documenting rather than fixing.

**Remediation (if later needed).** Wrap responses in a fixed-delay jitter. Not recommended for the current threat model.

---

### BUG-045 — Browser-open failures swallowed with no user-visible warning

**Severity:** LOW
**File:** `server/src/cocoon/cli.ts:264-271`

**What happens.** `await opener(dashboardUrl)` is wrapped in `try { … } catch { /* best-effort */ }`. If `open` fails (no default browser, sandboxed environment, invalid URL), the user sees the success message but no browser, and has no idea why.

**Remediation.** Log the caught error at `console.error` level with the URL: "Could not open browser automatically: <err>. Open this URL manually: <url>".

---

### BUG-046 — Success message reports placeholder tool count as a confident number

**Severity:** LOW
**File:** `server/src/cocoon/cli.ts:273-282` (caller), implementation at `cli.ts:543-548`

**What happens.** `countUpstreamTools(upstreamServers)` returns `servers.length` (a placeholder — tool discovery hasn't happened yet), but the success banner prints it as `N tools registered across M upstream servers`. If a user wraps two servers, the banner reads "2 tools registered across 2 upstream servers" — which is almost certainly wrong and misleading.

**Remediation.** Either change the banner to "2 upstream servers (tool count available after first connection)" or defer printing the line until `client-manager` reports discovered tools.

---

### BUG-047 — `publish()` does not runtime-validate `event.type`

**Severity:** LOW
**File:** `server/src/dashboard/server.ts:60-67`

**What happens.** The `publish(event)` helper trusts its type parameter. If an internal caller someday passes an unexpected `event.type`, the SSE stream will include `event: <unknown>` lines that clients ignore silently.

**Remediation.** Runtime-assert `event.type` ∈ `{"snapshot","activity","approval"}`.

---

### CLEAN-011 — Pause-Agent button in fortress-view has `TODO: POST /api/cocoon/pause` but ships interactive

**Severity:** LOW
**File:** `server/src/cocoon/fortress-view.ts:753`

**What happens.** The button appears clickable but the handler is a `TODO` — it updates local state only.

**Remediation.** Either implement `/api/cocoon/pause` (set all tiers to 1) or disable the button with a tooltip "Coming in v0.9.1".

---

### CLEAN-012 — Backup metadata file still named `cocoon-meta.json` / `cocoon-profile.json`

**Severity:** LOW
**File:** `server/src/cocoon/cli.ts:211, ~87`; helpers in `config-reader.ts:110`

**What happens.** The release retired "Cocoon" from user-facing surfaces, but on-disk filenames under `~/.sanctuary/` still read `cocoon-*.json`. Users who list that directory see stale branding.

**Remediation.** Rename new files to `wrap-meta.json` / `sovereignty-profile.json`; on read, fall back to the old names for migration.

---

### CLEAN-013 — `cocoon` deprecated alias not mentioned in `sanctuary --help`

**Severity:** LOW
**File:** `server/src/cli.ts:206-228` (`printHelp`)

**What happens.** Running `sanctuary cocoon` prints a deprecation notice and works, but `sanctuary --help` no longer mentions `cocoon` at all. Users with existing scripts that call `sanctuary cocoon` will get no signal from `--help` to update.

**Remediation.** Add one line under `Subcommands`: `cocoon               (deprecated — use "wrap")`.

---

### CLEAN-014 — Server-name sanitization silently transforms illegal chars

**Severity:** LOW
**File:** `server/src/cocoon/config-reader.ts:276-277`

**What happens.** `name.replace(/[^a-zA-Z0-9_-]/g, "-")` is lossy; two distinct server names could collide after sanitization (`my server` and `my-server` → both `my-server`).

**Remediation.** Reject unsafe names with a clear error at wrap time, or surface the sanitized name to the user: "Server name 'X' will be displayed as 'Y'".

---

### CLEAN-015 — `generatePassphrase()` uses base64 padding, `generateAuthToken()` uses base64url

**Severity:** LOW
**File:** `server/src/cocoon/passphrase.ts:133-136` vs. `server/src/cocoon/cli.ts:~529`

**What happens.** Inconsistent encodings for similar secrets. Not a security bug; a readability/consistency one.

**Remediation.** Switch `generatePassphrase()` to base64url (no padding) to match; update the `>= 43 chars` test expectation to `=== 43`.

---

### CLEAN-016 — "Cocoon proxy" reference in dashboard `server.ts` comment

**Severity:** LOW
**File:** `server/src/dashboard/server.ts:38`

**Remediation.** Replace with "Sanctuary proxy" or "upstream clients". Not user-visible; one-line fix.

---

### CLEAN-017 — Dashboard auth test coverage gap

**Severity:** LOW
**File:** `server/test/dashboard/api.test.ts`

**Missing cases:** mixed header + query token, malformed `Authorization` header, empty token string, very long token.

**Remediation.** Add four tests mirroring the `extractToken` branches.

---

### CLEAN-018 — Wrap test coverage gap: no end-to-end `--passphrase → config rewrite` test

**Severity:** LOW
**File:** `server/test/wrap/wrap-cli.test.ts`

**Why it matters.** This coverage hole is why SEC-061 wasn't caught. Adding the test pins the fix in place.

**Remediation.** Add a test that invokes `runWrap` with `{ passphrase: "CHECK-ME" }`, spies on `rewriteConfigForCocoon`, and asserts the argument list does NOT contain `"CHECK-ME"`.

---

### CLEAN-019 — Hero copy "options for Erik to pick" comment still present

**Severity:** INFO
**File:** `server/src/dashboard/html.ts:14-23`

**Why info.** Erik chose "Your agent is protected." (per the 2026-04-16 night handoff). The options comment above the constant is now stale context.

**Remediation.** Delete lines 14-22 or replace with a one-liner noting the chosen copy. Zero urgency.

---

## Non-Dependency Compliance

Reviewed imports across the delta: dashboard module and wrap CLI do **not** import from `@concordia-protocol/*` or Verascore. The only Verascore reference is a plain URL in the L4 claim CTA, which is allowed by the repo's non-dependency principle. Compliant.

## Attribution Compliance

No CIMC attribution in any of the new source, tests, or docs. Release body authorship line reads "Built by Erik Newton with Claude Code." Compliant.

---

## Recommended Action Before v0.9.0 Final (target 2026-04-23)

**Must-fix (blocks promotion):**
1. SEC-061 — remove `--passphrase` leak into rewritten config; add regression test (CLEAN-018).
2. SEC-062 — distinguish `NOT_FOUND` vs `UNREADABLE` in fallback-file read; never auto-regenerate on `UNREADABLE`.

**Should-fix (soak-window work):**
3. SEC-065, SEC-066 — dashboard security headers + Origin check on approval POSTs.
4. SEC-063, SEC-064 — surface Keychain / fallback warnings to the user.
5. SEC-067 — redact upstream error strings on the UI.
6. BUG-041 — per-layer error boxes in aggregator.

**Nice-to-have (v0.9.1):**
All LOWs; the `cocoon-meta.json` rename; the auth edge-case tests.

---

## Methodology Notes

- Two parallel Explore subagents reviewed the dashboard and wrap CLI independently. Prompts recorded coordinator-side.
- Coordinator verified the 4 CRITICALs the wrap subagent initially flagged against ground-truth source. Two confirmed (SEC-061 → CRITICAL; SEC-062 → HIGH — the subagent had it as WRAP-BUG-003 / HIGH, coordinator agrees). Two downgraded after re-reading: the Keychain-collision claim (subagent called CRITICAL) is not a collision because the read-before-write flow makes it idempotent (LOW as SEC-069); the re-wrap-without-gate claim is LOW because the operation is idempotent in the common case (SEC-068).
- One subagent finding dropped as hallucinated: an `IDX-BUG-001` claim referenced `server/src/index.ts:777` with a "2-second wait for upstream tools" race. The actual `index.ts` delta in v0.9.0-rc.1 is 25 lines of dashboard re-exports only; the subagent was reading pre-existing code outside the delta.
- Report style matches `docs/audit/DELTA_REVIEW_COCOON_FULL.md` for continuity with prior audit artifacts.
