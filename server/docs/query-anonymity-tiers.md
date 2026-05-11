# Query-layer anonymity tiers (WP-V1.x-QUERY-LAYER-ANONYMITY)

Sanctuary's query-layer anonymity work package closes Principle 4
(Opacity at the query layer) of the seven-principle sovereignty
framework. Per the Sovereignty Stack Assessment 2026-05-10, no
comparator surveyed (SSI stacks, personal data stores, decentralized
social, confidential computing) ships query-layer anonymity at
strength — this is a genuinely novel surface.

The work package is tiered: each tier closes a piece of the
principle, with progressively higher implementation cost + steeper
operator-facing trade-offs.

## Tier A — header strip (Rho-1, this PR, default-on)

Strip fingerprintable HTTP headers from every outbound
substrate-selector call. Structurally similar to Apple Private Relay
or Tor's HTTP-stripping logic, applied at the operator-substrate
boundary rather than the network layer.

**Status:** ships in this PR. Default-on. Structurally
unconditional — no operator-side opt-out at v1.x. Bypass requires
changing the selector constructor's `createAnonymizedFetch` wrap.

### Canonical strip list

| Header | Reason |
|---|---|
| `User-Agent` | Fingerprints OS + Node runtime + version |
| `Sec-CH-UA*` (family) | Fingerprints browser/runtime UA capabilities |
| `Accept-Language` | Fingerprints operator locale |
| `Referer` / `Referrer-Policy` / `Origin` | Leaks operator's request origin |
| `Via` / `Forwarded` / `X-Forwarded-For` / `X-Real-IP` / `X-Client-IP` | Leaks operator's IP / proxy chain |
| `DNT` / `Sec-GPC` | Anti-tracking signals are themselves fingerprintable subsets |

If you add to this list, also add a regression test in
`server/test/query-anonymity/header-strip.test.ts`.

### Required-header allowlist (never stripped)

`Authorization`, `Content-Type`, `Content-Length`, `Host`, `Accept`,
`x-api-key` (Anthropic), `anthropic-version`, `anthropic-beta`,
`openai-organization`, `x-stainless-package-version`, `x-goog-api-key`
(Google), `x-goog-user-project`.

If a provider needs a new required header, add it to
`REQUIRED_HEADERS` in `server/src/query-anonymity/header-strip.ts`
AND in the provider's substrate client.

### Operator-visible audit

Every outbound substrate call emits a
`query_anonymity_headers_stripped` L2 audit event with:

```json
{
  "url": "https://api.anthropic.com/v1/messages",
  "method": "POST",
  "stripped_count": 3,
  "removed": [
    { "name": "User-Agent", "reason": "user-agent" },
    { "name": "Accept-Language", "reason": "locale-fingerprint" },
    { "name": "DNT", "reason": "unnecessary-metadata" }
  ],
  "required_preserved": ["Content-Type", "x-api-key", "anthropic-version"]
}
```

The Query Anonymity dashboard view (backend route shipped here;
SPA-side panel deferred to a follow-up build) aggregates these into
the operator-visible stats:

- Total outbound calls in the last 24h
- Total headers stripped
- Top-5 stripped header names
- Per-reason breakdown

### Zero-PII ship gate (mandatory)

`detectPiiInHeaders()` (exported from `header-strip.ts`) detects four
PII classes on a headers map:

1. **Email** — any `@`-containing token.
2. **IP address** — IPv4 or IPv6 regex match.
3. **Hostname** — operator's system hostname appearing as a value.
4. **System/locale** — `User-Agent` or `Accept-Language` present
   with a non-empty value (also strip-list-covered; this is a
   belt-and-suspenders catch).

Regression test asserts a real selector call path with a mock
outbound interceptor passes through no PII. CI fails fast with a
clear message on regression.

### Castle-walking discipline

This module introduces NO new outbound surface; it is a *reduction*
of metadata on EXISTING outbound calls. The substrate selector
remains the only outbound LLM channel; Castle Wall egress filter
still binds; Rho-1 makes that channel measurably more anonymous.

## Tier B — PII rewrite opt-in (Rho-2 dispatch, gated)

Rewrite query *content* to remove PII before the substrate sees it.
Opt-in because rewrite affects LLM functionality:

- Operator's name in a "draft an email to <person>" prompt becomes
  a placeholder, which may change the LLM's output.
- Operator's address in a "schedule a delivery to <street>" prompt
  may force the LLM to ask for clarification.

**Status: NOT in Rho-1.** Tier B awaits Erik's morning read on:

1. Default-on vs opt-in.
2. Prompt-engineering surface (how the operator overrides for
   functionality-critical queries).
3. Substrate-selector functionality impact (which substrate
   surfaces accept PII-rewritten prompts cleanly vs. degrade).

The Rho-1 module structure is forward-compatible with Tier B:
`stripHeaders` is at the HTTP layer; Tier B would add a parallel
`rewriteContentPii` at the request-body layer, wired through the
same selector hook. No Tier B knobs in `principal-policy.yaml` yet.

## Tier C — mix network / ZK (research, out of v1.x)

Route substrate calls through a mix network (Tor-like onion routing)
or use zero-knowledge proofs for the query content. Paper-grade
research. Not v1.x ship.

## Operator quickstart

There is nothing to configure for Tier A. Rho-1's surface is
default-on, structurally unconditional. To inspect what's being
stripped:

1. Open the operator dashboard.
2. Navigate to the Query Anonymity view (shipping in a follow-up SPA
   build; for now, query the audit log directly).
3. The view renders rolling 24-hour stats.

Or query the audit log directly via the secrets / sentinels CLIs:

```
sanctuary secrets audit --operation query_anonymity_headers_stripped
```

(audit query CLI surface to be wired post-Rho-1 if there's operator demand).

## Cross-references

- `server/src/query-anonymity/header-strip.ts` — Tier A module.
- `server/src/query-anonymity/query-anonymity-routes.ts` — dashboard
  backend route.
- `server/src/intelligence/selector.ts` — substrate selector
  integration point (Rho-1 wrap in the constructor).
- `server/test/query-anonymity/header-strip.test.ts` — regression
  suite + zero-PII ship gate.
- `server/docs/test-concurrency-discipline.md` — sibling test
  discipline doc.
