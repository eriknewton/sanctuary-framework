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
`query_anonymity_headers_stripped` Operational audit event with:

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

**Status: SHIPPED and wired live (Rho-2 primitive + Rho-3 smart mode +
Rho-2.5 live wiring).** Ratified decisions: default-OFF, opt-in
per-fortress toggle, consent-gated (the operator must acknowledge the
trade-off explainer before the toggle can flip on), with a per-query
override in the config store API.

The live path has two legs:

1. **Concierge query path** (`chat/operator-chat-service.ts`): when the
   fortress opted in with recorded consent, the Tier B treatment is
   applied to BOTH the operator query and the assembled prior-turns
   context before the substrate-selector summarize call. Secrets,
   credentials, account numbers, and file paths are scrubbed ahead of
   the rewrite so they never reach the helper surfaces. Smart mode
   (`smart_mode_enabled`) runs the intent-aware rewrite with encrypted
   reverse mappings restored at render time; the basic toggle
   (`enabled`) runs anonymize-all (regex + LLM-assist on residuals)
   with no restoration. Both legs emit a
   `query_anonymity_pii_rewritten` audit event with per-category
   counts (preserved classes zeroed and listed separately), a `leg`
   marker, and the consent snapshot.

   Stated precisely, what the regression tests prove: the disabled
   default is byte-identical to the pre-Tier-B behavior; with Tier B
   on, the query and context legs are both treated before egress; a
   config record that cannot be read (storage throw, reason
   `read_failed`) or cannot be decoded (reason `decode_failed`) FAILS
   the query with `query_anonymity_pii_config_unreadable`, and only a
   genuinely absent record evaluates to the default-off posture, so an
   unknown posture is never a silent un-rewritten send. Two scoped
   non-claims: smart mode restores
   intent-preserved classes to originals by ratified design (the
   always-on concierge Tier 1 filter still re-covers its own classes
   on the composed text), and regex residuals can still reach the
   `privacy-filter-tier-2` helper surface via LLM-assist, which
   matters only if that surface is bound to a remote substrate (open
   follow-up, escalated).
2. **Frontier egress redactor**
   (`intelligence/privacy-tier2-redactor.ts`): every production
   `SubstrateSelector` installs the consent-gated Tier 2 redactor via
   the `installConsentGatedRedactor` chokepoint, covering the
   frontier-with-filter substrate. It reads the live `PiiConfigStore`
   per call and passes text through unchanged when Tier B is off.

Operator surface: `/api/query-anonymity/pii` (config read/patch with
the consent gate, trade-off explainer, stateless rewrite preview). The
route reports `effective_tier_b_enabled` derived from the live config
plus the redactor-installed signal (never-overclaim rule).

## Tier 3a: network-path anonymity (two-hop egress proxy), Slice 1

Tiers A and B clean the *bytes of the request* (headers and content).
They do not touch the **transport** beneath: the wrapped fetch still opens
a direct TLS connection from the operator host to the provider, so the
operator's IP and the operator-to-provider path linkage still leak. Tier 3a
hides the network path itself.

**Mechanism (this slice).** A two-hop egress proxy (HTTP CONNECT over TLS;
MASQUE later). The client opens a tunnel to a **relay** (hop 1) and asks it
to connect onward to an **egress** (hop 2), which makes the actual TLS
connection to the provider. The relay sees the operator's IP but only an
opaque tunnel (not the destination); the egress sees the destination but
connects from its own IP, not the operator's. No single hop sees both. This
is the architecture Apple iCloud Private Relay uses for its traffic. It
reaches providers that have not opted in (unlike OHTTP), since a CONNECT
tunnel reaches any HTTPS destination.

**What Slice 1 delivers, Property 1 only.** *IP-decoupling and path-linkage
removal.* The provider no longer sees the operator's source IP; a path /
network observer cannot link operator to destination. Delivered at any relay
size N. **Approved external wording:** "removes the operator's IP and path
linkage as deanonymizing side channels."

**What Slice 1 does NOT claim.**
- **Property 2 (unlinkability / anonymity-set).** Hiding *which* operator
  sent a query requires a live crowd. A relay with a handful of users is "a
  crowd of N," not anonymity. This slice surfaces no anonymity-set claim;
  live-set instrumentation is a later slice and any future claim is gated on
  it. **Forbidden wording:** "full anonymity," "anonymous queries," or any
  phrasing implying a crowd we do not have.
- **Credential decoupling.** The API key is in the Tier A
  `REQUIRED_HEADERS` allowlist and is never stripped; against the provider
  specifically, IP-hiding is necessary but not sufficient because the key
  already keys a per-operator profile. The unconditional win is against the
  path / network observer, not the provider. Key rotation / pooled keys are
  a LATER slice with a billing/quota tradeoff.
- **GPA resistance.** No low-latency two-hop system defeats a global passive
  adversary who watches both ends. That is the Tier-3b mixnet's job.

**Trust model (non-collusion).** Security rests on relay ≠ egress being
operated by non-colluding parties. If they collude, the operator IP and the
destination reunite and the protection collapses. The **default posture is
operator-run / federated** (the hops sit inside, or are chosen by, the
operator), which keeps Sanctuary off the critical path and preserves the
non-domination thesis. Sanctuary-hosted and third-party / Tor postures are
**labeled opt-ins**, never a Sanctuary-embedded default.

**Fail-closed.** When armed and the anonymous path cannot be established, the
query is **denied** (a `Tier3FailClosedError`); it is never silently
fulfilled over a direct deanonymizing connection. A direct fallback exists
only via an explicit operator opt-in (`onTunnelFailure: "fallback-direct"`),
which is audited as a deanonymizing event.

**Castle Wall stays whole (AC-1).** The Tier 3 transport is composed
*beneath* the Tier A anonymized fetch:
`createAnonymizedFetch(createTunneledFetch(baseFetch, cfg), audit)`. Because
the substrate clients hold only the wrapped fetch, the tunnel is reachable
only through that single channel and opens no unwrapped outbound socket, so
Castle Wall's egress filter still binds the sole outbound channel and the
`query_anonymity_headers_stripped` audit still fires on every call. A
regression test asserts there is no unwrapped socket (AC-1), that the
provider observes the egress IP (AC-2), and that token-by-token streaming
survives the tunnel (AC-4).

**Status:** opt-in, **disarmed by default** (zero behavioral / latency change
for operators who have not enabled it). The reference operator-run dialer is
an in-process two-hop CONNECT chain on Node core sockets; production
federated / hosted dialers implement the same `TunnelDialer` interface.

## Tier 3b: mix network / ZK (research, out of v1.x)

Route substrate calls through a mix network (Tor-like onion routing, e.g.
Nym/Loopix with cover traffic) for global-passive-adversary resistance, with
source-side traffic shaping to close the still-open packet-timing leak.
Higher latency / bandwidth cost; an opt-in high-assurance mode, not an
interactive default. Zero-knowledge / Privacy-Pass anonymous credentials
enter only as the relay-authorization scheme, never as the network-path
mechanism. Paper-grade for now; not v1.x ship.

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
- `server/src/query-anonymity/tier3-transport.ts`: Tier 3a network-path
  transport (two-hop egress proxy, Slice 1) + reference loopback CONNECT
  dialer.
- `server/src/query-anonymity/query-anonymity-routes.ts` — dashboard
  backend route.
- `server/src/intelligence/selector.ts` — substrate selector
  integration point (Rho-1 strip wrap + Tier 3a tunnel composed beneath
  it, in the constructor).
- `server/test/query-anonymity/header-strip.test.ts`: Tier A regression
  suite + zero-PII ship gate.
- `server/test/query-anonymity/tier3-transport.test.ts`: Tier 3a
  regression suite (AC-1 sole-egress / AC-2 IP-decoupling / AC-4 streaming,
  fail-closed, end-to-end through the selector).
- `Review/Sanctuary/Query_Anon_Tier3_Design_Revised_2026-06-13.md`:
  ratified Tier 3 design (source of truth).
- `server/docs/test-concurrency-discipline.md` — sibling test
  discipline doc.
