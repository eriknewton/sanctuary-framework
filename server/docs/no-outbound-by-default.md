# Sanctuary, no outbound by default

**Status:** active rule (WP-V1.2 reshape)
**Date:** 2026-05-01
**Scope:** server runtime, dashboard, MCP servers, broker, hub
**Enforcement:** `server/scripts/outbound-audit.sh` (manual + acceptance drill)

## The rule

Sanctuary initiates no network connection except to operator-configured
endpoints. Specifically, the server runtime, dashboard, MCP servers,
broker, and hub MUST NOT:

- Phone home for telemetry, version checks, or analytics.
- Run a Sanctuary-hosted SMTP relay or any other Sanctuary-hosted
  outbound channel.
- Open any connection to a destination the operator did not explicitly
  configure (substrate endpoint, webhook URL, federation peer, etc.).

The only outbound destinations a fresh Sanctuary install reaches are:

1. **localhost** (broker stdio, dashboard, local-Ollama if the operator
   selected it as substrate).
2. **Operator-configured substrate endpoints** declared in the
   intelligence-layer config (Venice.ai, frontier provider with filter,
   custom endpoints).
3. **Operator-configured outbound channels** declared in the principal
   policy or hub config (webhook approval channel pointed at an
   operator-chosen URL, future operator-chosen SMTP for daily digest,
   etc.). All such channels are explicit operator opt-in, default off.

## Why

**Sovereignty-strict operators will not allow phone-home.** Enterprises
running Sanctuary as the operator-sovereign agent control plane reject
any vendor-controlled network egress on principle. A single
Sanctuary-initiated connection to a vendor endpoint disqualifies the
product for the segment we are building for. The rule is load-bearing
to the substrate-position thesis.

**The Castle Layer 1 enforcement story (RFC-0003) layers on this.**
Once the OS-level egress filter ships, even prompt-injected wrapped
agents cannot bypass operator-configured destinations. The "no outbound
by default" rule guarantees the Sanctuary substrate itself never
contributes to that egress profile, so the wall has a clean baseline to
enforce against.

**Trust precondition for the audit log.** The audit log is the operator's
source of truth for what their fortress has done. If the runtime can
quietly call out to vendor endpoints, the log is incomplete by
construction. The rule keeps the log honest.

## How the rule is enforced

### Build-time

- No HTTP client libraries are imported into the runtime hot path
  except for the operator-configured substrate adapters and the
  operator-configured webhook channel.
- Pre-commit grep gates would catch a `fetch(`, `https.request(`, etc.
  introduction in unauthorized modules. (Suggested follow-up:
  `.githooks/pre-commit` extension; not blocking this rule.)

### Runtime

- `server/scripts/outbound-audit.sh` boots Sanctuary in a smoke fortress
  with no operator-configured external substrates, captures all outbound
  connections from the **full process tree** rooted at the dashboard
  parent (parent plus every descendant resolved via per-tick `ps` walk)
  for the soak window (`SOAK_SECONDS`, default 60), and asserts every
  destination is in the allowed-pattern list (localhost variants only
  by default).
- The process-tree refresh on each tick is load-bearing: a child process
  spawned mid-soak (Concordia sidecar, substrate worker, future helper)
  is picked up the next tick, so its outbound is captured. Filtering by
  parent PID alone would miss those connections.
- Failure exits non-zero and prints the unauthorized destinations.
- Run as part of the v1.2.0 acceptance drill before npm publish.
- `--report-only` mode prints the destination list without asserting,
  for triage when the rule legitimately needs an addition.

## Operator-opt-in escape hatches

The rule applies to default behavior. Operators can explicitly enable
outbound channels by configuring them:

- **Substrate endpoint:** `intelligence/config.json` substrate selection
  (Venice, frontier with filter, custom). The substrate selector is the
  single authority for inference egress; no other module calls vendor
  inference endpoints.
- **Webhook approval channel:** `principal-policy/channel` set to
  `webhook` with operator-chosen URL. HMAC-signed POSTs only; payload
  is operation metadata, never state content.
- **Future daily digest delivery:** when daily digest ships, default is
  OS notification + dashboard view + signed local file write. Email
  (operator-chosen SMTP), Slack webhook, Telegram bot are explicit
  operator opt-in with operator-chosen endpoints.
- **Transparency anchoring:** `sanctuary transparency anchor enable`
  (or `sanctuary wrap --anchor-transparency`) publishes a salted hash
  commitment of each enforcement checkpoint to a public transparency
  log. OFF by default behind an explicit consent flow; the operator
  confirms (and may override with `--rekor-url`) the log endpoint,
  which defaults to the community-run `https://rekor.sigstore.dev`.
  The consent record and every anchor attempt (success or failure) are
  logged in the audit chain. Payload is a salted SHA-256 digest, a
  signature from a dedicated derived key, and that key's public half,
  never state content, counts, policy data, or fortress identifiers.
  See `docs/transparency-checkpoints.md`, "External anchoring".

### Documented default-on exceptions (install/wrap-time only)

These are the two known deviations from strict zero-outbound: neither
runs in the server/dashboard/broker/hub runtime the rule above governs;
both are CLI-invocation-time-only checks against the public npm
registry, unauthenticated, status-code-only, and both are disabled by
the same operator knob.

- **`checkPinnedVersionResolvable` (wrap-time pin-resolvability probe,**
  `server/src/wrap/cli.ts`): during `sanctuary protect` / `sanctuary
  wrap` (skipped for dev-dist installs), an unauthenticated HEAD-class
  GET to the resolved npm registry checks whether the version being
  pinned still resolves, so the operator gets an honest warning instead
  of a silently dead pin. Default ON; disabled by
  `SANCTUARY_NO_UPDATE_CHECK=1` (the documented zero-outbound knob).
  No credential is ever attached to the request; only the response
  status code is consulted.
- **`update-check.ts`** (pre-existing): a similar unauthenticated
  registry check for a newer published version. Default ON; also
  disabled by `SANCTUARY_NO_UPDATE_CHECK=1`.

Operators who require strict zero-outbound at wrap/install time set
`SANCTUARY_NO_UPDATE_CHECK=1` in the environment before running
`sanctuary protect` / `sanctuary wrap`.

Each escape hatch must be:

1. Configured by the operator (no Sanctuary-shipped default endpoint).
2. Documented as outbound in the `outbound-audit.sh` allowed-pattern
   list when enabled, with a comment naming the operator-config source.
3. Logged in the audit chain on every use.

## Related

- RFC-0003 Castle Architecture (`server/rfcs/`, queued).
- WP-V1.x-CASTLE-WALL milestone (Phase 1 macOS+Linux egress filter).
- Substrate selector (`server/src/intelligence/selector.ts`) is the
  canonical inference egress point.
- Webhook approval channel
  (`server/src/principal-policy/approval-channel.ts`).

## Baseline result on this PR

Captured 2026-05-01 against `wp-v1.2-chat-removal-reshape` HEAD with a
15-second soak (lower bound; production drill will run the default
60-second window). Process-tree capture confirmed: the audit polls the
full descendant set on every tick, not just the parent dashboard PID.

```
outbound-audit: soak window 15s, platform Darwin
outbound-audit: Sanctuary running as PID 56879. Capturing outbound connections...
outbound-audit: soak complete; analyzing connections...

outbound-audit: connection summary
  total unique connections: 0
  unauthorized destinations: 0
  peak Sanctuary process tree size during soak: 1 pid(s)

outbound-audit: PASS - no unauthorized outbound destinations.
```

The dashboard process opened zero outbound connections during the soak.
The peak process-tree size of 1 pid means the dashboard did not spawn
any child processes during normal startup; the methodology is correct
regardless (when a child does spawn, e.g., a Concordia sidecar handling
a composition request, the tree-refresh on the next tick picks it up).
This baseline ships with the PR; subsequent changes that introduce a
new outbound destination (substrate adapter, federation peer, future
daily-digest channel) MUST update the allowed-pattern list and surface
the addition in PR review.

### Methodology fix on this PR (Codex 5.5 second-opinion review feedback)

The initial wave-6 audit script filtered by parent PID only. Codex
correctly flagged that a child process opening an outbound connection
(future helper, sidecar, substrate worker) would not be captured, so
the empirical "0 unauthorized destinations" baseline was hollow against
the script's own claim of auditing the "Sanctuary process tree." This
PR fixes the script to walk descendants per tick (`get_pid_tree()`
helper plus per-platform PID-set filter for `lsof` on macOS and `ss`
on Linux) and re-runs the baseline against the new methodology. The
0-connection result holds; the difference is that the result now
empirically matches the claim.

## Open follow-ups

- Wiki copy at `Wiki/decisions/sanctuary-no-outbound-by-default.md`
  (separate `newton-wiki` repo; coordinator drafts when convenient).
- Pre-commit grep gate for unauthorized HTTP client imports.
- CI integration: a sanitized variant of `outbound-audit.sh` that runs
  in the Linux CI runner against a stubbed substrate.
