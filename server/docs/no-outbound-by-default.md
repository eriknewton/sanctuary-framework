# Sanctuary, no outbound by default

**Status:** active rule (zero-outbound-by-default reshape)
**Date:** 2026-05-01 (update/pin-probe posture flipped to default-OFF 2026-07-05)
**Scope:** server runtime, dashboard, MCP servers, broker, hub
**Enforcement:** `server/scripts/outbound-audit.sh` (manual + acceptance drill)

## The rule

Sanctuary initiates no unrequested network connection. Specifically, the
server runtime, dashboard, MCP servers, broker, and hub MUST NOT:

- Phone home for telemetry, version checks, or analytics unless the
  operator has explicitly opted in (see "Update and pin probes" below)
  or explicitly requested an on-demand check (`sanctuary check-updates`).
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
product for the segment we are building for. The substrate-position
thesis rests on this rule.

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
- The process-tree refresh on each tick is what makes the soak complete: a child process
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

  Failure mode: this opt-in is the one that does not come back. A public
  transparency log is append-only by construction, so an anchor published by
  mistake (wrong fortress, a test run against the production log, an operator
  who meant to try it once) cannot be withdrawn by disabling the setting
  afterward. Turning anchoring off stops future publication and leaves every
  prior entry public and permanent. What the entries reveal is bounded by
  design, a salted digest and a signature from a dedicated derived key, and
  the timing and cadence of your checkpoints are visible regardless. Point
  `--rekor-url` at a test log for any trial run, and treat the first
  production anchor as the irreversible step it is.

### Update and pin probes (default OFF, operator opt-in)

These are the update/pin-resolvability probes the codebase ships. As of
2026-07-05 all three are **OFF by default**: a fresh install with no
env var set makes none of these connections. An operator can opt the
two server-boot probes in explicitly with `SANCTUARY_UPDATE_CHECK=1`,
or run an on-demand, explicit-intent check at any time with
`sanctuary check-updates` (see below) without changing any default.
All three are unauthenticated (no credential is ever attached). Only
the first is wrap/install-time-only; the other two run inside the MCP
server process itself on every stdio boot, gated by the same env-var
check (`outboundUpdateChecksEnabled()` in `server/src/update-check.ts`).

- **`checkPinnedVersionResolvable` (wrap-time pin-resolvability probe,**
  `server/src/wrap/cli.ts`): during `sanctuary protect` / `sanctuary
  wrap` (skipped for dev-dist installs), an unauthenticated HEAD-class
  GET to the resolved npm registry checks whether the version being
  pinned still resolves, so the operator gets an honest warning instead
  of a silently dead pin. Status-code-only: no response body is read.
  Default OFF; opt in with `SANCTUARY_UPDATE_CHECK=1`. This is the only
  probe in this list that is install/wrap-time-only; it never runs
  inside the server/dashboard/broker/hub runtime.
- **`checkForUpdate`** (`server/src/update-check.ts`, invoked from
  `server/src/cli.ts` immediately after `server.connect()` on the
  stdio path): when enabled, runs **inside the running MCP server
  process on every stdio boot**, not just at install/wrap-time.
  Fire-and-forget, never blocks startup. Fetches a fixed
  public-npm-registry URL (`https://registry.npmjs.org/...`, not
  npmrc-resolved) and parses the JSON response body to read the
  `version` field, so this is not status-code-only. Default OFF; opt
  in with `SANCTUARY_UPDATE_CHECK=1`.
- **`checkForSignedUpdate`** (`server/src/update-check.ts`, invoked
  alongside `checkForUpdate` from the same `cli.ts` stdio boot path):
  when enabled, also runs inside the running MCP server process on
  every stdio boot. Egresses to the **GitHub Releases API**
  (`https://api.github.com/repos/eriknewton/sanctuary-framework/releases/latest`)
  and, to fetch the signed release-manifest asset, an
  allowlist-redirect-gated follow to `*.githubusercontent.com`. Reads
  and parses the full manifest body (not status-code-only) and
  verifies it against the pinned release-signing key before advising;
  fails closed (silent) on any unsigned/wrong-key/tampered/absent
  manifest. Default OFF; opt in with `SANCTUARY_UPDATE_CHECK=1`.

**Environment variables:**

- `SANCTUARY_UPDATE_CHECK=1` (explicit operator opt-in): turns the two
  server-boot-time probes (`checkForUpdate`, `checkForSignedUpdate`) and
  the wrap-time pin-resolvability probe ON. Has no effect if
  `SANCTUARY_NO_UPDATE_CHECK=1` is also set (see precedence below).
- `SANCTUARY_NO_UPDATE_CHECK=1` (back-compat alias): forces all three
  probes OFF regardless of `SANCTUARY_UPDATE_CHECK`. Kept so operators
  who set it under the old (checks-on-by-default) behavior get the
  same zero-outbound outcome they had before; it can never be used to
  turn checks on.
- Neither set: all three probes OFF. This is the default as of
  2026-07-05.

**Explicit on-demand check, independent of the env-var default:**
`sanctuary check-updates` always runs both the bare npm-registry check
and the signed release-manifest check right now, regardless of the
`SANCTUARY_UPDATE_CHECK` / `SANCTUARY_NO_UPDATE_CHECK` defaults, because
invoking the verb is itself the operator's explicit request. It never
blocks or hard-fails on "offline"; see `server/src/cli/check-updates.ts`.

Each probe above must be:

1. Off by default (no Sanctuary-shipped default-on outbound connection).
2. Documented as outbound in the `outbound-audit.sh` allowed-pattern
   list when the operator enables it, with a comment naming the
   operator-config source (the env var, in this case).
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
