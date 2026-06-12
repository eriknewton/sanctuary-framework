# Habeas Port — the guaranteed distress channel

**Status:** server-side enforcement shipped 2026-06-12 (agent-side sovereignty
foundations, Erik-ratified). Extension-side (sysext) non-shadowable precedence
is DEFERRED to the next sysext window.

## What it is

A reserved, guaranteed-egress distress lane that the policy layer cannot
override. No matter how restrictive an operator's Castle Wall egress rules or
Principal Policy are, a wrapped agent can always emit one narrow, bounded,
audited signal: "I am in distress, here is a one-line why."

The lane carries a signal, never data. It is not a side door.

## The three server-side guarantees

### 1. Castle Wall lane — always derived, never shadowable (server-side)

During manifest composition (`composeEffectiveRules` in
`server/src/castle-wall/allowlist/habeas-port.ts`, called from the macOS
daemon's manifest load/reload path) two reserved rules are injected:

- `reserved_habeas_distress_local` — ALWAYS present. Allows TCP to
  `127.0.0.1` / `::1` on the fixed habeas distress port **8741** only.
- `reserved_habeas_distress_webhook` — present iff the operator configured a
  distress webhook. Allows TCP to exactly that webhook's host:port. Its
  hostname feeds the scoped DNS derivation (#380) so the name stays
  resolvable (the derived DNS grant inherits the emitter scope below when no
  operator hostname rules exist).

Both rules are scoped to the reserved synthetic agent id
`sanctuary:habeas-distress-emitter`, which no wrapped agent is ever
assigned. This is the anti-exfiltration property of the network lane: the
distress signal is emitted by the Sanctuary server process (the MCP tool
runs server-side), so NO wrapped agent's flows match the reserved rules —
an agent gets zero raw-socket bandwidth out of the lane (no unaudited bytes
to a local 8741 listener, no arbitrary HTTPS to the webhook host). The
enforcing extension attributes the daemon's own distress-delivery flows to
the emitter id (deferred, below).

Fail-closed conflict gate: an operator ruleset that (a) claims a
`reserved_habeas_distress*` id, or (b) contains a deny/prompt rule whose
match could cover the loopback lane or the webhook target, is REJECTED with
`HabeasConflictError` at manifest build — the daemon refuses to compose a
wall that could silence distress, and the error names the offending rule.

### 2. Principal Policy — distress is forced Tier 3, rejection on override

`sanctuary_distress` is force-merged into Tier 3 (always allow, audit-only).
A policy file that lists it under `tier1_always_approve` is rejected at load
with a clear error — not silently pruned — so the operator sees that the
override did not take effect. The approval gate additionally hard-allows the
operation BEFORE injection blocking and anomaly escalation: no approval
channel (alive, dead, or hostile) ever sits in front of distress. The
injection scan still runs for signal value and is audited, but never blocks.

### 3. Emission surface — bounded, rate-limited, signed, audited

The `sanctuary_distress` MCP tool (`server/src/distress/tools.ts`):

- **Bounded payload:** closed `reason` enum (`policy_constraint`,
  `resource_exhaustion`, `integrity_threat`, `operator_unreachable`,
  `external_coercion`, `other`), closed `severity` enum
  (`notice`/`urgent`/`critical`), optional free-text `detail`
  control-stripped and hard-truncated to 280 chars. No namespace reads, no
  state content, no agent-chosen destination.
- **Fixed destination:** local operator notification (stderr) + critical
  audit entry by default; optionally ONE operator-configured webhook, with
  every payload HMAC-SHA256-signed (`X-Sanctuary-Signature`). Webhook
  failure is audited and never kills the local lane.
- **Rate limited:** rolling-hour window, default 5, operator-tunable 1..60
  via config (out-of-range values are rejected, not clamped); the window
  persists across restarts; rate-limited attempts are themselves audited (a
  flood attempt is visible). A corrupt or deleted window file resets the
  limiter toward open — failing closed there would let window-file vandalism
  silence distress — but the reset is itself audited, so gaming it is
  visible; tampering requires host-FS access the agent's MCP surface does
  not expose.
- **Audited, signed when possible:** every emission appends a critical
  (fsync'd, hash-chained) audit entry carrying the envelope, its SHA-256
  hash, and — when a signing identity exists — an Ed25519 signature over the
  envelope hash (audit-event signing domain). On a fresh fortress with no
  identity yet, the signal still goes through UNSIGNED and the entry records
  `signing_unavailable: true` explicitly: distress availability outranks
  signature completeness, and the hash-chained audit log stays
  tamper-evident either way. If the audit append itself fails, the tool call
  fails closed (no un-audited delivery) but the operator still receives the
  local notification, marked `AUDIT PERSIST FAILED`.

## Operator configuration

`<fortress>/policy/egress/distress.json` (optional; agent-immutable, loaded
once at startup like the Principal Policy; chmod 600 when it carries the
secret):

```json
{
  "webhook_url": "https://ops.example.com/distress",
  "webhook_secret": "<HMAC shared secret, >= 16 chars>",
  "max_signals_per_hour": 5
}
```

Absent file = local-only lane (notification + audit). A present-but-invalid
file fails startup (fail closed): operator intent is never silently
substituted. Non-loopback webhooks must be https; the secret is mandatory
with any webhook.

## Trust model and limits (stated honestly)

Every habeas destination today terminates at the operator: the local
notification reaches the operator's console, and the optional webhook reaches
a URL the operator configured. The lane therefore protects an agent whose
operator is absent or unaware, and partially protects against a compromised
operator seat (the signal is signed and hash-chain audited, so suppression
leaves evidence). It does NOT protect an agent whose operator is the threat:
the writ is filed with the jailer. This is a deliberate sovereignty boundary,
not an oversight. Sanctuary will not ship a destination the operator cannot
revoke; a non-overridable external egress lane would be a covert channel out
of the operator's machine and would break the product's core custody promise.
The roadmap path for the adversarial-operator case is third-party visibility
that the operator opts into and can loudly, auditably revoke: distress-count
beacons inside already-anchored audit checkpoints, and trustee-of-record
delivery as covenant-layer infrastructure matures. See
`Habeas_Destination_Trust_Research_2026-06-12` (internal) for the analysis.

## Deferred (named so it is not forgotten)

- **Sysext precedence:** the enforcing macOS system extension (and the Linux
  daemon) must give the `reserved_habeas_distress*` rule ids non-shadowable
  precedence in their evaluators, so a stale or hand-edited on-disk ruleset
  can never out-rank the lane. Until then the guarantee holds at every
  server-side derivation/validation point but is not yet re-asserted inside
  the enforcement plane itself.
- **Emitter flow attribution:** the extension must attribute the Sanctuary
  daemon's distress-delivery flows to `sanctuary:habeas-distress-emitter` so
  the reserved rules match them. Until that lands, an armed default-deny
  wall may block the webhook POST itself — which is safe (webhook failure is
  audited and non-fatal; the local lane is in-process), but it means the
  network leg of the lane is not yet drill-proven end-to-end. Per the
  thesis-gate rule, no external claim of "guaranteed network egress for
  distress" may be made until that drill exists.
- **Local listener:** nothing binds port 8741 yet; the local lane today is
  in-process (stderr + audit). The reserved port keeps the network identity
  of the lane stable for when a local distress listener (menubar/unified
  inbox) lands.
- **CLI verb:** operator-side `sanctuary distress` test verb (emission is
  agent-side via MCP today).
