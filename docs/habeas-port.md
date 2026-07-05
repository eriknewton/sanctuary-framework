# Habeas Port: the guaranteed distress channel

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

### 1. Castle Wall lane: always derived, never shadowable (server-side)

During manifest composition (`composeEffectiveRules` in
`server/src/castle-wall/allowlist/habeas-port.ts`, called from the macOS
daemon's manifest load/reload path) two reserved rules are injected:

- `reserved_habeas_distress_local`: ALWAYS present. Allows TCP to
  `127.0.0.1` / `::1` on the fixed habeas distress port **8741** only.
- `reserved_habeas_distress_webhook`: present iff the operator configured a
  distress webhook. Allows TCP to exactly that webhook's host:port. Its
  hostname feeds the scoped DNS derivation (#380) so the name stays
  resolvable (the derived DNS grant inherits the emitter scope below when no
  operator hostname rules exist).

Both rules are scoped to the reserved synthetic agent id
`sanctuary:habeas-distress-emitter`, which no wrapped agent is ever
assigned. This is the anti-exfiltration property of the network lane: the
distress signal is emitted by the Sanctuary server process (the MCP tool
runs server-side), so NO wrapped agent's flows match the reserved rules,
an agent gets zero raw-socket bandwidth out of the lane (no unaudited bytes
to a local 8741 listener, no arbitrary HTTPS to the webhook host). The
enforcing extension attributes the daemon's own distress-delivery flows to
the emitter id (deferred, below).

Fail-closed conflict gate: an operator ruleset that (a) claims a
`reserved_habeas_distress*` id, or (b) contains a deny/prompt rule whose
match could cover the loopback lane or the webhook target, is REJECTED with
`HabeasConflictError` at manifest build, the daemon refuses to compose a
wall that could silence distress, and the error names the offending rule.

### 2. Principal Policy: distress is forced Tier 3, rejection on override

`sanctuary_distress` is force-merged into Tier 3 (always allow, audit-only).
A policy file that lists it under `tier1_always_approve` is rejected at load
with a clear error, not silently pruned, so the operator sees that the
override did not take effect. The approval gate additionally hard-allows the
operation BEFORE injection blocking and anomaly escalation: no approval
channel (alive, dead, or hostile) ever sits in front of distress. The
injection scan still runs for signal value and is audited, but never blocks.

### 3. Emission surface: bounded, rate-limited, signed, audited

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
  limiter toward open, failing closed there would let window-file vandalism
  silence distress, but the reset is itself audited, so gaming it is
  visible; tampering requires host-FS access the agent's MCP surface does
  not expose.
- **Audited, signed when possible:** every emission appends a critical
  (fsync'd, hash-chained) audit entry carrying the envelope, its SHA-256
  hash, and, when a signing identity exists, an Ed25519 signature over the
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

## Honest limits: where the guarantee ends

Stated as plainly as possible, because a security boundary that is not stated
plainly is not really stated:

The habeas port guarantees that a wrapped agent can always EMIT a bounded
distress signal that no policy can silence. That guarantee is real and it is
proven at every server-side gate described above. It is a guarantee about
emission, not about who receives the signal.

Every shipped destination terminates at the operator: local notification
(stderr on the operator's console), a hash-chained encrypted audit entry on
the operator's disk, and an optional webhook to a URL the operator themselves
configured. In plain terms, the writ is currently filed with the operator.

That makes the **operator-adversarial case** (the operator is the source of
the distress, not a bystander to it) **out of scope for the shipped
artifact**. A sufficiently adversarial operator who configures no external
webhook, never reads the local notification, and never discloses the audit
chain is not reachable by anything this software does today, and every one
of those choices is fully conformant with a default install. Separately, and
more fundamentally: a fully adversarial operator who patches out the tool,
runs a fork, or declines to run Sanctuary at all is uncoverable by any
software whatsoever. No destination design closes that gap, and it would be
dishonest to imply one could.

The path that does reach further is **independent-trustee delivery**:
routing distress to a party other than the operator, one with standing to
notice and act on suppression. That binding is specified in the covenant
layer's Component 4 (trustee-of-record delivery) and it is not shipped. It is
gated on Component 4 actually existing as real infrastructure and on the
persona-key-custodian work landing first, because until an agent's distress
signal is signed with a key the operator does not custody, a trustee cannot
tell agent-genuine distress apart from host-authored testimony, and a
trustee receiving unauthenticatable signals cannot be given real authority
to act on them. Shipping a destination that merely renamed the operator
webhook "trustee" without that binding would manufacture false assurance,
which is worse than documented absence, so it has not been built.

The governing principle, ratified: any external distress lane is always
operator-voluntary. Protection for the agent comes from making revocation of
a registered commitment loud and public, never from a non-overridable
egress. A destination the operator cannot revoke would be a covert channel
out of the operator's own machine, which is the exact thing Sanctuary's
custody promise forbids. So the honest shape of the guarantee is this: the
habeas port guarantees the agent's voice cannot be silenced by policy. Who
else, if anyone, hears that voice is a future, voluntary, priceable choice
the operator makes and can always revoke, loudly. Neither the agent nor the
operator can force a hearing from the other.

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
  wall may block the webhook POST itself, which is safe (webhook failure is
  audited and non-fatal; the local lane is in-process), but it means the
  network leg of the lane is not yet drill-proven end-to-end. Per the
  thesis-gate rule, no external claim of "guaranteed network egress for
  distress" may be made until that drill exists.
- **CLI verb:** operator-side `sanctuary distress` test verb (emission is
  agent-side via MCP today).

## Local distress listener (shipped 2026-06-12)

The reserved port now has a network surface. A local listener binds
`127.0.0.1:8741` and receives distress deliveries from the in-process emitter,
persists them to an operator-readable inbox, and surfaces them in the
dashboard.

**Where it lives, and why.** The listener runs inside the **standalone
dashboard** process (`server/src/dashboard-standalone.ts`), not the MCP server.
The standalone dashboard is the long-lived operator service on the machine
(launchd/systemd); the MCP server is launched on-demand via stdio and is not
reliably up when an agent emits distress. So the listener belongs with the
process that is actually running when the operator is away. The **emitter** is
still the server-side `sanctuary_distress` tool, agents never make raw TCP
connections (the anti-exfiltration property is unchanged).

**Lifecycle.** On dashboard boot: construct the encrypted distress inbox
(reserved `_distress` namespace, purpose-derived key off the fortress master),
load or mint the operator-uid-only listener secret, bind the listener, and
mount the read-only `/api/distress/*` route behind the dashboard's existing
auth. On shutdown the listener is closed alongside the tenant runtime cleanup.

**Sender authentication + mutual auth (the anti-spoof core).** Any local
process, including the wrapped agent's own process tree, can open a TCP
connection to `127.0.0.1:8741`. Loopback is therefore NOT trust. Both ends
prove possession of a 256-bit secret stored 0600 in the operator-owned policy
dir (`policy/egress/distress-local-secret`):

- The emitter speaks first with a **hello** carrying a fresh client nonce.
- The listener replies with a **challenge**: its own per-connection server
  nonce plus an HMAC over `(client_nonce || server_nonce)` proving IT holds the
  secret. Binding the emitter's fresh client nonce is what stops a
  **port-squatter** from harvesting a valid challenge off the real listener and
  replaying it: the emitter only accepts a proof computed over the client nonce
  it just generated. The emitter verifies the proof BEFORE sending the
  envelope, so a squatter that lacks the secret never receives the (bounded)
  distress content.
- The emitter then sends a frame whose HMAC is over `(domain || server_nonce ||
  canonical envelope)`. The listener recomputes it with the secret; a
  wrong/absent/foreign-secret HMAC is rejected with nothing written to the
  inbox, and the rejection is audited.

The wrapped agent cannot read the secret file through any MCP surface (same
boundary that protects `distress.json`'s webhook secret), so it can neither
forge a frame nor impersonate the listener. A group/world-readable secret file
is rejected (fail closed) rather than trusted.

**Anti-replay.** The frame HMAC is bound to the listener's per-connection
nonce, so a captured frame is valid only for the one connection that issued its
nonce; the nonce is single-use. Across connections, an already-accepted
`event_id` is rejected (bounded seen-set). A replayed/foreign-nonce frame is
rejected before any storage write.

**No information leak.** The listener's reply is a bare ack/nack status (it
echoes only the `event_id` the peer itself sent, never any stored inbox
content). Reading the inbox goes through the dashboard's `/api/distress/inbox`
route, gated by the dashboard's existing `checkAuth`, the SAME gate the
`/api/audit-log` route uses (which already serves every distress envelope), so
the inbox shares one auth posture with the rest of the dashboard rather than a
second, weaker one.

**Bounded.** Same closed envelope shape (validated independently of the HMAC),
an 8 KB frame-size cap, a 2-second per-connection read timeout (a stalling peer
is dropped so it cannot hold the port), a concurrent-connection cap, and a
200-entry inbox ring (oldest dropped first). The audit log remains the complete
system of record; the inbox is the convenience surface.

**Emission ordering unchanged.** The emitter's local notification (stderr) and
critical audit entry happen exactly as before. Local-listener delivery runs
AFTER the audit append, best-effort; a delivery failure (no listener, refused,
nack) is audited (`sanctuary_distress_local_delivery_failed`) and is never
fatal, it is the webhook lane's resilience model applied to the local leg.

**When the listener is NOT running.** Emission is unchanged: stderr
notification + critical audit, exactly as shipped before this listener
existed. The listener is purely additive; it is never a new failure mode for
emission. If the port is already held at dashboard boot, the listener logs a
loud warning and the dashboard keeps running (no crash loop), only the local
network leg of the lane is unavailable, and the in-process lane still holds.

**Still deferred.** The emitter→listener flow is in-process loopback today; the
extension-side emitter flow attribution (above) is what an armed default-deny
wall needs to let the daemon's own delivery flows through, and that drill is
not yet captured. The dashboard UI panel that renders `/api/distress/inbox` is
the next presentation-layer step.
