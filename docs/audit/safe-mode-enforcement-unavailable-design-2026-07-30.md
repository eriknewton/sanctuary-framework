---
review_status: revised-after-independent-blocker-review
date: 2026-07-30
scope: Castle Wall safe-mode enforcement availability status
---

# Safe-Mode `enforcement_unavailable` Design

## Problem

The 2026-07-29 Mini2 finding showed the dangerous unattended-reboot shape:

- safe mode delivered a signed manifest
- the extension reported `manifest_received=true`
- no arm lease reached the provider
- operator-visible surfaces still looked healthy enough to miss the outage

PR #1045 changes the enforcement consequence for the lease-never-received path: the provider denies instead of allowing. That closes the security hole, but by itself creates a silent availability outage. After an unattended reboot the agent may be correctly denied, but the operator still needs every status surface to say why.

This design deliberately does not widen any reboot-survival claim. The 2026-07-28 reboot evidence remains attended until an unattended-reboot drill passes.

## Decision

Ship the refuse-loud path first. Do not add a new auto-arm claim in this build.

Safe mode still attempts to deliver the in-memory arm lease exactly as the daemon does today. The new behavior is that a direct extension diagnostic proving `manifest_received=true` and `arm_lease_received=false` becomes the stable status reason `enforcement_unavailable` everywhere:

- `castle-wall status` prints a loud local diagnostic
- top-level `sanctuary status` renders the reason, not just the bare arm state
- `/api/posture/castle-wall` returns `arm_state: "degraded"` with `evidence_basis: "enforcement_unavailable"`
- `/api/posture/feature-health` renders the Castle Wall row as `fault` with `basis: "enforcement_unavailable"`
- `/api/posture/home`, `/v1/status`, and the dashboard inherit those same values from the existing canonical posture builders

The arm state remains non-green. `enforcement_unavailable` is a reason for `degraded`, not a new arm state.

## Source Of Truth

Use the extension's existing `audit_emit` diagnostic:

```json
{
  "event_type": "provider_unbound",
  "details": {
    "manifest_received": true,
    "arm_lease_received": false
  }
}
```

This is better than trusting `systemextensionsctl`, a live daemon PID, handshake success, or `castle-wall-lease.json`. The field failure proved those can all look healthy while enforcement is absent or unavailable.

The at-rest audit operation remains `provider_unbound`; this avoids expanding the audit event vocabulary in this build. The trusted macOS flow-event consumer must stamp the normal Castle Wall provenance marker after it spreads the extension details:

```ts
[CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE
```

That is load-bearing because `buildCastleWallPosture` intentionally ignores entries without this marker. The marker is stamped by the consumer, last, so an extension-supplied `cw_source` cannot forge or remove the stored provenance value. Read-side code maps the specific detail combination to the status reason `enforcement_unavailable`.

## CLI Status

`sanctuary castle-wall status` cannot require the fortress master key, especially in safe mode. Add a small local diagnostic file next to the advisory lease file:

```json
{
  "state": "enforcement_unavailable",
  "reason": "manifest_present_arm_lease_missing",
  "updated_at": "2026-07-30T00:00:00.000Z",
  "source": "macos_extension_provider_unbound",
  "manifest_received": true,
  "arm_lease_received": false
}
```

The macOS flow-event consumer writes this file when it records the matching `provider_unbound` diagnostic. This file is the canonical fallback for safe mode because the boot daemon writes to a boot-token audit segment, while full dashboard/posture reads can be pointed at the master-key audit log after login. The fallback prevents a safe-mode-only diagnostic from being loud in one CLI path and invisible in API/dashboard paths.

`castle-wall status` reads it best-effort and, when fresh, prints:

```text
Enforcement availability: unavailable (extension reported manifest present with no arm lease; a #1045-capable extension should deny agents fail-closed, while older extensions may be unfiltered). Remediation: Install/reload the current Castle Wall extension, log in, run 'sanctuary castle-wall enable', and verify with an as-uid differential probe.
```

Freshness uses the existing Castle Wall enforcement freshness window. A stale file is mentioned as historical, but only a fresh valid file drives the loud unavailable line. A present-but-unreadable file is different from an absent file: read errors, truncated JSON, corrupt JSON, and schema mismatches synthesize a fresh non-green `status_present_unreadable` diagnostic until the file is fixed or removed.

The dead-man lease line stays advisory and should say so plainly. The status command must not treat an on-disk `armed: true` lease as proof that the provider received an arm lease.

Top-level `sanctuary status` consumes the `/v1/status` payload. Its table renderer must render `castle_wall.evidence_basis === "enforcement_unavailable"` as a loud reason line, so a user does not see only:

```text
castle wall: degraded
```

## Posture And Dashboard

Extend the canonical posture reason vocabulary:

- `CastleWallPosture.evidence_basis += "enforcement_unavailable"`
- `FeatureHealthBasis += "enforcement_unavailable"`

Mapping rule:

- fresh `provider_unbound` with `manifest_received=true` and `arm_lease_received=false` is a subclass of fault, not an alternative to fault
- feature-health records that entry in both the specific `enforcement_unavailable` accumulator and the generic fault accumulator, so a newer allow cannot turn the row green while the fault remains in the freshness window
- wall posture stays degraded while a fresh local `enforcement_unavailable` fallback is present; confirmed flow-decision recovery clears the local file, and only then can fresh adjudication recover the surface to green
- other fresh not-enforcing events continue to map to `not_enforcing_evidence` / `fault_evidence`

There are two accepted sources for this read-side signal:

1. A fresh, provenance-stamped `provider_unbound` audit entry in the audit log being read.
2. A fresh local `castle-wall-enforcement-status.json` diagnostic file with the exact `enforcement_unavailable` shape above.

Every caller of the canonical builders must thread the same local diagnostic snapshot into those builders:

- posture routes, including `/api/posture/castle-wall`, `/api/posture/feature-health`, `/api/posture/home`, and `/api/posture/stream`
- `Dashboard.buildStatusCastleWall()` for `/v1/status`
- the dashboard aggregator hero-shield path
- wrap's protection-claim probe and wrap-served dashboard startup/update source wiring

This is additive evidence only in the non-green direction. A local diagnostic can degrade or fault the wall, but can never arm it. While the diagnostic is fresh, newer live adjudication does not recover the surface to green; confirmed flow-decision recovery must clear the diagnostic first, or the diagnostic must age outside the freshness window.

Dashboard copy should be direct:

```text
Enforcement unavailable: manifest loaded, arm lease missing
```

## Non-Goals

This build does not:

- remove the deliberate dead-man fail-open path after a lease was received and then expires or is revoked
- give `castle-wall-lease.json` a TTL or make stale lease files read as unarmed
- run the unattended-reboot hardware drill
- claim unattended reboot survival
- touch Mini2
- add a Swift-to-daemon arm-lease acknowledgement protocol

The ack protocol is the stronger future proof, but it is not the close-behind status fix. This build uses the extension diagnostic already emitted in the failing condition.

Residual bounds called out by independent review:

- this PR closes the lease-never-received status-surface gap only; it does not close the deliberate dead-man fail-open path after a lease was received and then expired
- `castle-wall status` still exits 0 when enforcement is unavailable, so scripted monitors must inspect the status text or a structured surface
- local fallback injection occurs after some posture early-return paths, so those paths can remain non-green without carrying the exact `enforcement_unavailable` reason
- same-millisecond generic not-enforcing versus enforcement-unavailable ordering can mislabel the specific reason, but not the non-green state
- agent-facing MCP health/attestation surfaces remain bounded to degraded/not-green state and do not yet render this specific diagnostic

## Independent Review Notes

The first independent design review blocked implementation until four gaps were closed:

- safe-mode diagnostics could be trapped in the boot-token audit segment and remain invisible to dashboard/posture reads
- accepted `provider_unbound` audit entries were not explicitly required to carry the `cw_source` provenance marker
- top-level `sanctuary status` was missing from the status surface list
- feature-health needed to track the specific unavailable fault timestamp, not only the latest generic fault timestamp

This revision closes those gaps by requiring the canonical local diagnostic fallback, provenance stamping, top-level CLI rendering, and timestamp-specific unavailable tracking.

The second independent review found two merge-blockers and six follow-ups. This revision closes the blockers by treating `enforcement_unavailable` as fault evidence as well as a specific basis, and by chowning the safe-mode status file to the fortress owner while preserving `0600`. It also changes present-but-unreadable status files from silent `null` to a fail-closed local diagnostic, validates diagnostic timestamps before writing, clears the file on confirmed flow-decision recovery, wires the resolver through wrap/dashboard construction sites, and adds route-level coverage.

## Acceptance Criteria

Host-free tests:

- a `provider_unbound` diagnostic with manifest present and arm lease absent persists the local status file with `state: "enforcement_unavailable"`
- the accepted `provider_unbound` audit entry carries the Castle Wall provenance marker stamped by the consumer
- `castle-wall status` prints the loud unavailable line for a fresh status file, even if `castle-wall-lease.json` says `armed: true`
- top-level `sanctuary status` prints the unavailable reason from the `/v1/status` castle-wall payload
- `buildCastleWallPosture` returns `arm_state: "degraded"` and `evidence_basis: "enforcement_unavailable"` for the matching diagnostic
- `buildCastleWallPosture` returns the same degraded basis when the fresh local diagnostic fallback is supplied and the audit log lacks the boot-token entry
- `buildFeatureHealthPanel` returns Castle Wall `status: "fault"` and `basis: "enforcement_unavailable"` for the same diagnostic
- `buildFeatureHealthPanel` stays non-green when the unavailable diagnostic remains present even if a newer allow is observed
- the wrap protection claim does not render protected in that state
- present-but-unreadable status files synthesize a non-green local diagnostic rather than disappearing as `null`
- a successful flow decision clears the local diagnostic so genuine recovery does not stay loud for the full freshness window
- posture routes and the dashboard HTTP API surface the diagnostic end to end
- dashboard label rendering recognizes `enforcement_unavailable`

Hardware acceptance, owed after PR review:

- target: Erik-present real macOS box, Mini2 only when Erik is present and ready
- setup: signed manifest present, safe-mode or equivalent harness condition with no arm lease delivered
- probe: as-agent-uid flow against a manifest-allowed endpoint
- expected: DENIED, and every status surface above says `enforcement_unavailable`
- repetitions: N>=3
