# W4 Handoff

## Step 1 Findings

The provider does attempt to bind the daemon from `startFilter`: it resolves a socket path, loads the pinned public key, creates an `IPCClient`, starts the dispatcher, and the dispatcher sends `manifest_subscribe` after handshake.

The Mini1 symptom, however, was zero daemon subscriber/manifest/descriptor/lease lines. That places the failing hop before or at subscription, not in manifest fan-out. Static source tracing corrected part of the leading hypothesis: Swift already reads the `/tmp/sanctuary-castle-active.json` fallback when the protected active-config is unavailable, and the fortress-match guard only rejects when the provider has a non-nil mismatching fortress path. In the normal system-extension case, that env value should be nil.

The exact live hop was not recoverable from the old drill logs because the provider did not log enough bootstrap state. W4 adds those diagnostics so the next Mini1 run can distinguish active-config rejection, stale/missing pin, connect failure, handshake rejection, and subscribe/no-manifest.

## What Was Built

- Swift socket resolution now carries diagnostics for protected active config, legacy `/tmp` fallback, selected config, and selected fortress.
- Provider bootstrap/reconnect logs the socket diagnostics.
- Extension dispatcher tracks `connected`, `manifestReceived`, and `armLeaseReceived`.
- Connected-but-unbound enforcement now emits a `provider_unbound` diagnostic audit event once, either after a bounded timeout or when a verdict is evaluated while connected but unbound.
- Server macOS IPC listener routes extension `audit_emit` messages.
- MacOS flow-event consumer records `provider_unbound` through the audit sink and rejects non-provider extension audit attempts.
- `provider_unbound` is an accepted Castle Wall audit event type.
- Synthetic daemon integration now proves a sysext-style client using a non-default fortress active config can subscribe and receive both `manifest_updated` and `arm_lease`.
- Tahoe re-drill runbook was updated outside the worktree with a W4 binding preflight before any arm leg.

## Test Results

- `npm run typecheck` in `server/`: passed.
- `npm test` in `server/`: passed, 493 files passed, 5936 tests passed, 8 skipped.
- `swift build` in `castle-wall-macos/`: passed.
- `swift test` in `castle-wall-macos/`: passed, 274 XCTest cases passed.

## Divergence From Hypothesis

The `/tmp` fallback and fortress-match guard were not proven to be the direct cause. The code already accepts the fallback when the provider has no fortress env. The actual pre-W4 failure is best described as unobservable provider bootstrap/connect/subscription failure. This implementation adapts by making that hop observable and fail-loud, while preserving the existing root-owned fingerprint trust gate.

## Open Risks

- The authoritative proof remains the Erik-present Mini1 drill. CI proves the synthetic bind path and unbound audit plumbing, not the loaded system extension on Tahoe.
- If Mini1 has a stale non-nil `SANCTUARY_FORTRESS_PATH` in the provider environment, the new diagnostics should expose a `fortress_mismatch`; the code does not remove that guard because it still protects explicit-fortress callers from cross-fortress discovery.
- If the provider cannot connect at all, it can only surface through provider logs until IPC exists; the `provider_unbound` audit event requires a connected IPC channel.

No wall was armed, no Network Extension preferences were written, and `ASSURANCE_MATRIX.md` was not touched.
