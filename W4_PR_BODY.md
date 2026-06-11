Title: Castle Wall W4 provider-daemon binding diagnostics and unbound audit

## Step 1 Diagnostic Findings

### 1. Does the provider attempt to connect to the daemon socket on arm?

Yes, the provider code attempts the bind during `CastleWallFilterProvider.startFilter`:

- `startFilter` calls `bootstrapDispatcherIfNeeded(reason: "startFilter")`.
- Bootstrap calls `SocketPath.resolve(platform: "darwin", fortressPath: ProcessInfo.processInfo.environment["SANCTUARY_FORTRESS_PATH"], homeDir: NSHomeDirectory(), explicitOverride: ProcessInfo.processInfo.environment["SANCTUARY_CASTLE_SOCKET"])`.
- It loads the pinned public key via `loadPinnedPublicKey()`.
- It constructs `IPCClient(options: IPCClientOptions(path: resolved.path), pinnedPublicKey: keyLoad.key, pathResolver: { SocketPath.resolve(...).path })`.
- It constructs `ExtensionDispatcher(engine: ipcClient:)` and starts it.
- `ExtensionDispatcher.start()` calls `ipcClient.start()`, then sends `manifest_subscribe`.
- The daemon listener registers the connection as a subscriber on connection and, on `manifest_subscribe`, sends `manifest_updated`; if an arm lease exists it also sends `arm_lease`.

What was missing before W4 was provider-side evidence of the resolved discovery path, active-config statuses, selected fortress path, connect/handshake/subscription state, and whether manifest plus lease arrived. This is why the Mini1 drill had daemon-side zero subscriber/manifest/descriptor/lease lines but no provider-side failing-hop evidence.

### 2. Where is rendezvous breaking?

Source trace shows the observed drill outcome breaks before or at subscription:

- The daemon fan-out path only emits manifest/lease after the extension connects and sends `manifest_subscribe`.
- The drill had zero subscriber/manifest/descriptor/lease/broadcast daemon lines, so the provider did not reach a registered post-handshake subscription.
- The protected active-config to `/tmp` fallback split is not, by itself, sufficient to explain the observed zero-subscriber state: Swift `SocketPath.resolve` already reads `/tmp/sanctuary-castle-active.json` when the protected config is absent and `activeConfigPath` is the production default.
- The fortress-match guard only rejects discovery when the provider has a non-nil `SANCTUARY_FORTRESS_PATH` that differs from the discovery file. A normal system extension should not receive the drill fortress env, so the guard is not the primary explanation unless Mini1 has a stale extension environment.

Exact failing hop in the pre-W4 build: provider bootstrap/connect/handshake/subscription did not complete, and the old provider did not emit enough state to distinguish `active-config rejected`, `pinned key unavailable/mismatch`, `connect failed`, `handshake rejected`, or `subscribe sent but no manifest/lease`. W4 makes that hop observable and makes connected-but-unbound enforcement auditable.

### 3. Confirm/correct the hypothesis

The hypothesis is partially corrected:

- Correct: the system extension cannot rely on `SANCTUARY_STORAGE_PATH`/drill-fortress env, so runtime discovery is the right rendezvous.
- Correct: a drill/non-default fortress needs a pre-arm proof that the provider selected the daemon's active-config and received manifest, descriptor, and lease.
- Corrected: the `/tmp` fallback fortress-match guard is not the likely sole cause when `SANCTUARY_FORTRESS_PATH` is nil; Swift already accepts the `/tmp` discovery file in that case.
- Remaining live-hardware question: Mini1's exact failed bootstrap hop was not recoverable from the old logs. The new provider diagnostics name active-config status, legacy fallback status, selected config, selected fortress, IPC state, and bound state.

Evidence added in this PR:

- Provider logs active-config path/status, legacy path/status, selected config, selected fortress, and env fortress at bootstrap and reconnect.
- Dispatcher tracks `connected`, `manifestReceived`, and `armLeaseReceived`.
- Dispatcher emits one `provider_unbound` diagnostic audit event if connected but manifest+lease do not arrive within the bounded window, or if a verdict occurs while connected but unbound.
- Server listener now routes extension `audit_emit` diagnostics to the macOS flow-event audit sink instead of dropping them.

## Fix Summary

- Added `SocketPathDiagnostics` to Swift socket resolution and surfaced diagnostics from provider bootstrap/reconnect.
- Added `ExtensionDispatcher.BindingState` and bound-state tracking for manifest plus arm lease receipt.
- Added bounded connected-but-unbound detection in the dispatcher.
- Added `provider_unbound` audit event type and server-side macOS listener/consumer routing for extension diagnostic audit events.
- Extended daemon integration coverage so a sysext-style non-default-fortress client connects via active config, subscribes, and receives both `manifest_updated` and `arm_lease`.
- Updated the Tahoe re-drill runbook outside this worktree with a W4 provider↔daemon binding preflight before any arm leg.

## Test Summary

- `npm run typecheck` in `server/`: passed.
- `npm test` in `server/`: passed, 493 files passed, 5936 tests passed, 8 skipped.
- `swift build` in `castle-wall-macos/`: passed.
- `swift test` in `castle-wall-macos/`: passed, 274 XCTest cases passed.

No wall was armed, no Network Extension preferences were written, and `ASSURANCE_MATRIX.md` was not touched.
