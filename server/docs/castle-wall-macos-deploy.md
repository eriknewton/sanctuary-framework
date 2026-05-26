# Castle Wall macOS - operator deploy guide

Trust claims for macOS egress enforcement are tracked in [../../ASSURANCE_MATRIX.md](../../ASSURANCE_MATRIX.md).

This guide covers installing and verifying the Castle Wall macOS system
extension. Castle Wall is the Castle Layer 1 enforcement piece: a
kernel-level egress filter that blocks unauthorized network calls from
wrapped agents on the operator's Mac. The macOS implementation uses
Apple's `NetworkExtension` framework (`NEFilterDataProvider`) and runs
as a system-extension bundle.

## Phase 2 (Alpha-3) scope

What Phase 2 ships:

- Real verdict-emit wiring. Every flow decision the extension reaches
  (`allow` / `drop` / `uncertain`) fires an IPC notification back to
  Sanctuary main (`flow_decision_recorded` / `flow_pending_approval`).
- Manifest hot-reload. When the operator's allowlist changes, the
  extension's `ManifestStore` is replaced atomically and the verdict
  cache clears in the same critical section.
- Server-side UDS listener. Sanctuary main hosts the listener; the
  extension connects as a client and registers as a manifest
  subscriber.
- Developer-ID-signed build pipeline. The extension is produced as a
  Developer-ID-signed `.app` with hardened runtime + entitlements.
  Notarization (`xcrun notarytool`) is operator-side and out of scope
  for the build; the produced binary is notarization-ready.

What is NOT in Phase 2 (deferred to a follow-up):

- `.systemextension` bundle wrapping. The Developer-ID-signed `.app`
  is the substrate; wrapping it as a system-extension bundle inside
  the operator's host application is part of the install scope.
- Live operator demo against a loaded kernel extension. The Swift +
  TypeScript test suites exercise every contract at the IPC + verdict
  layers, but a real "wrapped agent attempts curl exfil and the wall
  blocks at kernel boundary" demo requires the loaded extension and
  is documented as a manual verification in this guide.
- Full handshake signature round-trip. The Swift `IPCClient` is at
  foundation scope: it receives the server's `handshake_challenge`
  and treats arrival as handshake-complete without verifying the
  server's signature. Hardening the round-trip is a separate PR.
- `decision_response` operator-resume path for uncertain flows.
  Uncertain verdicts return `.pause()` to the framework; resuming
  the flow once the operator decides requires `resumeFlow(_:with:)`
  wiring that lands with the install flow.

## Prerequisites

- **macOS 13 or newer.** The extension targets `.macOS(.v13)` per
  `castle-wall-macos/Package.swift`.
- **Xcode 14 or newer** (development only). Production deployment
  does NOT require Xcode; the signed `.app` artifact is the
  distribution unit.
- **Apple Developer Program enrollment + Developer ID Application
  cert in the keychain** (signer only). The Team ID and App ID are
  the maintainer's; the consuming operator only needs the signed
  binary.

## Architecture at a glance

```
Sanctuary main process                       macOS NEFilterDataProvider
  ┌────────────────────┐                       ┌─────────────────────┐
  │ MacOSFlowEvent     │                       │ CastleWallFilter    │
  │   Consumer         │  ◀─── flow_decision   │   Provider          │
  │                    │       _recorded ───── │                     │
  │ AuditSink          │                       │ FlowEvaluatorEngine │
  │ ApprovalQueue      │  ◀─── flow_pending    │   ManifestStore     │
  │                    │       _approval ──── │   FlowCache          │
  │ MacOSFlowIpc       │                       │ ExtensionDispatcher │
  │   Listener (UDS)   │ ───── manifest_       │                     │
  │                    │       updated ──────▶ │                     │
  └────────────────────┘                       └─────────────────────┘
         ▲                                              ▲
         │ UDS at ~/.sanctuary/castle.sock              │
         └──────────────────────────────────────────────┘
```

The daemon binds the UDS path resolved by `resolveCastleWallSocketPath`.
After bind, it atomically writes `/tmp/sanctuary-castle-active.json` with
the active `socket_path`, `fortress_id`, daemon `pid`, and `started_at`.
The system extension checks that file before environment-driven fallbacks
because it does not inherit the `sanctuary wrap` environment. The file is
mode `0644` under world-writable `/tmp` for this first integration; Phase 3
hardens the location to `/Library/Application Support/Sanctuary/active.json`.

## Build the signed `.app`

From the repo root:

```bash
./castle-wall-macos/scripts/build-signed.sh
```

The script:

1. Runs `swift build -c release` to produce the executable.
2. Assembles a `.app` bundle layout (Contents/MacOS/, Contents/Info.plist).
3. Signs with the Developer ID Application identity, hardened runtime,
   embedded entitlements (Network Extension filter-provider).
4. Verifies the signature and surfaces the SHA-256 of the signed binary.

Output: `castle-wall-macos/build/CastleWallExtension.app`.

Override the identity by exporting `SIGNING_IDENTITY` first:

```bash
SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
  ./castle-wall-macos/scripts/build-signed.sh
```

## Verify the signed `.app`

```bash
# Confirm Developer-ID signature + hardened runtime + entitlements.
codesign -dvvv castle-wall-macos/build/CastleWallExtension.app

# Should print:
#   Authority=Developer ID Application: Erik Newton (YFQSWQ9BJN)
#   TeamIdentifier=YFQSWQ9BJN
#   flags=0x10000(runtime)        ← hardened runtime

codesign --verify --deep --strict --verbose=2 \
  castle-wall-macos/build/CastleWallExtension.app
# Expected: "valid on disk" + "satisfies its Designated Requirement"

codesign -d --entitlements - castle-wall-macos/build/CastleWallExtension.app
# Expected entitlements:
#   com.apple.developer.networking.networkextension
#   com.apple.security.app-sandbox
#   com.apple.security.network.client
```

## Notarize (operator step, optional)

Notarization is required for distribution to other Macs. Submit to
Apple Notary Service:

```bash
xcrun notarytool submit \
  castle-wall-macos/build/CastleWallExtension.app \
  --keychain-profile <your-notary-profile> \
  --wait
xcrun stapler staple castle-wall-macos/build/CastleWallExtension.app
```

Sanctuary itself does not perform this step; it is operator-controlled
infrastructure.

## Run Sanctuary main with the listener active

The `MacOSFlowIpcListener` is wired into the Sanctuary runtime
lifecycle alongside the rest of the Castle Wall stack. On macOS, when
the runtime starts, the listener:

1. Resolves the UDS path via `resolveCastleWallSocketPath`.
2. Binds the path with mode `0600`.
3. Begins accepting extension connections.

Verify Sanctuary main is listening:

```bash
sanctuary castle-wall status
# Expected:
#   listener: ai.sanctuaryprotocol.macos.castle-wall
#   socket:   /Users/<you>/.sanctuary/castle.sock (active)
#   subscribers: 1   ← once the extension has connected
```

## Manual end-to-end verification

The full kernel-level demo (curl exfil → kernel block → operator
notification → approve under 10s) requires the loaded system
extension. The verification below walks the operator through it.

1. Build the signed `.app` (above).
2. Wrap the `.app` into a `.systemextension` bundle inside the
   operator's host application. This step is the Alpha-4 install
   scope; the build script alone does not produce a
   `.systemextension`.
3. Install the system extension: from the host app, call
   `OSSystemExtensionManager`'s `submitRequest(_:)` with a
   `OSSystemExtensionRequest.activationRequest`. macOS will prompt
   the operator to approve in System Settings → Privacy & Security.
4. Approve in System Settings. The extension loads; sysextd dispatches
   `startFilter(completionHandler:)`. The dispatcher opens the UDS
   connection to Sanctuary main and registers as a subscriber.
5. Configure an allowlist that includes `api.anthropic.com:443/tcp`
   but excludes `evil.example.com`.
6. Wrap an agent (Claude / OpenAI / etc.). The agent attempts curl
   `evil.example.com` (prompt-injected exfil attempt).
7. Observe at three points:
   - **Kernel block.** The curl call fails with `EHOSTUNREACH` or
     similar; the extension dropped the flow.
   - **Operator notification.** Sanctuary main's audit log records
     `egress_blocked` with the destination + agent attribution. The
     menubar surface fires (this is the same Tauri menubar Phase 2
     work shipped in PR #104).
   - **Operator decision.** The operator opens the dashboard,
     reviews the block, approves or denies. (For uncertain flows
     the resume-via-`decision_response` path lands in a follow-up.)

Expected timing: kernel block is synchronous within the
NEFilterDataProvider callback. IPC notification + audit-log write +
menubar notification fire within ~50ms of the block.

## Performance invariants

- **Verdict latency.** The verdict path is the engine's
  `evaluate(_:)` call plus the cache lookup. Allowed traffic on the
  hot path is a cache hit (single dictionary lookup) and never
  touches the manifest rule walker. The IPC notification is
  fire-and-forget AFTER the verdict has been returned to
  NEFilterDataProvider; a slow / broken IPC channel never delays
  the verdict.
- **Manifest hot-reload.** A 1000-rule manifest replaces in under
  100ms on a 2024-era Mac (covered by
  `test_handleInbound_manifestUpdated_hotReload_under_100ms`).

## Fail-closed invariants

- **No manifest loaded.** The evaluator returns `.drop(matchedRuleId:
  nil)` for every flow. No "evaluate-against-stale-cache" path can
  surface an allow when the manifest substrate is empty
  (`test_failClosed_emptyManifest_answersDrop`).
- **Empty rules snapshot.** Same outcome: every flow drops by
  default-deny.
- **IPC dropped mid-flight.** The dispatcher's `ipcClient.send` is
  fire-and-forget; verdict return to the framework completes
  regardless. The extension continues evaluating against the cached
  manifest snapshot. Reconnect logic + manifest re-subscribe land
  in a follow-up; today the dispatcher logs and continues.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `sanctuary castle-wall status` shows `listener: not active` on macOS | Sanctuary main did not start the macOS listener (e.g. on Linux that is expected) | confirm platform is darwin; check the runtime startup logs for `MacOSFlowIpcListener` |
| Extension loaded but every flow is default-denied; logs show "no pinned key" | `~/.sanctuary/castle-pinned-pubkey.bin` is missing | run `sanctuary castle-wall provision-pin` to provision the pin and activate enforcement |
| Codesign fails with "unable to read identity" | Developer-ID cert not in keychain | run `security find-identity -v -p codesigning` and import the cert from the Apple Developer portal |
| Build succeeds but `spctl assess` reports `rejected` | unnotarized bundle | run `xcrun notarytool submit` (operator step) |
| Latency spikes under load | Flow cache eviction churn | inspect `FlowCache.count` via the engine's debug surface; cap defaults to 1024 entries |

## Castle-walking acknowledgement

This PR IS the load-bearing Castle Layer 1 enforcement piece on
Apple silicon: the kernel-level decision sits inside
`CastleWallFilterProvider.handleNewFlow` (a `NEFilterDataProvider`
subclass), which sysextd loads as a kernel extension. Real
enforcement is preserved by the substrate; cooperative MCP
(Castle Layer 3) is the parallel sovereignty surface for
compliant agents and is NOT a substitute for this piece.

The fail-closed invariant test (no manifest loaded → engine
default-denies every flow) is the structural commitment that an
operator's Mac is never silently passing traffic the manifest does
not explicitly authorize.
