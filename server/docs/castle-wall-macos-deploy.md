# Castle Wall macOS - operator deploy guide

Trust claims for macOS egress enforcement are tracked in [../../ASSURANCE_MATRIX.md](../../ASSURANCE_MATRIX.md).

This guide covers installing and verifying the Castle Wall macOS system
extension. Castle Wall is the Castle Layer 1 enforcement piece: a
kernel-level egress filter that blocks unauthorized network calls from
wrapped agents on the operator's Mac. The macOS implementation uses
Apple's `NetworkExtension` framework (`NEFilterDataProvider`) and runs
as a system-extension bundle.

Boot-service install (daemon up at boot in safe mode, F1 Option C) is
documented in
[castle-wall-macos-boot-service.md](castle-wall-macos-boot-service.md);
headless arm/disarm (`sanctuary castle-wall enable|disable`, shipped in PR
#448) is summarized in
[castle-wall-headless-arm-design.md](castle-wall-headless-arm-design.md).

## Shipped capability

This doc originally staged large parts of the flow as unbuilt "Phase 2 /
Alpha-3 / Alpha-4" scope. Those have since shipped. What is live today (traced to
ASSURANCE_MATRIX row 18 "Egress enforcement: macOS"):

- **The system extension enforces per-uid allow/deny that survives reboot** on a
  Developer-ID-signed + notarized + stapled binary, proven by the drills linked
  in ASSURANCE_MATRIX row 18. Do not claim beyond that row (in particular this is
  NOT tamper-evident per-flow audit).
- **`.systemextension` bundle wrapping + install.** The signed `.app` is wrapped
  and installed; the sysext is approved in System Settings and (on Tahoe)
  toggled ON.
- **Headless arm/disarm CLI.** `sanctuary castle-wall enable` / `disable` arm and
  disarm the live content filter (SSH-safe after the one-time GUI consent),
  shipped in PR #448.
- **Safe-mode boot service.** `sudo sanctuary castle-wall install-boot` installs
  a launchd boot service so a reboot does not come up deny-all with no daemon
  (F1 Option C); see [castle-wall-macos-boot-service.md](castle-wall-macos-boot-service.md).
- **Trust-anchor re-pin.** `sanctuary castle-wall re-pin` migrates the trust
  anchor to the root signer helper's key.
- **Real verdict-emit wiring + manifest hot-reload + server-side UDS listener**,
  as described in the architecture section below.

For the end-to-end arm / verify / disarm sequence as an operator runbook, see
[castle-wall-macos-arm-runbook.md](castle-wall-macos-arm-runbook.md).

Known bounds still owed (per ASSURANCE_MATRIX row 18, do NOT claim past these):

- The TTL-expiry leg through the pure CLI `enable` path on Tahoe is still
  inconclusive (the headless-arm wedge, W7-1); arm is proven via the GUI toggle +
  safe-mode boot daemon.
- Full IPC handshake signature round-trip: the Swift `IPCClient` receives the
  server's `handshake_challenge` and treats arrival as handshake-complete without
  verifying the server's signature. Hardening the round-trip is a separate PR.
- `decision_response` operator-resume path for uncertain flows: uncertain
  verdicts return `.pause()`; resuming a paused flow once the operator decides is
  a follow-up.

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

### Build gotchas

| Gotcha | Symptom | What to do |
|---|---|---|
| **Someone else's cert is the default** | The script's built-in `SIGNING_IDENTITY` is the maintainer's cert, so on any other machine the preflight refuses with `signing identity '<name>' not in keychain` and exits 1 before building anything | export `SIGNING_IDENTITY` with your own Developer ID Application common name; `security find-identity -v -p codesigning` prints the exact string |
| **No partition-list grant on the login keychain** | The build **appears to hang.** It signs several bundles in sequence, and without the grant macOS pops a "codesign wants to use key" dialog for each one. Over SSH or from an automated thread there is nobody to click them, so the terminal simply stops with no error | run the one-time grant interactively: `security set-key-partition-list -S apple-tool:,apple:,codesign: -s ~/Library/Keychains/login.keychain-db`. For a session that must self-heal (a locked keychain after sleep re-introduces the prompts), export `SANCTUARY_KEYCHAIN_PW` and the script re-asserts the grant and unlocks before signing |
| **Wrong keychain password when self-healing** | `keychain unlock failed (wrong SANCTUARY_KEYCHAIN_PW?)`, exit 1 | fix the value, or unset it and rely on the one-time grant |

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

Failure mode: `codesign -d` writes its report to **stderr**, not stdout. Piping it
(`codesign -dvvv ... | grep Authority`) returns nothing at all, which reads as an
unsigned bundle when the signature is fine. Redirect first (`2>&1 | grep ...`) before
concluding anything from an empty result. Read these three commands as a set: the first
two can pass on a bundle whose entitlements are missing, and an extension without
`com.apple.developer.networking.networkextension` installs and then never filters.

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

Failure mode: the two commands are one step, and skipping the second one fails later
and elsewhere. `notarytool submit --wait` can report `Accepted` while the bundle on
disk still carries no stapled ticket, so Gatekeeper has to reach Apple to verify it.
The build machine, which is online and has already seen the ticket, launches it
without complaint. The failure surfaces on the target Mac, offline or behind a
restrictive network, as a refusal to launch that looks like a signing problem rather
than a missing staple. Run `xcrun stapler validate <path>.app` on the artifact you
are about to ship, not on the one you just submitted.

Failure mode: `--wait` blocks until Apple answers, and the answer can be `Invalid`.
Read the printed status line explicitly and pull the detail with `xcrun notarytool log
<submission-id>` when it is anything other than `Accepted`. A rejected submission
changes nothing on disk, so `build/` looks identical either way and a later `stapler
staple` is the first thing that complains.

## Run Sanctuary main with the listener active

The `MacOSFlowIpcListener` is wired into the Sanctuary runtime
lifecycle alongside the rest of the Castle Wall stack. On macOS, when
the runtime starts, the listener:

1. Resolves the UDS path via `resolveCastleWallSocketPath`.
2. Binds the path with mode `0600`.
3. Begins accepting extension connections.

Verify enforcement state with the live status probe:

```bash
sanctuary castle-wall status
```

`status` re-reads the LIVE Network Extension filter state (it never infers
"enforcing" from config presence). The current output reports the pinned-key
fingerprint, the global pin + trust-anchor verdict, the sysext state, the
`Content filter:` state (`enabled` when the wall is live), the app build
identity, and a dead-man lease line (labeled advisory, not enforcement, when the
filter is disabled). Read the live output rather than matching a fixed sample;
the exact lines evolve with the CLI.

## Manual end-to-end verification

The full kernel-level demo (curl exfil → kernel block → operator
notification → approve under 10s) requires the loaded system
extension. The verification below walks the operator through it.

1. Build the signed `.app` (above).
2. Wrap the `.app` into a `.systemextension` bundle inside the
   operator's host application (shipped; the build script alone does
   not produce a `.systemextension`).
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
- **Manifest hot-reload.** A 1000-rule manifest replaces in well under
  100ms on an unloaded 2024-era Mac; the CI-gated assertion allows up
  to 600ms (best of 3 samples) to absorb wall-clock jitter on shared
  runners without weakening the regression guard (covered by
  `test_handleInbound_manifestUpdated_hotReload_withinPerfCeiling`).

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
| `sanctuary castle-wall status` shows the sysext not loaded / `Content filter: disabled` on macOS you expect armed | the system extension is not loaded or the filter is not armed (on Linux this path is expected) | confirm platform is darwin; confirm the sysext is approved + (Tahoe) toggled ON; check the runtime startup logs for `MacOSFlowIpcListener` |
| Extension loaded but every flow is default-denied; logs show "no pinned key" | `~/.sanctuary/castle-pinned-pubkey.bin` is missing | run `sanctuary castle-wall provision-pin` to provision the pin and activate enforcement |
| Codesign fails with "unable to read identity" | Developer-ID cert not in keychain | run `security find-identity -v -p codesigning` and import the cert from the Apple Developer portal |
| Build succeeds but `spctl assess` reports `rejected` | unnotarized bundle | run `xcrun notarytool submit` (operator step) |
| Latency spikes under load | Flow cache eviction churn | inspect `FlowCache.count` via the engine's debug surface; cap defaults to 1024 entries |

## Castle-walking acknowledgement

This PR IS the Castle Layer 1 enforcement piece that does the blocking on
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
