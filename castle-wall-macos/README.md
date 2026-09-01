# Castle Wall macOS

Trust claims for macOS egress enforcement are tracked in [../ASSURANCE_MATRIX.md](../ASSURANCE_MATRIX.md).

Phase 1 foundation of WP-V1.x-CASTLE-WALL on macOS. Castle Architecture's
Castle Wall layer lives at the OS-level egress filter; on macOS the
`com.apple.developer.networking.networkextension` `content-filter-provider-systemextension`
entitlement gates the kernel-attached chokepoint.

## Status

**Packet filter logic + manifest sync engaged (Alpha-2).** The package
ships a working `handleNewFlow` verdict path that consults a manifest
snapshot received via IPC, an LRU flow cache for hot destinations, and
new IPC notifications for flow decisions + pending approvals.
Loaded-extension integration tests + audit-emit pipeline + install flow
land in subsequent Alpha builds.

| Build | Scope | Status |
|-------|-------|--------|
| Alpha-1 | Project structure, NEFilterProvider subclass, UDS IPC client, Ed25519 handshake verification, macOS CI, unit tests | Shipped (PR #150) |
| Alpha-2 (this) | NEFilterProvider verdict logic, manifest store + flow cache, IPC bridge for manifest sync + flow decision telemetry, server-side handler module | This PR |
| Alpha-3 | Audit emit pipeline, Tier B coverage (DoH, DoT, content-filter equivalents), loaded-extension integration tests, p99 perf measurement | Pending |
| Alpha-4 | Install + uninstall flow, signed dmg, notarization, host-app launcher with operator notification UX | Pending |

## Relationship to `castle-wall-daemon/` (Linux)

Different platform, same IPC protocol, same Sanctuary-main-side runtime.

| Concern | Linux | macOS |
|---------|-------|-------|
| Kernel binding | nftables + nfqueue (root daemon) | NEFilterProvider system extension (user-approved) |
| IPC transport | UDS at `/run/sanctuary/<fortress-id>/filter.sock` | UDS via the fallback chain in `Sources/CastleWallIPC/SocketPath.swift` |
| Wire framing | LSP-style `Content-Length` headers | Same |
| Wire envelope | JSON-RPC 2.0 over the framing | Same |
| Authentication | Ed25519 challenge-response + SO_PEERCRED | Ed25519 challenge-response (no SO_PEERCRED equivalent on macOS Network framework) |
| Privilege | Root daemon, dropped to `sanctuary` group | User-space system extension; user approval per Apple sysextd |
| Distribution | Native package + systemd unit | Notarized signed dmg (Alpha-4) |

The Sanctuary main side speaks the SAME wire protocol regardless of which
platform the kernel-binding side runs on. `server/src/castle-wall/ipc/`
is the cross-platform reference.

## UDS socket path resolution

Both sides converge on the same socket path via a fallback chain. The
authoritative implementation is
`server/src/castle-wall/runtime/socket-path.ts`; the Swift mirror in
`Sources/CastleWallIPC/SocketPath.swift` MUST agree byte-for-byte for
every fixture in the parity test.

Order of resolution:

1. **macOS**: `/tmp/sanctuary-castle-active.json` when present, valid,
   and either missing `pid` or pointing at a live daemon process.
2. `SANCTUARY_CASTLE_SOCKET` environment variable (explicit override).
3. **Linux**: `/run/sanctuary/<fortress-id>/filter.sock` (root daemon path).
4. **macOS**: `${SANCTUARY_FORTRESS_PATH}/castle.sock` if set.
5. **macOS**: `~/.sanctuary/castle.sock` if `HOME` is set.
6. **macOS**: `/var/run/sanctuary-castle.sock` (last resort; only writable as root).

macOS rootless protections block `/var/run` for unprivileged processes,
which is why the per-fortress and home-default fallbacks come first.
The active discovery file is intentionally first because the system
extension does not inherit the `sanctuary wrap` environment. The file is
written atomically with mode `0644`; `/tmp` remains world-writable in this
first integration and is slated for hardening to `/Library/Application
Support/Sanctuary/active.json`.

## Architectural decisions

- **Language: Swift.** NEFilterProvider is the Apple-native API; Swift
  gives clean access without the Objective-C bridge tax.
- **Build system: Swift Package Manager.** `xcodebuild` drives the
  package directly via `-scheme` + `-package-path`. The `.systemextension`
  bundle wrapping happens in Alpha-4 install flow.
- **IPC: UDS, not XPC.** XPC requires the system extension to embed
  inside a host-app bundle and run as a privileged helper. UDS keeps the
  protocol identical to the Linux daemon, eliminates a layer, and reuses
  the cross-platform server-side code path.
- **Test framework: XCTest** for Swift-side unit tests; vitest stays for
  server-side integration on the TypeScript side.
- **Signing: Developer-ID + Network Extensions entitlement.**
  Apple Team ID `YFQSWQ9BJN`, App ID `ai.sanctuaryprotocol.macos`, sub-App-ID
  for the system extension `ai.sanctuaryprotocol.macos.castle-wall`.
  Notarization lands in Alpha-4.
- **CI: `macos-latest` GitHub runner.** Builds the package without code
  signing (CI cannot sign; foundation does not require a signed binary
  to run unit tests). Loaded-extension scenarios CANNOT be exercised in
  CI because user approval is required.

## Local build

Requires Xcode 15+ on macOS 13+.

Build the package:

```sh
xcodebuild build \
  -scheme CastleWallExtension \
  -package-path castle-wall-macos \
  -destination 'platform=macOS' \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO
```

Run unit tests:

```sh
xcodebuild test \
  -scheme CastleWallIPCTests \
  -package-path castle-wall-macos \
  -destination 'platform=macOS' \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO
```

Or directly via SwiftPM:

```sh
cd castle-wall-macos
swift test
```

## Security model

The macOS NEFilterProvider runs unprivileged in user space, but its
content-filter callbacks are invoked synchronously by the kernel for
every flow on the system. Apple gates loading via a user approval
prompt + signed-with-entitlement check at install time; once loaded, a
prompt-injected user-space agent cannot bypass the filter within the proven
scope: one host, one OS version, signed extension installed and armed, and
attended reboot proof only.

The Sanctuary-main IPC connection authenticates via Ed25519
challenge-response: the macOS extension issues a 32-byte nonce, the
Sanctuary-main side signs it with the fortress identity key, the
extension verifies against a TOFU-pinned public key. SO_PEERCRED-style
UID binding is unavailable on macOS BSD sockets, so the fortress
identity binding is the primary trust anchor.

## What ships in subsequent builds

- Alpha-3: audit-emit pipeline, Tier B test surface (DoH, DoT, content
  filter parity with the Linux daemon's coverage matrix), loaded-extension
  integration tests against real NEFilterFlow shapes, p99 performance
  measurement on allowed traffic.
- Alpha-4: install / uninstall flow, signed dmg, notarization, host-app
  launcher with operator-facing notification UX, operator approval flow
  wiring (the verdict path here surfaces `flow_pending_approval`; the
  operator-decision IPC return path lands in Alpha-4 alongside the
  notification UX).

Phase 2 (Windows) and Phase 3 (container/microVM) are out of scope for
the macOS work package.

## Known issue: do not run `sanctuary init` followed by `sanctuary wrap`

`sanctuary init` and `sanctuary wrap` currently derive the fortress master
key from different sources:

- `init` derives from a random recovery key.
- `wrap` derives from a passphrase and does not consume `SANCTUARY_RECOVERY_KEY`.

Running `init` and then `wrap` against the same fortress can produce
`aes/gcm: invalid ghash tag` when the daemon decrypts the pinned IPC keypair.

Current workaround:

- Skip `init`.
- Use `sanctuary wrap` only. It creates the fortress, generates the passphrase,
  and derives the master key in one consistent pass.

Tracking reference: Newton Wiki session `sanctuary-castle-wall-mac-phase-2-5-track-4a-ipc-drill-mini1-2026-05-26.md` (operator-local; not part of this repo).

A future PR will either deprecate `init` for filesystem-only Castle Wall
fortresses or wire recovery-key consumption through `wrap`.

## Headless arm / disarm (SSH-safe operation)

Arm and disarm no longer require the GUI. The host-app binary doubles as a
headless filter CLI, and `sanctuary castle-wall enable|disable` drives it:

```
sanctuary castle-wall enable        # arm; refuses without a reachable policy daemon
sanctuary castle-wall enable --force
sanctuary castle-wall disable      # disarm; unconditional dead-man lever
```

Under the hood this launches the app through LaunchServices:
`open -n -W Sanctuary-CastleWall.app --args --headless <enable|disable|status|deactivate-system-extension> --report-file=<tmp>`.
If the GUI app is already running, the CLI first terminates that instance and
then relaunches the same signed app bundle headlessly. This preserves the
operator-granted macOS content-filter consent while avoiding LaunchServices'
`Unable to block on application` failure for already-running apps.
The host app prints one JSON line and exits 0 (success), 1 (failure), 2
(usage), 3 (needs the one-time consent), or 4 (NE preferences timeout).
Running the host-app binary itself is required: the NE content-filter
configuration is owned by the signed app identity that created it, so only
that binary can toggle `NEFilterManager.isEnabled` without re-prompting. The
headless path never initializes SwiftUI, so it needs no WindowServer and works
over SSH.

Every headless report includes a deployed-app build identity:

```json
{"build":{"git_sha":"<sha>","headless_contract_version":"3"}}
```

The TypeScript CLI carries its own git SHA and headless contract version and
fails loudly when the deployed signed app reports a different value. Whenever
the headless contract changes, rebuild the CLI from the same commit, rebuild
the signed `Sanctuary-CastleWall.app`, deploy that matching app, and verify
`sanctuary castle-wall status` prints the expected `Castle Wall app build`
line before drilling. A stale app must never be treated as a host-state or
Network Extensions problem.

**Why LaunchServices and not a direct exec (macOS Tahoe).** On macOS Tahoe
(26.x), a directly-exec'd binary cannot reach NE preferences:
`NEFilterManager.loadFromPreferences` hangs indefinitely for any binary that
was not started as a LaunchServices instance (console or SSH alike). Launching
through `open` runs the app as a proper LaunchServices instance, which CAN
reach NE prefs. Because `open` does not relay the child's stdout, the host app
also writes its JSON report to the caller-supplied `--report-file`; the CLI
reads that file back, and fail-closes to a generic failure if it is missing,
empty, or unparseable. (Mini1 Tahoe drill, 2026-06-10, finding 1.)

The remaining GUI steps are console-only macOS requirements, each done once
per install:

1. **Content-filter consent.** Launch the app at the console once and click
   Allow on the content-filter prompt. Until this is granted, `enable` exits
   3 with recovery instructions.
2. **System-extension toggle (Tahoe).** On macOS Tahoe the Castle Wall system
   extension ships toggled OFF and must be switched on once at the console:
   System Settings > General > Login Items & Extensions > Network Extensions >
   Castle Wall. Until this is on, `enable` detects the `[activated disabled]`
   state, exits 4, and prints toggle instructions rather than saving an NE
   configuration that would never enforce.

After both one-time steps, remote drills can arm with a delivered policy and
disarm again without any console click, and a remote dead-man auto-disarm is
just a scheduled `sanctuary castle-wall disable`.

`enable` refuses to arm when no Castle Wall daemon answers on the fortress
socket, because filter-on + daemon-down fail-closes the machine to deny-all
(the 2026-06-09 Hermes drill lockout). `--force` overrides for setups where
the daemon is supervised out-of-band. `disable` deliberately has no
preconditions. Both verbs append a best-effort audit entry (`wall_armed` /
`wall_disarmed`, source `castle-wall-cli`) and re-verify the live state
through `--headless status` before reporting success.

`sanctuary castle-wall status` also uses the probe: when the host-app binary
is installed, it appends a `Content filter: enabled|disabled` line reporting
the live NE filter state. The sysext line alone is not that signal:
`[activated enabled]` means the extension is installed and approved, not that
the content filter is armed. When the binary is absent the line is omitted;
when the probe fails it prints `Content filter: unknown (<reason>)`.
