# Castle Wall macOS

Phase 1 foundation of WP-V1.x-CASTLE-WALL on macOS. Castle Architecture
Layer 1 lives at the OS-level egress filter; on macOS the
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

1. `SANCTUARY_CASTLE_SOCKET` environment variable (explicit override).
2. **Linux**: `/run/sanctuary/<fortress-id>/filter.sock` (root daemon path).
3. **macOS**: `${SANCTUARY_FORTRESS_PATH}/castle.sock` if set.
4. **macOS**: `~/.sanctuary/castle.sock` if `HOME` is set.
5. **macOS**: `/var/run/sanctuary-castle.sock` (last resort; only writable as root).

macOS rootless protections block `/var/run` for unprivileged processes,
which is why the per-fortress and home-default fallbacks come first.

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
prompt-injected user-space agent CANNOT bypass the filter without the
operator removing the system extension.

The Sanctuary-main IPC connection authenticates via Ed25519
challenge-response: the macOS extension issues a 32-byte nonce, the
Sanctuary-main side signs it with the fortress identity key, the
extension verifies against a TOFU-pinned public key. SO_PEERCRED-style
UID binding is unavailable on macOS BSD sockets, so the fortress
identity binding is the load-bearing trust anchor.

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
