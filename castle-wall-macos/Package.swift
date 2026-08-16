// swift-tools-version: 5.9
//
// Castle Wall macOS — packet filter + system extension (enforcement layer).
//
// SwiftPM is the source of truth for the build. Xcode and `xcodebuild` both
// drive the package directly via -scheme + -package-path.
//
// Deployment floor: macOS 13. These enforcement products (system extension,
// host app, packet filter, IPC library) must install on the macOS 13/14/15
// Macs most operators run. The Apple Containerization-based VM launcher
// (SanctuaryVMM / sanctuary-vmm), which requires macOS 26 + Swift tools 6.2,
// was split into the sibling `castle-wall-vmm` package on 2026-06-04 so it can
// no longer drag this package's floor up to macOS 26 (a latent product bug
// caught by the A1 acceptance drill — the released sysext was macOS-26-only).
//
// Targets:
//   - CastleWallIPC: pure wire / framing / messages library. No
//     NetworkExtension dependency. Mirrors `server/src/castle-wall/ipc/`.
//   - AgentDetector: typed audit-token decode + agent/operator origin
//     classification (F0 origin classifier).
//   - CastleWallFilter: NEFilterDataProvider subclass + manifest store +
//     allowlist evaluator + flow cache + IPC bridge for filter-side
//     notifications. Depends on CastleWallIPC and links NetworkExtension.
//   - CastleWallExtension: thin executable wrapper that registers the
//     NEFilterProvider class and runs the dispatch loop.
//   - CastleWallHostApp: SwiftUI host app that requests sysext activation
//     and drives Protect / status / audit-viewer.

import PackageDescription

let package = Package(
    name: "CastleWallExtension",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "CastleWallIPC",
            targets: ["CastleWallIPC"]
        ),
        .library(
            name: "CastleWallFilter",
            targets: ["CastleWallFilter"]
        ),
        .library(
            name: "AgentDetector",
            targets: ["AgentDetector"]
        ),
        .executable(
            name: "CastleWallExtension",
            targets: ["CastleWallExtension"]
        ),
        .executable(
            name: "CastleWallHostApp",
            targets: ["CastleWallHostApp"]
        ),
        // A2/B2 helper-as-signer: a root SMAppService daemon owns the signing
        // key; a code-signed shim relays the daemon's sign requests over XPC.
        .library(
            name: "CastleWallSigner",
            targets: ["CastleWallSigner"]
        ),
        .executable(
            name: "CastleWallSignerHelper",
            targets: ["CastleWallSignerHelper"]
        ),
        .executable(
            name: "CastleWallSignerClient",
            targets: ["CastleWallSignerClient"]
        ),
        .executable(
            name: "SanctuaryLauncher",
            targets: ["SanctuaryLauncher"]
        ),
    ],
    targets: [
        .target(
            name: "CastleWallIPC",
            path: "Sources/CastleWallIPC"
        ),
        .target(
            name: "AgentDetector",
            path: "Sources/AgentDetector"
        ),
        .target(
            name: "CastleWallFilter",
            dependencies: ["CastleWallIPC", "CastleWallSigner"],
            path: "Sources/CastleWallFilter",
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("Security"),
                // libbsm provides audit_token_to_pid/ruid/pidversion used by
                // AuditTokenDecode for typed origin classification.
                .linkedLibrary("bsm"),
            ]
        ),
        .executableTarget(
            name: "CastleWallExtension",
            dependencies: ["CastleWallIPC", "CastleWallFilter"],
            path: "Sources/CastleWallExtension",
            exclude: [
                "Info.plist",
                "CastleWallExtension.entitlements",
            ],
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
            ]
        ),
        .executableTarget(
            name: "CastleWallHostApp",
            dependencies: ["CastleWallIPC", "AgentDetector", "CastleWallSigner"],
            path: "Sources/CastleWallHostApp",
            exclude: [
                "Info.plist",
                "CastleWallHostApp.entitlements",
            ],
            linkerSettings: [
                .linkedFramework("SystemExtensions"),
                .linkedFramework("SwiftUI"),
                // SMAppService (register the root signer helper) — A2/B2.
                .linkedFramework("ServiceManagement"),
            ]
        ),
        // A2/B2 helper-as-signer targets. CastleWallSigner is the shared,
        // unit-testable core (key gen, raw Ed25519 sign/verify over OPAQUE
        // bytes, root-only key + pin storage, code-requirement string, peer
        // audit-token decode). It is deliberately macOS-13-compatible (no
        // macOS-26-only symbol) so it stays on the macos-latest CI floor.
        .target(
            name: "CastleWallSigner",
            // FileCustody (root-ownership custody checks, A2/B2) is shared with
            // the sysext side, so it lives in the pure CastleWallIPC library.
            dependencies: ["CastleWallIPC"],
            path: "Sources/CastleWallSigner",
            linkerSettings: [
                // SecRequirementCreateWithString for the caller code-requirement.
                .linkedFramework("Security"),
                // audit_token_to_ruid/pid/pidversion for peer decode.
                .linkedLibrary("bsm"),
            ]
        ),
        .executableTarget(
            name: "CastleWallSignerHelper",
            dependencies: ["CastleWallSigner"],
            path: "Sources/CastleWallSignerHelper",
            exclude: [
                "CastleWallSignerHelper.entitlements",
                "ai.sanctuaryprotocol.macos.castle-wall.signer-helper.plist",
            ]
        ),
        .executableTarget(
            name: "CastleWallSignerClient",
            dependencies: ["CastleWallSigner"],
            path: "Sources/CastleWallSignerClient",
            exclude: [
                "CastleWallSignerClient.entitlements",
            ]
        ),
        .executableTarget(
            name: "SanctuaryLauncher",
            path: "Sources/SanctuaryLauncher"
        ),
        .testTarget(
            name: "CastleWallSignerTests",
            dependencies: ["CastleWallSigner"],
            path: "Tests/CastleWallSignerTests"
        ),
        .testTarget(
            name: "CastleWallIPCTests",
            dependencies: ["CastleWallIPC"],
            path: "Tests/CastleWallIPCTests"
        ),
        .testTarget(
            name: "CastleWallExtensionTests",
            dependencies: ["CastleWallIPC", "CastleWallFilter"],
            path: "Tests/CastleWallExtensionTests",
            resources: [
                .copy("Fixtures"),
            ]
        ),
        .testTarget(
            name: "CastleWallHostAppTests",
            dependencies: ["CastleWallHostApp", "AgentDetector", "CastleWallIPC"],
            path: "Tests/CastleWallHostAppTests"
        ),
    ]
)
