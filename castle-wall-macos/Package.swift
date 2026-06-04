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
            dependencies: ["CastleWallIPC"],
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
            dependencies: ["CastleWallIPC", "AgentDetector"],
            path: "Sources/CastleWallHostApp",
            exclude: [
                "Info.plist",
                "CastleWallHostApp.entitlements",
            ],
            linkerSettings: [
                .linkedFramework("SystemExtensions"),
                .linkedFramework("SwiftUI"),
            ]
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
            dependencies: ["CastleWallHostApp", "AgentDetector"],
            path: "Tests/CastleWallHostAppTests"
        ),
    ]
)
