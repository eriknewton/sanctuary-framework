// swift-tools-version: 5.9
//
// Castle Wall macOS Phase 1.
//
// SwiftPM is the source of truth for the build. Xcode and `xcodebuild` both
// drive the package directly via -scheme + -package-path. The eventual
// system-extension product (.systemextension bundle) is wired in Alpha-4
// (install + signing) on top of the executable target produced here.
//
// Targets:
//   - CastleWallIPC: pure wire / framing / messages library. No
//     NetworkExtension dependency. Mirrors `server/src/castle-wall/ipc/`.
//   - CastleWallFilter: NEFilterDataProvider subclass + manifest store +
//     allowlist evaluator + flow cache + IPC bridge for filter-side
//     notifications. Depends on CastleWallIPC and links NetworkExtension.
//   - CastleWallExtension: thin executable wrapper that registers the
//     NEFilterProvider class and runs the dispatch loop. Depends on
//     CastleWallFilter.
//   - CastleWallIPCTests: covers wire/framing types.
//   - CastleWallExtensionTests: covers manifest store + allowlist
//     evaluator + flow cache + IPC bridge notifications + filter-provider
//     verdict glue. NEFilterDataProvider lifecycle itself is exercised in
//     Alpha-3 with loaded-extension integration tests; the testable
//     verdict-decision surface here is the substrate that build wires up.
//
// Source: Castle Wall macOS Phase 1 packet filter + manifest sync spawn
// prompt (2026-05-11).

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
        .executable(
            name: "CastleWallExtension",
            targets: ["CastleWallExtension"]
        ),
    ],
    targets: [
        .target(
            name: "CastleWallIPC",
            path: "Sources/CastleWallIPC"
        ),
        .target(
            name: "CastleWallFilter",
            dependencies: ["CastleWallIPC"],
            path: "Sources/CastleWallFilter",
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
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
        .testTarget(
            name: "CastleWallIPCTests",
            dependencies: ["CastleWallIPC"],
            path: "Tests/CastleWallIPCTests"
        ),
        .testTarget(
            name: "CastleWallExtensionTests",
            dependencies: ["CastleWallIPC", "CastleWallFilter"],
            path: "Tests/CastleWallExtensionTests"
        ),
    ]
)
