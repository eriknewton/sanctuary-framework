// swift-tools-version: 6.2
//
// Castle Wall macOS — packet filter + VM sandbox.
//
// SwiftPM is the source of truth for the build. Xcode and `xcodebuild` both
// drive the package directly via -scheme + -package-path.
//
// Targets:
//   - CastleWallIPC: pure wire / framing / messages library. No
//     NetworkExtension dependency. Mirrors `server/src/castle-wall/ipc/`.
//   - CastleWallFilter: NEFilterDataProvider subclass + manifest store +
//     allowlist evaluator + flow cache + IPC bridge for filter-side
//     notifications. Depends on CastleWallIPC and links NetworkExtension.
//   - CastleWallExtension: thin executable wrapper that registers the
//     NEFilterProvider class and runs the dispatch loop.
//   - SanctuaryVMM: Apple Containerization-based VM launcher. Boots
//     no-network Linux guests with single-vsock egress. B1 re-platform
//     — replaces the hand-rolled guest plumbing.
//   - sanctuary-vmm: CLI entry point for SanctuaryVMM.
//
// B1 re-platform: added Apple Containerization dependency (pinned 0.33.3)
// and SanctuaryVMM module. The old hand-rolled guest stack (sanctuary-init,
// kernel decompression, busybox modprobe, raw-fd vsock bridge) is deleted.

import PackageDescription

let package = Package(
    name: "CastleWallExtension",
    platforms: [
        .macOS("26.0"),
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
        .library(
            name: "SanctuaryVMM",
            targets: ["SanctuaryVMM"]
        ),
        .executable(
            name: "CastleWallExtension",
            targets: ["CastleWallExtension"]
        ),
        .executable(
            name: "CastleWallHostApp",
            targets: ["CastleWallHostApp"]
        ),
        .executable(
            name: "sanctuary-vmm",
            targets: ["sanctuary-vmm"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/containerization.git", exact: "0.33.3"),
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
        .target(
            name: "SanctuaryVMM",
            dependencies: [
                .product(name: "Containerization", package: "containerization"),
                .product(name: "ContainerizationOS", package: "containerization"),
            ],
            path: "Sources/SanctuaryVMM"
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
        .executableTarget(
            name: "sanctuary-vmm",
            dependencies: ["SanctuaryVMM"],
            path: "Sources/sanctuary-vmm"
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
        .testTarget(
            name: "SanctuaryVMMTests",
            dependencies: ["SanctuaryVMM"],
            path: "Tests/SanctuaryVMMTests"
        ),
    ],
    // Tools 6.2 (required by apple/containerization 0.33.3) defaults to Swift 6
    // strict-concurrency-as-error; pin to Swift 5 mode so the pre-existing
    // CastleWall targets compile as they did on main (the B1 tools-version bump
    // otherwise breaks CastleWallIPC et al.).
    swiftLanguageModes: [.v5]
)
