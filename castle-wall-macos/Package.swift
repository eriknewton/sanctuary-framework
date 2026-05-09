// swift-tools-version: 5.9
//
// Castle Wall macOS Phase 1 Foundation.
//
// SwiftPM is the source of truth for the build. Xcode and `xcodebuild` both
// drive the package directly via -scheme + -package-path. The eventual
// system-extension product (.systemextension bundle) is wired in Alpha-4
// (install + signing) on top of the executable target produced here. For
// foundation scope (compiles, signs eventually, IPC contract defined) this
// shape is sufficient.
//
// Source: Castle Wall macOS Phase 1 Foundation spawn prompt (2026-05-11).

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
        .executableTarget(
            name: "CastleWallExtension",
            dependencies: ["CastleWallIPC"],
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
    ]
)
