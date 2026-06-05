// swift-tools-version: 6.2
//
// Castle Wall VMM — Apple Containerization-based VM launcher.
//
// Split out of the `castle-wall-macos` package (2026-06-04). The enforcement
// products (system extension, host app, packet filter, IPC library) have NO
// Containerization dependency and must install on the macOS 13/14/15 Macs most
// operators run. Apple's Containerization library requires macOS 26 + Swift
// tools 6.2, and SwiftPM has no per-target deployment floor, so keeping the VM
// in the same package dragged the whole package — including the sysext — up to
// a macOS-26 floor (a latent product bug surfaced by the A1 acceptance drill:
// the released sysext would refuse to install on 13/14/15). This package
// isolates the macOS-26 VM runtime; `castle-wall-macos` drops back to a
// macOS-13 floor.
//
// Targets:
//   - SanctuaryVMM: Apple Containerization-based VM launcher. Boots
//     no-network Linux guests with single-vsock egress (B1 re-platform).
//   - sanctuary-vmm: CLI entry point for SanctuaryVMM.

import PackageDescription

let package = Package(
    name: "SanctuaryVMM",
    platforms: [
        .macOS("26.0"),
    ],
    products: [
        .library(
            name: "SanctuaryVMM",
            targets: ["SanctuaryVMM"]
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
            name: "SanctuaryVMM",
            dependencies: [
                .product(name: "Containerization", package: "containerization"),
                .product(name: "ContainerizationOS", package: "containerization"),
            ],
            path: "Sources/SanctuaryVMM"
        ),
        .executableTarget(
            name: "sanctuary-vmm",
            dependencies: ["SanctuaryVMM"],
            path: "Sources/sanctuary-vmm"
        ),
        .testTarget(
            name: "SanctuaryVMMTests",
            dependencies: ["SanctuaryVMM"],
            path: "Tests/SanctuaryVMMTests"
        ),
    ],
    // Tools 6.2 (required by apple/containerization 0.33.3) defaults to Swift 6
    // strict-concurrency-as-error; pin to Swift 5 mode so the VM targets compile
    // as they did when they lived in the castle-wall-macos package.
    swiftLanguageModes: [.v5]
)
