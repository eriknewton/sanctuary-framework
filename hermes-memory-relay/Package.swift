// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "HermesMemoryRelay",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "HermesMemoryRelayCore", targets: ["HermesMemoryRelayCore"]),
        .executable(name: "HermesMemoryRelay", targets: ["HermesMemoryRelay"])
    ],
    dependencies: [.package(path: "../castle-wall-macos")],
    targets: [
        .target(name: "HermesMemoryRelayCore", dependencies: [
            .product(name: "MemoryGrantPeer", package: "castle-wall-macos")
        ]),
        .executableTarget(
            name: "HermesMemoryRelay",
            dependencies: ["HermesMemoryRelayCore"]
        ),
        .testTarget(
            name: "HermesMemoryRelayCoreTests",
            dependencies: ["HermesMemoryRelayCore"],
            resources: [
                .copy("Fixtures/relay-frames.json")
            ]
        )
    ]
)
