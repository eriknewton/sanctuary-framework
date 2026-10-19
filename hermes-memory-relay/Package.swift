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
    targets: [
        .target(name: "HermesMemoryRelayCore"),
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
