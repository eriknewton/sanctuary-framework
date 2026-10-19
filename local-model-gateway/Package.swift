// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "LocalModelGateway",
    platforms: [.macOS(.v14)],
    products: [.library(name: "LocalModelGatewayCore", targets: ["LocalModelGatewayCore"])],
    targets: [
        .target(name: "LocalModelGatewayCore"),
        .testTarget(name: "LocalModelGatewayCoreTests", dependencies: ["LocalModelGatewayCore"],
                    resources: [.copy("Fixtures")])
    ]
)
