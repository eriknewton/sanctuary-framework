import XCTest
@testable import SanctuaryVMM

final class SanctuaryVsockEgressBridgeTests: XCTestCase {

    func testDefaultConfig() {
        let config = SanctuaryVsockEgressConfig()
        XCTAssertEqual(config.hostPort, 0x0FFF_0001)
        XCTAssertEqual(config.guestSocketPath, "/run/sanctuary-egress.sock")
        XCTAssertEqual(config.proxyListenAddress, "127.0.0.1")
        XCTAssertEqual(config.proxyListenPort, 0)
    }

    func testCustomConfig() {
        let config = SanctuaryVsockEgressConfig(
            hostPort: 0x0FFF_0002,
            guestSocketPath: "/run/custom-egress.sock",
            proxyListenAddress: "127.0.0.1",
            proxyListenPort: 9090
        )
        XCTAssertEqual(config.hostPort, 0x0FFF_0002)
        XCTAssertEqual(config.guestSocketPath, "/run/custom-egress.sock")
        XCTAssertEqual(config.proxyListenPort, 9090)
    }

    func testBridgeCreation() {
        let config = SanctuaryVsockEgressConfig()
        let bridge = SanctuaryVsockEgressBridge(config: config)
        XCTAssertEqual(bridge.config.hostPort, 0x0FFF_0001)
    }

    func testHostPortBelowAppleRange() {
        // The host port must be below LinuxPod's 0x1000_0000 range
        let config = SanctuaryVsockEgressConfig()
        XCTAssertTrue(config.hostPort < 0x1000_0000,
            "Egress vsock port must be below Apple's hostVsockPorts range")
        XCTAssertTrue(config.hostPort > 1024,
            "Egress vsock port must be above vminitd control port 1024")
    }
}
