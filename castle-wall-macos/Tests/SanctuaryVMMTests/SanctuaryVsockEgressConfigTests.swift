import XCTest
@testable import SanctuaryVMM

final class SanctuaryVsockEgressConfigTests: XCTestCase {

    func testDefaultGuestSocketPath() {
        let config = SanctuaryVsockEgressConfig(hostProxyUdsPath: "/tmp/egress.sock")
        XCTAssertEqual(config.hostProxyUdsPath, "/tmp/egress.sock")
        XCTAssertEqual(config.guestSocketPath, "/run/sanctuary-egress.sock")
    }

    func testCustomConfig() {
        let config = SanctuaryVsockEgressConfig(
            hostProxyUdsPath: "/var/run/sanctuary/egress-proxy.sock",
            guestSocketPath: "/run/custom-egress.sock"
        )
        XCTAssertEqual(config.hostProxyUdsPath, "/var/run/sanctuary/egress-proxy.sock")
        XCTAssertEqual(config.guestSocketPath, "/run/custom-egress.sock")
    }

    func testConfigIsSendable() {
        // Compile-time guarantee the config can cross the @Sendable create
        // closure boundary in launchWithEgress.
        func requireSendable<T: Sendable>(_ value: T) -> T { value }
        let config = requireSendable(
            SanctuaryVsockEgressConfig(hostProxyUdsPath: "/tmp/egress.sock"))
        XCTAssertEqual(config.guestSocketPath, "/run/sanctuary-egress.sock")
    }

    func testHostProxyUdsPathPreserved() {
        let path = "/tmp/sanctuary-egress-proxy-12345.sock"
        let config = SanctuaryVsockEgressConfig(hostProxyUdsPath: path)
        XCTAssertEqual(config.hostProxyUdsPath, path)
    }
}
