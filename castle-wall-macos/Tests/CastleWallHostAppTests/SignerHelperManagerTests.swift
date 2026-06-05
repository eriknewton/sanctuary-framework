//
// SignerHelperManagerTests.swift
//
// Unit coverage for the pure parts of the signer-helper manager: SMAppService
// status mapping and the auto-arm precondition. The privileged register/approve
// path is console-only and not exercised here.
//

import XCTest
import ServiceManagement
@testable import CastleWallHostApp

final class SignerHelperManagerTests: XCTestCase {

    func testStatusMapping() {
        XCTAssertEqual(SignerHelperManager.map(.notRegistered), .notRegistered)
        XCTAssertEqual(SignerHelperManager.map(.enabled), .enabled)
        XCTAssertEqual(SignerHelperManager.map(.requiresApproval), .requiresApproval)
        XCTAssertEqual(SignerHelperManager.map(.notFound), .notFound)
    }

    func testShouldAutoArmRequiresBothHelperAndPin() {
        XCTAssertTrue(SignerHelperManager.shouldAutoArm(helperEnabled: true, pinPresent: true))
        XCTAssertFalse(SignerHelperManager.shouldAutoArm(helperEnabled: true, pinPresent: false))
        XCTAssertFalse(SignerHelperManager.shouldAutoArm(helperEnabled: false, pinPresent: true))
        XCTAssertFalse(SignerHelperManager.shouldAutoArm(helperEnabled: false, pinPresent: false))
    }

    func testPlistNameMatchesHelperIdentifier() {
        XCTAssertEqual(
            SignerHelperManager.plistName,
            "ai.sanctuaryprotocol.macos.castle-wall.signer-helper.plist"
        )
    }
}
