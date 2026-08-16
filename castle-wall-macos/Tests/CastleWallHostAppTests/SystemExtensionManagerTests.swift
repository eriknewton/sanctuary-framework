import XCTest
@testable import CastleWallHostApp

final class SystemExtensionManagerTests: XCTestCase {
    private struct MockError: LocalizedError {
        var errorDescription: String? {
            return "activation failed"
        }
    }

    func testUnknownToActivatingToActivated() {
        let manager = SystemExtensionManager()

        XCTAssertEqual(manager.extensionState, .unknown)

        manager.handleRequestStarted(isActivation: true)
        XCTAssertEqual(manager.extensionState, .activating)

        manager.handleRequestFinished()
        XCTAssertEqual(manager.extensionState, .activated)
    }

    func testActivatedToDeactivatingToDeactivated() {
        let manager = SystemExtensionManager()

        manager.handleRequestStarted(isActivation: true)
        manager.handleRequestFinished()
        XCTAssertEqual(manager.extensionState, .activated)

        manager.handleRequestStarted(isActivation: false)
        XCTAssertEqual(manager.extensionState, .deactivating)

        manager.handleRequestFinished()
        XCTAssertEqual(manager.extensionState, .deactivated)
    }

    func testDeactivationDeferredUntilRebootStaysDistinct() {
        let manager = SystemExtensionManager()

        manager.handleRequestStarted(isActivation: false)
        manager.handleRequestFinished(result: .willCompleteAfterReboot)

        XCTAssertEqual(manager.extensionState, .deactivatedRequiresReboot)
    }

    func testActivatingToErrorState() {
        let manager = SystemExtensionManager()

        manager.handleRequestStarted(isActivation: true)
        XCTAssertEqual(manager.extensionState, .activating)

        manager.handleRequestFailed(MockError())

        XCTAssertEqual(manager.extensionState, .error("activation failed"))
    }

    func testActivatingToNeedsUserApproval() {
        let manager = SystemExtensionManager()

        manager.handleRequestStarted(isActivation: true)
        XCTAssertEqual(manager.extensionState, .activating)

        manager.handleNeedsUserApproval()

        XCTAssertEqual(manager.extensionState, .needsUserApproval)
    }

    func testReplaceActionReturnsReplace() {
        let manager = SystemExtensionManager()

        XCTAssertEqual(manager.replacementAction(), .replace)
    }

    func testLaunchActivationRefreshAdvancesAfterHelperApprovalWithoutPinInput() {
        XCTAssertTrue(
            SystemExtensionManager.shouldSubmitLaunchActivationRefresh(
                didSubmit: false,
                helperApproved: true,
                extensionState: .unknown
            )
        )
        XCTAssertTrue(
            SystemExtensionManager.shouldSubmitLaunchActivationRefresh(
                didSubmit: false,
                helperApproved: true,
                extensionState: .activated
            )
        )
    }

    func testLaunchActivationRefreshRemainsOneShotAndApprovalGated() {
        XCTAssertFalse(
            SystemExtensionManager.shouldSubmitLaunchActivationRefresh(
                didSubmit: false,
                helperApproved: false,
                extensionState: .unknown
            )
        )
        XCTAssertFalse(
            SystemExtensionManager.shouldSubmitLaunchActivationRefresh(
                didSubmit: true,
                helperApproved: true,
                extensionState: .unknown
            )
        )
        XCTAssertFalse(
            SystemExtensionManager.shouldSubmitLaunchActivationRefresh(
                didSubmit: false,
                helperApproved: true,
                extensionState: .needsUserApproval
            )
        )
    }
}
