import XCTest

@testable import CastleWallHostApp

final class HeadlessFilterCLITests: XCTestCase {
    // MARK: - parse

    func testParseReturnsNilForGUILaunch() {
        XCTAssertNil(HeadlessFilterCLI.parse(["/path/to/CastleWallHostApp"]))
        XCTAssertNil(HeadlessFilterCLI.parse(["app", "-NSDocumentRevisionsDebugMode", "YES"]))
    }

    func testParseEnableDisableStatus() {
        for action in ["enable", "disable", "status"] {
            let result = HeadlessFilterCLI.parse(["app", "--headless", action])
            guard case let .invocation(invocation)? = result else {
                XCTFail("expected invocation for \(action), got \(String(describing: result))")
                continue
            }
            XCTAssertEqual(invocation.action.rawValue, action)
            XCTAssertEqual(invocation.timeoutSeconds, 30.0)
        }
    }

    func testParseCustomTimeout() {
        let result = HeadlessFilterCLI.parse(["app", "--headless", "enable", "--timeout=5"])
        guard case let .invocation(invocation)? = result else {
            return XCTFail("expected invocation, got \(String(describing: result))")
        }
        XCTAssertEqual(invocation.timeoutSeconds, 5.0)
    }

    func testParseInvalidTimeoutIsUsageError() {
        for bad in ["--timeout=abc", "--timeout=0", "--timeout=-3"] {
            let result = HeadlessFilterCLI.parse(["app", "--headless", "enable", bad])
            guard case .usageError? = result else {
                return XCTFail("expected usageError for \(bad), got \(String(describing: result))")
            }
        }
    }

    func testParseMissingActionIsUsageError() {
        guard case let .usageError(message)? = HeadlessFilterCLI.parse(["app", "--headless"]) else {
            return XCTFail("expected usageError")
        }
        XCTAssertTrue(message.contains("enable|disable|status"))
    }

    func testParseUnknownArgumentIsUsageError() {
        guard case let .usageError(message)? =
            HeadlessFilterCLI.parse(["app", "--headless", "enable", "--bogus"]) else {
            return XCTFail("expected usageError")
        }
        XCTAssertTrue(message.contains("--bogus"))
    }

    func testParseRejectsSecondAction() {
        guard case .usageError? =
            HeadlessFilterCLI.parse(["app", "--headless", "enable", "disable"]) else {
            return XCTFail("expected usageError for two actions")
        }
    }

    // MARK: - report encoding

    func testReportEncodingIsSingleStableJSONLine() {
        let report = HeadlessFilterCLI.Report(
            ok: true, action: "enable", state: "enabled", error: nil
        )
        let encoded = HeadlessFilterCLI.encode(report)
        XCTAssertFalse(encoded.contains("\n"))
        XCTAssertEqual(
            encoded,
            #"{"action":"enable","ok":true,"state":"enabled"}"#
        )
    }

    func testReportEncodingWithError() {
        let report = HeadlessFilterCLI.Report(
            ok: false, action: "enable", state: "needs_user_approval",
            error: "one-time content-filter consent not granted"
        )
        let encoded = HeadlessFilterCLI.encode(report)
        XCTAssertTrue(encoded.contains(#""state":"needs_user_approval""#))
        XCTAssertTrue(encoded.contains(#""ok":false"#))
    }

    func testExitCodesAreStableContract() {
        // The TypeScript CLI (server/src/cli/castle-wall.ts) matches on these
        // exact values; changing them is a cross-package breaking change.
        XCTAssertEqual(HeadlessFilterCLI.ExitCode.success.rawValue, 0)
        XCTAssertEqual(HeadlessFilterCLI.ExitCode.failure.rawValue, 1)
        XCTAssertEqual(HeadlessFilterCLI.ExitCode.usage.rawValue, 2)
        XCTAssertEqual(HeadlessFilterCLI.ExitCode.needsUserApproval.rawValue, 3)
        XCTAssertEqual(HeadlessFilterCLI.ExitCode.timeout.rawValue, 4)
    }
}
