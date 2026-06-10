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

    // MARK: - report-file (LaunchServices/Tahoe round-trip)

    func testParseReportFilePath() {
        let result = HeadlessFilterCLI.parse(
            ["app", "--headless", "enable", "--report-file=/tmp/cw-report.json"]
        )
        guard case let .invocation(invocation)? = result else {
            return XCTFail("expected invocation, got \(String(describing: result))")
        }
        XCTAssertEqual(invocation.reportFilePath, "/tmp/cw-report.json")
        XCTAssertEqual(invocation.action, .enable)
    }

    func testParseReportFileDefaultsToNil() {
        let result = HeadlessFilterCLI.parse(["app", "--headless", "status"])
        guard case let .invocation(invocation)? = result else {
            return XCTFail("expected invocation, got \(String(describing: result))")
        }
        XCTAssertNil(invocation.reportFilePath)
    }

    func testParseEmptyReportFileIsUsageError() {
        guard case let .usageError(message)? =
            HeadlessFilterCLI.parse(["app", "--headless", "enable", "--report-file="]) else {
            return XCTFail("expected usageError for empty --report-file")
        }
        XCTAssertTrue(message.contains("--report-file"))
    }

    func testWriteReportFileWritesValidJSONLine() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("cw-report-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("report.json").path

        let report = HeadlessFilterCLI.Report(
            ok: true, action: "enable", state: "enabled", error: nil
        )
        let line = HeadlessFilterCLI.encode(report)
        HeadlessFilterCLI.writeReportFile(line, to: path)

        let contents = try String(contentsOfFile: path, encoding: .utf8)
        let trimmed = contents.trimmingCharacters(in: .whitespacesAndNewlines)
        let data = Data(trimmed.utf8)
        let decoded = try JSONDecoder().decode(HeadlessFilterCLI.Report.self, from: data)
        XCTAssertEqual(decoded, report)

        // 0600: only the owner can read the report the CLI reads back.
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
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
