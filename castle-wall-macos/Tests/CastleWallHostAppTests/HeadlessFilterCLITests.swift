import XCTest

@testable import CastleWallHostApp

final class HeadlessFilterCLITests: XCTestCase {
    // MARK: - parse

    func testParseReturnsNilForGUILaunch() {
        XCTAssertNil(HeadlessFilterCLI.parse(["/path/to/CastleWallHostApp"]))
        XCTAssertNil(HeadlessFilterCLI.parse(["app", "-NSDocumentRevisionsDebugMode", "YES"]))
    }

    func testParseAllActions() {
        for action in ["enable", "disable", "status", "deactivate-system-extension"] {
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

    func testParseLeaseFlags() {
        let ttl = HeadlessFilterCLI.parse(["app", "--headless", "enable", "--ttl=300"])
        guard case let .invocation(ttlInvocation)? = ttl else {
            return XCTFail("expected ttl invocation")
        }
        XCTAssertEqual(ttlInvocation.ttlSeconds, 300)
        XCTAssertFalse(ttlInvocation.noTTL)

        let durable = HeadlessFilterCLI.parse(["app", "--headless", "enable", "--no-ttl"])
        guard case let .invocation(durableInvocation)? = durable else {
            return XCTFail("expected durable invocation")
        }
        XCTAssertNil(durableInvocation.ttlSeconds)
        XCTAssertTrue(durableInvocation.noTTL)
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
        XCTAssertTrue(message.contains("enable|disable|status|deactivate-system-extension"))
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

    // MARK: - RunLoop wait

    func testWaitForDrainsRunLoopDeliveredCompletion() {
        let started = Date()

        let result = HeadlessFilterCLI.waitFor(1.0) { completion in
            RunLoop.current.perform(inModes: [.default]) {
                completion(nil)
            }
        }

        switch result {
        case .completed(nil):
            break
        case let .completed(.some(error)):
            XCTFail("expected success, got \(error)")
        case .timedOut:
            XCTFail("run-loop-delivered completion timed out")
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 0.5)
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
        let build = HeadlessFilterCLI.Report.Build(
            gitSha: "abc1234",
            headlessContractVersion: HeadlessFilterCLI.headlessContractVersion
        )
        let report = HeadlessFilterCLI.Report(
            ok: true, action: "enable", state: "enabled", error: nil, build: build
        )
        let encoded = HeadlessFilterCLI.encode(report)
        XCTAssertFalse(encoded.contains("\n"))
        XCTAssertEqual(
            encoded,
            #"{"action":"enable","build":{"git_sha":"abc1234","headless_contract_version":"3"},"ok":true,"state":"enabled"}"#
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
        XCTAssertTrue(encoded.contains(#""headless_contract_version":"3""#))
    }

    func testReportCarriesCurrentBuildIdentity() {
        let report = HeadlessFilterCLI.Report(
            ok: true, action: "status", state: "disabled", error: nil
        )

        XCTAssertEqual(report.build.headlessContractVersion, HeadlessFilterCLI.headlessContractVersion)
        XCTAssertFalse(report.build.gitSha.isEmpty)
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

    func testSystemExtensionDeactivationReportsKeepCompletedAndRebootDeferredDistinct() {
        let completed = HeadlessFilterCLI.reportForSystemExtensionDeactivation(.deactivated)
        XCTAssertEqual(completed.exitCode, .success)
        XCTAssertTrue(completed.report.ok)
        XCTAssertEqual(completed.report.state, "deactivated")

        let deferred = HeadlessFilterCLI.reportForSystemExtensionDeactivation(.willCompleteAfterReboot)
        XCTAssertEqual(deferred.exitCode, .success)
        XCTAssertTrue(deferred.report.ok)
        XCTAssertEqual(deferred.report.state, "will_complete_after_reboot")
    }

    func testSystemExtensionDeactivationFailureStatesStayNonSuccess() {
        let approval = HeadlessFilterCLI.reportForSystemExtensionDeactivation(.needsUserApproval)
        XCTAssertEqual(approval.exitCode, .needsUserApproval)
        XCTAssertFalse(approval.report.ok)

        let timeout = HeadlessFilterCLI.reportForSystemExtensionDeactivation(.timedOut)
        XCTAssertEqual(timeout.exitCode, .timeout)
        XCTAssertFalse(timeout.report.ok)

        let failure = HeadlessFilterCLI.reportForSystemExtensionDeactivation(.failed("boom"))
        XCTAssertEqual(failure.exitCode, .failure)
        XCTAssertEqual(failure.report.error, "boom")
    }
}
