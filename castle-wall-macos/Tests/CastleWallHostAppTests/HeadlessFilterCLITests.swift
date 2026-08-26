import SystemExtensions
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
        let completed = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(result: .deactivated, remediation: nil)
        )
        XCTAssertEqual(completed.exitCode, .success)
        XCTAssertTrue(completed.report.ok)
        XCTAssertEqual(completed.report.state, "deactivated")

        let deferred = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(result: .willCompleteAfterReboot, remediation: nil)
        )
        XCTAssertEqual(deferred.exitCode, .success)
        XCTAssertTrue(deferred.report.ok)
        XCTAssertEqual(deferred.report.state, "will_complete_after_reboot")
    }

    func testSystemExtensionDeactivationFailureStatesStayNonSuccess() {
        let approval = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(result: .needsUserApproval, remediation: nil)
        )
        XCTAssertEqual(approval.exitCode, .needsUserApproval)
        XCTAssertFalse(approval.report.ok)

        let timeout = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(result: .timedOut, remediation: nil)
        )
        XCTAssertEqual(timeout.exitCode, .timeout)
        XCTAssertFalse(timeout.report.ok)

        let failure = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(
                result: .failed(.init(message: "boom", domain: nil, code: nil)),
                remediation: nil
            )
        )
        XCTAssertEqual(failure.exitCode, .failure)
        XCTAssertEqual(failure.report.error, "boom")
    }

    func testTimeoutReportCarriesNoFailureIdentity() {
        // error_domain/error_code are the identity of the failure being
        // reported; a timeout never came from an NSError, so its report must
        // carry NO identity rather than a stale or fabricated one.
        let timeout = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(result: .timedOut, remediation: nil)
        )
        XCTAssertNil(timeout.report.errorDomain)
        XCTAssertNil(timeout.report.errorCode)
        let encoded = HeadlessFilterCLI.encode(timeout.report)
        XCTAssertFalse(encoded.contains("error_domain"))
        XCTAssertFalse(encoded.contains("error_code"))
        XCTAssertEqual(timeout.report.error, "system-extension deactivation timed out")
    }

    // MARK: - failure identity (error_domain / error_code)

    func testDelegateFailureMapsNSErrorDomainAndCodeIntoFailureDetail() {
        // The exact defect shape: sysextd answers extensionNotFound (code 4)
        // while the extension is still listed. The detail must preserve the
        // structured identity, not only the prose.
        let error = NSError(
            domain: OSSystemExtensionErrorDomain,
            code: OSSystemExtensionError.extensionNotFound.rawValue,
            userInfo: [NSLocalizedDescriptionKey: "OSSystemExtensionErrorDomain error 4."]
        )
        let detail = HeadlessFilterCLI.systemExtensionFailureDetail(from: error)
        XCTAssertEqual(detail.domain, OSSystemExtensionErrorDomain)
        XCTAssertEqual(detail.code, OSSystemExtensionError.extensionNotFound.rawValue)
        XCTAssertEqual(detail.message, "OSSystemExtensionErrorDomain error 4.")
    }

    func testFailedReportCarriesMachineReadableDomainAndCode() throws {
        let failure = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(
                result: .failed(.init(
                    message: "OSSystemExtensionErrorDomain error 4.",
                    domain: OSSystemExtensionErrorDomain,
                    code: OSSystemExtensionError.extensionNotFound.rawValue
                )),
                remediation: nil
            )
        )
        XCTAssertEqual(failure.report.errorDomain, OSSystemExtensionErrorDomain)
        XCTAssertEqual(failure.report.errorCode, 4)

        let encoded = HeadlessFilterCLI.encode(failure.report)
        XCTAssertTrue(encoded.contains(#""error_domain":"OSSystemExtensionErrorDomain""#))
        XCTAssertTrue(encoded.contains(#""error_code":4"#))
    }

    func testReportOmitsAdditiveFieldsWhenAbsentSoTheWireShapeIsUnchanged() {
        // Additive-only contract: a report with no failure identity and no
        // remediation must serialize byte-identically to the pre-change shape,
        // which is why headlessContractVersion stays "3". Asserting the FULL
        // string (not key absence) pins the legacy wire shape exactly: any
        // accidental new key, reorder, or format drift fails here.
        let report = HeadlessFilterCLI.Report(
            ok: true, action: "deactivate-system-extension", state: "deactivated",
            error: nil,
            build: .init(gitSha: "abc1234", headlessContractVersion: "3")
        )
        let encoded = HeadlessFilterCLI.encode(report)
        XCTAssertEqual(
            encoded,
            #"{"action":"deactivate-system-extension","build":{"git_sha":"abc1234","headless_contract_version":"3"},"ok":true,"state":"deactivated"}"#
        )
    }

    func testRemediationHintSurvivesIntoTheEncodedReport() {
        // The hint travels inside the outcome so no caller can observe the
        // failure without it; this pins the wire spelling the CLI parses.
        let skewed = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(
                result: .failed(.init(
                    message: "OSSystemExtensionErrorDomain error 4.",
                    domain: OSSystemExtensionErrorDomain,
                    code: OSSystemExtensionError.extensionNotFound.rawValue
                )),
                remediation: HeadlessFilterCLI.extensionVersionSkewRemediation
            )
        )
        XCTAssertEqual(
            skewed.report.remediation,
            "extension_version_skew_reregister_required"
        )
        XCTAssertEqual(skewed.report.errorCode, 4)
        XCTAssertTrue(
            HeadlessFilterCLI.encode(skewed.report)
                .contains(#""remediation":"extension_version_skew_reregister_required""#)
        )
    }

    // MARK: - skew detection (no mutation)

    private static func error4Failure() -> HeadlessFilterCLI.SystemExtensionFailure {
        .init(
            message: "OSSystemExtensionErrorDomain error 4.",
            domain: OSSystemExtensionErrorDomain,
            code: OSSystemExtensionError.extensionNotFound.rawValue
        )
    }

    /// Drives the teardown with counting fakes. Returns the outcome plus the
    /// observed call counts so every test can assert the exact number of
    /// deactivation submissions (always at most one; there is no activation
    /// seam at all - the verb's type surface cannot express one).
    private func teardown(
        deactivation: HeadlessFilterCLI.SystemExtensionDeactivationResult,
        listed: Bool,
        timeoutSeconds: Double = 60
    ) -> (
        outcome: HeadlessFilterCLI.SystemExtensionTeardownOutcome,
        deactivations: Int,
        presenceProbes: Int
    ) {
        var deactivations = 0
        var presenceProbes = 0
        let outcome = HeadlessFilterCLI.performSystemExtensionTeardown(
            timeoutSeconds: timeoutSeconds,
            deactivate: { _ in
                deactivations += 1
                return deactivation
            },
            isExtensionListedActivated: { _ in
                presenceProbes += 1
                return listed
            }
        )
        return (outcome, deactivations, presenceProbes)
    }

    func testSkewDetectionAddsRemediationOnErrorFourWhileListed() {
        let run = teardown(
            deactivation: .failed(Self.error4Failure()),
            listed: true
        )
        // Detection only: exactly one deactivation was submitted, and the
        // failure keeps its own identity while gaining the attended guidance.
        XCTAssertEqual(run.deactivations, 1)
        XCTAssertEqual(run.presenceProbes, 1)
        XCTAssertEqual(
            run.outcome.remediation,
            HeadlessFilterCLI.extensionVersionSkewRemediation
        )
        guard case let .failed(failure) = run.outcome.result else {
            return XCTFail("expected failed, got \(run.outcome.result)")
        }
        XCTAssertEqual(failure.domain, OSSystemExtensionErrorDomain)
        XCTAssertEqual(failure.code, 4)
        XCTAssertTrue(failure.message.hasPrefix("OSSystemExtensionErrorDomain error 4."))
        XCTAssertTrue(failure.message.contains("re-registers the extension"))
        // Honesty: launch alone only re-registers when the background signer
        // helper is enabled, so the guidance must name the helper approval
        // and the wait before the re-run.
        XCTAssertTrue(failure.message.contains(
            "approve or re-enable the Sanctuary background helper if macOS "
            + "prompts for it, wait for re-registration to complete, then "
            + "re-run the deactivation"
        ))
    }

    func testSkewDetectionNeverFiresOnOtherFailureCodes() {
        // Same domain, different codes (13 = authorizationRequired, 8 =
        // codeSignatureInvalid): the hint must not fire, and the probe must
        // not even run (the gate is the structured error-4 identity).
        for code in [13, 8, 9, 3] {
            let failure = HeadlessFilterCLI.SystemExtensionFailure(
                message: "OSSystemExtensionErrorDomain error \(code).",
                domain: OSSystemExtensionErrorDomain,
                code: code
            )
            let run = teardown(deactivation: .failed(failure), listed: true)
            XCTAssertEqual(run.deactivations, 1, "extra submission on code \(code)")
            XCTAssertEqual(run.presenceProbes, 0, "probe ran on code \(code)")
            XCTAssertNil(run.outcome.remediation)
            XCTAssertEqual(run.outcome.result, .failed(failure))
        }
    }

    func testSkewDetectionNeverFiresOnForeignDomainOrMissingIdentity() {
        // A code-4 NSError from a DIFFERENT domain, and a prose-only failure
        // with no identity at all: both must pass through untouched.
        for failure in [
            HeadlessFilterCLI.SystemExtensionFailure(
                message: "some other error 4", domain: "NSCocoaErrorDomain", code: 4
            ),
            HeadlessFilterCLI.SystemExtensionFailure(
                message: "unknown system-extension request result", domain: nil, code: nil
            ),
        ] {
            let run = teardown(deactivation: .failed(failure), listed: true)
            XCTAssertEqual(run.deactivations, 1)
            XCTAssertEqual(run.presenceProbes, 0)
            XCTAssertNil(run.outcome.remediation)
            XCTAssertEqual(run.outcome.result, .failed(failure))
        }
    }

    func testSkewDetectionNeverFiresOnNonFailureResults() {
        for result in [
            HeadlessFilterCLI.SystemExtensionDeactivationResult.deactivated,
            .willCompleteAfterReboot,
            .needsUserApproval,
            .timedOut,
        ] {
            let run = teardown(deactivation: result, listed: true)
            XCTAssertEqual(run.deactivations, 1)
            XCTAssertEqual(run.presenceProbes, 0)
            XCTAssertNil(run.outcome.remediation)
            XCTAssertEqual(run.outcome.result, result)
        }
    }

    func testSkewDetectionRequiresPositiveListedObservation() {
        // Fail-safe direction: an unlisted (or unreadable, which the probe
        // reports as unlisted) extension suppresses the hint; the original
        // failure passes through byte-identically.
        let run = teardown(
            deactivation: .failed(Self.error4Failure()),
            listed: false
        )
        XCTAssertEqual(run.deactivations, 1)
        XCTAssertEqual(run.presenceProbes, 1)
        XCTAssertNil(run.outcome.remediation)
        XCTAssertEqual(run.outcome.result, .failed(Self.error4Failure()))
    }

    func testSkewProbeIsSkippedWhenTheDeadlineIsAlreadyExhausted() {
        // Inject a clock whose later readings are past the deadline: the
        // probe must not run (detection can never stretch the verb past the
        // timeout its caller relied on) and the failure passes through.
        var deactivations = 0
        var presenceProbes = 0
        var clockReads = 0
        let start = Date(timeIntervalSince1970: 1_000)
        let outcome = HeadlessFilterCLI.performSystemExtensionTeardown(
            timeoutSeconds: 60,
            deactivate: { _ in
                deactivations += 1
                return .failed(Self.error4Failure())
            },
            isExtensionListedActivated: { _ in
                presenceProbes += 1
                return true
            },
            now: {
                clockReads += 1
                // First read anchors the deadline; later reads are past it.
                return clockReads == 1 ? start : start.addingTimeInterval(61)
            }
        )
        XCTAssertEqual(deactivations, 1)
        XCTAssertEqual(presenceProbes, 0)
        XCTAssertNil(outcome.remediation)
        XCTAssertEqual(outcome.result, .failed(Self.error4Failure()))
    }

    func testSkewProbeBudgetIsCappedByTheRemainingDeadline() {
        // 2 seconds of the 60 already spent: the probe budget must be the
        // probe cap itself, and with only 3 left it must shrink to 3.
        for (spent, expectedBudget) in [
            (2.0, HeadlessFilterCLI.extensionListProbeTimeoutSeconds),
            (57.0, 3.0),
        ] {
            var clockReads = 0
            var observedBudget: Double?
            let start = Date(timeIntervalSince1970: 1_000)
            _ = HeadlessFilterCLI.performSystemExtensionTeardown(
                timeoutSeconds: 60,
                deactivate: { _ in .failed(Self.error4Failure()) },
                isExtensionListedActivated: { budget in
                    observedBudget = budget
                    return false
                },
                now: {
                    clockReads += 1
                    return clockReads == 1 ? start : start.addingTimeInterval(spent)
                }
            )
            XCTAssertEqual(observedBudget, expectedBudget)
        }
    }

    // MARK: - systemextensionsctl list parsing (hardened)

    func testListedActivatedEnabledMatchesTheExactColumnBoundRow() {
        // Realistic `systemextensionsctl list` shape from the Mini1 capture:
        // team id in the teamID column, bundle id leading the bundleID
        // column, and an [activated enabled] state field.
        let listed = """
        1 extension(s)
        --- com.apple.system_extension.network_extension
        enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
        *\t*\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\t[activated enabled]
        """
        XCTAssertTrue(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(inListOutput: listed)
        )

        // Terminated-old-beside-active: the activated+enabled row still
        // counts even after a non-matching history row.
        let replaced = """
        \t\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\t[terminated waiting to uninstall on reboot]
        *\t*\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1472)\tCastle Wall\t[activated enabled]
        """
        XCTAssertTrue(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(inListOutput: replaced)
        )
    }

    func testListedActivatedEnabledRejectsForeignTeamAndForeignIdentifier() {
        // A foreign-team extension may reuse our bundle id: the team-id bind
        // must reject it even though every other column matches.
        let foreignTeam =
            "*\t*\tZZOTHERTEAM\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\t[activated enabled]"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(inListOutput: foreignTeam)
        )

        // A different extension's activated row must not read as ours.
        let foreignBundle =
            "*\t*\tYFQSWQ9BJN\tcom.example.other-extension (1.0/7)\tOther\t[activated enabled]"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(inListOutput: foreignBundle)
        )

        // Our identifiers appearing OUTSIDE their columns prove nothing: here
        // the bundle id sits in the name column and the team id in the
        // bundleID column.
        let misplacedColumns =
            "*\t*\tai.sanctuaryprotocol.macos.castle-wall\tYFQSWQ9BJN (0.1.0/1421)\tai.sanctuaryprotocol.macos.castle-wall\t[activated enabled]"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(
                inListOutput: misplacedColumns
            )
        )
    }

    func testListedActivatedEnabledRejectsNonEnabledStatesAndUnparseableRows() {
        // Waiting-for-user is activated but NOT enabled; under the detection
        // design a conservative NOT-listed answer only suppresses the hint.
        let waitingForUser =
            "*\t*\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1472)\tCastle Wall\t[activated waiting for user]"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(
                inListOutput: waitingForUser
            )
        )

        let terminatedOnly =
            "\t\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\t[terminated waiting to uninstall on reboot]"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(
                inListOutput: terminatedOnly
            )
        )

        // Space-separated (localized/reformatted) output has no tab columns
        // and must read as NOT-listed rather than being guessed at.
        let spaceSeparated =
            "* * YFQSWQ9BJN ai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421) Castle Wall [activated enabled]"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(
                inListOutput: spaceSeparated
            )
        )

        // A state field that does not look like a bracketed state list is
        // ambiguous, even if the words appear in it.
        let unbracketedState =
            "*\t*\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\tactivated enabled"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(
                inListOutput: unbracketedState
            )
        )

        XCTAssertFalse(HeadlessFilterCLI.isExtensionListedActivatedEnabled(inListOutput: ""))
    }

    func testListedActivatedEnabledRequiresExactWholeTokenStateMatch() {
        // "deactivated" CONTAINS "activated": a substring match would read
        // this row as activated. Exact whole-token matching must reject it.
        let deactivated =
            "*\t*\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\t[deactivated enabled]"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(
                inListOutput: deactivated
            )
        )

        // Text outside the final bracketed group makes the row unparseable
        // (NOT-listed), never a positive observation.
        let trailingText =
            "*\t*\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\t[activated enabled] trailing"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(
                inListOutput: trailingText
            )
        )

        // A single fused token is not the two required whole tokens.
        let fusedToken =
            "*\t*\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\t[activated_enabled]"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivatedEnabled(
                inListOutput: fusedToken
            )
        )
    }
}
