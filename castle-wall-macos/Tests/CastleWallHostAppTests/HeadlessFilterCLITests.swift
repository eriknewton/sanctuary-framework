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
            .init(result: .deactivated, recovery: nil)
        )
        XCTAssertEqual(completed.exitCode, .success)
        XCTAssertTrue(completed.report.ok)
        XCTAssertEqual(completed.report.state, "deactivated")

        let deferred = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(result: .willCompleteAfterReboot, recovery: nil)
        )
        XCTAssertEqual(deferred.exitCode, .success)
        XCTAssertTrue(deferred.report.ok)
        XCTAssertEqual(deferred.report.state, "will_complete_after_reboot")
    }

    func testSystemExtensionDeactivationFailureStatesStayNonSuccess() {
        let approval = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(result: .needsUserApproval, recovery: nil)
        )
        XCTAssertEqual(approval.exitCode, .needsUserApproval)
        XCTAssertFalse(approval.report.ok)

        let timeout = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(result: .timedOut, recovery: nil)
        )
        XCTAssertEqual(timeout.exitCode, .timeout)
        XCTAssertFalse(timeout.report.ok)

        let failure = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(
                result: .failed(.init(message: "boom", domain: nil, code: nil)),
                recovery: nil
            )
        )
        XCTAssertEqual(failure.exitCode, .failure)
        XCTAssertEqual(failure.report.error, "boom")
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
                recovery: nil
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
        // recovery must serialize byte-identically to the pre-change shape,
        // which is why headlessContractVersion stays "3".
        let report = HeadlessFilterCLI.Report(
            ok: true, action: "deactivate-system-extension", state: "deactivated",
            error: nil,
            build: .init(gitSha: "abc1234", headlessContractVersion: "3")
        )
        let encoded = HeadlessFilterCLI.encode(report)
        XCTAssertFalse(encoded.contains("error_domain"))
        XCTAssertFalse(encoded.contains("error_code"))
        XCTAssertFalse(encoded.contains("recovery"))
    }

    func testRecoveryDisclosureSurvivesIntoSuccessAndFailureReports() {
        let recovered = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(
                result: .deactivated,
                recovery: HeadlessFilterCLI.teardownRecoveryDisclosure
            )
        )
        XCTAssertEqual(recovered.report.recovery, "activate_replace_then_deactivate")
        XCTAssertTrue(
            HeadlessFilterCLI.encode(recovered.report)
                .contains(#""recovery":"activate_replace_then_deactivate""#)
        )

        let stillFailed = HeadlessFilterCLI.reportForSystemExtensionDeactivation(
            .init(
                result: .failed(.init(
                    message: "second failure",
                    domain: OSSystemExtensionErrorDomain,
                    code: OSSystemExtensionError.extensionNotFound.rawValue
                )),
                recovery: HeadlessFilterCLI.teardownRecoveryDisclosure
            )
        )
        XCTAssertEqual(stillFailed.report.recovery, "activate_replace_then_deactivate")
        XCTAssertEqual(stillFailed.report.errorCode, 4)
    }

    // MARK: - skew-recovery orchestration

    private static func error4Failure() -> HeadlessFilterCLI.SystemExtensionFailure {
        .init(
            message: "OSSystemExtensionErrorDomain error 4.",
            domain: OSSystemExtensionErrorDomain,
            code: OSSystemExtensionError.extensionNotFound.rawValue
        )
    }

    /// Drives the orchestrator with counting fakes. Returns the outcome plus
    /// the observed submission counts so every test can assert the exact
    /// number of host mutations, not just the terminal state.
    private func orchestrate(
        firstDeactivation: HeadlessFilterCLI.SystemExtensionDeactivationResult,
        listed: Bool,
        activation: HeadlessFilterCLI.SystemExtensionRequestOutcome = .completed,
        secondDeactivation: HeadlessFilterCLI.SystemExtensionDeactivationResult = .deactivated,
        timeoutSeconds: Double = 60
    ) -> (
        outcome: HeadlessFilterCLI.SystemExtensionTeardownOutcome,
        deactivations: Int,
        activations: Int,
        presenceProbes: Int
    ) {
        var deactivations = 0
        var activations = 0
        var presenceProbes = 0
        let outcome = HeadlessFilterCLI.orchestrateSystemExtensionTeardown(
            timeoutSeconds: timeoutSeconds,
            deactivate: { _ in
                deactivations += 1
                return deactivations == 1 ? firstDeactivation : secondDeactivation
            },
            isExtensionListedActivated: {
                presenceProbes += 1
                return listed
            },
            activateReplacement: { _ in
                activations += 1
                return activation
            }
        )
        return (outcome, deactivations, activations, presenceProbes)
    }

    func testRecoveryRunsExactlyOnceOnErrorFourWhileListed() {
        let run = orchestrate(
            firstDeactivation: .failed(Self.error4Failure()),
            listed: true,
            activation: .completed,
            secondDeactivation: .deactivated
        )
        XCTAssertEqual(run.outcome.result, .deactivated)
        XCTAssertEqual(
            run.outcome.recovery,
            HeadlessFilterCLI.teardownRecoveryDisclosure
        )
        XCTAssertEqual(run.deactivations, 2)
        XCTAssertEqual(run.activations, 1)
        XCTAssertEqual(run.presenceProbes, 1)
    }

    func testRecoveryNeverFiresOnOtherFailureCodes() {
        // Same domain, different codes (13 = authorizationRequired, 8 =
        // codeSignatureInvalid): the recovery mutation must not fire even
        // though the extension is listed.
        for code in [13, 8, 9, 3] {
            let run = orchestrate(
                firstDeactivation: .failed(.init(
                    message: "OSSystemExtensionErrorDomain error \(code).",
                    domain: OSSystemExtensionErrorDomain,
                    code: code
                )),
                listed: true
            )
            XCTAssertEqual(run.activations, 0, "recovery fired on code \(code)")
            XCTAssertEqual(run.deactivations, 1, "re-deactivation fired on code \(code)")
            XCTAssertNil(run.outcome.recovery)
        }
    }

    func testRecoveryNeverFiresOnForeignDomainOrMissingIdentity() {
        // A code-4 NSError from a DIFFERENT domain, and a prose-only failure
        // with no identity at all: both must be inert.
        for failure in [
            HeadlessFilterCLI.SystemExtensionFailure(
                message: "some other error 4", domain: "NSCocoaErrorDomain", code: 4
            ),
            HeadlessFilterCLI.SystemExtensionFailure(
                message: "unknown system-extension request result", domain: nil, code: nil
            ),
        ] {
            let run = orchestrate(firstDeactivation: .failed(failure), listed: true)
            XCTAssertEqual(run.activations, 0)
            XCTAssertEqual(run.deactivations, 1)
            XCTAssertNil(run.outcome.recovery)
        }
    }

    func testRecoveryNeverFiresOnNonFailureResults() {
        for result in [
            HeadlessFilterCLI.SystemExtensionDeactivationResult.deactivated,
            .willCompleteAfterReboot,
            .needsUserApproval,
            .timedOut,
        ] {
            let run = orchestrate(firstDeactivation: result, listed: true)
            XCTAssertEqual(run.activations, 0)
            XCTAssertEqual(run.deactivations, 1)
            XCTAssertNil(run.outcome.recovery)
            XCTAssertEqual(run.outcome.result, result)
        }
    }

    func testRecoveryRequiresPositiveListedObservation() {
        // Fail-safe direction: an unlisted (or unreadable, which the probe
        // reports as unlisted) extension forbids the recovery activation.
        let run = orchestrate(
            firstDeactivation: .failed(Self.error4Failure()),
            listed: false
        )
        XCTAssertEqual(run.activations, 0)
        XCTAssertEqual(run.deactivations, 1)
        XCTAssertNil(run.outcome.recovery)
        XCTAssertEqual(run.outcome.result, .failed(Self.error4Failure()))
    }

    func testSecondErrorFourIsReportedTruthfullyAndNeverRetried() {
        let run = orchestrate(
            firstDeactivation: .failed(Self.error4Failure()),
            listed: true,
            activation: .completed,
            secondDeactivation: .failed(Self.error4Failure())
        )
        // Single-shot cap: a second error 4 does not loop back into recovery.
        XCTAssertEqual(run.deactivations, 2)
        XCTAssertEqual(run.activations, 1)
        XCTAssertEqual(run.outcome.result, .failed(Self.error4Failure()))
        XCTAssertEqual(
            run.outcome.recovery,
            HeadlessFilterCLI.teardownRecoveryDisclosure
        )
    }

    func testFailedRecoveryActivationIsDisclosedAndStopsTheSequence() {
        let run = orchestrate(
            firstDeactivation: .failed(Self.error4Failure()),
            listed: true,
            activation: .failed(.init(
                message: "activation refused",
                domain: OSSystemExtensionErrorDomain,
                code: 9
            ))
        )
        // The activation WAS submitted, so the disclosure must survive even
        // though the recovery did not reach the re-deactivation.
        XCTAssertEqual(run.activations, 1)
        XCTAssertEqual(run.deactivations, 1)
        XCTAssertEqual(
            run.outcome.recovery,
            HeadlessFilterCLI.teardownRecoveryDisclosure
        )
        guard case let .failed(failure) = run.outcome.result else {
            return XCTFail("expected failed, got \(run.outcome.result)")
        }
        XCTAssertTrue(failure.message.contains("recovery activation failed"))
        XCTAssertEqual(failure.code, 9)
    }

    func testRecoveryActivationParkedOnApprovalReportsNeedsUserApproval() {
        let run = orchestrate(
            firstDeactivation: .failed(Self.error4Failure()),
            listed: true,
            activation: .needsUserApproval
        )
        XCTAssertEqual(run.outcome.result, .needsUserApproval)
        XCTAssertEqual(
            run.outcome.recovery,
            HeadlessFilterCLI.teardownRecoveryDisclosure
        )
        XCTAssertEqual(run.deactivations, 1)
    }

    func testRecoveryIsSkippedWhenTheDeadlineIsAlreadyExhausted() {
        // Inject a clock whose second reading is past the deadline: the
        // orchestrator must skip the recovery mutation, disclose why in the
        // message, and set no recovery marker (nothing was submitted).
        var deactivations = 0
        var activations = 0
        var clockReads = 0
        let start = Date(timeIntervalSince1970: 1_000)
        let outcome = HeadlessFilterCLI.orchestrateSystemExtensionTeardown(
            timeoutSeconds: 60,
            deactivate: { _ in
                deactivations += 1
                return .failed(Self.error4Failure())
            },
            isExtensionListedActivated: { true },
            activateReplacement: { _ in
                activations += 1
                return .completed
            },
            now: {
                clockReads += 1
                // First read anchors the deadline; later reads are past it.
                return clockReads == 1 ? start : start.addingTimeInterval(61)
            }
        )
        XCTAssertEqual(deactivations, 1)
        XCTAssertEqual(activations, 0)
        XCTAssertNil(outcome.recovery)
        guard case let .failed(failure) = outcome.result else {
            return XCTFail("expected failed, got \(outcome.result)")
        }
        XCTAssertTrue(failure.message.contains("recovery not attempted"))
        XCTAssertEqual(failure.code, 4)
    }

    // MARK: - systemextensionsctl list parsing

    func testListedActivatedMatchesActivatedRowsForTheExactIdentifier() {
        // Realistic `systemextensionsctl list` shape from the Mini1 capture.
        let listed = """
        1 extension(s)
        --- com.apple.system_extension.network_extension
        enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
        *\t*\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\t[activated enabled]
        """
        XCTAssertTrue(HeadlessFilterCLI.isExtensionListedActivated(inListOutput: listed))

        // Terminated-old-beside-active: any activated row counts.
        let replaced = """
        \t\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\t[terminated waiting to uninstall on reboot]
        *\t*\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1472)\tCastle Wall\t[activated waiting for user]
        """
        XCTAssertTrue(HeadlessFilterCLI.isExtensionListedActivated(inListOutput: replaced))
    }

    func testListedActivatedRejectsOtherIdentifiersAndNonActivatedStates() {
        // A different extension's activated row must not read as ours, and a
        // terminated-only history must not read as present.
        let foreign =
            "*\t*\tTEAMID\tcom.example.other-extension (1.0/7)\tOther\t[activated enabled]"
        XCTAssertFalse(HeadlessFilterCLI.isExtensionListedActivated(inListOutput: foreign))

        let terminatedOnly =
            "\t\tYFQSWQ9BJN\tai.sanctuaryprotocol.macos.castle-wall (0.1.0/1421)\tCastle Wall\t[terminated waiting to uninstall on reboot]"
        XCTAssertFalse(
            HeadlessFilterCLI.isExtensionListedActivated(inListOutput: terminatedOnly)
        )

        XCTAssertFalse(HeadlessFilterCLI.isExtensionListedActivated(inListOutput: ""))
    }
}
