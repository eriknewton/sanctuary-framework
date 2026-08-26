import Foundation
import NetworkExtension
import SystemExtensions

/// Headless driver for the Castle Wall content-filter configuration.
///
/// Invoked as `Sanctuary-CastleWall.app/Contents/MacOS/CastleWallHostApp
/// --headless <enable|disable|status|deactivate-system-extension>` (typically by `sanctuary castle-wall
/// enable|disable` over SSH). Running the HOST APP BINARY itself is the load-
/// bearing design point: the NE content-filter configuration is owned by the
/// signed app identity that created it, so only this binary can toggle
/// `NEFilterManager.isEnabled` without re-triggering the one-time user
/// consent. A separate helper would need its own restricted-entitlement
/// provisioning profile AND would prompt again; IPC to the GUI app would
/// require a console session - exactly what a headless operator lacks.
///
/// This path never touches SwiftUI/AppKit, so it needs no WindowServer and
/// works from an SSH session. The ONE thing it cannot do is grant the initial
/// content-filter consent (`needsUserApproval` → exit 3): macOS requires a
/// console click for that, once per install.
enum HeadlessFilterCLI {
    static let headlessFlag = "--headless"
    /// Must match CASTLE_WALL_HEADLESS_CONTRACT_VERSION in
    /// server/src/cli/castle-wall.ts (the CLI hard-fails on inequality). Bump
    /// only when an existing report field changes meaning or a REQUIRED field
    /// is added/removed; purely additive optional fields (error_domain,
    /// error_code, recovery, 2026-08-26) do not bump it, because the CLI's
    /// parser requires only `ok` and `state` and ignores unknown keys.
    static let headlessContractVersion = "3"
    /// Must match extensionIdentifier in SystemExtensionManager.swift and the
    /// CASTLE_WALL_SYSTEM_EXTENSION_ID constants in server/src/cli/uninstall.ts
    /// and server/src/cli/castle-wall.ts: every activation/deactivation request
    /// and every presence probe must name the same extension.
    static let systemExtensionIdentifier = "ai.sanctuaryprotocol.macos.castle-wall"
    private static let defaultTimeoutSeconds = 30.0
    /// `systemextensionsctl list` is a local, fast read; this bound only keeps
    /// a wedged sysextd from hanging the teardown recovery gate. A probe that
    /// times out reads as NOT-listed, which fail-safes the recovery to "do not
    /// submit an activation" (never the reverse).
    private static let extensionListProbeTimeoutSeconds = 5.0

    enum Action: String {
        case enable
        case disable
        case status
        case deactivateSystemExtension = "deactivate-system-extension"
    }

    struct Invocation: Equatable {
        let action: Action
        let timeoutSeconds: Double
        let ttlSeconds: UInt32?
        let noTTL: Bool
        /// When set, the JSON report is ALSO written here (in addition to
        /// stdout). `sanctuary castle-wall enable|disable` launches this binary
        /// through `open` on macOS Tahoe - the only way to reach NE preferences
        /// there - but `open` does not relay the child's stdout, so the CLI
        /// reads the report back from this file instead.
        let reportFilePath: String?

        init(
            action: Action,
            timeoutSeconds: Double,
            reportFilePath: String? = nil,
            ttlSeconds: UInt32? = nil,
            noTTL: Bool = false
        ) {
            self.action = action
            self.timeoutSeconds = timeoutSeconds
            self.reportFilePath = reportFilePath
            self.ttlSeconds = ttlSeconds
            self.noTTL = noTTL
        }
    }

    enum ParseResult: Equatable {
        case invocation(Invocation)
        case usageError(String)
    }

    /// Exit codes consumed by `sanctuary castle-wall enable|disable`.
    enum ExitCode: Int32 {
        case success = 0
        case failure = 1
        case usage = 2
        /// The one-time content-filter consent has not been granted yet; the
        /// operator must launch the app at the console once. Distinct from
        /// generic failure so the CLI can print recovery instructions.
        case needsUserApproval = 3
        case timeout = 4
    }

    /// Machine-readable result, one JSON line on stdout.
    struct Report: Codable, Equatable {
        struct Build: Codable, Equatable {
            let gitSha: String
            let headlessContractVersion: String

            enum CodingKeys: String, CodingKey {
                case gitSha = "git_sha"
                case headlessContractVersion = "headless_contract_version"
            }

            static func current() -> Build {
                Build(
                    gitSha: HeadlessFilterCLI.currentBuildGitSha(),
                    headlessContractVersion: HeadlessFilterCLI.headlessContractVersion
                )
            }
        }

        let ok: Bool
        let action: String
        /// Content-filter states plus the system-extension teardown states:
        /// "enabled" | "disabled" | "needs_user_approval" | "unknown" |
        /// "deactivated" | "will_complete_after_reboot" | "failed".
        let state: String
        let error: String?
        /// Machine-readable identity of a failure: the NSError domain/code the
        /// OS returned (e.g. OSSystemExtensionErrorDomain / 4). `error` alone
        /// collapses these into prose a caller cannot branch on; these fields
        /// are ADDITIVE alongside it and never change its meaning. Wire names
        /// must match the optional error_domain/error_code fields of
        /// HeadlessReport in server/src/cli/castle-wall.ts.
        let errorDomain: String?
        let errorCode: Int?
        /// Disclosure that a recovery mutation ran inside this verb (currently
        /// only "activate_replace_then_deactivate"). A teardown verb that
        /// silently submitted an activation would hide a host mutation from the
        /// operator, so the recovery may run ONLY if it is named here. Wire
        /// name must match the optional recovery field of HeadlessReport in
        /// server/src/cli/castle-wall.ts.
        let recovery: String?
        let build: Build

        init(
            ok: Bool,
            action: String,
            state: String,
            error: String?,
            errorDomain: String? = nil,
            errorCode: Int? = nil,
            recovery: String? = nil,
            build: Build = .current()
        ) {
            self.ok = ok
            self.action = action
            self.state = state
            self.error = error
            self.errorDomain = errorDomain
            self.errorCode = errorCode
            self.recovery = recovery
            self.build = build
        }

        enum CodingKeys: String, CodingKey {
            case ok
            case action
            case state
            case error
            case errorDomain = "error_domain"
            case errorCode = "error_code"
            case recovery
            case build
        }
    }

    /// Returns nil when the process was launched normally (GUI mode).
    static func parse(_ arguments: [String]) -> ParseResult? {
        guard let flagIndex = arguments.firstIndex(of: headlessFlag) else {
            return nil
        }
        var action: Action?
        var timeout = defaultTimeoutSeconds
        var reportFilePath: String?
        var ttlSeconds: UInt32?
        var noTTL = false
        for argument in arguments[(flagIndex + 1)...] {
            if argument.hasPrefix("--timeout=") {
                guard let value = Double(argument.dropFirst("--timeout=".count)),
                      value > 0 else {
                    return .usageError("invalid --timeout value: \(argument)")
                }
                timeout = value
            } else if argument.hasPrefix("--report-file=") {
                let path = String(argument.dropFirst("--report-file=".count))
                guard !path.isEmpty else {
                    return .usageError("invalid --report-file value: \(argument)")
                }
                reportFilePath = path
            } else if argument.hasPrefix("--ttl=") {
                guard let value = UInt32(argument.dropFirst("--ttl=".count)),
                      value > 0 else {
                    return .usageError("invalid --ttl value: \(argument)")
                }
                ttlSeconds = value
            } else if argument == "--no-ttl" {
                noTTL = true
            } else if action == nil, let parsed = Action(rawValue: argument) {
                action = parsed
            } else {
                return .usageError("unknown argument: \(argument)")
            }
        }
        guard let action else {
            return .usageError(
                "usage: \(headlessFlag) <enable|disable|status|deactivate-system-extension> "
                    + "[--timeout=seconds] [--report-file=path]"
            )
        }
        return .invocation(
            Invocation(
                action: action,
                timeoutSeconds: timeout,
                reportFilePath: reportFilePath,
                ttlSeconds: ttlSeconds,
                noTTL: noTTL
            )
        )
    }

    static func encode(_ report: Report) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(report),
              let text = String(data: data, encoding: .utf8) else {
            return #"{"action":"\#(report.action)","error":"report encoding failed","ok":false,"state":"unknown"}"#
        }
        return text
    }

    private static func currentBuildGitSha() -> String {
        // This env read echoes the caller's value back as the reported build
        // identity, which is why the CLI's direct-exec disarm fallback
        // (makeIdentityIndependentHostAppInvoke in server/src/cli/castle-wall.ts,
        // must match) strips SANCTUARY_CASTLE_BUILD_SHA from the child
        // environment: an inherited value would let the CLI validate its own
        // expectation against itself instead of the embedded plist identity.
        if let envSha = ProcessInfo.processInfo.environment["SANCTUARY_CASTLE_BUILD_SHA"],
           !envSha.isEmpty {
            return envSha
        }
        if let plistSha = Bundle.main.object(forInfoDictionaryKey: "SanctuaryCastleWallGitSHA")
            as? String,
            !plistSha.isEmpty {
            return plistSha
        }
        return "unknown"
    }

    /// Write the single JSON report line to `path` (0600, the caller-supplied
    /// temp file the CLI then reads back). Best-effort: a write failure leaves
    /// the file missing/empty, and the CLI fail-closes to a generic failure
    /// rather than a false success.
    static func writeReportFile(_ contents: String, to path: String) {
        let data = Data((contents + "\n").utf8)
        FileManager.default.createFile(
            atPath: path,
            contents: data,
            attributes: [.posixPermissions: 0o600]
        )
    }

    static func run(
        _ invocation: Invocation,
        manager: NEFilterManager = .shared(),
        deactivateSystemExtension: (Double) -> SystemExtensionTeardownOutcome =
            runSystemExtensionTeardown,
        output: (String) -> Void = { print($0) }
    ) -> ExitCode {
        let action = invocation.action.rawValue

        func emit(_ report: Report, _ code: ExitCode) -> ExitCode {
            let line = encode(report)
            output(line)
            if let path = invocation.reportFilePath {
                writeReportFile(line, to: path)
            }
            return code
        }

        switch waitFor(invocation.timeoutSeconds, manager.loadFromPreferences) {
        case .timedOut:
            return emit(
                Report(ok: false, action: action, state: "unknown",
                       error: "loadFromPreferences timed out"),
                .timeout
            )
        case let .completed(.some(error)):
            return emit(
                Report(ok: false, action: action, state: "unknown",
                       error: "loadFromPreferences failed: \(error.localizedDescription)"),
                .failure
            )
        case .completed(nil):
            break
        }

        let currentlyEnabled =
            manager.providerConfiguration != nil && manager.isEnabled

        switch invocation.action {
        case .status:
            return emit(
                Report(ok: true, action: action,
                       state: currentlyEnabled ? "enabled" : "disabled",
                       error: nil),
                .success
            )

        case .enable:
            if currentlyEnabled {
                return emit(
                    Report(ok: true, action: action, state: "enabled", error: nil),
                    .success
                )
            }
            FilterConfigurationManager.applyDesiredProviderConfiguration(to: manager)
            manager.isEnabled = true
            return save(manager, invocation: invocation, emit: emit) {
                Report(ok: true, action: action, state: "enabled", error: nil)
            }

        case .disable:
            // Disarm is the dead-man recovery lever: succeed idempotently and
            // never add preconditions here.
            guard manager.providerConfiguration != nil || manager.isEnabled else {
                return emit(
                    Report(ok: true, action: action, state: "disabled", error: nil),
                    .success
                )
            }
            manager.isEnabled = false
            return save(manager, invocation: invocation, emit: emit) {
                Report(ok: true, action: action, state: "disabled", error: nil)
            }

        case .deactivateSystemExtension:
            // Deactivation removes the enforcement code from the host. It is
            // never allowed to substitute for disarm: an enabled filter must
            // be turned off and corroborated before the sysext request starts.
            guard !currentlyEnabled else {
                return emit(
                    Report(
                        ok: false,
                        action: action,
                        state: "unknown",
                        error: "content filter is still enabled; disable it before deactivating the system extension"
                    ),
                    .failure
                )
            }
            let outcome = reportForSystemExtensionDeactivation(
                deactivateSystemExtension(invocation.timeoutSeconds),
                action: action
            )
            return emit(outcome.report, outcome.exitCode)
        }
    }

    static func reportForSystemExtensionDeactivation(
        _ outcome: SystemExtensionTeardownOutcome,
        action: String = Action.deactivateSystemExtension.rawValue
    ) -> (report: Report, exitCode: ExitCode) {
        // Every branch threads outcome.recovery through: the recovery
        // disclosure must survive into the report on SUCCESS paths too, or a
        // recovered teardown would hide its activation submission behind a
        // clean "deactivated".
        let recovery = outcome.recovery
        switch outcome.result {
            case .deactivated:
                return (
                    Report(ok: true, action: action, state: "deactivated",
                           error: nil, recovery: recovery),
                    .success
                )
            case .willCompleteAfterReboot:
                return (
                    Report(
                        ok: true,
                        action: action,
                        state: "will_complete_after_reboot",
                        error: nil,
                        recovery: recovery
                    ),
                    .success
                )
            case .needsUserApproval:
                return (
                    Report(
                        ok: false,
                        action: action,
                        state: "needs_user_approval",
                        error: "macOS requires operator approval to deactivate the system extension",
                        recovery: recovery
                    ),
                    .needsUserApproval
                )
            case let .failed(failure):
                return (
                    Report(ok: false, action: action, state: "unknown",
                           error: failure.message,
                           errorDomain: failure.domain,
                           errorCode: failure.code,
                           recovery: recovery),
                    .failure
                )
            case .timedOut:
                return (
                    Report(
                        ok: false,
                        action: action,
                        state: "unknown",
                        error: "system-extension deactivation timed out",
                        recovery: recovery
                    ),
                    .timeout
                )
        }
    }

    /// Machine-readable identity of a system-extension request failure.
    /// `domain`/`code` are the NSError values the OS delegate delivered; nil
    /// only for failures that never came from an NSError (e.g. an unknown
    /// delegate result). Downstream branching (the error-4 recovery gate)
    /// compares BOTH domain and code, never the prose message.
    struct SystemExtensionFailure: Equatable {
        let message: String
        let domain: String?
        let code: Int?
    }

    enum SystemExtensionDeactivationResult: Equatable {
        case deactivated
        case willCompleteAfterReboot
        case needsUserApproval
        case failed(SystemExtensionFailure)
        case timedOut
    }

    /// Outcome of one system-extension request (activation or deactivation),
    /// before the deactivation-specific naming is applied.
    enum SystemExtensionRequestOutcome: Equatable {
        case completed
        case willCompleteAfterReboot
        case needsUserApproval
        case failed(SystemExtensionFailure)
        case timedOut
    }

    /// The deactivation verb's full result: the terminal request result plus
    /// the disclosure of any recovery mutation the verb performed. The two
    /// travel together so no caller can observe the result without the
    /// disclosure.
    struct SystemExtensionTeardownOutcome: Equatable {
        let result: SystemExtensionDeactivationResult
        /// Non-nil iff a recovery activation (replace) request was submitted;
        /// see teardownRecoveryDisclosure.
        let recovery: String?
    }

    /// The only recovery this verb ever performs: one activation (replacement)
    /// request to re-bind the OS activation record to the installed app's
    /// embedded extension version, then one re-submitted deactivation.
    static let teardownRecoveryDisclosure = "activate_replace_then_deactivate"

    static func systemExtensionFailureDetail(from error: Error) -> SystemExtensionFailure {
        let nsError = error as NSError
        return SystemExtensionFailure(
            message: error.localizedDescription,
            domain: nsError.domain,
            code: nsError.code
        )
    }

    /// True only for the exact failure the skew recovery is allowed to answer:
    /// OSSystemExtensionErrorDomain / extensionNotFound (code 4). Matching on
    /// the structured domain+code (never the prose message) is what keeps the
    /// recovery from firing on any other failure class.
    static func isExtensionNotFoundFailure(
        _ result: SystemExtensionDeactivationResult
    ) -> Bool {
        guard case let .failed(failure) = result else { return false }
        return failure.domain == OSSystemExtensionErrorDomain
            && failure.code == OSSystemExtensionError.extensionNotFound.rawValue
    }

    static func deactivationResult(
        from outcome: SystemExtensionRequestOutcome
    ) -> SystemExtensionDeactivationResult {
        switch outcome {
        case .completed: return .deactivated
        case .willCompleteAfterReboot: return .willCompleteAfterReboot
        case .needsUserApproval: return .needsUserApproval
        case let .failed(failure): return .failed(failure)
        case .timedOut: return .timedOut
        }
    }

    /// Deactivation with single-shot skew recovery.
    ///
    /// A host app redeployed at a newer bundle version than the activated
    /// extension record can be refused deactivation with extensionNotFound
    /// even while `systemextensionsctl list` still shows the extension
    /// activated. The arm path already re-submits activation on a version diff
    /// (ContentView.armProtectionAfterProbe); this gives the teardown path the
    /// same replace-first awareness: activate (replacement) once to re-bind
    /// the record to the installed bundle - the standard app-update path - and
    /// then re-submit the deactivation once.
    ///
    /// Bounds, in order of enforcement:
    /// - The recovery gate requires the exact error-4 failure AND a positive
    ///   "still listed activated" observation from the OS's own list output;
    ///   an unreadable or negative probe means NO recovery (fail-safe: never
    ///   mutate the host on an unconfirmed premise).
    /// - Exactly one activation and one re-deactivation, no loops: a second
    ///   error 4 is reported truthfully, never retried.
    /// - Every stage spends only the time remaining under the single
    ///   invocation deadline, so recovery can never stretch the verb past the
    ///   timeout its caller relied on.
    /// - The content filter was already verified off before any teardown
    ///   request (see the deactivateSystemExtension guard in run), so the
    ///   transient replacement activation opens no enforcement window.
    static func orchestrateSystemExtensionTeardown(
        timeoutSeconds: Double,
        deactivate: (Double) -> SystemExtensionDeactivationResult,
        isExtensionListedActivated: () -> Bool,
        activateReplacement: (Double) -> SystemExtensionRequestOutcome,
        now: () -> Date = Date.init
    ) -> SystemExtensionTeardownOutcome {
        let deadline = now().addingTimeInterval(timeoutSeconds)
        let first = deactivate(timeoutSeconds)
        guard isExtensionNotFoundFailure(first) else {
            return SystemExtensionTeardownOutcome(result: first, recovery: nil)
        }
        guard case let .failed(firstFailure) = first else {
            return SystemExtensionTeardownOutcome(result: first, recovery: nil)
        }
        guard isExtensionListedActivated() else {
            return SystemExtensionTeardownOutcome(result: first, recovery: nil)
        }

        let activationBudget = deadline.timeIntervalSince(now())
        guard activationBudget > 0 else {
            return SystemExtensionTeardownOutcome(
                result: .failed(SystemExtensionFailure(
                    message: firstFailure.message
                        + " (skew recovery not attempted: deactivation deadline exhausted)",
                    domain: firstFailure.domain,
                    code: firstFailure.code
                )),
                recovery: nil
            )
        }

        // From here on an activation request HAS been submitted, so every
        // return path below must carry the recovery disclosure.
        let activation = activateReplacement(activationBudget)
        switch activation {
        case .completed:
            break
        case .needsUserApproval:
            // The replacement itself is parked on operator approval; that is
            // the truthful terminal state for this run.
            return SystemExtensionTeardownOutcome(
                result: .needsUserApproval,
                recovery: teardownRecoveryDisclosure
            )
        case .willCompleteAfterReboot:
            return SystemExtensionTeardownOutcome(
                result: .failed(SystemExtensionFailure(
                    message: firstFailure.message
                        + "; recovery activation completes only after reboot - reboot, then re-run deactivation",
                    domain: firstFailure.domain,
                    code: firstFailure.code
                )),
                recovery: teardownRecoveryDisclosure
            )
        case let .failed(activationFailure):
            return SystemExtensionTeardownOutcome(
                result: .failed(SystemExtensionFailure(
                    message: "deactivation failed (\(firstFailure.message)); "
                        + "recovery activation failed: \(activationFailure.message)",
                    domain: activationFailure.domain,
                    code: activationFailure.code
                )),
                recovery: teardownRecoveryDisclosure
            )
        case .timedOut:
            return SystemExtensionTeardownOutcome(
                result: .failed(SystemExtensionFailure(
                    message: firstFailure.message + "; recovery activation timed out",
                    domain: firstFailure.domain,
                    code: firstFailure.code
                )),
                recovery: teardownRecoveryDisclosure
            )
        }

        let retryBudget = deadline.timeIntervalSince(now())
        guard retryBudget > 0 else {
            return SystemExtensionTeardownOutcome(
                result: .failed(SystemExtensionFailure(
                    message: firstFailure.message
                        + "; recovery activation completed but the deactivation deadline "
                        + "was exhausted before the re-submitted deactivation",
                    domain: firstFailure.domain,
                    code: firstFailure.code
                )),
                recovery: teardownRecoveryDisclosure
            )
        }
        // Second failure (any code, including another error 4) is reported
        // truthfully with its own domain/code; the single-shot cap means it is
        // never retried.
        let second = deactivate(retryBudget)
        return SystemExtensionTeardownOutcome(
            result: second,
            recovery: teardownRecoveryDisclosure
        )
    }

    /// True iff `systemextensionsctl list` output shows the identified
    /// extension in any `[activated ...]` state. Row matching mirrors
    /// parseInstallSystemExtensionState in server/src/cli/install.ts (every
    /// matching row participates; list order must never hide a live record)
    /// and the `[activated` states enumerated by parseCastleWallState in
    /// server/src/cli/castle-wall.ts.
    static func isExtensionListedActivated(
        inListOutput output: String,
        identifier: String = systemExtensionIdentifier
    ) -> Bool {
        output.split(separator: "\n").contains { line in
            line.split(whereSeparator: { $0 == " " || $0 == "\t" })
                .contains(Substring(identifier))
                && line.contains("[activated")
        }
    }

    /// Production presence probe behind the recovery gate. Fail-safe: any
    /// probe failure (spawn error, timeout, nonzero exit, undecodable output)
    /// reads as NOT listed, which forbids the recovery activation - a
    /// diagnostic failure must never authorize a host mutation.
    private static func defaultExtensionListedActivated() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/systemextensionsctl")
        process.arguments = ["list"]
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = Pipe()
        do {
            try process.run()
        } catch {
            return false
        }
        // Read concurrently with the bounded wait: `list` output is small, but
        // reading only after exit could deadlock if it ever exceeded the pipe
        // buffer. LockedDataBox formally synchronizes the reader-thread write
        // with the post-wait read (same pattern as LockedErrorBox below).
        let captured = LockedDataBox()
        let reader = Thread {
            captured.store(stdout.fileHandleForReading.readDataToEndOfFile())
        }
        reader.start()
        let deadline = Date().addingTimeInterval(extensionListProbeTimeoutSeconds)
        while process.isRunning, Date() < deadline {
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
        }
        if process.isRunning {
            process.terminate()
            return false
        }
        while captured.load() == nil, Date() < deadline {
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
        }
        guard process.terminationStatus == 0,
              let data = captured.load(),
              let text = String(data: data, encoding: .utf8) else {
            return false
        }
        return isExtensionListedActivated(inListOutput: text)
    }

    private static func runSystemExtensionTeardown(
        timeoutSeconds: Double
    ) -> SystemExtensionTeardownOutcome {
        orchestrateSystemExtensionTeardown(
            timeoutSeconds: timeoutSeconds,
            deactivate: { seconds in
                // OSSystemExtensionRequest.delegate is weak, so the runner
                // stays alive for the entire bounded run-loop wait.
                let runner = HeadlessSystemExtensionRequestRunner(kind: .deactivation)
                return deactivationResult(from: runner.run(timeoutSeconds: seconds))
            },
            isExtensionListedActivated: defaultExtensionListedActivated,
            activateReplacement: { seconds in
                let runner = HeadlessSystemExtensionRequestRunner(kind: .activation)
                return runner.run(timeoutSeconds: seconds)
            }
        )
    }

    private static func save(
        _ manager: NEFilterManager,
        invocation: Invocation,
        emit: (Report, ExitCode) -> ExitCode,
        onSuccess: () -> Report
    ) -> ExitCode {
        let action = invocation.action.rawValue
        switch waitFor(invocation.timeoutSeconds, manager.saveToPreferences) {
        case .timedOut:
            return emit(
                Report(ok: false, action: action, state: "unknown",
                       error: "saveToPreferences timed out"),
                .timeout
            )
        case let .completed(.some(error)):
            let nsError = error as NSError
            if nsError.domain == NEFilterErrorDomain,
               nsError.code == NEFilterManagerError.configurationPermissionDenied.rawValue {
                return emit(
                    Report(ok: false, action: action, state: "needs_user_approval",
                           error: "one-time content-filter consent not granted; "
                               + "launch Sanctuary-CastleWall.app at the console once "
                               + "and approve the filter, then retry headlessly"),
                    .needsUserApproval
                )
            }
            return emit(
                Report(ok: false, action: action, state: "unknown",
                       error: "saveToPreferences failed: \(error.localizedDescription)"),
                .failure
            )
        case .completed(nil):
            return emit(onSuccess(), .success)
        }
    }

    enum SyncResult {
        case completed(Error?)
        case timedOut
    }

    /// Wait for an NEFilterManager completion handler while keeping the calling
    /// (main) run loop live.
    ///
    /// W7-1 (2026-06-17): a bare `DispatchSemaphore.wait` parks this thread and
    /// services nothing, so a completion handler that Tahoe delivers to the MAIN
    /// queue/run loop can never fire - the thread that must drain the callback is
    /// the thread parked on the semaphore. That self-deadlock produced the
    /// deterministic 30s `loadFromPreferences timed out` on Mini1's first arm.
    ///
    /// Spinning a bounded `RunLoop.current.run(mode:before:)` instead keeps the
    /// run loop draining, so a main-queue-delivered handler executes and the
    /// wedge disappears. It cannot self-deadlock, preserves the exact return
    /// contract (`.timedOut` at the deadline, `.completed(error)` on completion)
    /// and the `timeoutSeconds` bound, and is behavior-identical on the fast
    /// path: an internal-queue delivery flips the flag and exits immediately.
    static func waitFor(
        _ timeoutSeconds: Double,
        _ body: (@escaping (Error?) -> Void) -> Void
    ) -> SyncResult {
        let captured = LockedErrorBox()
        let done = LockedFlag()
        body { error in
            captured.store(error)
            done.set()
        }
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while !done.isSet() {
            if Date() >= deadline {
                return .timedOut
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
        }
        return .completed(captured.load())
    }
}

/// Bounded delegate bridge for the signed host app's system-extension
/// requests (deactivation, and the single-shot skew-recovery activation).
/// Node cannot own these requests: macOS binds them to the app identity that
/// owns the bundled system extension.
private final class HeadlessSystemExtensionRequestRunner: NSObject,
    OSSystemExtensionRequestDelegate
{
    enum Kind {
        case activation
        case deactivation
    }

    private let kind: Kind
    private let lock = NSLock()
    private var result: HeadlessFilterCLI.SystemExtensionRequestOutcome?
    private var approvalNeeded = false

    init(kind: Kind) {
        self.kind = kind
    }

    func run(timeoutSeconds: Double) -> HeadlessFilterCLI.SystemExtensionRequestOutcome {
        let request: OSSystemExtensionRequest
        switch kind {
        case .activation:
            request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: HeadlessFilterCLI.systemExtensionIdentifier,
                queue: .main
            )
        case .deactivation:
            request = OSSystemExtensionRequest.deactivationRequest(
                forExtensionWithIdentifier: HeadlessFilterCLI.systemExtensionIdentifier,
                queue: .main
            )
        }
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)

        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            if let completed = loadResult() {
                return completed
            }
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
        }
        if let completed = loadResult() {
            return completed
        }
        return loadApprovalNeeded() ? .needsUserApproval : .timedOut
    }

    private func storeResult(_ value: HeadlessFilterCLI.SystemExtensionRequestOutcome) {
        lock.lock()
        result = value
        lock.unlock()
    }

    private func loadResult() -> HeadlessFilterCLI.SystemExtensionRequestOutcome? {
        lock.lock()
        defer { lock.unlock() }
        return result
    }

    private func noteApprovalNeeded() {
        lock.lock()
        approvalNeeded = true
        lock.unlock()
    }

    private func loadApprovalNeeded() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return approvalNeeded
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        switch result {
        case .completed:
            storeResult(.completed)
        case .willCompleteAfterReboot:
            storeResult(.willCompleteAfterReboot)
        @unknown default:
            // Not from an NSError, so there is no domain/code to preserve.
            storeResult(.failed(HeadlessFilterCLI.SystemExtensionFailure(
                message: "unknown system-extension request result",
                domain: nil,
                code: nil
            )))
        }
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        // Preserve the NSError domain/code, not only the prose: the error-4
        // recovery gate and the CLI's report consumers branch on the
        // structured identity (RCA defect.sysext-deactivation-extension-not-found).
        storeResult(.failed(HeadlessFilterCLI.systemExtensionFailureDetail(from: error)))
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // Informational, not terminal: macOS can still deliver didFinish after
        // approval. Remember it for timeout reporting without racing completion.
        noteApprovalNeeded()
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Answering .replace is what lets the recovery activation re-bind the
        // stale activated record to this bundle's embedded extension version
        // (the standard app-update path); must match
        // SystemExtensionManager.replacementAction.
        .replace
    }
}

/// Lock-guarded capture of the systemextensionsctl reader thread's output so
/// the cross-thread write/read is formally synchronized (same rationale as
/// LockedErrorBox). `nil` means "not read yet"; a completed read stores the
/// (possibly empty) data.
private final class LockedDataBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Data?

    func store(_ data: Data) {
        lock.lock()
        value = data
        lock.unlock()
    }

    func load() -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

/// Minimal lock-guarded box so the completion-handler write and the post-wait
/// read are formally synchronized (the run-loop spin orders them, but the box
/// keeps the Sendable checker satisfied without @unchecked on CLI state).
private final class LockedErrorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Error?

    func store(_ error: Error?) {
        lock.lock()
        value = error
        lock.unlock()
    }

    func load() -> Error? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

/// Lock-guarded completion flag set on the NE completion handler's thread and
/// polled by the run-loop wait spin (W7-1, 2026-06-17). NSLock-guarded so the
/// cross-thread set/read is formally synchronized without `@unchecked` leaking
/// onto a bare `Bool`.
private final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false

    func set() {
        lock.lock()
        flag = true
        lock.unlock()
    }

    func isSet() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return flag
    }
}
