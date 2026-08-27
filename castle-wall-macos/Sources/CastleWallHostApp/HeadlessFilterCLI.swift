import CastleWallSigner
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
    /// error_code, remediation, 2026-08-26) do not bump it, because the CLI's
    /// parser requires only `ok` and `state` and ignores unknown keys.
    static let headlessContractVersion = "3"
    /// Must match extensionIdentifier in SystemExtensionManager.swift,
    /// CASTLE_WALL_SYSTEM_EXTENSION_BUNDLE_ID in server/src/cli/castle-wall.ts,
    /// and CASTLE_WALL_SYSTEM_EXTENSION_ID in server/src/cli/uninstall.ts:
    /// every deactivation request and every presence probe must name the same
    /// extension.
    static let systemExtensionIdentifier = "ai.sanctuaryprotocol.macos.castle-wall"
    private static let defaultTimeoutSeconds = 30.0
    /// `systemextensionsctl list` is a local, fast read; this bound only keeps
    /// a wedged sysextd from hanging the post-failure skew-detection probe. A
    /// probe that times out reads as NOT-listed, which merely suppresses the
    /// remediation hint (never the reverse: an unreadable probe can never
    /// manufacture a positive observation).
    static let extensionListProbeTimeoutSeconds = 5.0

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
        /// Machine-readable remediation id (currently only
        /// "extension_version_skew_reregister_required"). This verb never
        /// mutates the host beyond the deactivation request itself; when the
        /// OS refuses that request and the extension is positively observed
        /// still activated, this field names the attended remediation the
        /// operator must perform. Wire name must match the optional
        /// remediation field of HeadlessReport in server/src/cli/castle-wall.ts.
        let remediation: String?
        let build: Build

        init(
            ok: Bool,
            action: String,
            state: String,
            error: String?,
            errorDomain: String? = nil,
            errorCode: Int? = nil,
            remediation: String? = nil,
            build: Build = .current()
        ) {
            self.ok = ok
            self.action = action
            self.state = state
            self.error = error
            self.errorDomain = errorDomain
            self.errorCode = errorCode
            self.remediation = remediation
            self.build = build
        }

        enum CodingKeys: String, CodingKey {
            case ok
            case action
            case state
            case error
            case errorDomain = "error_domain"
            case errorCode = "error_code"
            case remediation
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
        // Every branch threads outcome.remediation through so the hint can
        // never be dropped between detection and the report the CLI parses.
        let remediation = outcome.remediation
        switch outcome.result {
            case .deactivated:
                return (
                    Report(ok: true, action: action, state: "deactivated",
                           error: nil, remediation: remediation),
                    .success
                )
            case .willCompleteAfterReboot:
                return (
                    Report(
                        ok: true,
                        action: action,
                        state: "will_complete_after_reboot",
                        error: nil,
                        remediation: remediation
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
                        remediation: remediation
                    ),
                    .needsUserApproval
                )
            case let .failed(failure):
                // error_domain/error_code are the identity of THIS deactivation
                // failure (the NSError the OS delegate delivered), never of any
                // other request or probe.
                return (
                    Report(ok: false, action: action, state: "unknown",
                           error: failure.message,
                           errorDomain: failure.domain,
                           errorCode: failure.code,
                           remediation: remediation),
                    .failure
                )
            case .timedOut:
                // A timeout has no NSError identity; the report carries no
                // error_domain/error_code rather than a stale one.
                return (
                    Report(
                        ok: false,
                        action: action,
                        state: "unknown",
                        error: "system-extension deactivation timed out",
                        remediation: remediation
                    ),
                    .timeout
                )
        }
    }

    /// Machine-readable identity of a system-extension request failure.
    /// `domain`/`code` are the NSError values the OS delegate delivered; nil
    /// only for failures that never came from an NSError (e.g. an unknown
    /// delegate result). Downstream branching (the skew-detection gate)
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

    /// The deactivation verb's full result: the terminal request result plus
    /// any remediation hint the verb detected. The two travel together so no
    /// caller can observe the result without the hint.
    struct SystemExtensionTeardownOutcome: Equatable {
        let result: SystemExtensionDeactivationResult
        /// Non-nil iff the deactivation failed with the exact skew signature
        /// AND the extension was positively observed still activated; see
        /// extensionVersionSkewRemediation.
        let remediation: String?
    }

    /// Remediation id for the version-skew refusal: the installed app's
    /// registration no longer matches the activated extension record, so an
    /// attended re-registration (launch the app at the console so its normal
    /// activation flow re-registers, then re-run deactivation) is required.
    /// This verb only ever DETECTS the condition; it never submits an
    /// activation of any kind. Value must match the remediation ids the
    /// server-side tests pin (server/test/cli/castle-wall-headless-disarm.test.ts,
    /// server/test/cli/uninstall.test.ts).
    static let extensionVersionSkewRemediation =
        "extension_version_skew_reregister_required"

    /// Operator guidance appended to the failure message on skew detection.
    /// Describes the attended remediation only; it must never promise an
    /// automated one, because this verb performs none. Launching the app
    /// only re-registers the extension when the background signer helper is
    /// enabled; with the helper unregistered, launch first lands in an
    /// approval-gated state, so the guidance names the helper approval and
    /// the wait honestly. The remediation sentence from "launch" through
    /// "then re-run"/"then rerun" is mirrored wire text: must stay in
    /// agreement with emitSysextVersionSkewNotice in
    /// server/src/cli/castle-wall.ts and the remediation note in
    /// server/src/cli/uninstall.ts.
    static let extensionVersionSkewGuidance =
        "the installed app's registration no longer matches the activated "
        + "system extension; launch Sanctuary-CastleWall.app at the console so "
        + "its normal activation flow re-registers the extension, approve or "
        + "re-enable the Sanctuary background helper if macOS prompts for it, "
        + "wait for re-registration to complete, then re-run the deactivation"

    static func systemExtensionFailureDetail(from error: Error) -> SystemExtensionFailure {
        let nsError = error as NSError
        return SystemExtensionFailure(
            message: error.localizedDescription,
            domain: nsError.domain,
            code: nsError.code
        )
    }

    /// True only for the exact failure the skew detection is allowed to
    /// answer: OSSystemExtensionErrorDomain / extensionNotFound (code 4).
    /// Matching on the structured domain+code (never the prose message) is
    /// what keeps the hint from firing on any other failure class.
    static func isExtensionNotFoundFailure(
        _ result: SystemExtensionDeactivationResult
    ) -> Bool {
        guard case let .failed(failure) = result else { return false }
        return failure.domain == OSSystemExtensionErrorDomain
            && failure.code == OSSystemExtensionError.extensionNotFound.rawValue
    }

    /// Deactivation with version-skew DETECTION (never mutation).
    ///
    /// A host app redeployed at a newer bundle version than the activated
    /// extension record can be refused deactivation with extensionNotFound
    /// even while `systemextensionsctl list` still shows the extension
    /// activated. This verb submits deactivation ONLY. There is no automated
    /// re-registration here by design: macOS offers no cancellation API for a
    /// submitted activation and no durable resume marker, so any
    /// activate-then-deactivate sequence has failure modes that end with the
    /// extension MORE active than before the teardown started. Detection plus
    /// truthful guidance is the whole mechanism.
    ///
    /// Bounds:
    /// - The hint requires the exact error-4 failure AND a positive "still
    ///   listed activated+enabled" observation from the OS's own list output;
    ///   an unreadable, ambiguous, or negative probe merely suppresses the
    ///   hint (fail-safe in the harmless direction: no hint, never a wrong
    ///   report state).
    /// - The probe spends only what remains of the verb's declared timeout
    ///   (capped at extensionListProbeTimeoutSeconds), so detection can never
    ///   stretch the verb past the deadline its caller relied on.
    /// - The failure's error_domain/error_code stay the identity of the
    ///   deactivation attempt; detection appends guidance to the message and
    ///   never rewrites the identity.
    static func performSystemExtensionTeardown(
        timeoutSeconds: Double,
        deactivate: (Double) -> SystemExtensionDeactivationResult,
        isExtensionListedActivated: (Double) -> Bool,
        now: () -> Date = Date.init
    ) -> SystemExtensionTeardownOutcome {
        let deadline = now().addingTimeInterval(timeoutSeconds)
        let result = deactivate(timeoutSeconds)
        guard isExtensionNotFoundFailure(result),
              case let .failed(failure) = result else {
            return SystemExtensionTeardownOutcome(result: result, remediation: nil)
        }
        let probeBudget = min(
            extensionListProbeTimeoutSeconds,
            deadline.timeIntervalSince(now())
        )
        guard probeBudget > 0, isExtensionListedActivated(probeBudget) else {
            return SystemExtensionTeardownOutcome(result: result, remediation: nil)
        }
        return SystemExtensionTeardownOutcome(
            result: .failed(SystemExtensionFailure(
                message: failure.message + "; " + extensionVersionSkewGuidance,
                domain: failure.domain,
                code: failure.code
            )),
            remediation: extensionVersionSkewRemediation
        )
    }

    /// Apple Developer team id the Castle Wall extension is signed under.
    /// SignerConstants.teamID is the shared source (must stay equal to the
    /// codesign requirements in server/src/cli/castle-wall-boot-runtime.ts).
    static let systemExtensionTeamIdentifier = SignerConstants.teamID

    /// True iff `systemextensionsctl list` output contains a row whose PARSED
    /// columns positively identify our extension as activated and enabled:
    /// the bundle id in the bundleID column, our team id in the teamID column
    /// (a foreign-team extension may reuse the bundle id, so a substring hit
    /// anywhere on the line proves nothing), and a single-bracket state field
    /// whose whitespace-separated tokens include exactly "activated" and
    /// "enabled" as whole tokens. Anything unparseable,
    /// localized, or ambiguous reads as NOT-listed, which under this design
    /// merely suppresses the skew remediation hint - never a wrong claim.
    /// Column layout follows the observed header
    /// `enabled\tactive\tteamID\tbundleID (version)\tname\t[state]`
    /// (tab-separated; Mini1 capture).
    static func isExtensionListedActivatedEnabled(
        inListOutput output: String,
        identifier: String = systemExtensionIdentifier,
        teamID: String = systemExtensionTeamIdentifier
    ) -> Bool {
        output.split(separator: "\n").contains { line in
            let fields = line.split(
                separator: "\t",
                omittingEmptySubsequences: false
            ).map { $0.trimmingCharacters(in: .whitespaces) }
            // 6 = the columns of the observed header row (enabled, active,
            // teamID, bundleID (version), name, [state]); fewer means a
            // banner/header/unknown row and reads as NOT-listed.
            guard fields.count >= 6 else { return false }
            guard fields[2] == teamID else { return false }
            // The bundleID column is `<id> (<versions>)`; the id must be the
            // exact first token, not a substring of a longer identifier.
            guard fields[3].split(separator: " ").first.map(String.init)
                == identifier else { return false }
            // The state field must be exactly one bracketed group with
            // nothing outside it; trailing text after `]` (or a second
            // bracket) makes the row unparseable and reads as NOT-listed.
            guard let state = fields.last, state.hasPrefix("["),
                  state.hasSuffix("]"), state.count >= 2 else {
                return false
            }
            let interior = state.dropFirst().dropLast()
            guard !interior.contains("["), !interior.contains("]") else {
                return false
            }
            // Exact-token match: substring matching accepts the deactivated
            // state, because "deactivated" contains "activated". Both words
            // must appear as whole whitespace-separated tokens. (Must stay in
            // agreement with the column/state binding of
            // parseActivatedCastleWallBundleVersions in
            // server/src/cli/castle-wall.ts.)
            let tokens = Set(
                interior.split(whereSeparator: { $0 == " " || $0 == "\t" })
                    .map(String.init)
            )
            // Both required tokens must be present, and every token must be
            // a known-benign state word: an unknown or contradictory token
            // (e.g. "activated enabled deactivated") is ambiguous, and
            // ambiguity must read NOT-listed, never as a positive
            // observation. Allowlist, not a contradiction denylist, so the
            // unknown case fails safe. (Must stay in agreement with
            // KNOWN_STATE_TOKENS in parseActivatedCastleWallBundleVersions,
            // server/src/cli/castle-wall.ts.)
            let knownStateTokens: Set<String> = [
                "activated", "enabled", "waiting", "for", "user",
            ]
            guard tokens.contains("activated"), tokens.contains("enabled"),
                  tokens.isSubset(of: knownStateTokens) else {
                return false
            }
            return true
        }
    }

    /// Production presence probe behind the skew-detection gate. Fail-safe:
    /// any probe failure (spawn error, timeout, nonzero exit, undecodable
    /// output) reads as NOT listed, which suppresses the remediation hint - a
    /// diagnostic failure must never manufacture a positive observation.
    private static func defaultExtensionListedActivated(
        timeoutSeconds: Double
    ) -> Bool {
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
        let deadline = Date().addingTimeInterval(timeoutSeconds)
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
        return isExtensionListedActivatedEnabled(inListOutput: text)
    }

    private static func runSystemExtensionTeardown(
        timeoutSeconds: Double
    ) -> SystemExtensionTeardownOutcome {
        performSystemExtensionTeardown(
            timeoutSeconds: timeoutSeconds,
            deactivate: { seconds in
                // OSSystemExtensionRequest.delegate is weak, so the runner
                // stays alive for the entire bounded run-loop wait.
                let runner = HeadlessSystemExtensionRequestRunner()
                return runner.run(timeoutSeconds: seconds)
            },
            isExtensionListedActivated: defaultExtensionListedActivated
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
/// DEACTIVATION request - the only request kind the headless teardown verb
/// ever submits (the activation path lives solely in the GUI app's
/// SystemExtensionManager, where the operator is present to answer prompts).
/// Node cannot own these requests: macOS binds them to the app identity that
/// owns the bundled system extension.
private final class HeadlessSystemExtensionRequestRunner: NSObject,
    OSSystemExtensionRequestDelegate
{
    private let lock = NSLock()
    private var result: HeadlessFilterCLI.SystemExtensionDeactivationResult?
    private var approvalNeeded = false

    func run(timeoutSeconds: Double) -> HeadlessFilterCLI.SystemExtensionDeactivationResult {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: HeadlessFilterCLI.systemExtensionIdentifier,
            queue: .main
        )
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

    private func storeResult(_ value: HeadlessFilterCLI.SystemExtensionDeactivationResult) {
        lock.lock()
        result = value
        lock.unlock()
    }

    private func loadResult() -> HeadlessFilterCLI.SystemExtensionDeactivationResult? {
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
            storeResult(.deactivated)
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
        // skew-detection gate and the CLI's report consumers branch on the
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
        // Required by OSSystemExtensionRequestDelegate but never consulted for
        // a deactivation request (this runner submits nothing else). Answer
        // .replace, the same policy as SystemExtensionManager.replacementAction,
        // so the two delegates cannot diverge if macOS ever consults it.
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
