import Foundation
import NetworkExtension

/// Headless driver for the Castle Wall content-filter configuration.
///
/// Invoked as `Sanctuary-CastleWall.app/Contents/MacOS/CastleWallHostApp
/// --headless <enable|disable|status>` (typically by `sanctuary castle-wall
/// enable|disable` over SSH). Running the HOST APP BINARY itself is the load-
/// bearing design point: the NE content-filter configuration is owned by the
/// signed app identity that created it, so only this binary can toggle
/// `NEFilterManager.isEnabled` without re-triggering the one-time user
/// consent. A separate helper would need its own restricted-entitlement
/// provisioning profile AND would prompt again; IPC to the GUI app would
/// require a console session — exactly what a headless operator lacks.
///
/// This path never touches SwiftUI/AppKit, so it needs no WindowServer and
/// works from an SSH session. The ONE thing it cannot do is grant the initial
/// content-filter consent (`needsUserApproval` → exit 3): macOS requires a
/// console click for that, once per install.
enum HeadlessFilterCLI {
    static let headlessFlag = "--headless"
    static let headlessContractVersion = "2"
    private static let defaultTimeoutSeconds = 30.0

    enum Action: String {
        case enable
        case disable
        case status
    }

    struct Invocation: Equatable {
        let action: Action
        let timeoutSeconds: Double
        let ttlSeconds: UInt32?
        let noTTL: Bool
        /// When set, the JSON report is ALSO written here (in addition to
        /// stdout). `sanctuary castle-wall enable|disable` launches this binary
        /// through `open` on macOS Tahoe — the only way to reach NE preferences
        /// there — but `open` does not relay the child's stdout, so the CLI
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
        /// "enabled" | "disabled" | "needs_user_approval" | "unknown"
        let state: String
        let error: String?
        let build: Build

        init(
            ok: Bool,
            action: String,
            state: String,
            error: String?,
            build: Build = .current()
        ) {
            self.ok = ok
            self.action = action
            self.state = state
            self.error = error
            self.build = build
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
                "usage: \(headlessFlag) <enable|disable|status> "
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
        }
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

    private enum SyncResult {
        case completed(Error?)
        case timedOut
    }

    /// Block the calling thread on an NEFilterManager completion handler.
    /// Safe here because headless mode runs no main run loop the callback
    /// could depend on (NE completion handlers arrive on an internal queue).
    private static func waitFor(
        _ timeoutSeconds: Double,
        _ body: (@escaping (Error?) -> Void) -> Void
    ) -> SyncResult {
        let semaphore = DispatchSemaphore(value: 0)
        let captured = LockedErrorBox()
        body { error in
            captured.store(error)
            semaphore.signal()
        }
        switch semaphore.wait(timeout: .now() + timeoutSeconds) {
        case .success:
            return .completed(captured.load())
        case .timedOut:
            return .timedOut
        }
    }
}

/// Minimal lock-guarded box so the completion-handler write and the post-wait
/// read are formally synchronized (the semaphore already orders them, but the
/// box keeps the Sendable checker satisfied without @unchecked on CLI state).
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
