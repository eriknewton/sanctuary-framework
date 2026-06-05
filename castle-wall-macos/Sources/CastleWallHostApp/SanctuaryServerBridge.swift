import Foundation

/// Bridge between the host app and the `sanctuary` CLI / server.
/// All agent protection actions delegate to `sanctuary wrap`; the host
/// app never directly kills or relaunches processes.
final class SanctuaryServerBridge: ObservableObject {
    enum ServerStatus: Equatable {
        case unknown
        case reachable
        case unreachable
    }

    @Published private(set) var serverStatus: ServerStatus = .unknown
    @Published private(set) var sanctuaryPath: String?

    private let dashboardPort: Int = 3501

    init() {
        resolveSanctuaryBinary()
    }

    // MARK: - Binary resolution

    /// Resolve the `sanctuary` CLI binary.
    ///
    /// A Finder- or `open`-launched app does NOT inherit the login shell PATH
    /// (it gets a bare `/usr/bin:/bin:/usr/sbin:/sbin`), so the old
    /// `/usr/bin/which sanctuary` found nothing and the whole host app —
    /// Protect, status, audit viewer — went inert when launched normally
    /// (Finding C, A1 drill 2026-06-04). Probe the common npm/Homebrew install
    /// locations directly, then fall back to asking the user's login shell to
    /// resolve it (handles nvm / a custom `npm prefix`). Every candidate is
    /// ownership-validated to prevent PATH hijacking.
    func resolveSanctuaryBinary() {
        sanctuaryPath = Self.resolveSanctuaryBinary(
            candidates: Self.candidateSanctuaryPaths(),
            isValidBinary: Self.isOwnerTrustedExecutable
        )
    }

    /// Pure selection: the first candidate that passes `isValidBinary`.
    /// Factored out so the priority ordering can be tested without touching the
    /// filesystem or spawning a shell.
    static func resolveSanctuaryBinary(
        candidates: [String],
        isValidBinary: (String) -> Bool
    ) -> String? {
        for candidate in candidates where isValidBinary(candidate) {
            return candidate
        }
        return nil
    }

    /// Candidate locations for the `sanctuary` CLI, highest priority first: the
    /// common npm/Homebrew install dirs (no subprocess), then whatever the
    /// user's login shell resolves.
    static func candidateSanctuaryPaths() -> [String] {
        let home = NSHomeDirectory()
        var candidates = [
            "\(home)/.npm-global/bin/sanctuary",
            "/opt/homebrew/bin/sanctuary",
            "/usr/local/bin/sanctuary",
            "\(home)/.local/bin/sanctuary",
        ]
        if let viaShell = resolveViaLoginShell() {
            candidates.append(viaShell)
        }
        return candidates
    }

    /// Ask the user's login shell to resolve `sanctuary` from its full PATH
    /// (`$SHELL -lc 'command -v sanctuary'`). Returns nil on any failure. This
    /// runs the user's own shell rc, exactly as a terminal would.
    static func resolveViaLoginShell() -> String? {
        let shell = ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/zsh"
        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: shell)
        process.arguments = ["-l", "-c", "command -v sanctuary"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }

        guard process.terminationStatus == 0 else { return nil }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let path = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
            !path.isEmpty else {
            return nil
        }
        return path
    }

    /// True iff `path` is an existing regular file owned by root or the current
    /// user. The ownership gate prevents PATH hijacking via a binary an
    /// attacker dropped in a world-writable directory.
    static func isOwnerTrustedExecutable(_ path: String) -> Bool {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir), !isDir.boolValue else {
            return false
        }
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let ownerUID = attrs[.ownerAccountID] as? NSNumber else {
            return false
        }
        let currentUID = getuid()
        return ownerUID.uint32Value == 0 || ownerUID.uint32Value == currentUID
    }

    // MARK: - Server health check

    @MainActor
    func checkServerHealth() async {
        let url = URL(string: "http://127.0.0.1:\(dashboardPort)/api/health")!
        var request = URLRequest(url: url)
        request.timeoutInterval = 2.0

        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            if let http = response as? HTTPURLResponse,
               (200...499).contains(http.statusCode) {
                // Any HTTP response (including 401 unauthorized) means the server is up
                serverStatus = .reachable
            } else {
                serverStatus = .unreachable
            }
        } catch {
            serverStatus = .unreachable
        }
    }

    // MARK: - Protect / Unprotect

    enum ProtectResult {
        case success
        case serverUnreachable
        case sanctuaryNotFound
        case failed(String)
    }

    func protect(harnessFlag: String) async -> ProtectResult {
        guard let path = sanctuaryPath else {
            return .sanctuaryNotFound
        }

        // `sanctuary wrap` is a long-running process (it IS the server).
        // Launch it in the background and wait briefly to confirm it started.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["wrap", harnessFlag, "--no-open"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return .failed(error.localizedDescription)
        }

        // Give it a moment to start, then check if it's still alive
        // (immediate crash = failure; still running = success)
        try? await Task.sleep(nanoseconds: 2_000_000_000)

        if process.isRunning {
            return .success
        } else if process.terminationStatus == 0 {
            return .success
        } else {
            return .failed("sanctuary wrap exited with code \(process.terminationStatus)")
        }
    }

    func unprotect(harnessFlag: String) async -> ProtectResult {
        guard let path = sanctuaryPath else {
            return .sanctuaryNotFound
        }

        let pipe = Pipe()
        let errPipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["wrap", harnessFlag, "--unwrap"]
        process.standardOutput = pipe
        process.standardError = errPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return .failed(error.localizedDescription)
        }

        if process.terminationStatus == 0 {
            return .success
        }

        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        let errMsg = String(data: errData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? "Unknown error"
        return .failed(errMsg)
    }

    // MARK: - Start server

    func startServer() async -> Bool {
        guard let path = sanctuaryPath else { return false }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["--dashboard"]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            // Don't wait -- server runs in background
            return true
        } catch {
            return false
        }
    }

    // MARK: - Audit log

    func fetchAuditLog(limit: Int = 50) async -> [AuditEvent] {
        let url = URL(string: "http://127.0.0.1:\(dashboardPort)/api/audit-log?limit=\(limit)")!
        var request = URLRequest(url: url)
        request.timeoutInterval = 3.0

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return []
            }
            return (try? JSONDecoder().decode([AuditEvent].self, from: data)) ?? []
        } catch {
            return []
        }
    }
}

// MARK: - Audit event model

struct AuditEvent: Identifiable, Decodable {
    let id: String
    let type: String
    let agent: String?
    let destination: String?
    let decision: String?
    let timestamp: String
    let details: String?

    /// Plain-English translation of the event.
    var plainEnglish: String {
        switch type {
        case "egress_blocked":
            let who = agent ?? "An agent"
            let where_ = destination ?? "an unknown host"
            return "\(who) tried to connect to \(where_). Blocked."
        case "egress_allowed":
            let who = agent ?? "An agent"
            let where_ = destination ?? "an unknown host"
            return "\(who) connected to \(where_). Allowed."
        case "filter_started":
            return "Protection activated."
        case "filter_stopped":
            return "Protection paused."
        case "operator_decision":
            let who = agent ?? "an agent"
            let where_ = destination ?? "a host"
            return "You allowed \(who) to access \(where_)."
        case "policy_loaded":
            return "Security policy loaded."
        case "manifest_updated":
            return "Agent protection rules updated."
        case "ipc_connected":
            return "Connected to Sanctuary server."
        case "ipc_disconnected":
            return "Lost connection to Sanctuary server."
        case "handshake_completed":
            return "Secure handshake completed."
        case "handshake_failed":
            return "Secure handshake failed."
        case "key_provisioned":
            return "Security key provisioned."
        case "flow_pending_approval":
            let who = agent ?? "An agent"
            let where_ = destination ?? "a host"
            return "\(who) wants to access \(where_). Waiting for your decision."
        default:
            return details ?? "Event: \(type)"
        }
    }

    /// Color category for the event.
    enum EventColor {
        case red, green, yellow, neutral
    }

    var color: EventColor {
        switch type {
        case "egress_blocked", "handshake_failed", "ipc_disconnected":
            return .red
        case "egress_allowed", "filter_started", "handshake_completed", "ipc_connected":
            return .green
        case "operator_decision", "flow_pending_approval":
            return .yellow
        default:
            return .neutral
        }
    }
}
