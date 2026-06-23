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

    /// What the operator's posture surface should show, derived from the raw
    /// `ServerStatus` plus whether we have a last-known snapshot to orient them
    /// with. This is the three-honest-states model (Slice 1a design §3.1):
    ///
    ///   - `.live`          server reachable + fresh read -> embedded board.
    ///   - `.reconnecting`  server WAS reachable, now failing probes, still
    ///                      inside the bounded recovery budget. We have a
    ///                      last-known posture to show DIMMED + timestamped +
    ///                      banner-marked "reconnecting" so the operator stays
    ///                      oriented while recovery is attempted. NEVER green
    ///                      (the badge falls to `.unknown` independently).
    ///   - `.unreachable`   genuinely down: cold start with no successful probe
    ///                      yet (no snapshot to show), OR a previously-reachable
    ///                      server that has stayed down past the recovery budget
    ///                      with no progress. Shows the native down-screen.
    ///
    /// Honest by construction: `.reconnecting` is reachable ONLY when we actually
    /// have a last-known frame to dim (`hasLastKnownPosture`). Cold start (never
    /// reachable) can never enter `.reconnecting`; it falls straight to the
    /// native empty-state, preserving today's correct cold-start behavior.
    enum PostureSurfaceState: Equatable {
        case live
        case reconnecting
        case unreachable
    }

    @Published private(set) var serverStatus: ServerStatus = .unknown

    /// Enforcement-evidenced arm state, mirroring the server's
    /// `CastleWallArmState` (`server/src/principal-policy/posture.ts`). This is
    /// the ONE source of truth for "is protection actually enforcing." It is
    /// derived on the server from fresh, producer-signature-re-verified
    /// enforcement evidence — never from "policy loaded" or "filter toggled on."
    /// The native badge adopts this so it can never disagree with the web board
    /// on green (Dashboard one-surface spec, Piece B; Delta Review line 132).
    enum WallArmState: String, Equatable {
        case armed
        case degraded
        case unknown
        case notInstalled = "not_installed"

        /// Decode tolerantly: any unrecognized/missing value falls CLOSED to
        /// `.unknown` (never to a green `.armed`), preserving never-fake-green.
        init(serverValue: String?) {
            switch serverValue {
            case "armed": self = .armed
            case "degraded": self = .degraded
            case "not_installed": self = .notInstalled
            default: self = .unknown
            }
        }
    }

    /// The cryptographic basis the server says an armed green rests on, mirroring
    /// the server's `producer_authenticity` (`server/src/principal-policy/posture.ts`).
    /// The native badge reads this so its tooltip can word the basis HONESTLY and
    /// match the web board (`posture-home-html.ts` `renderWall`) instead of
    /// asserting "signed" on the macOS channel-authenticated floor, where no
    /// per-producer signature is available (H3 second-source honesty; F1 thesis
    /// gate). Never decode this into an overclaim: an unknown/missing value falls
    /// CLOSED to `.notApplicable`, so the badge defaults to NOT claiming a
    /// producer signature.
    enum ProducerAuthenticity: String, Equatable {
        case producerSigned = "producer_signed"
        case channelAuthenticated = "channel_authenticated"
        case notApplicable = "not_applicable"

        init(serverValue: String?) {
            switch serverValue {
            case "producer_signed": self = .producerSigned
            case "channel_authenticated": self = .channelAuthenticated
            default: self = .notApplicable
            }
        }
    }

    @Published private(set) var sanctuaryPath: String?

    /// Latest enforcement-evidenced arm state from `/api/posture/castle-wall`.
    /// `nil` until the first successful read; `.unknown` once read but not
    /// evidenced. The badge treats both nil and `.unknown` as non-green.
    @Published private(set) var wallArmState: WallArmState?

    /// The cryptographic basis the latest armed read rests on, read from the same
    /// `/api/posture/castle-wall` payload. `nil` until the first successful read.
    /// Used ONLY to word the armed-state tooltip honestly (producer-signed vs the
    /// channel-authenticated macOS floor); it never affects the green/red
    /// determination, which is `wallArmState` alone.
    @Published private(set) var producerAuthenticity: ProducerAuthenticity?

    /// Timestamp of the most recent CONFIRMED-reachable health probe. `nil` until
    /// the server is reached for the first time (cold start). Drives the honest
    /// "as of HH:MM:SS, reconnecting..." banner in the Reconnecting state: it is
    /// the moment we last saw the server alive, NOT the current time, so the
    /// operator knows exactly how stale the dimmed last-known frame is. Reset
    /// every time a reachable probe lands (so it always reflects the latest live
    /// contact, never an older one).
    @Published private(set) var lastReachableAt: Date?

    /// Whether the server has EVER been confirmed reachable in this app session.
    /// This is the honesty gate that keeps cold start from ever rendering a
    /// stale-posture frame: only once we have actually loaded the board (so there
    /// is a real last-known frame behind the dimming) can the surface enter
    /// `.reconnecting`. Before the first successful probe it stays false, so the
    /// surface falls to the native empty-state, not a fabricated stale view.
    @Published private(set) var hasLastKnownPosture: Bool = false

    /// The operator-facing surface state, recomputed on every health probe from
    /// the raw `serverStatus`, the failure count, and `hasLastKnownPosture`. The
    /// view layer reads THIS (not raw `serverStatus`) to choose between the live
    /// board, the dimmed reconnecting frame, and the native down-screen. See
    /// `Self.postureSurfaceState`.
    @Published private(set) var surfaceState: PostureSurfaceState = .unreachable

    private let dashboardPort: Int = 3501

    /// Monotonic generation tokens for the two async polls. Because each poll
    /// `await`s a network call before publishing, a slow earlier request can
    /// finish AFTER a newer one and clobber it with a stale value. Each call
    /// claims the next token and only commits its result if it is still the
    /// latest in-flight request for that poll. All reads/writes happen on the
    /// main actor (the methods are `@MainActor`), so the counters need no extra
    /// locking.
    @MainActor private var healthGeneration: UInt64 = 0
    @MainActor private var armStateGeneration: UInt64 = 0

    /// Consecutive failed/timed-out health probes since the server was last seen
    /// `.reachable`. The 5s poll uses a short 2s timeout with no smoothing, so a
    /// SINGLE transient loopback hiccup (or a >2s response under load) would
    /// otherwise flip `serverStatus` to `.unreachable`. When the server has been
    /// reachable, that flip tears down the embedded `PostureWebView` and the next
    /// successful poll rebuilds a fresh one that reloads from the home URL —
    /// snapping the operator's in-board navigation (drill-downs, filters, scroll)
    /// back to home. We require `unreachableHysteresisThreshold` consecutive
    /// failures before declaring a previously-reachable server `.unreachable`, so
    /// one blip is absorbed. Reset to 0 on any reachable probe. See
    /// `nextServerStatus`.
    @MainActor private var consecutiveHealthFailures: Int = 0

    /// Number of consecutive failed probes required to flip a server that was
    /// `.reachable` to `.unreachable`. Two probes at the 5s cadence means a real
    /// outage still surfaces in ~5-10s, while a single-tick blip is absorbed.
    static let unreachableHysteresisThreshold = 2

    /// The bounded recovery budget, in consecutive failed probes since the server
    /// was last reachable, during which a previously-reachable server shows the
    /// honest Reconnecting state (dimmed last-known posture + "reconnecting..."
    /// banner) instead of the bare down-screen. Once failures reach this budget
    /// with no successful probe, the surface falls to `.unreachable` (the native
    /// down-screen): we have given recovery a fair window and it did not arrive,
    /// so continuing to show a "reconnecting" promise would be dishonest.
    ///
    /// At the 5s poll cadence, 6 failures is roughly a 30s recovery window. This
    /// is deliberately generous: Slice 1a has no restart producer signal yet
    /// (`/api/health.instance`/`since` is Slice 1b), so the budget is the only
    /// thing distinguishing "transient, likely coming back" from "genuinely
    /// down." A user-driven manual restart (the "Start Sanctuary server" button)
    /// is still available from the down-screen if recovery never arrives.
    static let recoveryBudgetFailures = 6

    init() {
        // Resolve the CLI OFF the calling thread. Resolution probes candidate
        // paths and may spawn a login shell (`resolveViaLoginShell` ->
        // `Process.waitUntilExit`), which pumps a nested run loop. Doing that
        // synchronously here is fatal (#596): SwiftUI constructs this
        // @StateObject DURING AttributeGraph evaluation (window restoration at
        // login), so a nested main-thread run loop delivers a queued
        // screen-parameters notification that re-enters AttributeGraph
        // mid-update -> AG precondition abort (the crash had zero app frames,
        // entirely inside SwiftUI's implicit screen-params delegate). Resolving
        // on a background queue keeps init non-blocking, so no run loop is
        // pumped on the main thread during view construction.
        resolveSanctuaryBinaryAsync()
    }

    // MARK: - Binary resolution

    /// Resolve the `sanctuary` CLI off the main thread, then publish the result
    /// on the main actor. Unlike `resolveSanctuaryBinary()` this never blocks or
    /// pumps a run loop on the calling thread, so it is safe to invoke during
    /// SwiftUI view construction (see `init`, #596 boot/login crash).
    func resolveSanctuaryBinaryAsync() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let resolved = Self.resolveSanctuaryBinary(
                candidates: Self.candidateSanctuaryPaths(),
                isValidBinary: Self.isOwnerTrustedExecutable
            )
            DispatchQueue.main.async {
                self?.sanctuaryPath = resolved
            }
        }
    }

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
        healthGeneration &+= 1
        let generation = healthGeneration

        let url = URL(string: "http://127.0.0.1:\(dashboardPort)/api/health")!
        var request = URLRequest(url: url)
        request.timeoutInterval = 2.0

        let probeReachable: Bool
        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            if let http = response as? HTTPURLResponse,
               (200...499).contains(http.statusCode) {
                // Any HTTP response (including 401 unauthorized) means the server is up
                probeReachable = true
            } else {
                probeReachable = false
            }
        } catch {
            probeReachable = false
        }

        // Commit only if no newer health probe started while we were awaiting,
        // so a slow stale response cannot overwrite a fresher result.
        guard generation == healthGeneration else { return }

        // Apply failure hysteresis so a single transient probe blip does not flip
        // a previously-reachable server to `.unreachable` and tear down the
        // embedded board (which would lose the operator's in-board navigation).
        let transition = Self.nextServerStatus(
            current: serverStatus,
            probeReachable: probeReachable,
            consecutiveFailures: consecutiveHealthFailures,
            threshold: Self.unreachableHysteresisThreshold
        )
        consecutiveHealthFailures = transition.consecutiveFailures
        serverStatus = transition.status

        // On a confirmed-reachable probe, record that we now have a real
        // last-known frame to dim during a future outage, and stamp the moment we
        // last saw the server alive (the "as of HH:MM:SS" the banner shows). Only
        // a genuine reachable probe sets these, so cold start (never reachable)
        // can never present a fabricated stale frame.
        if probeReachable {
            hasLastKnownPosture = true
            lastReachableAt = Date()
        }

        // Recompute the operator-facing surface state. The view reads THIS to
        // choose live board / dimmed reconnecting frame / native down-screen, so
        // the three-state honesty model lives in one tested place.
        surfaceState = Self.postureSurfaceState(
            status: serverStatus,
            consecutiveFailures: consecutiveHealthFailures,
            hasLastKnownPosture: hasLastKnownPosture,
            recoveryBudget: Self.recoveryBudgetFailures
        )
    }

    /// Pure derivation of the operator-facing surface state (Slice 1a §3.1),
    /// factored out so the three-state honesty model is unit-testable without a
    /// network or a view.
    ///
    /// Rules (honesty is the whole point):
    ///   - `.reachable`                                  -> `.live`.
    ///   - failing, but we HAVE a last-known frame AND failures are still inside
    ///     the recovery budget                            -> `.reconnecting`
    ///     (show the dimmed, timestamped last-known board + "reconnecting..."
    ///     banner; the badge falls to `.unknown` independently).
    ///   - failing with NO last-known frame (cold start)  -> `.unreachable`
    ///     (native empty-state; never a fabricated stale frame).
    ///   - failing past the recovery budget               -> `.unreachable`
    ///     (recovery was given a fair window and did not arrive; the
    ///     "reconnecting" promise would now be dishonest).
    ///   - `.unknown` (cold start, below hysteresis)       -> `.unreachable`
    ///     surface, which the caller renders as the native empty-state. (There is
    ///     nothing live to show yet, and we never invent a stale frame.)
    ///
    /// `recoveryBudget` is clamped to at least 1 so the function terminates for
    /// any caller-supplied value.
    static func postureSurfaceState(
        status: ServerStatus,
        consecutiveFailures: Int,
        hasLastKnownPosture: Bool,
        recoveryBudget: Int
    ) -> PostureSurfaceState {
        if status == .reachable {
            return .live
        }
        // Not reachable. Only a server we have actually seen alive can show the
        // honest "reconnecting" frame, and only inside the bounded budget.
        let budget = max(1, recoveryBudget)
        if hasLastKnownPosture && consecutiveFailures < budget {
            return .reconnecting
        }
        return .unreachable
    }

    /// Pure server-status transition with failure hysteresis. Factored out so the
    /// (otherwise async, network-bound) behavior is unit-testable.
    ///
    /// Rules:
    ///   - A reachable probe is authoritative immediately: `.reachable`, failure
    ///     count reset to 0 (recovery is never delayed).
    ///   - A failed probe increments the failure count. The server only flips to
    ///     `.unreachable` once `consecutiveFailures` (post-increment) reaches
    ///     `threshold`, so a single blip while `.reachable` is absorbed (the
    ///     status stays `.reachable`, the embedded board is NOT torn down).
    ///   - Cold start is preserved: from `.unknown`, a single failure does NOT
    ///     report `.reachable` — the status only becomes `.reachable` on a real
    ///     reachable probe. Until then it stays `.unknown` (the caller keeps the
    ///     native empty-state, never a connection-refused page) and flips to
    ///     `.unreachable` once the threshold of failures is met.
    ///
    /// `threshold` is clamped to at least 1 so the function is well-defined for
    /// any caller-supplied value.
    static func nextServerStatus(
        current: ServerStatus,
        probeReachable: Bool,
        consecutiveFailures: Int,
        threshold: Int
    ) -> (status: ServerStatus, consecutiveFailures: Int) {
        if probeReachable {
            return (.reachable, 0)
        }
        let effectiveThreshold = max(1, threshold)
        let failures = consecutiveFailures + 1
        if failures >= effectiveThreshold {
            return (.unreachable, failures)
        }
        // Below threshold: hold the current status (absorb the blip). For
        // `.reachable` this keeps the embedded board mounted; for `.unknown`
        // (cold start) this keeps the native empty-state without prematurely
        // declaring the server down.
        return (current, failures)
    }

    // MARK: - Castle Wall arm-state (single source of truth)

    /// Read the enforcement-evidenced arm state from `/api/posture/castle-wall`
    /// — NOT `/api/health` (whose `castle_wall` field is still a `"unknown"`
    /// placeholder, Delta Review A3). This is the evidence-gated source the web
    /// board already uses; adopting it here gives the native badge and the
    /// embedded board ONE shared determination of green (Piece B).
    ///
    /// Loads over loopback auto-auth (no token in the URL). On any failure the
    /// arm state falls CLOSED to `.unknown` rather than leaving a stale green.
    @MainActor
    func refreshWallArmState() async {
        armStateGeneration &+= 1
        let generation = armStateGeneration

        let url = URL(string: "http://127.0.0.1:\(dashboardPort)/api/posture/castle-wall")!
        var request = URLRequest(url: url)
        request.timeoutInterval = 2.0

        let resolved: WallArmState
        let resolvedAuthenticity: ProducerAuthenticity
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                resolved = WallArmState(serverValue: Self.decodeArmState(from: data))
                resolvedAuthenticity = ProducerAuthenticity(
                    serverValue: Self.decodeProducerAuthenticity(from: data)
                )
            } else {
                resolved = .unknown
                resolvedAuthenticity = .notApplicable
            }
        } catch {
            // Unreachable / parse error: fail closed to unknown (never green).
            resolved = .unknown
            resolvedAuthenticity = .notApplicable
        }

        // Commit only if no newer arm-state refresh started while we were
        // awaiting, so an out-of-order slow response cannot momentarily write a
        // stale value over a fresher one. Commit both fields together so the
        // tooltip's authenticity basis never drifts from the arm state.
        guard generation == armStateGeneration else { return }
        wallArmState = resolved
        producerAuthenticity = resolvedAuthenticity
    }

    /// Pull the `arm_state` string out of the `/api/posture/castle-wall` JSON.
    /// Returns nil if the field is absent so the caller falls closed to unknown.
    static func decodeArmState(from data: Data) -> String? {
        guard
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return nil
        }
        return obj["arm_state"] as? String
    }

    /// Pull the `producer_authenticity` string out of the same payload. Returns
    /// nil if absent so the caller falls closed to `.notApplicable` (no claimed
    /// producer signature). Used only to word the armed tooltip honestly.
    static func decodeProducerAuthenticity(from data: Data) -> String? {
        guard
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return nil
        }
        return obj["producer_authenticity"] as? String
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
}
