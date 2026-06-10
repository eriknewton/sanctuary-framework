//
// SignerHelperManager.swift
//
// Host-app side of the A2/B2 root signer helper: register it as an SMAppService
// LaunchDaemon (one "Allow background item" approval in System Settings, the
// same pattern Little Snitch / Tailscale use), report its status, and gate the
// wall's auto-arm behind "helper enabled + pin present."
//
// SMAppService is macOS 13+ — exactly why the package floor is 13. The privileged
// register/approve path is console-only (not exercised in CI); the pure status
// mapping + the auto-arm precondition are unit-tested.
//

import Combine
import Foundation
import os
import ServiceManagement
import CastleWallSigner

final class SignerHelperManager: ObservableObject {
    enum HelperState: Equatable {
        case unknown
        case notRegistered
        case registering
        case requiresApproval
        case enabled
        case notFound
        case error(String)

        var description: String {
            switch self {
            case .unknown: return "Unknown"
            case .notRegistered: return "Not registered"
            case .registering: return "Finishing registration"
            case .requiresApproval: return "Waiting for approval in System Settings"
            case .enabled: return "Enabled"
            case .notFound: return "Not found"
            case let .error(message): return "Error: \(message)"
            }
        }
    }

    /// Filename of the bundled LaunchDaemon plist (Contents/Library/LaunchDaemons/).
    static let plistName = "\(SignerConstants.signerHelperIdentifier).plist"

    private let log = Logger(
        subsystem: SignerConstants.signerHelperIdentifier,
        category: "SignerHelperManager"
    )

    @Published var helperState: HelperState = .unknown

    /// True once `register()` has been attempted this launch. Lets the UI
    /// distinguish "haven't tried yet" from "tried and BTM still did not take
    /// it" — the latter needs an explicit retry/approve affordance (F-UX-1),
    /// not an EmptyView.
    @Published private(set) var hasAttemptedRegister = false

    /// The in-flight post-register settle loop (F-UX-1). Cancelled and
    /// replaced on every `register()`/`unregister()`.
    private var settleTask: Task<Void, Never>?

    /// True iff the root-owned trust-anchor pin exists on disk.
    var pinPresent: Bool {
        FileManager.default.fileExists(atPath: SignerConstants.pinnedPublicKeyPath)
    }

    /// The auto-arm precondition: only arm once the helper can sign AND the pin
    /// is in place. Pure so it is unit-testable.
    static func shouldAutoArm(helperEnabled: Bool, pinPresent: Bool) -> Bool {
        helperEnabled && pinPresent
    }

    var isReady: Bool {
        SignerHelperManager.shouldAutoArm(
            helperEnabled: helperState == .enabled,
            pinPresent: pinPresent
        )
    }

    /// The "Protection Active" green-state decision: the helper must be able to
    /// sign (ready) AND the sysext must be activated AND the content filter
    /// enabled. The filter toggle alone is NOT enough — without the helper + pin
    /// the wall has no trust anchor to verify policies against. Pure for testing.
    static func isProtectionActive(
        isReady: Bool,
        sysextActivated: Bool,
        filterEnabled: Bool
    ) -> Bool {
        isReady && sysextActivated && filterEnabled
    }

    /// Map an SMAppService status to our state. Pure for testing.
    static func map(_ status: SMAppService.Status) -> HelperState {
        switch status {
        case .notRegistered: return .notRegistered
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .notFound
        @unknown default: return .error("Unknown SMAppService status")
        }
    }

    /// Decide the post-register state from the register outcome (an optional
    /// thrown error) plus the service status read immediately afterwards.
    ///
    /// The status is the source of truth: `SMAppService.daemon(...).register()`
    /// *always* throws `SMAppServiceErrorDomain Code=1 "Operation not permitted"`
    /// on a daemon's first run — this is Apple-documented and benign. The helper
    /// is in fact registered into BTM in a `requiresApproval` state, awaiting the
    /// operator's one-time "Allow in the Background" approval. So a throw paired
    /// with a `.requiresApproval`/`.enabled` status is a SUCCESS, not an error.
    /// Only a status that never advanced past `.notRegistered` (with a throw) is a
    /// genuine failure worth surfacing as `.error`. Pure for testing.
    static func stateAfterRegister(error: Error?, status: SMAppService.Status) -> HelperState {
        switch status {
        case .requiresApproval: return .requiresApproval
        case .enabled: return .enabled
        case .notFound: return .notFound
        case .notRegistered:
            // register() did not land the helper in BTM at all. If it threw, that
            // throw is the real (non-benign) failure; surface it.
            if let error = error {
                return .error(error.localizedDescription)
            }
            return .notRegistered
        @unknown default:
            if let error = error {
                return .error(error.localizedDescription)
            }
            return .error("Unknown SMAppService status")
        }
    }

    // MARK: - Post-register settle loop (F-UX-1)

    /// How many times to re-poll `service.status` after `register()` before
    /// settling on whatever BTM reports. 10 × 300ms ≈ 3s — comfortably covers
    /// the observed BTM transition window without leaving the operator staring
    /// at a spinner.
    static let postRegisterMaxAttempts = 10

    /// Delay between post-register status polls.
    static let postRegisterPollInterval: UInt64 = 300_000_000 // 300ms

    /// Whether the post-register settle loop should keep polling. The re-drill
    /// (F-UX-1) showed BTM may take a moment to move a freshly-registered
    /// daemon from `.notRegistered` to `.requiresApproval`; a single
    /// synchronous read races that transition, the state settles wrong, and
    /// the approval banner never renders. Keep polling while the status is
    /// still pre-transition (`.notRegistered`/`.notFound`) and attempts
    /// remain; `.requiresApproval`/`.enabled` are terminal. Pure for testing.
    static func shouldKeepPolling(
        status: SMAppService.Status,
        attempt: Int,
        maxAttempts: Int
    ) -> Bool {
        guard attempt < maxAttempts else { return false }
        switch status {
        case .notRegistered, .notFound:
            return true
        default:
            return false
        }
    }

    private var service: SMAppService {
        SMAppService.daemon(plistName: SignerHelperManager.plistName)
    }

    /// Register the helper. On first run `register()` throws a benign EPERM while
    /// still landing the helper in BTM in a `.requiresApproval` state — so we read
    /// the status after the call (whether it returned or threw) and let
    /// `stateAfterRegister` decide. The status, not the throw, is authoritative.
    ///
    /// F-UX-1: the status read is a short poll, not a single racy read — BTM
    /// may report `.notRegistered` for a beat after `register()` returns. The
    /// state is `.registering` while the loop runs, so the UI can show a
    /// "finishing registration" affordance instead of nothing.
    func register() {
        settleTask?.cancel()
        hasAttemptedRegister = true
        helperState = .registering

        var registerError: Error?
        do {
            try service.register()
        } catch {
            registerError = error
        }
        log.log(
            "register: threw=\(registerError != nil, privacy: .public) initialStatus=\(self.service.status.rawValue, privacy: .public)"
        )

        settleTask = Task { @MainActor [weak self] in
            guard let self else { return }
            var attempt = 0
            var status = self.service.status
            while SignerHelperManager.shouldKeepPolling(
                status: status,
                attempt: attempt,
                maxAttempts: SignerHelperManager.postRegisterMaxAttempts
            ) {
                try? await Task.sleep(nanoseconds: SignerHelperManager.postRegisterPollInterval)
                if Task.isCancelled { return }
                attempt += 1
                status = self.service.status
            }
            self.helperState = SignerHelperManager.stateAfterRegister(
                error: registerError,
                status: status
            )
            self.log.log(
                "register settled: attempts=\(attempt, privacy: .public) status=\(status.rawValue, privacy: .public) state=\(self.helperState.description, privacy: .public)"
            )
        }
    }

    /// Jump the operator straight to System Settings → Login Items & Extensions →
    /// Allow in the Background, where the one-time helper approval lives.
    func openApprovalSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    /// Unregister the helper (clean teardown / reverse).
    func unregister() {
        settleTask?.cancel()
        settleTask = nil
        do {
            try service.unregister()
            // Direct read (not refreshStatus): we just cancelled the settle
            // loop, and refreshStatus deliberately no-ops while the state is
            // .registering — which would leave a stale .registering forever.
            helperState = SignerHelperManager.map(service.status)
        } catch {
            helperState = .error(error.localizedDescription)
        }
    }

    func refreshStatus() {
        // Never clobber an in-flight post-register settle loop with a racy
        // direct read (the loop publishes the settled state itself) — a
        // scene-activation refresh landing mid-poll would resurrect exactly
        // the F-UX-1 race this loop exists to close.
        if helperState == .registering { return }
        helperState = SignerHelperManager.map(service.status)
    }
}
