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
import ServiceManagement
import CastleWallSigner

final class SignerHelperManager: ObservableObject {
    enum HelperState: Equatable {
        case unknown
        case notRegistered
        case requiresApproval
        case enabled
        case notFound
        case error(String)

        var description: String {
            switch self {
            case .unknown: return "Unknown"
            case .notRegistered: return "Not registered"
            case .requiresApproval: return "Waiting for approval in System Settings"
            case .enabled: return "Enabled"
            case .notFound: return "Not found"
            case let .error(message): return "Error: \(message)"
            }
        }
    }

    /// Filename of the bundled LaunchDaemon plist (Contents/Library/LaunchDaemons/).
    static let plistName = "\(SignerConstants.signerHelperIdentifier).plist"

    @Published var helperState: HelperState = .unknown

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

    private var service: SMAppService {
        SMAppService.daemon(plistName: SignerHelperManager.plistName)
    }

    /// Register the helper. On first run this surfaces the System Settings
    /// approval prompt; status then transitions to `.requiresApproval` until the
    /// operator approves, then `.enabled`.
    func register() {
        do {
            try service.register()
            refreshStatus()
        } catch {
            helperState = .error(error.localizedDescription)
        }
    }

    /// Unregister the helper (clean teardown / reverse).
    func unregister() {
        do {
            try service.unregister()
            refreshStatus()
        } catch {
            helperState = .error(error.localizedDescription)
        }
    }

    func refreshStatus() {
        helperState = SignerHelperManager.map(service.status)
    }
}
