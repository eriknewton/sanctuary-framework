import Combine
import Foundation
import SystemExtensions

final class SystemExtensionManager: NSObject, ObservableObject {
    enum ExtensionState: Equatable {
        case unknown
        case activating
        case activated
        case activatedRequiresReboot
        case deactivating
        case deactivated
        case deactivatedRequiresReboot
        case needsUserApproval
        case error(String)

        var description: String {
            switch self {
            case .unknown:
                return "Unknown"
            case .activating:
                return "Activating"
            case .activated:
                return "Activated"
            case .activatedRequiresReboot:
                return "Activated (reboot required)"
            case .deactivating:
                return "Deactivating"
            case .deactivated:
                return "Deactivated"
            case .deactivatedRequiresReboot:
                return "Deactivation accepted (reboot required)"
            case .needsUserApproval:
                return "Needs user approval"
            case let .error(message):
                return "Error: \(message)"
            }
        }
    }

    private enum PendingOperation {
        case activation
        case deactivation
    }

    private let extensionIdentifier = "ai.sanctuaryprotocol.macos.castle-wall"
    private var pendingOperation: PendingOperation?

    @Published var extensionState: ExtensionState = .unknown

    func activate() {
        handleRequestStarted(isActivation: true)
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func deactivate() {
        handleRequestStarted(isActivation: false)
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func handleRequestStarted(isActivation: Bool) {
        pendingOperation = isActivation ? .activation : .deactivation
        extensionState = isActivation ? .activating : .deactivating
    }

    func handleRequestFinished() {
        handleRequestFinished(result: .completed)
    }

    func handleRequestFinished(result: OSSystemExtensionRequest.Result) {
        // The request was submitted with `queue: .main`, so this callback
        // already runs on the main queue.
        defer { pendingOperation = nil }
        switch pendingOperation {
        case .activation:
            switch result {
            case .completed:
                extensionState = .activated
            case .willCompleteAfterReboot:
                extensionState = .activatedRequiresReboot
            @unknown default:
                extensionState = .error("Unknown activation result")
            }
        case .deactivation:
            switch result {
            case .completed:
                extensionState = .deactivated
            case .willCompleteAfterReboot:
                extensionState = .deactivatedRequiresReboot
            @unknown default:
                extensionState = .error("Unknown deactivation result")
            }
        case .none:
            extensionState = .unknown
        }
    }

    func handleRequestFailed(_ error: Error) {
        pendingOperation = nil
        extensionState = .error(error.localizedDescription)
    }

    func handleNeedsUserApproval() {
        extensionState = .needsUserApproval
    }

    func replacementAction() -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {
    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        handleRequestFinished(result: result)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        handleRequestFailed(error)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return replacementAction()
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        handleNeedsUserApproval()
    }
}
