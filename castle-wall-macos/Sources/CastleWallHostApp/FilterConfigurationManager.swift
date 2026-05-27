import Combine
import Foundation
import NetworkExtension

/// Manages the NEFilterManager configuration for the Castle Wall content filter.
final class FilterConfigurationManager: NSObject, ObservableObject {
    enum FilterState: Equatable {
        case unknown
        case loading
        case disabled
        case enabling
        case enabled
        case needsUserApproval
        case error(String)

        var description: String {
            switch self {
            case .unknown:
                return "Unknown"
            case .loading:
                return "Loading"
            case .disabled:
                return "Disabled"
            case .enabling:
                return "Enabling"
            case .enabled:
                return "Enabled"
            case .needsUserApproval:
                return "Needs user approval"
            case let .error(message):
                return "Error: \(message)"
            }
        }
    }

    private let extensionBundleIdentifier = "ai.sanctuaryprotocol.macos.castle-wall"
    private let localizedDescription = "Sanctuary Castle Wall"

    @Published var filterState: FilterState = .unknown

    func refresh() {
        filterState = .loading
        NEFilterManager.shared().loadFromPreferences { [weak self] error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error {
                    self.filterState = .error(error.localizedDescription)
                    return
                }

                if NEFilterManager.shared().providerConfiguration != nil,
                   NEFilterManager.shared().isEnabled {
                    self.filterState = .enabled
                } else {
                    self.filterState = .disabled
                }
            }
        }
    }

    func enableFilter() {
        filterState = .enabling
        NEFilterManager.shared().loadFromPreferences { [weak self] loadError in
            DispatchQueue.main.async {
                guard let self else { return }
                if let loadError {
                    self.filterState = .error(loadError.localizedDescription)
                    return
                }

                if NEFilterManager.shared().providerConfiguration == nil {
                    let config = NEFilterProviderConfiguration()
                    config.filterPackets = false
                    config.filterSockets = true
                    config.filterDataProviderBundleIdentifier = self.extensionBundleIdentifier
                    NEFilterManager.shared().providerConfiguration = config
                    NEFilterManager.shared().localizedDescription = self.localizedDescription
                }

                // Preserve existing TCP connections across the startFilter
                // arming window. Without this (default false), every socket
                // open at the moment the filter starts is forcibly closed by
                // the kernel -- including SSH from a remote console, which
                // makes drill iteration impossible. Set via KVC because the
                // property is exposed publicly on the configuration class on
                // recent macOS but not always surfaced in older SDK headers.
                NEFilterManager.shared().providerConfiguration?.setValue(
                    true,
                    forKey: "preserveExistingConnections"
                )

                NEFilterManager.shared().isEnabled = true
                NEFilterManager.shared().saveToPreferences { [weak self] saveError in
                    DispatchQueue.main.async {
                        guard let self else { return }
                        if let saveError {
                            let nsError = saveError as NSError
                            if nsError.domain == NEFilterErrorDomain,
                               nsError.code == NEFilterManagerError.configurationPermissionDenied.rawValue {
                                self.filterState = .needsUserApproval
                            } else {
                                self.filterState = .error(saveError.localizedDescription)
                            }
                            return
                        }
                        self.filterState = .enabled
                    }
                }
            }
        }
    }

    func disableFilter() {
        NEFilterManager.shared().loadFromPreferences { [weak self] _ in
            DispatchQueue.main.async {
                guard let self else { return }
                NEFilterManager.shared().isEnabled = false
                NEFilterManager.shared().saveToPreferences { [weak self] saveError in
                    DispatchQueue.main.async {
                        guard let self else { return }
                        if let saveError {
                            self.filterState = .error(saveError.localizedDescription)
                        } else {
                            self.filterState = .disabled
                        }
                    }
                }
            }
        }
    }
}
