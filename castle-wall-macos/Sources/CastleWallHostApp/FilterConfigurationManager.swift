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

    static let extensionBundleIdentifier = "ai.sanctuaryprotocol.macos.castle-wall"
    static let localizedDescription = "Sanctuary Castle Wall"

    @Published var filterState: FilterState = .unknown

    /// Disarm safety invariant: true from the moment a disarm attempt starts
    /// until a re-read of the preferences PROVES `NEFilterManager.isEnabled == false`. While
    /// true, the UI must keep a retryable Disarm control on screen - a failed
    /// `saveToPreferences` (or an ignored load error) can leave the REAL
    /// filter enabled while `filterState` falls out of the armed states, and
    /// hiding Disarm at that moment removes the operator's exit path exactly
    /// when it matters. Cleared ONLY on verified-disabled (post-save verify
    /// re-read, or a later `refresh()` that observes the filter off).
    @Published var disarmPending = false

    // MARK: - Disarm state model (pure)

    /// Terminal events a disarm attempt can end on. Pure inputs to
    /// `disarmOutcome` so the state model is unit-testable without touching
    /// NEFilterManager.
    enum DisarmAttemptEvent: Equatable {
        /// `loadFromPreferences` before the disable failed. Previously
        /// ignored - it is a FAILED disarm attempt: nothing was saved.
        case loadFailed(String)
        /// `saveToPreferences` of `isEnabled = false` failed.
        case saveFailed(String)
        /// The post-save verification re-read failed; the disable may or may
        /// not have taken effect, so it is NOT verified.
        case verifyLoadFailed(String)
        /// The post-save verification re-read succeeded and reports whether
        /// the filter is still enabled.
        case verified(filterStillEnabled: Bool)
    }

    struct DisarmResolution: Equatable {
        let filterState: FilterState
        let disarmPending: Bool
    }

    /// The invariant, as a total function: `disarmPending` clears ONLY on
    /// `.verified(filterStillEnabled: false)`. Every failure or unverified
    /// path keeps it set, which keeps the retryable Disarm control visible.
    static func disarmOutcome(_ event: DisarmAttemptEvent) -> DisarmResolution {
        switch event {
        case let .loadFailed(message):
            return DisarmResolution(
                filterState: .error("Disarm failed: \(message)"),
                disarmPending: true
            )
        case let .saveFailed(message):
            return DisarmResolution(
                filterState: .error("Disarm failed: \(message)"),
                disarmPending: true
            )
        case let .verifyLoadFailed(message):
            return DisarmResolution(
                filterState: .error("Disarm unverified: \(message)"),
                disarmPending: true
            )
        case .verified(filterStillEnabled: true):
            return DisarmResolution(
                filterState: .error("Disarm did not take effect; the filter is still enabled."),
                disarmPending: true
            )
        case .verified(filterStillEnabled: false):
            return DisarmResolution(filterState: .disabled, disarmPending: false)
        }
    }

    private func resolveDisarm(_ event: DisarmAttemptEvent) {
        let resolution = Self.disarmOutcome(event)
        filterState = resolution.filterState
        disarmPending = resolution.disarmPending
    }

    /// Single source of truth for the desired provider configuration, shared
    /// by the GUI enable path and the headless CLI (HeadlessFilterCLI) so the
    /// two arming surfaces cannot drift.
    static func applyDesiredProviderConfiguration(to manager: NEFilterManager) {
        if manager.providerConfiguration == nil {
            let config = NEFilterProviderConfiguration()
            config.filterPackets = false
            config.filterSockets = true
            config.filterDataProviderBundleIdentifier = extensionBundleIdentifier
            manager.providerConfiguration = config
            manager.localizedDescription = localizedDescription
        }

        // Preserve existing TCP connections across the startFilter
        // arming window. Without this (default false), every socket
        // open at the moment the filter starts is forcibly closed by
        // the kernel -- including SSH from a remote console, which
        // makes drill iteration impossible. Set via KVC because the
        // property is exposed publicly on the configuration class on
        // recent macOS but not always surfaced in older SDK headers.
        manager.providerConfiguration?.setValue(
            true,
            forKey: "preserveExistingConnections"
        )
    }

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
                    // A refresh that observes the filter actually off is a
                    // verified-disabled - it completes any outstanding disarm
                    // attempt.
                    if !NEFilterManager.shared().isEnabled {
                        self.disarmPending = false
                    }
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

                Self.applyDesiredProviderConfiguration(to: NEFilterManager.shared())

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

    /// Disarm safety invariant: every exit of this flow routes through
    /// `resolveDisarm`, and only a post-save re-read proving `isEnabled == false` clears
    /// `disarmPending`. Load errors are FAILED disarm attempts (they were
    /// previously swallowed); a save "success" alone is not trusted - the
    /// preferences are re-read and the disable is verified before the UI may
    /// report the wall down.
    func disableFilter() {
        disarmPending = true
        NEFilterManager.shared().loadFromPreferences { [weak self] loadError in
            DispatchQueue.main.async {
                guard let self else { return }
                if let loadError {
                    self.resolveDisarm(.loadFailed(loadError.localizedDescription))
                    return
                }
                NEFilterManager.shared().isEnabled = false
                NEFilterManager.shared().saveToPreferences { [weak self] saveError in
                    DispatchQueue.main.async {
                        guard let self else { return }
                        if let saveError {
                            self.resolveDisarm(.saveFailed(saveError.localizedDescription))
                            return
                        }
                        // Verification re-read: trust the system's view, not
                        // the save callback, before declaring the wall down.
                        NEFilterManager.shared().loadFromPreferences { [weak self] verifyError in
                            DispatchQueue.main.async {
                                guard let self else { return }
                                if let verifyError {
                                    self.resolveDisarm(
                                        .verifyLoadFailed(verifyError.localizedDescription)
                                    )
                                    return
                                }
                                self.resolveDisarm(
                                    .verified(
                                        filterStillEnabled: NEFilterManager.shared().isEnabled
                                    )
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
