import SwiftUI

// Entry point lives in CastleWallMain (no @main here): headless `--headless`
// invocations must be routed before SwiftUI initializes.
struct CastleWallHostApp: App {
    @StateObject private var systemExtensionManager = SystemExtensionManager()
    @StateObject private var filterConfigurationManager = FilterConfigurationManager()
    @StateObject private var signerHelperManager = SignerHelperManager()

    var body: some Scene {
        WindowGroup {
            ContentView(
                systemExtensionManager: systemExtensionManager,
                filterConfigurationManager: filterConfigurationManager,
                signerHelperManager: signerHelperManager
            )
            .onAppear {
                ensureSignerHelper()
                autoArmProtection()
            }
        }
    }

    /// A2/B2: register the root signer helper and refresh its status. On first
    /// run this surfaces the one-time "Allow background item" approval; the wall
    /// must not arm until the helper is enabled and the pin is present.
    private func ensureSignerHelper() {
        signerHelperManager.refreshStatus()
        switch signerHelperManager.helperState {
        case .notRegistered, .notFound, .unknown:
            signerHelperManager.register()
        default:
            break
        }
    }

    private func autoArmProtection() {
        filterConfigurationManager.refresh()

        // Helper-as-signer precondition: a daemon cannot sign a policy without
        // the helper + the trust-anchor pin, so arming before both are ready
        // would fail-closed the machine to deny-all. Gate on readiness.
        guard signerHelperManager.isReady else {
            return
        }

        switch systemExtensionManager.extensionState {
        case .activated:
            if filterConfigurationManager.filterState != .enabled {
                filterConfigurationManager.enableFilter()
            }
        case .activatedRequiresReboot:
            break
        case .unknown, .deactivated:
            systemExtensionManager.activate()
        default:
            break
        }
    }
}
