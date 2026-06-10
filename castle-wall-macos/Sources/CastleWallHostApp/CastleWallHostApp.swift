import SwiftUI

@main
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
                // Arming (auto + manual) lives in ContentView (F-UX-2): it
                // re-evaluates on scene activation, helper-state changes, and
                // a periodic status tick — not only at this first onAppear.
                filterConfigurationManager.refresh()
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
}
