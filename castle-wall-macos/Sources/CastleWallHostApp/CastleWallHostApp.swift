import SwiftUI

// Entry point lives in CastleWallMain (no @main here): headless `--headless`
// invocations must be routed before SwiftUI initializes.
struct CastleWallHostApp: App {
    @StateObject private var systemExtensionManager = SystemExtensionManager()
    @StateObject private var filterConfigurationManager = FilterConfigurationManager()
    @StateObject private var signerHelperManager = SignerHelperManager()

    // One-shot guard: the launch sequence (helper register + auto-arm) must run
    // exactly once per process. `.task` already keys to view identity and so does
    // not re-fire on re-render, but a WindowGroup can recreate the content view
    // (e.g. on scene re-attach), which would otherwise re-run the arm path. The
    // guard keeps behavior identical to the old single `.onAppear` fire.
    @State private var didRunLaunchSequence = false

    var body: some Scene {
        WindowGroup {
            ContentView(
                systemExtensionManager: systemExtensionManager,
                filterConfigurationManager: filterConfigurationManager,
                signerHelperManager: signerHelperManager
            )
            // Launch side-effects run in `.task`, NOT `.onAppear`. `.onAppear`
            // fires synchronously inside the first view-update pass, so the
            // `@Published` writes these helpers perform (helperState,
            // extensionState, filterState) mutate observed state WHILE the graph
            // is being evaluated. AttributeGraph aborts that with a SIGABRT
            // precondition failure ("Publishing changes from within view
            // updates") - the nondeterministic launch crash seen on the
            // 2026-06-15/16 fresh-binary boot drill (v807, 3/5 reboots). `.task`
            // runs after the view is on screen, in an async MainActor context
            // outside the render cycle, so the same mutations are safe.
            .task {
                guard !didRunLaunchSequence else { return }
                didRunLaunchSequence = true
                ensureSignerHelper()
                // Arming, both automatic and manual, lives in ContentView: it
                // re-evaluates on scene activation, helper-state changes, and
                // a periodic status tick - not only at this first onAppear.
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
