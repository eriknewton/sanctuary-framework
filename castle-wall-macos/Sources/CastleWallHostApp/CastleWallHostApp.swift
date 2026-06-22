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
            // updates") — the nondeterministic launch crash seen on the
            // 2026-06-15/16 fresh-binary boot drill (v807, 3/5 reboots). `.task`
            // runs after the view is on screen, in an async MainActor context
            // outside the render cycle, so the same mutations are safe.
            .task {
                guard !didRunLaunchSequence else { return }
                didRunLaunchSequence = true
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
            // Re-submit an activation request on launch so a newer BUNDLED
            // extension version replaces the running one. macOS calls
            // actionForReplacingExtension (-> .replace) only when the bundled
            // version differs, and completes silently when it is unchanged.
            // Without this, a rebuilt/fixed extension NEVER loads while an old
            // one stays activated — root-caused on the 2026-06-11b drill, where
            // a W5-fixed extension could not reach the box because the host app
            // only re-enabled the filter and never re-requested activation.
            systemExtensionManager.activate()
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
