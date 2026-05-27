import SwiftUI

@main
struct CastleWallHostApp: App {
    @StateObject private var systemExtensionManager = SystemExtensionManager()
    @StateObject private var filterConfigurationManager = FilterConfigurationManager()

    var body: some Scene {
        WindowGroup {
            ContentView(
                systemExtensionManager: systemExtensionManager,
                filterConfigurationManager: filterConfigurationManager
            )
            .onAppear {
                autoArmProtection()
            }
        }
    }

    private func autoArmProtection() {
        filterConfigurationManager.refresh()
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
