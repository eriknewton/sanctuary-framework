import SwiftUI

@main
struct CastleWallHostApp: App {
    @StateObject private var systemExtensionManager = SystemExtensionManager()

    var body: some Scene {
        WindowGroup {
            ContentView(systemExtensionManager: systemExtensionManager)
        }
    }
}
