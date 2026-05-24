import SwiftUI

struct ContentView: View {
    @ObservedObject var systemExtensionManager: SystemExtensionManager

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Castle Wall Host App")
                .font(.title2)
                .fontWeight(.semibold)

            HStack {
                Text("Status:")
                    .fontWeight(.medium)
                Text(systemExtensionManager.extensionState.description)
            }

            HStack(spacing: 12) {
                Button("Activate") {
                    systemExtensionManager.activate()
                }
                .disabled(
                    systemExtensionManager.extensionState == .activated ||
                    systemExtensionManager.extensionState == .activating
                )

                Button("Deactivate") {
                    systemExtensionManager.deactivate()
                }
                .disabled(
                    systemExtensionManager.extensionState == .deactivated ||
                    systemExtensionManager.extensionState == .deactivating
                )
            }

            Text(systemExtensionManager.extensionState.description)
                .font(.body)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color(.windowBackgroundColor))
                .cornerRadius(8)
        }
        .padding(20)
        .frame(minWidth: 480, minHeight: 260)
    }
}
