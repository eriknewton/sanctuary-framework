import SwiftUI
import AgentDetector

/// First-run experience: detect agents, suggest protecting them all.
/// Shown once, then sets UserDefaults flag and transitions to main UI.
struct FirstRunView: View {
    @ObservedObject var agentDetector: AgentDetector
    @ObservedObject var serverBridge: SanctuaryServerBridge
    let onComplete: () -> Void

    @State private var selectedAgentIds: Set<String> = []
    @State private var isProtecting = false
    @State private var protectResults: [String: Bool] = [:]
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            // Castle icon
            Image(systemName: "shield.checkered")
                .font(.system(size: 48))
                .foregroundColor(.accentColor)

            Text("Welcome to Sanctuary")
                .font(.title2)
                .fontWeight(.semibold)

            if serverBridge.sanctuaryPath == nil {
                serverSetupView
            } else if agentDetector.isScanning {
                ProgressView("Looking for AI agents on your machine...")
            } else if agentDetector.agents.isEmpty {
                noAgentsView
            } else {
                agentSelectionView
            }

            Spacer()
        }
        .padding(24)
        .task {
            await agentDetector.scan()
            // Pre-select running agents
            selectedAgentIds = Set(
                agentDetector.agents
                    .filter { $0.suggestedProtectDefault }
                    .map { $0.id }
            )
        }
    }

    // MARK: - Server not installed

    private var serverSetupView: some View {
        VStack(spacing: 12) {
            Text("Sanctuary server not detected")
                .font(.headline)
                .foregroundColor(.secondary)
            Text("Install the Sanctuary server first:")
                .font(.subheadline)
                .foregroundColor(.secondary)
            Text("npm install -g @sanctuary-framework/mcp-server")
                .font(.system(.body, design: .monospaced))
                .padding(8)
                .background(Color(.windowBackgroundColor))
                .cornerRadius(6)
            HStack(spacing: 12) {
                Button("Check Again") {
                    serverBridge.resolveSanctuaryBinary()
                }
                Button("Skip for Now") {
                    onComplete()
                }
                .foregroundColor(.secondary)
            }
        }
    }

    // MARK: - No agents found

    private var noAgentsView: some View {
        VStack(spacing: 12) {
            Text("No AI agents found")
                .font(.headline)
                .foregroundColor(.secondary)
            Text("Install an agent like OpenClaw, Claude, or Cursor, then come back.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            HStack(spacing: 12) {
                Button("Scan Again") {
                    Task { await agentDetector.scan() }
                }
                Button("Continue") {
                    onComplete()
                }
            }
        }
    }

    // MARK: - Agent selection

    private var agentSelectionView: some View {
        VStack(spacing: 16) {
            Text("We found these agents. Protect them?")
                .font(.headline)

            VStack(spacing: 1) {
                ForEach(agentDetector.agents) { agent in
                    agentCheckRow(agent)
                }
            }
            .background(Color(.separatorColor).opacity(0.3))
            .cornerRadius(8)

            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
            }

            HStack(spacing: 12) {
                Button("Skip") {
                    onComplete()
                }
                .foregroundColor(.secondary)

                Button {
                    Task { await protectSelected() }
                } label: {
                    if isProtecting {
                        ProgressView()
                            .scaleEffect(0.7)
                    } else {
                        Text("Protect Selected")
                    }
                }
                .disabled(selectedAgentIds.isEmpty || isProtecting)
                .keyboardShortcut(.defaultAction)
            }
        }
    }

    private func agentCheckRow(_ agent: AgentRecord) -> some View {
        let isSelected = selectedAgentIds.contains(agent.id)
        let isDone = protectResults[agent.id] != nil

        return HStack(spacing: 12) {
            if isDone {
                Image(systemName: protectResults[agent.id] == true
                    ? "checkmark.circle.fill"
                    : "xmark.circle.fill")
                    .foregroundColor(protectResults[agent.id] == true ? .green : .red)
            } else {
                Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                    .foregroundColor(isSelected ? .accentColor : .secondary)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(agent.name)
                    .font(.body)
                HStack(spacing: 6) {
                    Circle()
                        .fill(agent.isRunning ? Color.green : Color.gray.opacity(0.3))
                        .frame(width: 6, height: 6)
                    Text(agent.isRunning ? "Running" : "Installed")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color(.controlBackgroundColor))
        .contentShape(Rectangle())
        .onTapGesture {
            guard !isDone && !isProtecting else { return }
            if isSelected {
                selectedAgentIds.remove(agent.id)
            } else {
                selectedAgentIds.insert(agent.id)
            }
        }
    }

    // MARK: - Batch protect

    private func protectSelected() async {
        isProtecting = true
        defer { isProtecting = false }

        let agentsToProtect = agentDetector.agents.filter { selectedAgentIds.contains($0.id) }

        for agent in agentsToProtect {
            guard let flag = agent.harnessFlag else {
                protectResults[agent.id] = false
                continue
            }

            let result = await serverBridge.protect(harnessFlag: flag)
            switch result {
            case .success:
                protectResults[agent.id] = true
            default:
                protectResults[agent.id] = false
            }
        }

        let allSucceeded = protectResults.values.allSatisfy { $0 }
        if allSucceeded {
            // Brief pause so user sees the checkmarks
            try? await Task.sleep(nanoseconds: 800_000_000)
            onComplete()
        } else {
            errorMessage = "Some agents couldn't be protected. You can try again from the main screen."
        }
    }
}
