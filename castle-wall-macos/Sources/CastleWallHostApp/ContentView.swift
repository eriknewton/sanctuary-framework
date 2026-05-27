import SwiftUI
import AgentDetector

struct ContentView: View {
    @ObservedObject var systemExtensionManager: SystemExtensionManager
    @ObservedObject var filterConfigurationManager: FilterConfigurationManager
    @StateObject private var agentDetector = AgentDetector()
    @StateObject private var serverBridge = SanctuaryServerBridge()

    @AppStorage("hasCompletedFirstRun") private var hasCompletedFirstRun = false
    @State private var selectedTab: Tab = .agents
    @State private var protectingAgent: String?
    @State private var protectedAgents: Set<String> = []
    @State private var showRestartWarning: AgentRecord?
    @State private var errorMessage: String?

    enum Tab: String {
        case agents = "Agents"
        case activity = "Activity"
    }

    var body: some View {
        VStack(spacing: 0) {
            // Top bar: app title + sysext status
            headerBar

            Divider()

            if !hasCompletedFirstRun {
                FirstRunView(
                    agentDetector: agentDetector,
                    serverBridge: serverBridge,
                    onComplete: { hasCompletedFirstRun = true }
                )
            } else if serverBridge.sanctuaryPath == nil {
                setupRequiredView
            } else {
                // Tab bar
                tabBar

                // Tab content
                switch selectedTab {
                case .agents:
                    agentListView
                case .activity:
                    ActivityLogView(serverBridge: serverBridge)
                }
            }
        }
        .frame(minWidth: 520, minHeight: 400)
        .task {
            await agentDetector.scan()
            await serverBridge.checkServerHealth()
        }
        .onChange(of: systemExtensionManager.extensionState) { newState in
            if newState == .activated,
               filterConfigurationManager.filterState != .enabled,
               filterConfigurationManager.filterState != .enabling {
                filterConfigurationManager.enableFilter()
            }
        }
        .alert("Restart Required", isPresented: .init(
            get: { showRestartWarning != nil },
            set: { if !$0 { showRestartWarning = nil } }
        )) {
            Button("Cancel", role: .cancel) { showRestartWarning = nil }
            Button("Restart and Protect") {
                if let agent = showRestartWarning {
                    Task { await protectAgent(agent) }
                }
                showRestartWarning = nil
            }
        } message: {
            if let agent = showRestartWarning {
                Text("This will restart \(agent.name). Unsaved work may be lost.")
            }
        }
    }

    // MARK: - Header

    private var headerBar: some View {
        HStack {
            Text("Sanctuary")
                .font(.title2)
                .fontWeight(.semibold)

            Spacer()

            sysextStatusBadge
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    private var sysextStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(protectionColor)
                .frame(width: 8, height: 8)
            Text(protectionLabel)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(protectionColor.opacity(0.1))
        .cornerRadius(12)
    }

    private var protectionColor: Color {
        if systemExtensionManager.extensionState == .activated,
           filterConfigurationManager.filterState == .enabled {
            return .green
        }
        if case .error = systemExtensionManager.extensionState { return .red }
        if case .error = filterConfigurationManager.filterState { return .red }
        if systemExtensionManager.extensionState == .needsUserApproval ||
            filterConfigurationManager.filterState == .needsUserApproval {
            return .yellow
        }
        if systemExtensionManager.extensionState == .activatedRequiresReboot {
            return .yellow
        }
        if systemExtensionManager.extensionState == .activating ||
            filterConfigurationManager.filterState == .enabling {
            return .yellow
        }
        return .gray
    }

    private var protectionLabel: String {
        if systemExtensionManager.extensionState == .activated,
           filterConfigurationManager.filterState == .enabled {
            return "Protection Active"
        }
        if systemExtensionManager.extensionState == .activatedRequiresReboot {
            return "Reboot Required"
        }
        if systemExtensionManager.extensionState == .needsUserApproval {
            return "Needs Sysext Approval"
        }
        if filterConfigurationManager.filterState == .needsUserApproval {
            return "Needs Filter Approval"
        }
        if case let .error(msg) = systemExtensionManager.extensionState {
            return "Sysext Error: \(msg)"
        }
        if case let .error(msg) = filterConfigurationManager.filterState {
            return "Filter Error: \(msg)"
        }
        if systemExtensionManager.extensionState == .activating ||
            filterConfigurationManager.filterState == .enabling {
            return "Activating..."
        }
        return "Protection Off"
    }

    // MARK: - Tab bar

    private var tabBar: some View {
        HStack(spacing: 0) {
            tabButton(.agents, label: "Agents", icon: "shield")
            tabButton(.activity, label: "Activity", icon: "list.bullet")
        }
        .padding(.horizontal, 16)
        .padding(.top, 8)
    }

    private func tabButton(_ tab: Tab, label: String, icon: String) -> some View {
        Button {
            selectedTab = tab
        } label: {
            HStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.caption)
                Text(label)
                    .font(.subheadline)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(selectedTab == tab ? Color.accentColor.opacity(0.15) : Color.clear)
            .cornerRadius(8)
        }
        .buttonStyle(.plain)
        .foregroundColor(selectedTab == tab ? .accentColor : .secondary)
    }

    // MARK: - Setup required view

    private var setupRequiredView: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundColor(.yellow)
            Text("Sanctuary server not detected")
                .font(.headline)
            Text("Install with:")
                .font(.subheadline)
                .foregroundColor(.secondary)
            Text("npm install -g @sanctuary-framework/mcp-server")
                .font(.system(.body, design: .monospaced))
                .padding(8)
                .background(Color(.windowBackgroundColor))
                .cornerRadius(6)
            Button("Check Again") {
                serverBridge.resolveSanctuaryBinary()
            }
            Spacer()
        }
        .padding(20)
    }

    // MARK: - Agent list (Track 2)

    private var agentListView: some View {
        VStack(spacing: 0) {
            if agentDetector.isScanning {
                Spacer()
                ProgressView("Scanning for agents...")
                Spacer()
            } else if agentDetector.agents.isEmpty {
                Spacer()
                Text("No agents detected")
                    .font(.headline)
                    .foregroundColor(.secondary)
                Text("Install an AI agent like OpenClaw, Claude, or Cursor to get started.")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.top, 4)
                Button("Scan Again") {
                    Task { await agentDetector.scan() }
                }
                .padding(.top, 12)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(spacing: 1) {
                        ForEach(agentDetector.agents) { agent in
                            agentRow(agent)
                        }
                    }
                    .padding(.vertical, 8)
                }
            }

            if let error = errorMessage {
                HStack {
                    Image(systemName: "exclamationmark.circle.fill")
                        .foregroundColor(.red)
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                    Spacer()
                    Button("Dismiss") { errorMessage = nil }
                        .font(.caption)
                }
                .padding(8)
                .background(Color.red.opacity(0.1))
            }
        }
    }

    private func agentRow(_ agent: AgentRecord) -> some View {
        HStack(spacing: 12) {
            // Running indicator
            Circle()
                .fill(agent.isRunning ? Color.green : Color.gray.opacity(0.3))
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 2) {
                Text(agent.name)
                    .font(.body)
                    .fontWeight(.medium)
                HStack(spacing: 8) {
                    if let version = agent.version {
                        Text("v\(version)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    if protectedAgents.contains(agent.id) {
                        Text("Protected")
                            .font(.caption)
                            .foregroundColor(.green)
                    } else {
                        Text(agent.isRunning ? "Running" : "Installed")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }

            Spacer()

            if protectingAgent == agent.id {
                ProgressView()
                    .scaleEffect(0.7)
                    .frame(width: 80)
            } else if protectedAgents.contains(agent.id) {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundColor(.green)
                    if let flag = agent.harnessFlag {
                        Button("Unprotect") {
                            Task { await unprotectAgent(agent) }
                        }
                        .font(.caption)
                        .foregroundColor(.secondary)
                    }
                }
            } else if let flag = agent.harnessFlag {
                protectButton(agent: agent, flag: flag)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color(.controlBackgroundColor))
    }

    private func protectButton(agent: AgentRecord, flag: String) -> some View {
        Button {
            if agent.isRunning {
                showRestartWarning = agent
            } else {
                Task { await protectAgent(agent) }
            }
        } label: {
            Text("Protect")
                .font(.subheadline)
        }
        .disabled(serverBridge.serverStatus == .unreachable)
    }

    // MARK: - Protect action

    private func protectAgent(_ agent: AgentRecord) async {
        guard let flag = agent.harnessFlag else { return }
        protectingAgent = agent.id
        defer { protectingAgent = nil }

        let result = await serverBridge.protect(harnessFlag: flag)
        switch result {
        case .success:
            protectedAgents.insert(agent.id)
            await agentDetector.scan()
        case .serverUnreachable:
            errorMessage = "Can't reach Sanctuary server. Make sure it's running."
        case .sanctuaryNotFound:
            errorMessage = "Sanctuary CLI not found. Install with: npm install -g @sanctuary-framework/mcp-server"
        case .failed(let msg):
            if msg.contains("same user") || msg.contains("permission") {
                errorMessage = "Couldn't restart \(agent.name). Try running Sanctuary as the same user that started the agent."
            } else {
                errorMessage = "Failed to protect \(agent.name): \(msg)"
            }
        }
    }

    private func unprotectAgent(_ agent: AgentRecord) async {
        guard let flag = agent.harnessFlag else { return }
        protectingAgent = agent.id
        defer { protectingAgent = nil }

        let result = await serverBridge.unprotect(harnessFlag: flag)
        switch result {
        case .success:
            protectedAgents.remove(agent.id)
            await agentDetector.scan()
        default:
            errorMessage = "Failed to unprotect \(agent.name)."
        }
    }
}
