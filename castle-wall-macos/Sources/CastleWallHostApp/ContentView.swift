import SwiftUI
import AgentDetector
import CastleWallIPC

struct ContentView: View {
    @ObservedObject var systemExtensionManager: SystemExtensionManager
    @ObservedObject var filterConfigurationManager: FilterConfigurationManager
    @ObservedObject var signerHelperManager: SignerHelperManager
    @StateObject private var agentDetector = AgentDetector()
    @StateObject private var serverBridge = SanctuaryServerBridge()

    @Environment(\.scenePhase) private var scenePhase

    @AppStorage("hasCompletedFirstRun") private var hasCompletedFirstRun = false

    /// F-UX-2 operator-disarm latch: set by the Disarm button, cleared by the
    /// Arm button. Persisted so a manual disarm survives an app relaunch —
    /// auto-arm must never silently undo the operator's explicit decision.
    @AppStorage("operatorDisarmed") private var operatorDisarmed = false

    /// F-UX-2 arm gate input: true iff the daemon's active-config names a live
    /// pid (written only after its listener + signed policy are up). Refreshed
    /// on scene activation and on the periodic status tick.
    @State private var daemonUpWithPolicy = false

    /// Periodic status tick (F-UX-2): keeps the Arm gate + helper status live
    /// while the app sits open, so "start the daemon, watch the Arm button
    /// light up" works without bouncing the app. Both probes are cheap (one
    /// stat+kill(0), one SMAppService status read).
    private let statusTick = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

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

            // One-time root-helper approval path (drill blocker fix): when the
            // helper is registered-but-unapproved, guide the operator to the
            // System Settings toggle instead of silently doing nothing.
            helperStatusBanner

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
            refreshProtectionInputs()
            evaluateAutoArm()
            await agentDetector.scan()
            await serverBridge.checkServerHealth()
        }
        .onChange(of: scenePhase) { newPhase in
            // Re-read helper + daemon status when the app reactivates so the
            // approval banner clears the moment the operator flips the toggle
            // and returns — and re-evaluate auto-arm on the same path (F-UX-2:
            // arming is no longer a one-shot at first onAppear).
            if newPhase == .active {
                refreshProtectionInputs()
                evaluateAutoArm()
            }
        }
        .onReceive(statusTick) { _ in
            refreshProtectionInputs()
            evaluateAutoArm()
        }
        .onChange(of: signerHelperManager.helperState) { newState in
            // The moment the operator approves the helper (state flips to
            // .enabled), re-evaluate arming — no relaunch required.
            if newState == .enabled {
                evaluateAutoArm()
            }
        }
        .onChange(of: systemExtensionManager.extensionState) { newState in
            // Final arming step once sysext activation lands. Re-checked
            // against the full fail-closed gate: the helper/daemon state may
            // have changed while activation was in flight, and an operator
            // disarm during that window must win.
            if newState == .activated,
               filterConfigurationManager.filterState != .enabled,
               filterConfigurationManager.filterState != .enabling,
               !operatorDisarmed,
               canArm {
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
        VStack(spacing: 4) {
            HStack {
                Text("Sanctuary")
                    .font(.title2)
                    .fontWeight(.semibold)

                Spacer()

                protectionControl

                sysextStatusBadge
            }

            // A blocked Arm must never be silent (F-UX-2): name the missing
            // precondition right under the control.
            if !isArmed, let reason = armBlockedReason {
                HStack {
                    Spacer()
                    Text(reason)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    // MARK: - Arm / Disarm (F-UX-2)

    /// Armed = the content filter is on (or coming up). The sysext being
    /// activated alone is not armed — only the filter actually intercepts
    /// flows.
    private var isArmed: Bool {
        filterConfigurationManager.filterState == .enabled ||
            filterConfigurationManager.filterState == .enabling
    }

    private var canArm: Bool {
        ProtectionGate.canArm(
            helperReady: signerHelperManager.isReady,
            daemonUpWithPolicy: daemonUpWithPolicy
        )
    }

    private var armBlockedReason: String? {
        ProtectionGate.armBlockedReason(
            helperReady: signerHelperManager.isReady,
            daemonUpWithPolicy: daemonUpWithPolicy
        )
    }

    /// The manual control: Disarm whenever armed (ALWAYS enabled — the
    /// operator can stand the wall down unconditionally), Arm otherwise
    /// (enabled only when the fail-closed gate passes).
    @ViewBuilder
    private var protectionControl: some View {
        if isArmed {
            Button("Disarm") {
                disarmProtection()
            }
            .disabled(!ProtectionGate.canDisarm())
            .help("Turn the Castle Wall off. Always available.")
        } else {
            Button("Arm") {
                armProtection()
            }
            .disabled(!canArm)
            .help(armBlockedReason ?? "Turn the Castle Wall on.")
        }
    }

    /// Refresh the inputs the arm gate + banners read: helper status and
    /// daemon liveness. Cheap; called on scene activation and the status tick.
    private func refreshProtectionInputs() {
        signerHelperManager.refreshStatus()
        daemonUpWithPolicy = SocketPath.activeDaemonPresent()
    }

    /// Auto-arm, re-evaluated on every refresh path (F-UX-2) — not a one-shot.
    /// Only acts from a settled "filter off" state so transient states
    /// (.loading at startup, .enabling mid-arm) and sticky ones
    /// (.needsUserApproval, .error — which need the operator) never loop.
    private func evaluateAutoArm() {
        guard filterConfigurationManager.filterState == .disabled else { return }
        // Auto-arm only drives from clean sysext states. In-flight, error,
        // needs-approval, and reboot-gated states are operator territory — a
        // 5s re-submit loop into a persistent error would churn forever.
        switch systemExtensionManager.extensionState {
        case .unknown, .deactivated, .activated:
            break
        default:
            return
        }
        guard ProtectionGate.shouldAutoArm(
            canArm: canArm,
            alreadyArmed: isArmed,
            operatorDisarmed: operatorDisarmed
        ) else { return }
        armProtection()
    }

    /// Arm the wall. Fail-closed: re-probe the daemon at gesture time and bail
    /// (never partially arm) if the gate no longer passes.
    private func armProtection() {
        daemonUpWithPolicy = SocketPath.activeDaemonPresent()
        guard canArm else { return }

        operatorDisarmed = false

        switch systemExtensionManager.extensionState {
        case .activated:
            if filterConfigurationManager.filterState != .enabled,
               filterConfigurationManager.filterState != .enabling {
                filterConfigurationManager.enableFilter()
            }
        case .activating, .deactivating, .activatedRequiresReboot, .needsUserApproval:
            // In-flight, reboot-gated, or parked on the System Settings sysext
            // approval: nothing sensible to re-submit now. The
            // onChange(extensionState) hook finishes arming when activation
            // lands.
            break
        case .unknown, .deactivated, .error:
            // .error reachable only via the manual Arm button (auto-arm skips
            // it) — an explicit operator retry.
            systemExtensionManager.activate()
        }
    }

    /// Disarm the wall. Unconditional, and sticky: sets the operator-disarm
    /// latch so auto-arm does not immediately re-arm.
    private func disarmProtection() {
        operatorDisarmed = true
        filterConfigurationManager.disableFilter()
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

    /// True only when the helper can sign (ready), the sysext is activated, and
    /// the filter is enabled. Gates the green "Protection Active" state so a bare
    /// filter toggle (no helper/pin) never reads as fully protected.
    private var protectionActive: Bool {
        SignerHelperManager.isProtectionActive(
            isReady: signerHelperManager.isReady,
            sysextActivated: systemExtensionManager.extensionState == .activated,
            filterEnabled: filterConfigurationManager.filterState == .enabled
        )
    }

    private var protectionColor: Color {
        if protectionActive {
            return .green
        }
        if case .error = signerHelperManager.helperState { return .red }
        if case .error = systemExtensionManager.extensionState { return .red }
        if case .error = filterConfigurationManager.filterState { return .red }
        if signerHelperManager.helperState == .requiresApproval ||
            signerHelperManager.helperState == .registering {
            return .yellow
        }
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
        if protectionActive {
            return "Protection Active"
        }
        if signerHelperManager.helperState == .requiresApproval {
            return "Needs Helper Approval"
        }
        if signerHelperManager.helperState == .registering {
            return "Registering Helper…"
        }
        if case let .error(msg) = signerHelperManager.helperState {
            return "Helper Error: \(msg)"
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

    // MARK: - Helper approval banner

    @ViewBuilder
    private var helperStatusBanner: some View {
        switch signerHelperManager.helperState {
        case .registering:
            // F-UX-1: the post-register settle window. Visible (not an
            // EmptyView race) so the operator sees registration in progress.
            helperBanner(
                icon: "hourglass",
                tint: .blue,
                title: "Registering Sanctuary background helper…",
                detail: "Waiting for macOS to accept the helper registration (a few seconds).",
                actionLabel: "Open Settings"
            ) {
                signerHelperManager.openApprovalSettings()
            }
        case .requiresApproval:
            helperBanner(
                icon: "exclamationmark.shield.fill",
                tint: .yellow,
                title: "Approve Sanctuary background helper",
                detail: "Enable Sanctuary-CastleWall under Allow in the Background, authenticate as admin.",
                actionLabel: "Open Settings"
            ) {
                signerHelperManager.openApprovalSettings()
            }
        case .notRegistered, .notFound:
            // F-UX-1: post-register fallthrough. If a register attempt was
            // made and BTM still reports nothing, give the operator an
            // explicit path (retry + the settings pane) instead of nothing.
            if signerHelperManager.hasAttemptedRegister {
                helperBanner(
                    icon: "exclamationmark.shield.fill",
                    tint: .yellow,
                    title: "Background helper not registered",
                    detail: "macOS did not accept the helper registration yet. Retry, then enable Sanctuary-CastleWall under Allow in the Background.",
                    actionLabel: "Retry",
                    secondaryActionLabel: "Open Settings",
                    secondaryAction: { signerHelperManager.openApprovalSettings() }
                ) {
                    signerHelperManager.register()
                }
            } else {
                EmptyView()
            }
        case let .error(msg):
            helperBanner(
                icon: "xmark.octagon.fill",
                tint: .red,
                title: "Background helper error",
                detail: msg,
                actionLabel: "Retry",
                secondaryActionLabel: "Open Settings",
                secondaryAction: { signerHelperManager.openApprovalSettings() }
            ) {
                signerHelperManager.register()
            }
        default:
            EmptyView()
        }
    }

    private func helperBanner(
        icon: String,
        tint: Color,
        title: String,
        detail: String,
        actionLabel: String,
        secondaryActionLabel: String? = nil,
        secondaryAction: (() -> Void)? = nil,
        action: @escaping () -> Void
    ) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundColor(tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text(detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if let secondaryActionLabel, let secondaryAction {
                Button(secondaryActionLabel, action: secondaryAction)
                    .font(.subheadline)
            }
            Button(actionLabel, action: action)
                .font(.subheadline)
        }
        .padding(12)
        .background(tint.opacity(0.12))
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
