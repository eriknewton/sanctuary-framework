import SwiftUI
import Combine
import AgentDetector

/// The native macOS app is a FRAME around the one Sanctuary posture board, not
/// a parallel product (Dashboard one-surface spec §1, Delta Review Part C
/// Option 2). The window is:
///
///   [ native top strip: badge + Mac-only system controls ]
///   [ ----------------------------------------------------- ]
///   [        embedded posture board (PostureWebView)        ]
///
/// The embedded board owns the *posture truth* (what is protected, exposed,
/// armed, what needs a decision, what happened). The native strip owns only the
/// handful of actions that are inherently platform-native and cannot live on a
/// web page: installing the system extension, enabling the network filter,
/// approving the privileged helper, and launching the protect / unprotect
/// process for an agent. We never reimplement the posture board in SwiftUI —
/// that would fork the never-fake-green honesty model (see PostureWebView).
///
/// This replaces the old two-tab (Agents / Activity) UI: both of those views
/// already exist, in a better and more honest form, on the embedded board.
struct ContentView: View {
    @ObservedObject var systemExtensionManager: SystemExtensionManager
    @ObservedObject var filterConfigurationManager: FilterConfigurationManager
    @ObservedObject var signerHelperManager: SignerHelperManager
    @StateObject private var agentDetector = AgentDetector()
    @StateObject private var serverBridge = SanctuaryServerBridge()

    @Environment(\.scenePhase) private var scenePhase

    @AppStorage("hasCompletedFirstRun") private var hasCompletedFirstRun = false
    @State private var protectingAgent: String?
    @State private var showRestartWarning: AgentRecord?
    @State private var errorMessage: String?
    @State private var showAgentControls = false

    /// The loopback URL of the one posture board the embedded view renders.
    /// `/posture` is the explicit path the dashboard serves the posture board at
    /// today (`POSTURE_HOME_PATH`); the server root `/` currently serves the
    /// Operator Hub SPA, so we target `/posture` directly rather than relying on
    /// a root-flip that is not in this repo. Pinned to `127.0.0.1` (see
    /// PostureWebView).
    private static let postureBoardURL = URL(string: "http://127.0.0.1:3501/posture")!

    /// Re-read the evidence-gated arm state on this cadence so the native badge
    /// tracks the same source the embedded board polls (5s, matching the board's
    /// live-refresh feel without hammering the loopback endpoint).
    private let armStatePollTimer = Timer.publish(
        every: 5.0, on: .main, in: .common
    ).autoconnect()

    var body: some View {
        VStack(spacing: 0) {
            // Native top strip: badge + Mac-only system controls. Always native;
            // these are the actions a web page cannot perform.
            headerBar

            Divider()

            // One-time root-helper approval path: when the helper is
            // registered-but-unapproved, guide the operator to the System
            // Settings toggle (Mac-only, stays native).
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
                // The embedded board IS the main surface. Server-down is shown
                // as a NATIVE empty-state (never a connection-refused page).
                postureSurface
            }
        }
        .frame(minWidth: 720, minHeight: 560)
        .task {
            await agentDetector.scan()
            await serverBridge.checkServerHealth()
            await serverBridge.refreshWallArmState()
        }
        .onReceive(armStatePollTimer) { _ in
            // Keep the native badge's evidence-gated arm state fresh on the same
            // cadence the web board refreshes, so the two never drift apart.
            Task {
                await serverBridge.checkServerHealth()
                await serverBridge.refreshWallArmState()
            }
        }
        .onChange(of: scenePhase) { newPhase in
            // Re-read helper status + arm state when the app reactivates so the
            // badge and approval banner reflect reality the moment the operator
            // returns from System Settings.
            if newPhase == .active {
                signerHelperManager.refreshStatus()
                Task {
                    await serverBridge.checkServerHealth()
                    await serverBridge.refreshWallArmState()
                }
            }
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

    // MARK: - Embedded posture board (the one surface)

    @ViewBuilder
    private var postureSurface: some View {
        // The Mac-only control error toast (protect / unprotect launch failures)
        // is hoisted ABOVE the reachable/server-down branch so it surfaces in
        // every server state. The protect/unprotect buttons stay enabled during
        // the `.unknown` cold-start window, so a failure there sets
        // `errorMessage` while `serverDownView` (not the web view) is rendered;
        // keeping the toast outside the `.reachable` branch is what makes that
        // error visible instead of silently lost. Posture truth never renders
        // here — the toast carries only Mac-control action feedback.
        ZStack(alignment: .bottom) {
            // Only embed the web view once server health is CONFIRMED reachable.
            // During the initial `.unknown` state (cold start, before the first
            // health probe returns) and `.unreachable`, show the native
            // empty-state instead — otherwise the web view would load and render
            // a raw connection-refused page on a cold launch (spec §3).
            if serverBridge.serverStatus == .reachable {
                // The embedded board renders the live posture page inside the
                // app. Loopback-pinned; loaded only because the server is
                // confirmed reachable above.
                PostureWebView(url: Self.postureBoardURL)
            } else {
                serverDownView
            }

            if let error = errorMessage {
                errorToast(error)
            }
        }
    }

    /// NATIVE empty-state shown while server health is `.unknown` (cold start)
    /// or `.unreachable`. The app already knows server health via
    /// `checkServerHealth`, so we present this instead of letting the web view
    /// load a raw browser connection-refused page (spec §3).
    private var serverDownView: some View {
        VStack(spacing: 14) {
            Spacer()
            Image(systemName: "bolt.horizontal.circle")
                .font(.largeTitle)
                .foregroundColor(.secondary)
            Text("Sanctuary server not running")
                .font(.headline)
            Text("The posture board lives in the local Sanctuary server. Start it to see your agents' sovereignty posture.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)
            if serverBridge.sanctuaryPath != nil {
                Button("Start Sanctuary server") {
                    Task {
                        _ = await serverBridge.startServer()
                        try? await Task.sleep(nanoseconds: 2_000_000_000)
                        await serverBridge.checkServerHealth()
                        await serverBridge.refreshWallArmState()
                    }
                }
            }
            Button("Check again") {
                Task {
                    await serverBridge.checkServerHealth()
                    await serverBridge.refreshWallArmState()
                }
            }
            .buttonStyle(.plain)
            .foregroundColor(.accentColor)
            .font(.subheadline)
            Spacer()
        }
        .padding(24)
    }

    private func errorToast(_ message: String) -> some View {
        HStack {
            Image(systemName: "exclamationmark.circle.fill")
                .foregroundColor(.red)
            Text(message)
                .font(.caption)
                .foregroundColor(.red)
            Spacer()
            Button("Dismiss") { errorMessage = nil }
                .font(.caption)
        }
        .padding(10)
        .background(.regularMaterial)
        .cornerRadius(8)
        .padding(12)
    }

    // MARK: - Header (native strip: badge + Mac-only controls)

    private var headerBar: some View {
        HStack(spacing: 12) {
            Text("Sanctuary")
                .font(.title2)
                .fontWeight(.semibold)

            Spacer()

            // Mac-only control: protect/unprotect launch. This is the native
            // action surface for `sanctuary wrap`; the posture *truth* about
            // which agents are protected lives on the embedded board.
            if serverBridge.sanctuaryPath != nil && hasCompletedFirstRun {
                agentControlsButton
            }

            armBadge
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    /// The protection badge. Piece B: its GREEN now comes solely from the
    /// evidence-gated arm state (`/api/posture/castle-wall`), NOT from local
    /// sysext/filter/signer state. The local install/config state is surfaced
    /// only as secondary, clearly-labeled "install/config" context when the wall
    /// is not evidenced-armed — it can never produce green on its own. This kills
    /// the second, audit-blind source of "is it armed" truth (Delta Review
    /// line 132): the native badge and the embedded board read the SAME source.
    private var armBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(armColor)
                .frame(width: 8, height: 8)
            Text(armLabel)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(armColor.opacity(0.1))
        .cornerRadius(12)
        .help(armHelp)
    }

    /// Green ONLY when the server reports evidence-gated `armed`. Everything
    /// else is amber/red/gray — never green from local config alone.
    private var armColor: Color {
        switch serverBridge.wallArmState {
        case .armed:
            return .green
        case .degraded:
            return .red
        case .notInstalled:
            return .gray
        case .unknown, .none:
            // Not evidenced-armed: fall back to install/config color so the
            // operator still sees actionable local state, but NEVER green.
            return configHintColor
        }
    }

    private var armLabel: String {
        switch serverBridge.wallArmState {
        case .armed:
            return "Protection Active"
        case .degraded:
            return "Protection Degraded"
        case .notInstalled:
            return "Not Installed"
        case .unknown, .none:
            // Honest: we cannot confirm enforcement. Show the install/config
            // state as the reason, labeled as config — not as "protected."
            return configHintLabel
        }
    }

    private var armHelp: String {
        switch serverBridge.wallArmState {
        case .armed:
            // Word the cryptographic basis HONESTLY and identically to the web
            // board (posture-home-html.ts renderWall): only claim a producer
            // signature when the server reports `producer_signed`. On the macOS
            // channel-authenticated floor (no pinned producer key on this reader)
            // we must NOT say "signed" — the two surfaces read the same source and
            // must agree (Piece B; H3 second-source honesty).
            switch serverBridge.producerAuthenticity {
            case .producerSigned:
                return "The wall is enforcing: it has allowed or blocked real traffic recently (enforcement evidence cryptographically re-verified against the pinned producer key)."
            case .channelAuthenticated:
                return "The wall is enforcing: it has allowed or blocked real traffic recently (channel-authenticated + tamper-evident chain; per-producer signing not available on this reader)."
            case .notApplicable, .none:
                // Armed but the basis didn't decode: state the enforcement fact
                // without claiming any signing.
                return "The wall is enforcing: it has allowed or blocked real traffic recently (recent enforcement evidence)."
            }
        case .degraded:
            return "The wall is installed but recent enforcement evidence is missing or stale. Not confirmed protecting."
        case .notInstalled:
            return "The Castle Wall enforcement layer is not installed."
        case .unknown, .none:
            return "Enforcement not confirmed yet. The label shows local install/config state, not a protection guarantee."
        }
    }

    /// Secondary install/config hint color, used ONLY when the wall is not
    /// evidenced-armed. Derived from local sysext/filter/helper state. This is
    /// install/config state, explicitly NOT a protection determination.
    private var configHintColor: Color {
        if case .error = signerHelperManager.helperState { return .red }
        if case .error = systemExtensionManager.extensionState { return .red }
        if case .error = filterConfigurationManager.filterState { return .red }
        if signerHelperManager.helperState == .requiresApproval { return .yellow }
        if systemExtensionManager.extensionState == .needsUserApproval ||
            filterConfigurationManager.filterState == .needsUserApproval {
            return .yellow
        }
        if systemExtensionManager.extensionState == .activatedRequiresReboot { return .yellow }
        if systemExtensionManager.extensionState == .activating ||
            filterConfigurationManager.filterState == .enabling {
            return .yellow
        }
        return .gray
    }

    /// Secondary install/config label. Never says "protected" — that word is
    /// reserved for the evidence-gated `.armed` state above.
    private var configHintLabel: String {
        if signerHelperManager.helperState == .requiresApproval {
            return "Needs Helper Approval"
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
        // Nothing is installed locally (fresh / uninstalled Mac): say so. We are
        // NOT "checking enforcement" — there is nothing installed to check. This
        // is honest copy for the cold/uninstalled case; "Checking enforcement..."
        // is reserved for when something IS installed but evidence isn't in yet.
        if configHintIsNotInstalled {
            return "Not Installed"
        }
        // Installed/enabled locally but no enforcement evidence yet: honest
        // "checking" state, NOT green.
        return "Checking enforcement..."
    }

    /// True when no Castle Wall component is installed/active locally: the
    /// sysext is not activated or mid-activation, and the signer helper is not
    /// registered/enabled. Used to give the badge honest "Not Installed" copy on
    /// a fresh Mac instead of implying an in-progress enforcement check.
    private var configHintIsNotInstalled: Bool {
        let sysextDown =
            systemExtensionManager.extensionState == .unknown ||
            systemExtensionManager.extensionState == .deactivated ||
            systemExtensionManager.extensionState == .deactivating
        let helperDown =
            signerHelperManager.helperState == .unknown ||
            signerHelperManager.helperState == .notRegistered ||
            signerHelperManager.helperState == .notFound
        return sysextDown && helperDown
    }

    // MARK: - Mac-only agent controls (protect / unprotect launch)

    private var agentControlsButton: some View {
        Button {
            showAgentControls.toggle()
        } label: {
            HStack(spacing: 4) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.caption)
                Text("Protect an agent")
                    .font(.subheadline)
            }
        }
        .buttonStyle(.bordered)
        .popover(isPresented: $showAgentControls, arrowEdge: .bottom) {
            agentControlsPanel
        }
    }

    /// A compact native control surface for the Mac-only protect/unprotect
    /// launch (`sanctuary wrap`). This is a CONTROL panel, not a posture
    /// surface: it lists detected agents so the operator can launch the native
    /// wrap action. The authoritative "what is protected/armed" view is the
    /// embedded board, which never disagrees with this panel because both the
    /// badge and the board read the evidence-gated arm state.
    private var agentControlsPanel: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Protect an agent")
                    .font(.headline)
                Spacer()
                Button {
                    Task { await agentDetector.scan() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.plain)
                .help("Rescan for agents")
            }
            .padding(.horizontal, 16)
            .padding(.top, 14)
            .padding(.bottom, 8)

            Divider()

            if agentDetector.isScanning {
                HStack {
                    ProgressView().scaleEffect(0.7)
                    Text("Scanning for agents...")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .padding(16)
            } else if agentDetector.agents.isEmpty {
                VStack(spacing: 6) {
                    Text("No agents detected")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    Text("Install an AI agent like OpenClaw, Claude, or Cursor to get started.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(16)
            } else {
                ScrollView {
                    LazyVStack(spacing: 1) {
                        ForEach(agentDetector.agents) { agent in
                            agentControlRow(agent)
                        }
                    }
                    .padding(.vertical, 6)
                }
                .frame(maxHeight: 280)
            }
        }
        .frame(width: 360)
    }

    private func agentControlRow(_ agent: AgentRecord) -> some View {
        HStack(spacing: 10) {
            Circle()
                .fill(agent.isRunning ? Color.green : Color.gray.opacity(0.3))
                .frame(width: 7, height: 7)

            VStack(alignment: .leading, spacing: 1) {
                Text(agent.name)
                    .font(.subheadline)
                    .fontWeight(.medium)
                if let version = agent.version {
                    Text("v\(version)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            if protectingAgent == agent.id {
                ProgressView()
                    .scaleEffect(0.6)
                    .frame(width: 70)
            } else if agent.harnessFlag != nil {
                // Both actions are Mac-only launches of `sanctuary wrap`. This is
                // a control surface: it does NOT assert whether the agent is
                // currently protected (that truth is on the embedded board, from
                // the evidence source). The operator picks the action they want.
                HStack(spacing: 6) {
                    Button("Protect") {
                        if agent.isRunning {
                            showRestartWarning = agent
                        } else {
                            Task { await protectAgent(agent) }
                        }
                    }
                    .font(.caption)
                    .disabled(serverBridge.serverStatus == .unreachable)

                    Button("Unprotect") {
                        Task { await unprotectAgent(agent) }
                    }
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .disabled(serverBridge.serverStatus == .unreachable)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    // MARK: - Helper approval banner (Mac-only, stays native)

    @ViewBuilder
    private var helperStatusBanner: some View {
        switch signerHelperManager.helperState {
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
        case let .error(msg):
            helperBanner(
                icon: "xmark.octagon.fill",
                tint: .red,
                title: "Background helper error",
                detail: msg,
                actionLabel: "Retry"
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
            Button(actionLabel, action: action)
                .font(.subheadline)
        }
        .padding(12)
        .background(tint.opacity(0.12))
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

    // MARK: - Protect action (Mac-only launch of `sanctuary wrap`)

    private func protectAgent(_ agent: AgentRecord) async {
        guard agent.harnessFlag != nil else { return }
        protectingAgent = agent.id
        defer { protectingAgent = nil }

        let result = await serverBridge.protect(harnessFlag: agent.harnessFlag!)
        switch result {
        case .success:
            await agentDetector.scan()
            // Protection state truth comes from the evidence source, not a local
            // optimistic flag: re-read it so the badge/board reflect reality.
            await serverBridge.refreshWallArmState()
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
        guard agent.harnessFlag != nil else { return }
        protectingAgent = agent.id
        defer { protectingAgent = nil }

        let result = await serverBridge.unprotect(harnessFlag: agent.harnessFlag!)
        switch result {
        case .success:
            await agentDetector.scan()
            await serverBridge.refreshWallArmState()
        default:
            errorMessage = "Failed to unprotect \(agent.name)."
        }
    }
}
