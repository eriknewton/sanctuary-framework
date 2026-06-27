import SwiftUI
import Combine
import AgentDetector
import CastleWallIPC

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
/// process for an agent. We never reimplement the posture board in SwiftUI -
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

    /// Manual disarm latch: set by the Disarm button, cleared by the Arm
    /// button. Persisted so a manual disarm survives an app relaunch -
    /// auto-arm must never silently undo the operator's explicit decision.
    @AppStorage("operatorDisarmed") private var operatorDisarmed = false

    /// Arm gate input: true only when active-config discovery resolves to a
    /// daemon that proves possession of the pinned fortress key via the IPC
    /// handshake. This supports the current operator daemon's legacy discovery
    /// writer without trusting the legacy file itself; a forged /tmp path cannot
    /// sign the challenge.
    @State private var daemonUpWithPolicy = false
    @State private var daemonProbeGeneration = 0
    @State private var didSubmitLaunchActivationRefresh = false

    /// Periodic status tick: keeps the Arm gate + helper status live while the
    /// app sits open, so "start the daemon, watch the Arm button light up" works
    /// without bouncing the app. Both probes are cheap (one
    /// short authenticated IPC probe, one SMAppService status read).
    private let statusTick = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

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
            refreshProtectionInputs()
            refreshActivatedSystemExtensionIfNeeded()
            evaluateAutoArm()
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
            // Re-read helper + daemon status AND the evidence-gated arm/server
            // state when the app reactivates: the approval banner clears the
            // moment the operator flips the System Settings toggle and returns,
            // auto-arm is re-evaluated on the same path instead of only at the
            // first onAppear, and the evidence-gated badge
            // tracks the server posture the embedded board reads. Note
            // `refreshProtectionInputs()` already re-reads the helper status, so
            // it covers main's prior `signerHelperManager.refreshStatus()`.
            if newPhase == .active {
                refreshProtectionInputs()
                refreshActivatedSystemExtensionIfNeeded()
                evaluateAutoArm()
                Task {
                    await serverBridge.checkServerHealth()
                    await serverBridge.refreshWallArmState()
                }
            }
        }
        .onReceive(statusTick) { _ in
            refreshProtectionInputs()
            evaluateAutoArm()
        }
        .onChange(of: signerHelperManager.helperState) { newState in
            // The moment the operator approves the helper (state flips to
            // .enabled), re-evaluate arming - no relaunch required.
            if newState == .enabled {
                refreshActivatedSystemExtensionIfNeeded()
                refreshProtectionInputs()
                evaluateAutoArm()
            }
        }
        .onChange(of: systemExtensionManager.extensionState) { newState in
            // Final arming step once sysext activation lands. Re-checked
            // against the full fail-closed gate: the helper/daemon state may
            // have changed while activation was in flight, and an operator
            // disarm during that window must win.
            if newState == .activated {
                Task {
                    await enableFilterAfterActivationIfAllowed()
                }
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
        // here - the toast carries only Mac-control action feedback.
        ZStack(alignment: .bottom) {
            // Three honest surface states (Slice 1a design §3.1), read from
            // `serverBridge.surfaceState` (derived in `postureSurfaceState`):
            //
            //   .live          server reachable -> embedded board (unchanged).
            //   .reconnecting  was reachable, now failing inside the recovery
            //                  budget -> the SAME last-known board, dimmed +
            //                  non-interactive, with a timestamped
            //                  "reconnecting..." banner overlaid. The operator
            //                  stays oriented (sees what WAS true, clearly marked
            //                  stale) while recovery is attempted; the badge has
            //                  already fallen to `.unknown` (never green).
            //   .unreachable   cold start (no last-known frame) OR down past the
            //                  recovery budget -> the native down-screen. We
            //                  never mount the web view onto a connection-refused
            //                  page, and never fabricate a stale frame on cold
            //                  start (spec §3).
            //
            // View-identity invariant (honesty fix, PR #715 review): `.live` and
            // `.reconnecting` mount EXACTLY ONE `PostureWebView` at the SAME
            // structural position in the tree, so SwiftUI keeps the same
            // `WKWebView` instance across the live<->reconnecting transition. The
            // dim + non-interactivity + stale banner are applied as a CONDITIONAL
            // OVERLAY on top of that single stable web view, not by mounting a
            // second `PostureWebView` inside a different container. If we instead
            // moved the representable to a different position, SwiftUI's
            // positional structural identity would treat it as a new view and
            // call `makeNSView` for a FRESH `WKWebView` whose `load()` fires
            // against the now-dead server -> the operator would see a blank or
            // connection-refused frame, NOT the genuinely last-rendered board,
            // and the "showing your last-known posture" banner would over-claim.
            // Keeping one instance guarantees the dimmed frame really is the last
            // board the operator saw (the web view does not reload on re-render).
            //
            // `.unreachable` (cold start or past the recovery budget) tears the
            // web view down on purpose: there is genuinely nothing to preserve
            // there, so the native down-screen replaces it.
            switch serverBridge.surfaceState {
            case .live, .reconnecting:
                postureBoardWithStaleOverlay
            case .unreachable:
                serverDownView
            }

            if let error = errorMessage {
                errorToast(error)
            }
        }
    }

    /// The one embedded posture board, plus the conditional stale overlay that
    /// turns it into the honest Reconnecting state (Slice 1a design §3.1, §3.2).
    ///
    /// There is exactly ONE `PostureWebView` here, mounted at a STABLE structural
    /// position for both `.live` and `.reconnecting`, so SwiftUI reuses the same
    /// `WKWebView` across the transition and the operator's genuinely
    /// last-rendered board is what gets dimmed (the web view does not reload on
    /// re-render; it is not refetched from the dead server). When the surface is
    /// `.reconnecting` we layer a dim + non-interactivity + timestamped banner ON
    /// TOP of that same board; in `.live` the overlay is absent and the board is
    /// fully interactive. Honesty rules enforced here:
    ///
    ///   - The last-known frame is NEVER presented as current while
    ///     reconnecting: it is dimmed (reduced opacity), made non-interactive
    ///     (`allowsHitTesting(false)`) so a stale control cannot be clicked as if
    ///     live, and overlaid with a timestamped "as of ..., reconnecting..."
    ///     banner.
    ///   - The arm badge is untouched here; it has already fallen to `.unknown`
    ///     on the failed posture read (never-fake-green across time). This view
    ///     only governs the board area, not the badge.
    @ViewBuilder
    private var postureBoardWithStaleOverlay: some View {
        let reconnecting = serverBridge.surfaceState == .reconnecting
        ZStack(alignment: .top) {
            // The single, stable embedded board. Loopback-pinned; loaded once and
            // reused. Dimmed + non-interactive ONLY while reconnecting, so the
            // exact same WKWebView instance carries the live view into the stale
            // view without a reload.
            PostureWebView(url: Self.postureBoardURL)
                .opacity(reconnecting ? 0.45 : 1.0)
                .allowsHitTesting(!reconnecting)
                .accessibilityHidden(reconnecting)

            if reconnecting {
                reconnectingBanner
            }
        }
    }

    /// Timestamped, plain-English banner overlaid on the dimmed last-known board
    /// during the Reconnecting state. Hyphens only (no em-dashes), per the
    /// public-artifact rule.
    private var reconnectingBanner: some View {
        HStack(spacing: 10) {
            ProgressView()
                .scaleEffect(0.6)
            VStack(alignment: .leading, spacing: 2) {
                Text("Reconnecting to the local Sanctuary server...")
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text(reconnectingStaleNotice)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
        }
        .padding(12)
        .background(.regularMaterial)
        .cornerRadius(10)
        .padding(.horizontal, 12)
        .padding(.top, 12)
        .shadow(radius: 2, y: 1)
    }

    /// "Showing your last-known posture as of <date+time> - this view is stale."
    /// The timestamp is the moment we last confirmed the server alive
    /// (`lastReachableAt`), so the operator knows exactly how old the dimmed
    /// frame is. We include the DATE, not just the time, so a long or overnight
    /// outage cannot read as a few seconds stale (a bare HH:mm:ss understates an
    /// hours-old or day-old frame). If we somehow have no timestamp, say so
    /// plainly rather than inventing a time.
    private var reconnectingStaleNotice: String {
        guard let at = serverBridge.lastReachableAt else {
            return "Showing your last-known posture - this view is stale."
        }
        return "Showing your last-known posture as of \(Self.staleTimestamp(at)) - this view is stale."
    }

    /// Format a last-reachable timestamp for the stale-state copy. Uses the
    /// system locale's medium date + medium time (for example "Jun 22, 2026 at
    /// 2:13:07 PM"), so the operator sees the DATE as well as the time. A bare
    /// HH:mm:ss would understate an overnight or multi-day outage as if the frame
    /// were seconds old; including the date keeps the staleness honest. Pure +
    /// static so the format is unit-testable without a view. Hyphens only.
    static func staleTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }

    /// NATIVE down-screen, shown for the genuinely-`.unreachable` surface state:
    /// cold start before any successful probe (nothing live to show yet), OR a
    /// previously-reachable server that stayed down past the recovery budget
    /// (Reconnecting gave up). The app already knows server health via
    /// `checkServerHealth`, so we present this instead of letting the web view
    /// load a raw browser connection-refused page (spec §3).
    ///
    /// Slice 1a reword (design §3.2): plain-English, a SPECIFIC reason for each of
    /// the two cases, a manual restart affordance (kept), and the last-known
    /// timestamp when we have one. Hyphens only (no em-dashes).
    private var serverDownView: some View {
        VStack(spacing: 14) {
            Spacer()
            Image(systemName: "bolt.horizontal.circle")
                .font(.largeTitle)
                .foregroundColor(.secondary)
            Text(serverDownTitle)
                .font(.headline)
            Text(serverDownDetail)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 380)
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

    /// Down-screen title, specific to the case. If we had previously reached the
    /// server (we have a last-known frame), the honest statement is that it
    /// stopped and did not come back; on a cold start it is simply not running
    /// yet.
    private var serverDownTitle: String {
        serverBridge.hasLastKnownPosture
            ? "The local Sanctuary server stopped"
            : "Sanctuary server not running"
    }

    /// Down-screen detail. For the "stopped and did not come back" case we say
    /// exactly that and surface the last-known timestamp so the operator knows
    /// how long ago they last saw real posture; for cold start we explain where
    /// the board lives and how to bring it up.
    private var serverDownDetail: String {
        if serverBridge.hasLastKnownPosture {
            let base = "The local server that serves your posture board stopped and did not come back on its own. Start it again to restore your live view."
            if let at = serverBridge.lastReachableAt {
                // Date + time (not a bare HH:mm:ss) so a long outage cannot read
                // as seconds-old.
                return base + " Last seen live at \(Self.staleTimestamp(at))."
            }
            return base
        }
        return "The posture board lives in the local Sanctuary server. Start it to see your agents' protection posture."
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
        // The header carries BOTH the local Arm/Disarm action control and the
        // evidence-gated posture badge. The control row is an
        // HStack; the blocked-arm reason stacks UNDER it in a VStack so a
        // refused arm is never silent. Posture TRUTH = `armBadge` (server-side
        // evidence-gated, the SOLE green source); the local Arm/Disarm control
        // and `sysextStatusBadge` are local-action / install-config surfaces and
        // never produce the green posture badge.
        VStack(spacing: 4) {
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

                // Manual Arm/Disarm action control + local install/config sysext
                // badge. These drive the local action only; they are NOT the
                // posture-truth badge.
                protectionControl

                sysextStatusBadge

                // Evidence-gated posture badge (main): the SOLE source of
                // "armed = green", read from the same server posture the
                // embedded board polls. Never green from local state.
                armBadge
            }

            // A blocked Arm must never be silent: name the missing precondition
            // right under the control.
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

    // MARK: - Arm / Disarm

    /// Armed = the content filter is on (or coming up). The sysext being
    /// activated alone is not armed - only the filter actually intercepts
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

    /// The manual control: Disarm whenever armed OR while a disarm attempt is
    /// pending/unverified (ALWAYS enabled - the operator can stand the wall
    /// down unconditionally, and a failed disarm must keep the retry on
    /// screen), Arm otherwise (enabled only when the fail-closed gate passes).
    @ViewBuilder
    private var protectionControl: some View {
        if ProtectionGate.disarmControlVisible(
            isArmed: isArmed,
            disarmPending: filterConfigurationManager.disarmPending
        ) {
            Button("Disarm") {
                disarmProtection()
            }
            .disabled(!ProtectionGate.canDisarm())
            .help(
                filterConfigurationManager.disarmPending && !isArmed
                    ? "The last disarm was not verified complete - retry until the filter is confirmed off."
                    : "Turn the Castle Wall off. Always available."
            )
        } else {
            Button("Arm") {
                armProtection()
            }
            .disabled(!canArm)
            .help(armBlockedReason ?? "Turn the Castle Wall on.")
        }
    }

    /// Refresh the inputs the arm gate + banners read: helper status and
    /// authenticated daemon readiness (active-config discovery + authenticated
    /// IPC handshake). Called on scene activation and the status tick.
    private func refreshProtectionInputs() {
        signerHelperManager.refreshStatus()
        refreshDaemonArmingReadiness(reevaluateAutoArm: true)
    }

    /// Re-submit activation once on launch / helper approval so a newer bundled
    /// sysext replaces an older running one. This must not depend on the filter
    /// being disabled: a fresh launch can start at `.unknown` while the filter is
    /// already enabled from a previous app session.
    private func refreshActivatedSystemExtensionIfNeeded() {
        guard !didSubmitLaunchActivationRefresh,
              signerHelperManager.isReady else {
            return
        }
        switch systemExtensionManager.extensionState {
        case .unknown, .activated:
            didSubmitLaunchActivationRefresh = true
            systemExtensionManager.activate()
        default:
            break
        }
    }

    private func refreshDaemonArmingReadiness(reevaluateAutoArm: Bool = false) {
        daemonProbeGeneration += 1
        let generation = daemonProbeGeneration
        daemonUpWithPolicy = false
        Task {
            let ready = await DaemonArmingProbe.authenticatedDaemonPresent()
            await MainActor.run {
                guard daemonProbeGeneration == generation else { return }
                daemonUpWithPolicy = ready
                if ready && reevaluateAutoArm {
                    evaluateAutoArm()
                }
            }
        }
    }

    @MainActor
    private func recheckDaemonArmingReadinessNow() async -> Bool {
        daemonProbeGeneration += 1
        let generation = daemonProbeGeneration
        daemonUpWithPolicy = false
        let ready = await DaemonArmingProbe.authenticatedDaemonPresent()
        guard daemonProbeGeneration == generation else {
            return false
        }
        daemonUpWithPolicy = ready
        return ready
    }

    /// Auto-arm, re-evaluated on every refresh path - not a one-shot.
    /// Only acts from a settled "filter off" state so transient states
    /// (.loading at startup, .enabling mid-arm) and sticky ones
    /// (.needsUserApproval, .error - which need the operator) never loop.
    private func evaluateAutoArm() {
        guard filterConfigurationManager.filterState == .disabled else { return }
        // Auto-arm only drives from clean sysext states. In-flight, error,
        // needs-approval, and reboot-gated states are operator territory - a
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

    /// Arm the wall. Fail-closed: re-probe the daemon at gesture time with the
    /// authenticated daemon-readiness check and bail (never partially arm) if
    /// the gate no longer passes. Also refuses to arm while a disarm attempt is
    /// pending/unverified - the filter's true state is unknown then, and the
    /// operator's standing order is "down".
    private func armProtection() {
        Task {
            await armProtectionAfterProbe()
        }
    }

    @MainActor
    private func armProtectionAfterProbe() async {
        guard !filterConfigurationManager.disarmPending else { return }
        guard await recheckDaemonArmingReadinessNow() else { return }
        guard canArm else { return }

        operatorDisarmed = false

        switch systemExtensionManager.extensionState {
        case .activated:
            // Re-submit the activation request so a newer bundled extension
            // version replaces a running older one. macOS calls
            // actionForReplacingExtension (-> .replace) only on a version diff
            // and completes silently when unchanged; when activation completes,
            // the extension-state observer re-probes before enabling the filter.
            systemExtensionManager.activate()
        case .activating, .deactivating, .activatedRequiresReboot, .needsUserApproval:
            // In-flight, reboot-gated, or parked on the System Settings sysext
            // approval: nothing sensible to re-submit now. The
            // onChange(extensionState) hook finishes arming when activation
            // lands.
            break
        case .unknown, .deactivated, .error:
            // .error reachable only via the manual Arm button (auto-arm skips
            // it) - an explicit operator retry.
            systemExtensionManager.activate()
        }
    }

    @MainActor
    private func enableFilterAfterActivationIfAllowed() async {
        guard filterConfigurationManager.filterState != .enabled,
              filterConfigurationManager.filterState != .enabling,
              !operatorDisarmed else {
            return
        }
        guard await recheckDaemonArmingReadinessNow() else { return }
        guard canArm else { return }
        filterConfigurationManager.enableFilter()
    }

    /// Disarm the wall. Unconditional, and sticky: sets the operator-disarm
    /// latch so auto-arm does not immediately re-arm.
    private func disarmProtection() {
        operatorDisarmed = true
        filterConfigurationManager.disableFilter()
    }

    // MARK: - Badges (posture truth + local install/config)

    /// Local install/config status pill: surfaces the LOCAL sysext / filter /
    /// signer-helper state so the operator can see what still needs approval or
    /// activation. This is install/config context
    /// ONLY - it is explicitly NOT a protection determination and can NEVER show
    /// green for "armed". The single evidence-gated green source is `armBadge`
    /// below. Reuses the same `configHintColor`/`configHintLabel` derivation the
    /// posture badge uses for its (non-green) fallback, so the two never drift.
    private var sysextStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(configHintColor)
                .frame(width: 8, height: 8)
            Text(configHintLabel)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(configHintColor.opacity(0.1))
        .cornerRadius(12)
        .help("Local install/config state (helper, system extension, filter). Not a protection guarantee - the armed/protected truth is the badge to the right.")
    }

    /// The protection badge. Piece B: its GREEN now comes solely from the
    /// evidence-gated arm state (`/api/posture/castle-wall`), NOT from local
    /// sysext/filter/signer state. The local install/config state is surfaced
    /// only as secondary, clearly-labeled "install/config" context when the wall
    /// is not evidenced-armed - it can never produce green on its own. This kills
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
    /// else is amber/red/gray - never green from local config alone.
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
            // state as the reason, labeled as config - not as "protected."
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
            // we must NOT say "signed" - the two surfaces read the same source and
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
        if signerHelperManager.helperState == .requiresApproval ||
            signerHelperManager.helperState == .registering {
            return .yellow
        }
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

    /// Secondary install/config label. Never says "protected" - that word is
    /// reserved for the evidence-gated `.armed` state above.
    private var configHintLabel: String {
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
        // Nothing is installed locally (fresh / uninstalled Mac): say so. We are
        // NOT "checking enforcement" - there is nothing installed to check. This
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
        case .registering:
            // Post-register settle window. Visible so the operator sees
            // registration in progress.
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
            // Post-register fallthrough. If a register attempt was made and BTM
            // still reports nothing, give the operator an explicit path (retry
            // + the settings pane) instead of nothing.
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
