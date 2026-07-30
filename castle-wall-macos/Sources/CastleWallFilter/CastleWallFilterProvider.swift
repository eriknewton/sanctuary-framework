//
// CastleWallFilterProvider.swift
//
// NEFilterDataProvider subclass: Castle Layer 1 macOS surface.
//
// Alpha-1 (PR #150): subclass exists, lifecycle hooks compile against the
// NetworkExtension framework, `startFilter` opens the IPC client toward
// Sanctuary main and idles. No actual packet decisions returned.
//
// Alpha-2 (this build) wires:
//   - ManifestStore + FlowCache + AllowlistEvaluator into the verdict path.
//   - IPCBridgeNotifications for flow_decision_recorded + flow_pending_approval.
//   - Subscribe-to-manifest_updated wiring from the runtime.
//
// `handleNewFlow(_:)` extracts a FilterFlowDescriptor from the
// NEFilterFlow and delegates to `evaluate(_:)` which is fully testable
// without the NetworkExtension framework.
//
// Failure mode (per spawn prompt):
//   - At extension start, if IPC handshake fails, `startFilter` returns
//     pass (refuse-to-load) so the extension does not silently break
//     all egress while the operator's Sanctuary main side is misconfigured.
//   - Mid-flight, if IPC drops AND no cached manifest is loaded yet, the
//     evaluator answers `drop` (fail-closed) so a wrapped agent that has
//     never seen the manifest cannot exfiltrate while the runtime is down.
//   - Mid-flight, if IPC drops AND a cached manifest IS loaded, the
//     evaluator keeps deny/default-deny semantics from the snapshot, but
//     refuses agent allow/prompt outcomes until a fresh arm lease arrives.
//     Operator-baseline flows remain reachable.
//

import Foundation
import NetworkExtension
import CastleWallIPC
import Darwin

/// Hook the test target uses to inject a fake (agentId, templateId) mapper.
/// Phase 1 default returns `(sourceAppIdentifier, "unknown")` so a wrapped
/// agent's flows are scoped per source app and pattern-match on `agent_ids`
/// against the source app identifier. The real wrapped-agent registry
/// surface lands in a follow-up.
public typealias AgentResolver = (String) -> (agentId: String, templateId: String)

@objc(CastleWallFilterProvider)
public final class CastleWallFilterProvider: NEFilterDataProvider {
    // MARK: - State

    /// Pure-Swift substrate: manifest store + flow cache + verdict logic.
    /// The provider delegates verdict decisions to the engine; test
    /// targets exercise the engine directly so they do not need to
    /// instantiate `NEFilterDataProvider` (which sysextd expects to set
    /// up).
    private let engine: FlowEvaluatorEngine
    private var ipcClient: IPCClient?
    /// Alpha-3 dispatcher that wires the verdict path to IPC notifications.
    /// Nil until `startFilter` completes the handshake successfully; the
    /// FilterProvider's verdict path still runs against the engine even
    /// when the dispatcher is absent (refuse-to-load fallback).
    private var dispatcher: ExtensionDispatcher?
    private let bootstrapQueue = DispatchQueue(
        label: "ai.sanctuaryprotocol.castle-wall.provider-bootstrap"
    )
    private var bootstrapTimer: DispatchSourceTimer?
    private var bootstrapRetryDelaySeconds: TimeInterval = 1.0

    // MARK: - Init

    /// Framework-driven init. sysextd calls this when the system extension
    /// loads; the engine is constructed with default substrate. Test
    /// targets do NOT instantiate this class; they use
    /// `FlowEvaluatorEngine` directly.
    public override init() {
        self.engine = FlowEvaluatorEngine(
            manifestStore: ManifestStore(
                lastValidManifestURL: ManifestStore.defaultLastValidManifestURL()
            )
        )
        super.init()
    }

    // MARK: - Lifecycle

    public override func startFilter(
        completionHandler: @escaping (Error?) -> Void
    ) {
        CastleWallLog.lifecycle.info("CastleWallFilterProvider.startFilter invoked")
        bootstrapDispatcherIfNeeded(reason: "startFilter")
        completionHandler(nil)
    }

    public override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        CastleWallLog.lifecycle.info("CastleWallFilterProvider.stopFilter reason=\(reason.rawValue)")
        bootstrapQueue.sync {
            bootstrapTimer?.cancel()
            bootstrapTimer = nil
            bootstrapRetryDelaySeconds = 1.0
        }
        dispatcher?.stop()
        dispatcher = nil
        ipcClient?.close()
        ipcClient = nil
        completionHandler()
    }

    private func bootstrapDispatcherIfNeeded(reason: String) {
        bootstrapQueue.async { [weak self] in
            guard let self else { return }
            guard self.dispatcher == nil else { return }

            let resolved = SocketPath.resolve(
                platform: "darwin",
                fortressPath: ProcessInfo.processInfo.environment["SANCTUARY_FORTRESS_PATH"],
                homeDir: NSHomeDirectory(),
                explicitOverride: ProcessInfo.processInfo.environment["SANCTUARY_CASTLE_SOCKET"]
            )
            CastleWallLog.lifecycle.notice(
                "ipc socket path resolved: \(resolved.path) (\(resolved.source.rawValue)); bootstrap_reason=\(reason)"
            )
            let diagnostics = resolved.diagnostics
            CastleWallLog.lifecycle.notice(
                "ipc socket diagnostics: active_config=\(diagnostics.activeConfigPath ?? "none") active_status=\(diagnostics.activeConfigStatus ?? "not_checked") legacy_config=\(diagnostics.legacyActiveConfigPath ?? "none") legacy_status=\(diagnostics.legacyActiveConfigStatus ?? "not_checked") selected_config=\(diagnostics.selectedConfigPath ?? "fallback") selected_fortress=\(diagnostics.selectedFortressPath ?? "none") env_fortress=\(ProcessInfo.processInfo.environment["SANCTUARY_FORTRESS_PATH"] ?? "none")"
            )

            let keyLoad: (path: URL, key: Data)
            do {
                keyLoad = try self.loadPinnedPublicKey()
            } catch {
                CastleWallLog.auth.notice(
                    "pinned public key not yet provisioned (default-deny fallback): \(String(describing: error))"
                )
                self.scheduleBootstrapRetry(reason: "pinned key unavailable")
                return
            }
            CastleWallLog.auth.notice("using pinned public key path: \(keyLoad.path.path)")

            let loadedFingerprint = SignedManifestVerifier.sha256Hex(keyLoad.key).lowercased()
            if let activeConfig = Self.activeConfigFingerprint(forSocketPath: resolved.path),
               activeConfig.pinnedPubkeySha256 != loadedFingerprint {
                CastleWallLog.auth.error(
                    "pinned key fingerprint mismatch: active-config fortress=\(activeConfig.fortressId) expects=\(Self.shortFingerprint(activeConfig.pinnedPubkeySha256)) loaded=\(Self.shortFingerprint(loadedFingerprint)); refusing stale key, will retry"
                )
                self.scheduleBootstrapRetry(reason: "pinned key fingerprint mismatch")
                return
            }

            self.bootstrapTimer?.cancel()
            self.bootstrapTimer = nil
            self.bootstrapRetryDelaySeconds = 1.0

            // Re-resolve the socket path on every (re)connect, not just at
            // bootstrap. On a fresh boot the sysext starts before the daemon,
            // so `resolved.path` here is the home-default fallback; once the
            // daemon comes up and writes its active-config, this closure lets
            // the reconnect loop pick up the real fortress path and the audit
            // back-channel reconnects (Finding B, A1 drill 2026-06-04).
            let client = IPCClient(
                options: IPCClientOptions(path: resolved.path),
                pinnedPublicKey: keyLoad.key,
                pathResolver: {
                    let rerResolved = SocketPath.resolve(
                        platform: "darwin",
                        fortressPath: ProcessInfo.processInfo.environment["SANCTUARY_FORTRESS_PATH"],
                        homeDir: NSHomeDirectory(),
                        explicitOverride: ProcessInfo.processInfo.environment["SANCTUARY_CASTLE_SOCKET"]
                    )
                    CastleWallLog.lifecycle.notice(
                        "ipc reconnect socket diagnostics: path=\(rerResolved.path) source=\(rerResolved.source.rawValue) active_status=\(rerResolved.diagnostics.activeConfigStatus ?? "not_checked") legacy_status=\(rerResolved.diagnostics.legacyActiveConfigStatus ?? "not_checked") selected_config=\(rerResolved.diagnostics.selectedConfigPath ?? "fallback")"
                    )
                    return rerResolved.path
                }
            )
            self.ipcClient = client
            let dispatcher = ExtensionDispatcher(engine: self.engine, ipcClient: client)
            self.dispatcher = dispatcher

            Task.detached {
                let started = await dispatcher.start()
                CastleWallLog.lifecycle.notice(
                    "ExtensionDispatcher.start completed; live=\(started)"
                )
            }
        }
    }

    private func scheduleBootstrapRetry(reason: String) {
        bootstrapQueue.async { [weak self] in
            guard let self else { return }
            guard self.dispatcher == nil else { return }

            self.bootstrapTimer?.cancel()
            self.bootstrapTimer = nil

            let delay = min(30.0, max(1.0, self.bootstrapRetryDelaySeconds))
            self.bootstrapRetryDelaySeconds = min(30.0, self.bootstrapRetryDelaySeconds * 2.0)
            CastleWallLog.lifecycle.notice(
                "dispatcher bootstrap retry scheduled in \(String(format: "%.2f", delay))s; reason=\(reason)"
            )

            let timer = DispatchSource.makeTimerSource(queue: self.bootstrapQueue)
            timer.schedule(deadline: .now() + delay)
            timer.setEventHandler { [weak self] in
                guard let self else { return }
                self.bootstrapTimer = nil
                self.bootstrapDispatcherIfNeeded(reason: "bootstrap retry")
            }
            self.bootstrapTimer = timer
            timer.resume()
        }
    }

    private func loadPinnedPublicKey() throws -> (path: URL, key: Data) {
        let globalDir = "/Library/Application Support/Sanctuary"
        let globalPath = URL(fileURLWithPath: globalDir)
            .appendingPathComponent("castle-pinned-pubkey.bin")
        if FileManager.default.fileExists(atPath: globalPath.path) {
            // F-A2-2: the global pin is the A2/B2 root-owned trust anchor. Assert
            // the custody chain (root-owned file in a root-owned, non-group/other-
            // writable dir) and FAIL CLOSED on a violation — do NOT fall through
            // to the home pin, which would let an attacker delete the global pin
            // and substitute a planted home-dir key (the swap path B2 closes).
            try FileCustody().assertFile(
                globalPath.path,
                directory: globalDir,
                forbiddenFileBits: 0o022
            )
            return (path: globalPath, key: try Auth.loadPinnedPublicKey(at: globalPath))
        }

        let homePath = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent(".sanctuary")
            .appendingPathComponent("castle-pinned-pubkey.bin")
        return (path: homePath, key: try Auth.loadPinnedPublicKey(at: homePath))
    }

    struct ActiveConfigFingerprint: Equatable {
        let fortressId: String
        let pinnedPubkeySha256: String
    }

    static func activeConfigFingerprint(
        forSocketPath socketPath: String,
        configPath: String = SocketPath.activeConfigPath,
        custody: FileCustody = FileCustody(),
        loadData: (String) -> Data? = { FileManager.default.contents(atPath: $0) },
        isPidAliveFn: (Int) -> Bool = CastleWallFilterProvider.isPidAlive
    ) -> ActiveConfigFingerprint? {
        // F-A2-4: ONLY a ROOT-OWNED protected active-config may drive the
        // fingerprint trust-gate. The legacy world-writable /tmp path (and any
        // operator-owned file) is NOT consumed here — otherwise any local user
        // could plant a config with a live pid + bogus `pinned_pubkey_sha256` and
        // force a perpetual fingerprint-mismatch retry, wedging the wall's
        // bootstrap (a default-deny DoS). When the protected config is absent or
        // not root-owned, advertise NO fingerprint -> the gate is skipped and
        // bootstrap proceeds; the IPC handshake still binds the pinned key.
        // (Socket *discovery* keeps its /tmp read-fallback in SocketPath.resolve;
        // discovery is handshake-protected, so it is not a trust gate.)
        guard custody.fileIsRootOwned(configPath) else {
            return nil
        }
        guard let data = loadData(configPath) else {
            return nil
        }
        return parseActiveConfigFingerprint(
            data: data,
            forSocketPath: socketPath,
            isPidAliveFn: isPidAliveFn
        )
    }

    /// Pure parse of an active-config blob into a fingerprint, with no I/O and no
    /// ownership decision (the caller gates ownership). Extracted so the parsing
    /// invariants are unit-testable against planted bytes.
    static func parseActiveConfigFingerprint(
        data: Data,
        forSocketPath socketPath: String,
        isPidAliveFn: (Int) -> Bool = CastleWallFilterProvider.isPidAlive
    ) -> ActiveConfigFingerprint? {
        guard
            let parsed = try? JSONSerialization.jsonObject(with: data),
            let object = parsed as? [String: Any],
            let activeSocketPath = object["socket_path"] as? String,
            activeSocketPath == socketPath,
            let fortressId = object["fortress_id"] as? String,
            let pid = object["pid"] as? Int,
            pid > 0,
            isPidAliveFn(pid),
            let fingerprint = object["pinned_pubkey_sha256"] as? String,
            !fingerprint.isEmpty
        else {
            return nil
        }
        return ActiveConfigFingerprint(
            fortressId: fortressId,
            pinnedPubkeySha256: fingerprint.lowercased()
        )
    }

    static func isPidAlive(_ pid: Int) -> Bool {
        return kill(pid_t(pid), 0) == 0 || errno == EPERM
    }

    private static func shortFingerprint(_ full: String) -> String {
        return String(full.prefix(12))
    }

    // MARK: - Verdict path

    /// NEFilter callback. Extracts a descriptor from the framework flow,
    /// delegates to the engine, returns the matching verdict.
    /// Loaded-extension integration tests in Alpha-3 exercise this path
    /// against real NEFilterFlow values; unit tests in Alpha-2 drive
    /// `FlowEvaluatorEngine.evaluate(_:)` directly.
    public override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let descriptor = makeDescriptor(from: flow) else {
            return CastleWallFilterProvider.verdictForUnsupportedFlow(
                flowType: String(describing: type(of: flow))
            )
        }
        let outcome = engine.evaluate(descriptor)
        // Fire-and-forget IPC notification AFTER computing the verdict.
        // The verdict path itself never waits on IPC liveness; this call
        // hops onto the IPC client's internal queue. A slow / broken IPC
        // channel preserves the <10ms-p99 verdict latency invariant.
        dispatcher?.notifyVerdict(outcome, for: descriptor)
        return CastleWallFilterProvider.verdict(for: outcome)
    }

    /// Translate an `EvaluationOutcome` to the framework verdict. Public
    /// for unit-test assertions; the test target compares verdicts via
    /// the EvaluationOutcome shape directly when feasible.
    ///
    /// Note: `NEFilterNewFlowVerdict.needRules()` is iOS-only. On macOS
    /// the deferred-decision API is `pause()` paired with a later
    /// `resumeFlow(_:with:)` once the operator decision lands. Phase 1
    /// returns `pause()` for uncertain flows; the resume path lands in
    /// Alpha-4 with the operator-approval IPC return wiring.
    public static func verdict(for outcome: EvaluationOutcome) -> NEFilterNewFlowVerdict {
        switch outcome {
        case .allow:
            return NEFilterNewFlowVerdict.allow()
        case .drop:
            return NEFilterNewFlowVerdict.drop()
        case .uncertain:
            return NEFilterNewFlowVerdict.pause()
        }
    }

    /// Unknown/future NetworkExtension flow subclasses must fail closed.
    /// The diagnostic intentionally names only the framework flow type so
    /// operators can debug compatibility without leaking destination data.
    public static func verdictForUnsupportedFlow(
        flowType: String
    ) -> NEFilterNewFlowVerdict {
        return verdictForUnsupportedFlow(
            flowType: flowType,
            emitDiagnostic: CastleWallFilterProvider.emitUnsupportedFlowDiagnostic
        )
    }

    public static func verdictForUnsupportedFlow(
        flowType: String,
        emitDiagnostic: (String) -> Void
    ) -> NEFilterNewFlowVerdict {
        emitDiagnostic("unsupported flow shape denied: \(flowType)")
        return NEFilterNewFlowVerdict.drop()
    }

    private static func emitUnsupportedFlowDiagnostic(_ message: String) {
        CastleWallLog.lifecycle.notice("\(message)")
    }

    /// Extract the substrate the evaluator needs from the framework flow.
    /// Returns `nil` for flow shapes Phase 1 does not yet handle (browser
    /// flows fold into Alpha-3 alongside the DoH / DoT Tier B coverage).
    ///
    /// Source-app attribution: macOS exposes
    /// `sourceAppAuditToken: Data?` (a 32-byte audit-token kernel
    /// structure) as the canonical per-flow attribution surface. We retain
    /// the hex-encoded bytes as a stable identifier for audit provenance
    /// (`sourceAppIdentifier`), AND decode the token into typed fields
    /// (`ruid`, `pid`, `pidVersion`, signing identity) that the fail-closed
    /// origin classifier consumes.
    ///
    /// FAIL-CLOSED: if the token is nil or undecodable, the descriptor is
    /// marked `sourceUnattributed = true`, which the classifier maps to
    /// `.unattributed` => deny side. The decode never throws the flow open.
    public func makeDescriptor(from flow: NEFilterFlow) -> FilterFlowDescriptor? {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return nil
        }
        let tokenData = flow.sourceAppAuditToken
        let sourceAppId: String
        if let tokenData {
            sourceAppId = tokenData.map { String(format: "%02x", $0) }.joined()
        } else {
            sourceAppId = "unknown"
        }
        let agent = engine.agentResolver(sourceAppId)

        // Typed decode for origin classification. Any failure path yields a
        // `sourceUnattributed = true` descriptor (deny side).
        let decoded = AuditTokenDecode.decode(tokenData: tokenData)

        let host: String? = socketFlow.remoteHostname
        let endpoint = socketFlow.remoteEndpoint as? NWHostEndpoint
        let ip = endpoint?.hostname ?? host ?? "0.0.0.0"
        let port = Int(endpoint?.port ?? "0") ?? 0

        let proto: FlowProtocol
        switch socketFlow.socketProtocol {
        case Int32(IPPROTO_TCP):
            proto = .tcp
        case Int32(IPPROTO_UDP):
            proto = .udp
        default:
            proto = .tcp
        }

        let opaque = host == nil
        let hostnameSource: String? = host != nil ? "sni" : nil

        return FilterFlowDescriptor(
            sourceAppIdentifier: sourceAppId,
            agentId: agent.agentId,
            templateId: agent.templateId,
            destinationHost: host,
            destinationIp: ip,
            destinationPort: port,
            networkProtocol: proto,
            hostnameSource: hostnameSource,
            opaqueDestination: opaque,
            sourceRuid: decoded.ruid,
            sourcePid: decoded.pid,
            sourcePidVersion: decoded.pidVersion,
            sourceSigningId: decoded.signingId,
            sourceTeamId: decoded.teamId,
            sourceUnattributed: decoded.unattributed
        )
    }
}
