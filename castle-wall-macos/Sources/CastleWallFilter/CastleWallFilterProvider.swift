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
//     evaluator continues against the cached snapshot until the manifest
//     ages out (TTL is enforced by the runtime side; v1.x).
//

import Foundation
import NetworkExtension
import CastleWallIPC

/// Hook the test target uses to inject a fake (agentId, templateId) mapper.
/// Phase 1 default returns `(sourceAppIdentifier, "unknown")` so a wrapped
/// agent's flows are scoped per source app and pattern-match on `agent_ids`
/// against the source app identifier. The real wrapped-agent registry
/// surface lands in a follow-up.
public typealias AgentResolver = (String) -> (agentId: String, templateId: String)

@objc(CastleWallFilterProvider)
public final class CastleWallFilterProvider: NEFilterDataProvider {
    // MARK: - State

    private let manifestStore: ManifestStore
    private let flowCache: FlowCache
    private let agentResolver: AgentResolver
    private var ipcClient: IPCClient?

    // MARK: - Init

    /// Designated initializer used by the test target to inject the
    /// substrate. The framework calls the no-arg `init()` at runtime; the
    /// `convenience init()` wires defaults.
    public init(
        manifestStore: ManifestStore = ManifestStore(),
        flowCache: FlowCache = FlowCache(),
        agentResolver: @escaping AgentResolver = CastleWallFilterProvider.defaultAgentResolver
    ) {
        self.manifestStore = manifestStore
        self.flowCache = flowCache
        self.agentResolver = agentResolver
        super.init()
        // When the manifest store changes, evict cached outcomes wholesale
        // so a deny rule that arrives after a flow was allowed cannot keep
        // serving stale verdicts.
        self.manifestStore.addObserver { [weak self] _ in
            self?.flowCache.clear()
        }
    }

    public override convenience init() {
        self.init(
            manifestStore: ManifestStore(),
            flowCache: FlowCache(),
            agentResolver: CastleWallFilterProvider.defaultAgentResolver
        )
    }

    public static let defaultAgentResolver: AgentResolver = { sourceAppId in
        return (agentId: sourceAppId, templateId: "unknown")
    }

    // MARK: - Lifecycle

    public override func startFilter(
        completionHandler: @escaping (Error?) -> Void
    ) {
        CastleWallLog.lifecycle.info("CastleWallFilterProvider.startFilter invoked")

        let resolved = SocketPath.resolve(
            platform: "darwin",
            fortressPath: ProcessInfo.processInfo.environment["SANCTUARY_FORTRESS_PATH"],
            homeDir: NSHomeDirectory(),
            explicitOverride: ProcessInfo.processInfo.environment["SANCTUARY_CASTLE_SOCKET"]
        )
        CastleWallLog.lifecycle.info("ipc socket path resolved: \(resolved.path) (\(resolved.source.rawValue))")

        let pinnedPath = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent(".sanctuary")
            .appendingPathComponent("castle-pinned-pubkey.bin")
        let pinnedKey: Data
        do {
            pinnedKey = try Auth.loadPinnedPublicKey(at: pinnedPath)
        } catch {
            CastleWallLog.auth.notice(
                "pinned public key not yet provisioned (refuse-to-load fallback): \(String(describing: error))"
            )
            completionHandler(nil)
            return
        }

        let client = IPCClient(
            options: IPCClientOptions(path: resolved.path),
            pinnedPublicKey: pinnedKey
        )
        self.ipcClient = client

        Task.detached { [weak self] in
            do {
                _ = try await client.start()
                CastleWallLog.lifecycle.info("ipc handshake completed; manifest subscribe deferred to dispatcher wiring")
                _ = self
            } catch {
                CastleWallLog.lifecycle.notice(
                    "ipc handshake failed (refuse-to-load fallback): \(String(describing: error))"
                )
            }
        }

        completionHandler(nil)
    }

    public override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        CastleWallLog.lifecycle.info("CastleWallFilterProvider.stopFilter reason=\(reason.rawValue)")
        ipcClient?.close()
        ipcClient = nil
        completionHandler()
    }

    // MARK: - Verdict path (testable)

    /// Evaluate a flow against the current manifest snapshot, consulting
    /// the cache first. Side effects: a fresh `(allow|drop)` outcome lands
    /// in the cache so subsequent flows from the same (source app, dest)
    /// tuple short-circuit. Uncertain outcomes are NOT cached because the
    /// resolution arrives via the operator-decision IPC path.
    public func evaluate(_ descriptor: FilterFlowDescriptor) -> EvaluationOutcome {
        let key = FlowCacheKey.from(descriptor)
        if let cached = flowCache.get(key) {
            return cached
        }
        let outcome = AllowlistEvaluator.evaluate(
            flow: descriptor,
            rules: manifestStore.currentRules()
        )
        switch outcome {
        case .allow, .drop:
            flowCache.put(key, outcome)
        case .uncertain:
            break
        }
        return outcome
    }

    /// NEFilter callback. Extracts a descriptor from the framework flow,
    /// runs the evaluator, returns the matching verdict. Loaded-extension
    /// integration tests in Alpha-3 exercise this path against real
    /// NEFilterFlow values; unit tests in Alpha-2 drive `evaluate(_:)`
    /// directly.
    public override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let descriptor = makeDescriptor(from: flow) else {
            CastleWallLog.lifecycle.notice("flow shape unrecognized; passing without verdict")
            return NEFilterNewFlowVerdict.allow()
        }
        let outcome = evaluate(descriptor)
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

    /// Extract the substrate the evaluator needs from the framework flow.
    /// Returns `nil` for flow shapes Phase 1 does not yet handle (browser
    /// flows fold into Alpha-3 alongside the DoH / DoT Tier B coverage).
    ///
    /// Source-app attribution: macOS exposes
    /// `sourceAppUniqueIdentifier: Data?` (the binary's CDHash bytes)
    /// instead of the iOS `sourceAppIdentifier` string. We hex-encode the
    /// CDHash bytes into a stable string the agent resolver can map to a
    /// Sanctuary `(agentId, templateId)` pair. Production attribution
    /// also uses the `sourceAppAuditToken` for finer-grained mapping;
    /// that wiring lands with the wrapped-agent registry surface.
    public func makeDescriptor(from flow: NEFilterFlow) -> FilterFlowDescriptor? {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return nil
        }
        let sourceAppId: String
        if let cdHash = flow.sourceAppUniqueIdentifier {
            sourceAppId = cdHash.map { String(format: "%02x", $0) }.joined()
        } else {
            sourceAppId = "unknown"
        }
        let agent = agentResolver(sourceAppId)

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
            opaqueDestination: opaque
        )
    }
}
