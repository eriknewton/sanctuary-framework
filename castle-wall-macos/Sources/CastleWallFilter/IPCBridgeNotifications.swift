//
// IPCBridgeNotifications.swift
//
// Notification surface for the IPC bridge between the macOS extension and
// Sanctuary main. Pure shape: this module assembles outbound `IpcMessage`
// values for `flow_decision_recorded` and `flow_pending_approval`, and
// applies inbound `manifest_updated` notifications to the local
// ManifestStore + FlowCache. The actual transport is owned by the IPC
// client; this file is the wiring between the filter substrate and that
// client.
//
// Splitting this out keeps the filter provider's NEFilterDataProvider
// callback paths thin and the message-shape surface unit-testable.
//
// Source: Castle Wall macOS Phase 1 packet filter + manifest sync spawn
// prompt (2026-05-11), section "Server-side IPC additions".
//

import Foundation
import CastleWallIPC

/// Generates a fresh request id matching the wire convention (16 bytes
/// hex-encoded => 32 chars).
public enum RequestIdGenerator {
    public static func make() -> String {
        var bytes = [UInt8](repeating: 0, count: CastleWallConstants.requestIdNonceBytes)
        let result = bytes.withUnsafeMutableBufferPointer { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return -1 }
            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, base)
        }
        precondition(result == errSecSuccess, "SecRandomCopyBytes failed for request id")
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
}

/// Builders + appliers used by the filter provider and by tests.
public enum IPCBridgeNotifications {

    /// Build the `manifest_subscribe` message the extension sends at start.
    public static func buildSubscribeRequest(requestId: String = RequestIdGenerator.make()) -> IpcMessage {
        return .manifestSubscribe(requestId: requestId)
    }

    /// Build a `flow_decision_recorded` notification from an evaluator
    /// outcome. Only allow / drop outcomes are encodable; an uncertain
    /// outcome routes through `buildFlowPendingApproval` instead.
    public static func buildFlowDecisionRecorded(
        outcome: EvaluationOutcome,
        flow: FilterFlowDescriptor,
        recordedAt: Date = Date()
    ) -> IpcMessage? {
        let decision: String
        let matchedRuleId: String?
        switch outcome {
        case .allow(let ruleId):
            decision = "allow"
            matchedRuleId = ruleId
        case .drop(let ruleId):
            decision = "drop"
            matchedRuleId = ruleId
        case .uncertain:
            return nil
        }
        let body = FlowDecisionRecordedBody(
            decision: decision,
            destination: destinationFor(flow: flow),
            agent: agentFor(flow: flow),
            matchedRuleId: matchedRuleId,
            recordedAt: iso8601(recordedAt)
        )
        return .flowDecisionRecorded(body)
    }

    /// Build a `flow_pending_approval` notification for an uncertain flow.
    public static func buildFlowPendingApproval(
        flow: FilterFlowDescriptor,
        requestId: String = RequestIdGenerator.make(),
        expiresInSeconds: UInt32 = 30
    ) -> IpcMessage {
        let body = FlowPendingApprovalBody(
            requestId: requestId,
            destination: destinationFor(flow: flow),
            agent: agentFor(flow: flow),
            surface: "egress",
            expiresInSeconds: expiresInSeconds
        )
        return .flowPendingApproval(body)
    }

    /// Apply an inbound `manifest_updated` notification to the local
    /// ManifestStore + FlowCache. Returns the new snapshot for inspection
    /// in tests.
    @discardableResult
    public static func applyManifestUpdated(
        message: IpcMessage,
        store: ManifestStore,
        cache: FlowCache,
        pinnedPublicKey: Data,
        now: Date = Date(),
        engine: FlowEvaluatorEngine? = nil
    ) -> ManifestSnapshot? {
        guard case .manifestUpdated(let body) = message else {
            return nil
        }
        let snapshot: ManifestSnapshot
        do {
            snapshot = try SignedManifestVerifier.verifiedSnapshot(
                from: body,
                pinnedPublicKey: pinnedPublicKey,
                now: now
            )
        } catch {
            CastleWallLog.ipc.notice(
                "manifest_updated rejected by extension verifier: \(String(describing: error))"
            )
            return nil
        }
        do {
            try store.persistLastValidManifest(body)
        } catch {
            CastleWallLog.ipc.notice(
                "last valid manifest persistence failed: \(String(describing: error))"
            )
        }
        store.update(snapshot)
        cache.clear()
        installAgentOriginIfPresent(snapshot: snapshot, engine: engine)
        CastleWallLog.ipc.notice("manifest applied; rule_count=\(snapshot.rules.count)")
        return snapshot
    }

    /// Install a verified `agentOrigin` descriptor onto the engine, when the
    /// signed snapshot carried a usable one.
    ///
    /// FAIL-CLOSED: when the snapshot carries NO descriptor, the existing
    /// retained descriptor is left untouched (pre-seed retention) -- it is
    /// NEVER cleared to a more-permissive state on a manifest update that
    /// happens to omit the field. A structurally-unusable wire descriptor
    /// (`AgentOriginDescriptor(wire:)` returns nil) is likewise ignored, so
    /// a half-built descriptor cannot mis-resolve a flow as operator.
    static func installAgentOriginIfPresent(
        snapshot: ManifestSnapshot,
        engine: FlowEvaluatorEngine?
    ) {
        guard let engine, let wire = snapshot.agentOrigin else {
            return
        }
        guard let descriptor = AgentOriginDescriptor(wire: wire) else {
            CastleWallLog.ipc.notice(
                "agent_origin present but structurally unusable; ignoring (fail-closed)"
            )
            return
        }
        engine.updateAgentOrigin(descriptor)
        CastleWallLog.ipc.notice("agent_origin installed; mode=\(descriptor.mode.rawValue)")
    }

    /// Recover the last persisted valid manifest after extension restart.
    /// Returns nil and leaves the active snapshot empty when no valid
    /// persisted manifest exists, preserving fail-closed startup.
    @discardableResult
    public static func recoverPersistedManifest(
        store: ManifestStore,
        cache: FlowCache,
        pinnedPublicKey: Data,
        now: Date = Date(),
        engine: FlowEvaluatorEngine? = nil
    ) -> ManifestSnapshot? {
        let body: ManifestUpdatedBody?
        do {
            body = try store.loadPersistedManifest()
        } catch {
            CastleWallLog.ipc.notice(
                "last valid manifest load failed: \(String(describing: error))"
            )
            return nil
        }
        guard let body else {
            return nil
        }
        let snapshot: ManifestSnapshot
        do {
            snapshot = try SignedManifestVerifier.verifiedSnapshot(
                from: body,
                pinnedPublicKey: pinnedPublicKey,
                now: now
            )
        } catch {
            CastleWallLog.ipc.notice(
                "persisted manifest rejected by extension verifier: \(String(describing: error))"
            )
            return nil
        }
        store.update(snapshot)
        cache.clear()
        installAgentOriginIfPresent(snapshot: snapshot, engine: engine)
        return snapshot
    }

    // MARK: - Helpers

    static func destinationFor(flow: FilterFlowDescriptor) -> IpcDestination {
        return IpcDestination(
            host: flow.destinationHost,
            ip: flow.destinationIp,
            port: UInt16(clamping: flow.destinationPort),
            protocolName: flow.networkProtocol.rawValue,
            hostnameSource: flow.hostnameSource,
            opaque: flow.opaqueDestination
        )
    }

    static func agentFor(flow: FilterFlowDescriptor) -> IpcAgentAttribution {
        return IpcAgentAttribution(id: flow.agentId, template: flow.templateId)
    }

    static func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}
