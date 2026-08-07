//
// AuditProducerSigning.swift
//
// macOS Slice M: per-flow audit-producer signing on the system-extension side.
// The private key is owned by the root helper's audit-producer Mach service and
// that service is pinned to the system extension bundle identifier, not the
// generic signer-client shim the TypeScript daemon can spawn.
//

import Foundation
import CryptoKit
import CastleWallIPC
import CastleWallSigner

public enum AuditProducerSigningError: Error, Equatable {
    case unsupportedOutcome
    case canonicalizationFailed(String)
    case signerUnavailable(String)
    case emptySignature
    case statePersistenceFailed(String)
    case chainAdvancedBeforeSignReply
}

public enum AuditProducerSigningConstants {
    public static let keyId = "cw-audit-producer-v1"
    public static let domainPrefix = "sanctuary.castle-wall.audit-producer.v1\n"
}

public struct AuditProducerChainState: Codable, Equatable {
    public let schemaVersion: Int
    public let nextSeq: UInt64
    public let priorSha256Hex: String?

    public init(
        schemaVersion: Int = 1,
        nextSeq: UInt64,
        priorSha256Hex: String?
    ) {
        self.schemaVersion = schemaVersion
        self.nextSeq = nextSeq
        self.priorSha256Hex = priorSha256Hex
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case nextSeq = "next_seq"
        case priorSha256Hex = "prior_sha256_hex"
    }
}

public protocol AuditProducerChainStateStore {
    func load() throws -> AuditProducerChainState?
    func save(_ state: AuditProducerChainState) throws
}

public enum AuditProducerChainStateError: Error, Equatable, CustomStringConvertible {
    case invalid(String)

    public var description: String {
        switch self {
        case .invalid(let reason):
            return reason
        }
    }
}

public final class FileAuditProducerChainStateStore: AuditProducerChainStateStore {
    private let url: URL

    public init(url: URL) {
        self.url = url
    }

    public static func defaultURL() -> URL? {
        guard let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            return nil
        }
        return base
            .appendingPathComponent("Sanctuary", isDirectory: true)
            .appendingPathComponent("CastleWall", isDirectory: true)
            .appendingPathComponent("audit-producer-chain-state.json")
    }

    public static func defaultStore() -> AuditProducerChainStateStore {
        guard let url = defaultURL() else {
            return UnavailableAuditProducerChainStateStore(
                reason: "application support directory unavailable"
            )
        }
        return FileAuditProducerChainStateStore(url: url)
    }

    public func load() throws -> AuditProducerChainState? {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }
        let data = try Data(contentsOf: url)
        let state = try JSONDecoder().decode(AuditProducerChainState.self, from: data)
        try Self.validate(state)
        return state
    }

    public func save(_ state: AuditProducerChainState) throws {
        try Self.validate(state)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(state)
        try data.write(to: url, options: [.atomic])
    }

    public static func validate(_ state: AuditProducerChainState) throws {
        guard state.schemaVersion == 1 else {
            throw AuditProducerChainStateError.invalid("unsupported schema_version \(state.schemaVersion)")
        }
        if state.nextSeq == 0 {
            guard state.priorSha256Hex == nil else {
                throw AuditProducerChainStateError.invalid("genesis state must not carry prior_sha256_hex")
            }
            return
        }
        guard let prior = state.priorSha256Hex else {
            throw AuditProducerChainStateError.invalid("non-genesis state must carry prior_sha256_hex")
        }
        guard prior.count == 64 && prior.allSatisfy({ $0.isHexDigit }) else {
            throw AuditProducerChainStateError.invalid("prior_sha256_hex must be a 64-character hex digest")
        }
    }
}

public final class UnavailableAuditProducerChainStateStore: AuditProducerChainStateStore {
    private let reason: String

    public init(reason: String) {
        self.reason = reason
    }

    public func load() throws -> AuditProducerChainState? {
        throw AuditProducerChainStateError.invalid(reason)
    }

    public func save(_ state: AuditProducerChainState) throws {
        throw AuditProducerChainStateError.invalid(reason)
    }
}

/// Explicit test seam for flows that need the pre-existing in-memory behavior.
/// Production uses `FileAuditProducerChainStateStore.defaultStore()`, which
/// returns a failing store rather than silently losing durability.
public final class VolatileAuditProducerChainStateStore: AuditProducerChainStateStore {
    public init() {}

    public func load() throws -> AuditProducerChainState? {
        return nil
    }

    public func save(_ state: AuditProducerChainState) throws {}
}

public protocol AuditProducerSigning {
    func signAuditProducerPayload(
        _ payload: Data,
        reply: @escaping (_ signature: Data?, _ error: String?) -> Void
    )
}

public final class XpcAuditProducerSigner: AuditProducerSigning {
    /// Self-deadline for a single privileged XPC sign call. Drill Leg 3
    /// (2026-07-15) found the reply can be DROPPED with the proxy error handler
    /// ALSO not firing; since the old code only ever `invalidate()`d the
    /// connection from inside those two handlers, a dropped reply leaked one
    /// privileged `NSXPCConnection` (plus its retained reply-closure graph, mach
    /// port, and fd) PER stalled flow, indefinitely, in the resource-constrained
    /// sysext (Opus re-gate F5). This deadline invalidates the connection and
    /// replies with a timeout if neither handler fires, so a sustained signer
    /// outage reclaims each connection instead of accumulating them. Kept
    /// slightly above the chain-level watchdog so the chain reports the loud
    /// drop first; both are independent one-shots.
    private let signCallTimeoutSeconds: TimeInterval

    public init(signCallTimeoutSeconds: TimeInterval = 6.0) {
        self.signCallTimeoutSeconds = signCallTimeoutSeconds
    }

    public func signAuditProducerPayload(
        _ payload: Data,
        reply: @escaping (Data?, String?) -> Void
    ) {
        let connection = NSXPCConnection(
            machServiceName: SignerConstants.auditProducerMachServiceName,
            options: .privileged
        )
        connection.remoteObjectInterface =
            NSXPCInterface(with: CastleWallSignerXPCProtocol.self)
        connection.resume()

        // Fire-EXACTLY-once terminator shared by the reply, the proxy error
        // handler, and the self-deadline. EVERY path invalidates the connection
        // (reclaiming it in the success, error, AND dropped-reply cases), then
        // delivers the reply once. Guarantees no connection leak and no double
        // reply regardless of which of the three fires.
        let replyLock = NSLock()
        var replied = false
        let finishOnce: (Data?, String?) -> Void = { signature, error in
            replyLock.lock()
            if replied {
                replyLock.unlock()
                return
            }
            replied = true
            replyLock.unlock()
            connection.invalidate()
            reply(signature, error)
        }

        // Cancellable self-deadline (F6): a fast success cancels it immediately
        // rather than retaining the closure graph for the full timeout.
        let deadline = DispatchWorkItem {
            finishOnce(
                nil,
                "audit producer sign call timed out; connection reclaimed"
            )
        }
        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + signCallTimeoutSeconds,
            execute: deadline
        )

        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            finishOnce(nil, "audit producer helper unreachable: \(error.localizedDescription)")
        }
        guard let signer = proxy as? CastleWallSignerXPCProtocol else {
            deadline.cancel()
            finishOnce(nil, "audit producer helper proxy unavailable")
            return
        }
        signer.sign(
            payload: payload,
            purpose: SignerConstants.SignPurpose.auditProducer
        ) { signature, error in
            deadline.cancel()
            finishOnce(signature, error)
        }
    }
}

public final class AuditProducerChain {
    private var nextSeq: UInt64
    private var priorHashHex: String?
    private let stateStore: AuditProducerChainStateStore
    private var stateLoadError: Error?
    private let stateQueue = DispatchQueue(
        label: "ai.sanctuaryprotocol.castle-wall.audit-producer-chain"
    )
    /// Watchdog deadline for a single sign call's completion. Drill Leg 3
    /// (2026-07-15) found per-flow audit emission stops SILENTLY ~350ms after
    /// bind: the XPC sign reply from the root audit-producer helper stopped
    /// arriving and NEITHER the reply block NOR the proxy error handler fired,
    /// so `buildSignedFlowDecision`'s completion never ran, so `notifyVerdict`
    /// emitted nothing AND logged no drop line (the wall kept enforcing, the
    /// record of it vanished). NSXPC does not guarantee a reply block runs if
    /// the connection is torn down mid-call, so a per-call watchdog is required
    /// to bound it: if neither reply nor error arrives within this window, the
    /// completion is fired with a signing-failure so the flow surfaces on the
    /// EXISTING loud drop path (`[slice-m-audit-drop] path=signing-failure`)
    /// instead of vanishing (AGENTS.md rule 5: never silently degrade). The
    /// wedged connection itself is reclaimed by `XpcAuditProducerSigner`'s own
    /// self-deadline (see there), so a sustained outage neither goes silent nor
    /// leaks a connection per flow; each subsequent flow opens a fresh one.
    private let signTimeoutSeconds: TimeInterval
    /// Queue the watchdog timer fires on. MUST be distinct from `stateQueue`
    /// (the completion path takes `stateQueue.sync`, which would deadlock if the
    /// watchdog ran on it).
    private let timeoutQueue = DispatchQueue(
        label: "ai.sanctuaryprotocol.castle-wall.audit-producer-chain.timeout"
    )

    public init(
        nextSeq: UInt64 = 0,
        priorHashHex: String? = nil,
        signTimeoutSeconds: TimeInterval = 5.0,
        stateStore: AuditProducerChainStateStore = FileAuditProducerChainStateStore.defaultStore()
    ) {
        var initialNextSeq = nextSeq
        var initialPriorHashHex = priorHashHex
        var initialLoadError: Error?
        if nextSeq == 0 && priorHashHex == nil {
            do {
                if let loaded = try stateStore.load() {
                    initialNextSeq = loaded.nextSeq
                    initialPriorHashHex = loaded.priorSha256Hex
                }
            } catch {
                initialLoadError = error
            }
        }
        self.nextSeq = initialNextSeq
        self.priorHashHex = initialPriorHashHex
        self.stateStore = stateStore
        self.stateLoadError = initialLoadError
        self.signTimeoutSeconds = signTimeoutSeconds
    }

    public func buildSignedFlowDecision(
        outcome: EvaluationOutcome,
        flow: FilterFlowDescriptor,
        enforcement: EnforcementAvailabilitySnapshotBody? = nil,
        recordedAt: Date = Date(),
        signer: AuditProducerSigning,
        completion: @escaping (Result<IpcMessage, AuditProducerSigningError>) -> Void
    ) {
        let pending: PendingDecision
        do {
            pending = try stateQueue.sync {
                try buildPendingDecisionLocked(
                    outcome: outcome,
                    flow: flow,
                    enforcement: enforcement,
                    recordedAt: recordedAt
                )
            }
        } catch let error as AuditProducerSigningError {
            completion(.failure(error))
            return
        } catch {
            completion(.failure(.canonicalizationFailed("\(error)")))
            return
        }

        // Fire-EXACTLY-once guard shared by the real reply and the watchdog. On
        // the WINNING success it advances the producer chain (seq/prior-hash);
        // a lost/late reply is a no-op, so the chain never advances for a flow
        // that was reported as dropped (the NEXT flow reuses the same seq, which
        // is correct: nothing was sent for the dropped one).
        // Fire-EXACTLY-once guard shared by the real reply and the watchdog. On
        // the WINNING success it advances the producer chain (seq/prior-hash);
        // a lost/late reply is a no-op, so the chain never advances for a flow
        // that was reported as dropped (the NEXT flow reuses the same seq, which
        // is correct: nothing was sent for the dropped one). The watchdog is a
        // plain `asyncAfter` (not a cancellable work item): on a fast success it
        // still fires at the deadline but is an immediate no-op via `didComplete`,
        // so its only cost is holding this small closure for the bounded timeout
        // (never a leak). A cancellable work item was rejected because cancelling
        // it from `finish` would require `finish` to capture the item, forming a
        // retain cycle that drains no earlier than the same deadline.
        let completionLock = NSLock()
        var didComplete = false
        let finish: (Result<IpcMessage, AuditProducerSigningError>, (seq: UInt64, hash: String)?) -> Void = { [weak self] result, advance in
            completionLock.lock()
            if didComplete {
                completionLock.unlock()
                return
            }
            didComplete = true
            completionLock.unlock()
            if let advance, let self {
                if let error = self.advanceAfterSignedResult(
                    seq: advance.seq,
                    hash: advance.hash
                ) {
                    completion(.failure(error))
                    return
                }
            }
            completion(result)
        }

        timeoutQueue.asyncAfter(deadline: .now() + signTimeoutSeconds) { [signTimeoutSeconds] in
            finish(
                .failure(.signerUnavailable(
                    "audit-producer sign reply did not arrive within \(signTimeoutSeconds)s (helper unreachable or XPC reply dropped)"
                )),
                nil
            )
        }

        signer.signAuditProducerPayload(pending.signingBytes) { signature, error in
            if let error {
                finish(.failure(.signerUnavailable(error)), nil)
                return
            }
            guard let signature, !signature.isEmpty else {
                finish(.failure(.emptySignature), nil)
                return
            }
            let producer = AuditProducerSignatureBody(
                eventCanonicalJson: pending.eventCanonicalJson,
                capturedAtUnixMs: pending.capturedAtUnixMs,
                seq: pending.seq,
                priorSha256Hex: pending.priorHashHex,
                signatureB64url: Base64URL.encode(signature),
                keyId: AuditProducerSigningConstants.keyId
            )
            let signedBody = FlowDecisionRecordedBody(
                decision: pending.body.decision,
                destination: pending.body.destination,
                agent: pending.body.agent,
                matchedRuleId: pending.body.matchedRuleId,
                recordedAt: pending.body.recordedAt,
                enforcement: pending.body.enforcement,
                producer: producer
            )
            finish(
                .success(.flowDecisionRecorded(signedBody)),
                (pending.seq, pending.eventHashHex)
            )
        }
    }

    public func buildSignedAvailabilityReport(
        enforcement: EnforcementAvailabilitySnapshotBody,
        fortressId: String,
        reportedAt: Date = Date(),
        signer: AuditProducerSigning,
        completion: @escaping (Result<IpcMessage, AuditProducerSigningError>) -> Void
    ) {
        let pending: PendingAvailability
        do {
            pending = try stateQueue.sync {
                try buildPendingAvailabilityLocked(
                    enforcement: enforcement,
                    fortressId: fortressId,
                    reportedAt: reportedAt
                )
            }
        } catch let error as AuditProducerSigningError {
            completion(.failure(error))
            return
        } catch {
            completion(.failure(.canonicalizationFailed("\(error)")))
            return
        }

        let completionLock = NSLock()
        var didComplete = false
        let finish: (Result<IpcMessage, AuditProducerSigningError>, (seq: UInt64, hash: String)?) -> Void = { [weak self] result, advance in
            completionLock.lock()
            if didComplete {
                completionLock.unlock()
                return
            }
            didComplete = true
            completionLock.unlock()
            if let advance, let self {
                if let error = self.advanceAfterSignedResult(
                    seq: advance.seq,
                    hash: advance.hash
                ) {
                    completion(.failure(error))
                    return
                }
            }
            completion(result)
        }

        timeoutQueue.asyncAfter(deadline: .now() + signTimeoutSeconds) { [signTimeoutSeconds] in
            finish(
                .failure(.signerUnavailable(
                    "audit-producer sign reply did not arrive within \(signTimeoutSeconds)s (helper unreachable or XPC reply dropped)"
                )),
                nil
            )
        }

        signer.signAuditProducerPayload(pending.signingBytes) { signature, error in
            if let error {
                finish(.failure(.signerUnavailable(error)), nil)
                return
            }
            guard let signature, !signature.isEmpty else {
                finish(.failure(.emptySignature), nil)
                return
            }
            let producer = AuditProducerSignatureBody(
                eventCanonicalJson: pending.eventCanonicalJson,
                capturedAtUnixMs: pending.capturedAtUnixMs,
                seq: pending.seq,
                priorSha256Hex: pending.priorHashHex,
                signatureB64url: Base64URL.encode(signature),
                keyId: AuditProducerSigningConstants.keyId
            )
            let body = EnforcementAvailabilityReportBody(
                enforcement: pending.enforcement,
                producer: producer
            )
            finish(
                .success(.enforcementAvailabilityReport(body)),
                (pending.seq, pending.eventHashHex)
            )
        }
    }

    private func buildPendingDecisionLocked(
        outcome: EvaluationOutcome,
        flow: FilterFlowDescriptor,
        enforcement: EnforcementAvailabilitySnapshotBody?,
        recordedAt: Date
    ) throws -> PendingDecision {
        try assertStateLoadSucceededLocked()
        try refreshFromDurableStateLocked()
        let decision: String
        let matchedRuleId: String?
        let operation: String
        let result: String
        switch outcome {
        case .allow(let ruleId):
            decision = "allow"
            matchedRuleId = ruleId
            operation = "egress_approved"
            result = "success"
        case .drop(let ruleId):
            decision = "drop"
            matchedRuleId = ruleId
            operation = "egress_blocked"
            result = "blocked"
        case .uncertain:
            throw AuditProducerSigningError.unsupportedOutcome
        }

        let recordedAtString = IPCBridgeNotifications.iso8601(recordedAt)
        let destination = IPCBridgeNotifications.destinationFor(flow: flow)
        let agent = IPCBridgeNotifications.agentFor(flow: flow)
        let seq = nextSeq
        let prior = priorHashHex
        let signedDetails = signedDetailsFor(
            decision: decision,
            destination: destination,
            agent: agent,
            matchedRuleId: matchedRuleId,
            seq: seq,
            priorHashHex: prior,
            enforcement: enforcement
        )
        let walBody = JSONValue.object([
            "timestamp": .string(recordedAtString),
            "layer": .string("l1"),
            "operation": .string(operation),
            "identity_id": .string(agent.id),
            "result": .string(result),
            "details": .object(signedDetails),
        ])
        let walCanonical = try canonicalJSONString(walBody)
        let capturedAtUnixMs = UInt64(recordedAt.timeIntervalSince1970 * 1000)
        let signingBytes = Data(
            "\(AuditProducerSigningConstants.domainPrefix)\(walCanonical)\n\(capturedAtUnixMs)\n\(seq)".utf8
        )
        return PendingDecision(
            body: FlowDecisionRecordedBody(
                decision: decision,
                destination: destination,
                agent: agent,
                matchedRuleId: matchedRuleId,
                recordedAt: recordedAtString,
                enforcement: enforcement
            ),
            eventCanonicalJson: walCanonical,
            // Chain over the SIGNED body, matching the availability path below
            // and the Rust producer (castle-wall-daemon/src/audit.rs). Hashing a
            // separately-built raw event here forked the chain on every macOS
            // deployment: the consumer could never reproduce these bytes.
            eventHashHex: sha256Hex(Data(walCanonical.utf8)),
            signingBytes: signingBytes,
            capturedAtUnixMs: capturedAtUnixMs,
            seq: seq,
            priorHashHex: prior
        )
    }

    private func signedDetailsFor(
        decision: String,
        destination: IpcDestination,
        agent: IpcAgentAttribution,
        matchedRuleId: String?,
        seq: UInt64,
        priorHashHex: String?,
        enforcement: EnforcementAvailabilitySnapshotBody?
    ) -> [String: JSONValue] {
        var details: [String: JSONValue] = [
            "agent_id": .string(agent.id),
            "agent_template": .string(agent.template),
            "dest_ip": .string(destination.ip),
            "dest_port": .number(Double(destination.port)),
            "dest_protocol": .string(destination.protocolName),
            "decision": .string(decision),
            "prior_sha256_hex": priorHashHex.map { .string($0) } ?? .null,
            "rule_id": matchedRuleId.map { .string($0) } ?? .null,
            "seq": .number(Double(seq)),
            "source": .string("macos_extension"),
        ]
        if let host = destination.host {
            details["dest_host"] = .string(host)
        }
        if let enforcement {
            details["enforcement"] = jsonValue(for: enforcement)
        }
        return details
    }

    private func buildPendingAvailabilityLocked(
        enforcement: EnforcementAvailabilitySnapshotBody,
        fortressId: String,
        reportedAt: Date
    ) throws -> PendingAvailability {
        try assertStateLoadSucceededLocked()
        try refreshFromDurableStateLocked()
        let seq = nextSeq
        let prior = priorHashHex
        let reportedAtString = enforcement.producerClaimedAt ?? IPCBridgeNotifications.iso8601(reportedAt)
        let details: [String: JSONValue] = [
            "seq": .number(Double(seq)),
            "prior_sha256_hex": prior.map { .string($0) } ?? .null,
            "enforcement": jsonValue(for: enforcement),
        ]
        let walBody = JSONValue.object([
            "timestamp": .string(reportedAtString),
            "layer": .string("l1"),
            "operation": .string("enforcement_availability_report"),
            "identity_id": .string(fortressId),
            "result": .string(isGreen(enforcement) ? "success" : "failure"),
            "details": .object(details),
        ])
        let walCanonical = try canonicalJSONString(walBody)
        let capturedAtUnixMs = UInt64(reportedAt.timeIntervalSince1970 * 1000)
        let signingBytes = Data(
            "\(AuditProducerSigningConstants.domainPrefix)\(walCanonical)\n\(capturedAtUnixMs)\n\(seq)".utf8
        )
        return PendingAvailability(
            enforcement: enforcement,
            eventCanonicalJson: walCanonical,
            eventHashHex: sha256Hex(Data(walCanonical.utf8)),
            signingBytes: signingBytes,
            capturedAtUnixMs: capturedAtUnixMs,
            seq: seq,
            priorHashHex: prior
        )
    }

    private func jsonValue(for enforcement: EnforcementAvailabilitySnapshotBody) -> JSONValue {
        var object: [String: JSONValue] = [
            "protocol_version": .number(Double(enforcement.protocolVersion)),
            "source": .string(enforcement.source),
            "lease_state": .string(enforcement.leaseState),
            "lease_reason": .string(enforcement.leaseReason),
            "manifest_state": .string(enforcement.manifestState),
            "manifest_signature_b64url": enforcement.manifestSignatureB64url.map { .string($0) } ?? .null,
            "provider_bound": .bool(enforcement.providerBound),
        ]
        if let producerClaimedAt = enforcement.producerClaimedAt {
            object["producer_claimed_at"] = .string(producerClaimedAt)
        }
        return .object(object)
    }

    private func isGreen(_ enforcement: EnforcementAvailabilitySnapshotBody) -> Bool {
        return enforcement.protocolVersion == 1 &&
            enforcement.source == "macos_extension" &&
            enforcement.leaseState == "live" &&
            enforcement.leaseReason == "ok" &&
            enforcement.manifestState == "applied" &&
            enforcement.manifestSignatureB64url?.isEmpty == false &&
            enforcement.providerBound
    }

    private func canonicalJSONString(_ value: JSONValue) throws -> String {
        let data = try SignedManifestVerifier.canonicalJSONData(value)
        guard let string = String(data: data, encoding: .utf8) else {
            throw AuditProducerSigningError.canonicalizationFailed("canonical JSON was not utf-8")
        }
        return string
    }

    private func sha256Hex(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func assertStateLoadSucceededLocked() throws {
        if let stateLoadError {
            throw AuditProducerSigningError.statePersistenceFailed(
                "audit producer chain state could not be loaded: \(stateLoadError)"
            )
        }
    }

    private func refreshFromDurableStateLocked() throws {
        guard let loaded = try stateStore.load() else {
            return
        }
        if loaded.nextSeq > nextSeq {
            nextSeq = loaded.nextSeq
            priorHashHex = loaded.priorSha256Hex
            return
        }
        if loaded.nextSeq == nextSeq && loaded.priorSha256Hex != priorHashHex {
            throw AuditProducerSigningError.statePersistenceFailed(
                "audit producer chain state conflicts with in-memory cursor at next_seq \(nextSeq)"
            )
        }
    }

    private func advanceAfterSignedResult(seq: UInt64, hash: String) -> AuditProducerSigningError? {
        return stateQueue.sync {
            if let stateLoadError {
                return .statePersistenceFailed(
                    "audit producer chain state could not be loaded: \(stateLoadError)"
                )
            }
            do {
                try refreshFromDurableStateLocked()
            } catch let error as AuditProducerSigningError {
                return error
            } catch {
                return .statePersistenceFailed(
                    "audit producer chain state could not be loaded: \(error)"
                )
            }
            guard nextSeq == seq else {
                return .chainAdvancedBeforeSignReply
            }
            let advancedState = AuditProducerChainState(
                nextSeq: seq + 1,
                priorSha256Hex: hash
            )
            do {
                try stateStore.save(advancedState)
            } catch {
                return .statePersistenceFailed(
                    "audit producer chain state could not be saved: \(error)"
                )
            }
            nextSeq = advancedState.nextSeq
            priorHashHex = advancedState.priorSha256Hex
            return nil
        }
    }

    private struct PendingDecision {
        let body: FlowDecisionRecordedBody
        let eventCanonicalJson: String
        let eventHashHex: String
        let signingBytes: Data
        let capturedAtUnixMs: UInt64
        let seq: UInt64
        let priorHashHex: String?
    }

    private struct PendingAvailability {
        let enforcement: EnforcementAvailabilitySnapshotBody
        let eventCanonicalJson: String
        let eventHashHex: String
        let signingBytes: Data
        let capturedAtUnixMs: UInt64
        let seq: UInt64
        let priorHashHex: String?
    }
}
