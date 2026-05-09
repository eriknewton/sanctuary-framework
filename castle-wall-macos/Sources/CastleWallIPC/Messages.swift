//
// Messages.swift
//
// JSON-RPC envelope shapes mirroring `server/src/castle-wall/ipc/messages.ts`
// and `castle-wall-daemon/src/ipc/messages.rs`. Every message variant on the
// wire MUST round-trip byte-equivalent across all three implementations.
//
// PR scope (Foundation): handshake_challenge, handshake_response,
// status_request, status_response, policy_reload_request,
// policy_reload_response, audit_emit, audit_emit_metric_batch,
// unlock_notification, lock_notification, decision_request,
// decision_response, audit_drain_request, audit_drain_response,
// audit_drain_ack. Subsequent builds may extend; existing variants are
// frozen wire shape.
//

import Foundation

// MARK: - Envelope

public struct MessageEnvelope: Codable, Equatable {
    public let jsonrpc: String
    public let method: String
    public let params: IpcMessage

    public init(jsonrpc: String, method: String, params: IpcMessage) {
        self.jsonrpc = jsonrpc
        self.method = method
        self.params = params
    }
}

// MARK: - Tagged union

/// Tagged union of every Castle Wall IPC message body. Internal `type`
/// discriminator is decoded against a stable set of literal strings. Unknown
/// types fail decoding.
public enum IpcMessage: Codable, Equatable {
    case statusRequest(requestId: String)
    case statusResponse(StatusResponseBody)
    case policyReloadRequest(requestId: String, manifestPath: String)
    case policyReloadResponse(PolicyReloadResponseBody)
    case decisionRequest(DecisionRequestBody)
    case decisionResponse(DecisionResponseBody)
    case auditEmit(event: JSONValue)
    case auditEmitMetricBatch(AuditEmitMetricBatchBody)
    case auditDrainRequest(requestId: String, afterSeq: UInt64?, maxEvents: UInt32)
    case auditDrainResponse(AuditDrainResponseBody)
    case auditDrainAck(requestId: String, lastAckedSeq: UInt64)
    case unlockNotification(fortressId: String, unlockedAt: String)
    case lockNotification(fortressId: String, lockedAt: String)
    case handshakeChallenge(nonceB64url: String)
    case handshakeResponse(HandshakeResponseBody)

    private enum DiscriminatorKeys: String, CodingKey {
        case type
    }

    public init(from decoder: Decoder) throws {
        let typeContainer = try decoder.container(keyedBy: DiscriminatorKeys.self)
        let typeString = try typeContainer.decode(String.self, forKey: .type)
        let body = try decoder.singleValueContainer()

        switch typeString {
        case "status_request":
            let inner = try body.decode(StatusRequestEnvelopeBody.self)
            self = .statusRequest(requestId: inner.requestId)
        case "status_response":
            self = .statusResponse(try body.decode(StatusResponseBody.self))
        case "policy_reload_request":
            let inner = try body.decode(PolicyReloadRequestEnvelopeBody.self)
            self = .policyReloadRequest(requestId: inner.requestId, manifestPath: inner.manifestPath)
        case "policy_reload_response":
            self = .policyReloadResponse(try body.decode(PolicyReloadResponseBody.self))
        case "decision_request":
            self = .decisionRequest(try body.decode(DecisionRequestBody.self))
        case "decision_response":
            self = .decisionResponse(try body.decode(DecisionResponseBody.self))
        case "audit_emit":
            let inner = try body.decode(AuditEmitEnvelopeBody.self)
            self = .auditEmit(event: inner.event)
        case "audit_emit_metric_batch":
            self = .auditEmitMetricBatch(try body.decode(AuditEmitMetricBatchBody.self))
        case "audit_drain_request":
            let inner = try body.decode(AuditDrainRequestEnvelopeBody.self)
            self = .auditDrainRequest(
                requestId: inner.requestId,
                afterSeq: inner.afterSeq,
                maxEvents: inner.maxEvents
            )
        case "audit_drain_response":
            self = .auditDrainResponse(try body.decode(AuditDrainResponseBody.self))
        case "audit_drain_ack":
            let inner = try body.decode(AuditDrainAckEnvelopeBody.self)
            self = .auditDrainAck(requestId: inner.requestId, lastAckedSeq: inner.lastAckedSeq)
        case "unlock_notification":
            let inner = try body.decode(UnlockNotificationEnvelopeBody.self)
            self = .unlockNotification(fortressId: inner.fortressId, unlockedAt: inner.unlockedAt)
        case "lock_notification":
            let inner = try body.decode(LockNotificationEnvelopeBody.self)
            self = .lockNotification(fortressId: inner.fortressId, lockedAt: inner.lockedAt)
        case "handshake_challenge":
            let inner = try body.decode(HandshakeChallengeEnvelopeBody.self)
            self = .handshakeChallenge(nonceB64url: inner.nonceB64url)
        case "handshake_response":
            self = .handshakeResponse(try body.decode(HandshakeResponseBody.self))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: typeContainer,
                debugDescription: "unknown IPC message type: \(typeString)"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .statusRequest(let requestId):
            try container.encode(StatusRequestEnvelopeBody(type: "status_request", requestId: requestId))
        case .statusResponse(let body):
            try container.encode(body)
        case .policyReloadRequest(let requestId, let manifestPath):
            try container.encode(PolicyReloadRequestEnvelopeBody(
                type: "policy_reload_request",
                requestId: requestId,
                manifestPath: manifestPath
            ))
        case .policyReloadResponse(let body):
            try container.encode(body)
        case .decisionRequest(let body):
            try container.encode(body)
        case .decisionResponse(let body):
            try container.encode(body)
        case .auditEmit(let event):
            try container.encode(AuditEmitEnvelopeBody(type: "audit_emit", event: event))
        case .auditEmitMetricBatch(let body):
            try container.encode(body)
        case .auditDrainRequest(let requestId, let afterSeq, let maxEvents):
            try container.encode(AuditDrainRequestEnvelopeBody(
                type: "audit_drain_request",
                requestId: requestId,
                afterSeq: afterSeq,
                maxEvents: maxEvents
            ))
        case .auditDrainResponse(let body):
            try container.encode(body)
        case .auditDrainAck(let requestId, let lastAckedSeq):
            try container.encode(AuditDrainAckEnvelopeBody(
                type: "audit_drain_ack",
                requestId: requestId,
                lastAckedSeq: lastAckedSeq
            ))
        case .unlockNotification(let fortressId, let unlockedAt):
            try container.encode(UnlockNotificationEnvelopeBody(
                type: "unlock_notification",
                fortressId: fortressId,
                unlockedAt: unlockedAt
            ))
        case .lockNotification(let fortressId, let lockedAt):
            try container.encode(LockNotificationEnvelopeBody(
                type: "lock_notification",
                fortressId: fortressId,
                lockedAt: lockedAt
            ))
        case .handshakeChallenge(let nonceB64url):
            try container.encode(HandshakeChallengeEnvelopeBody(
                type: "handshake_challenge",
                nonceB64url: nonceB64url
            ))
        case .handshakeResponse(let body):
            try container.encode(body)
        }
    }
}

// MARK: - Strongly-typed bodies

public struct StatusResponseBody: Codable, Equatable {
    public let type: String
    public let requestId: String
    public let uptimeSeconds: UInt64
    public let loadedManifestSignatureB64url: String?
    public let loadedRuleCount: UInt32
    public let noWallEngaged: Bool

    public init(
        requestId: String,
        uptimeSeconds: UInt64,
        loadedManifestSignatureB64url: String?,
        loadedRuleCount: UInt32,
        noWallEngaged: Bool
    ) {
        self.type = "status_response"
        self.requestId = requestId
        self.uptimeSeconds = uptimeSeconds
        self.loadedManifestSignatureB64url = loadedManifestSignatureB64url
        self.loadedRuleCount = loadedRuleCount
        self.noWallEngaged = noWallEngaged
    }

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
        case uptimeSeconds = "uptime_seconds"
        case loadedManifestSignatureB64url = "loaded_manifest_signature_b64url"
        case loadedRuleCount = "loaded_rule_count"
        case noWallEngaged = "no_wall_engaged"
    }
}

public struct PolicyReloadResponseBody: Codable, Equatable {
    public let type: String
    public let requestId: String
    public let ok: Bool
    public let loadedManifestSignatureB64url: String?
    public let loadedRuleCount: UInt32
    public let error: String?

    public init(
        requestId: String,
        ok: Bool,
        loadedManifestSignatureB64url: String?,
        loadedRuleCount: UInt32,
        error: String?
    ) {
        self.type = "policy_reload_response"
        self.requestId = requestId
        self.ok = ok
        self.loadedManifestSignatureB64url = loadedManifestSignatureB64url
        self.loadedRuleCount = loadedRuleCount
        self.error = error
    }

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
        case ok
        case loadedManifestSignatureB64url = "loaded_manifest_signature_b64url"
        case loadedRuleCount = "loaded_rule_count"
        case error
    }
}

public struct IpcDestination: Codable, Equatable {
    public let host: String?
    public let ip: String
    public let port: UInt16
    public let protocolName: String
    public let hostnameSource: String?
    public let opaque: Bool

    public init(
        host: String?,
        ip: String,
        port: UInt16,
        protocolName: String,
        hostnameSource: String?,
        opaque: Bool
    ) {
        self.host = host
        self.ip = ip
        self.port = port
        self.protocolName = protocolName
        self.hostnameSource = hostnameSource
        self.opaque = opaque
    }

    enum CodingKeys: String, CodingKey {
        case host
        case ip
        case port
        case protocolName = "protocol"
        case hostnameSource = "hostname_source"
        case opaque
    }
}

public struct IpcAgentAttribution: Codable, Equatable {
    public let id: String
    public let template: String

    public init(id: String, template: String) {
        self.id = id
        self.template = template
    }
}

public struct DecisionRequestBody: Codable, Equatable {
    public let type: String
    public let requestId: String
    public let surface: String
    public let destination: IpcDestination
    public let agent: IpcAgentAttribution
    public let timeoutSeconds: UInt32

    public init(
        requestId: String,
        surface: String,
        destination: IpcDestination,
        agent: IpcAgentAttribution,
        timeoutSeconds: UInt32
    ) {
        self.type = "decision_request"
        self.requestId = requestId
        self.surface = surface
        self.destination = destination
        self.agent = agent
        self.timeoutSeconds = timeoutSeconds
    }

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
        case surface
        case destination
        case agent
        case timeoutSeconds = "timeout_seconds"
    }
}

public struct LearnedDecisionEnvelope: Codable, Equatable {
    public let granularity: String

    public init(granularity: String) {
        self.granularity = granularity
    }
}

public struct DecisionResponseBody: Codable, Equatable {
    public let type: String
    public let requestId: String
    public let decision: String
    public let learn: LearnedDecisionEnvelope?

    public init(requestId: String, decision: String, learn: LearnedDecisionEnvelope?) {
        self.type = "decision_response"
        self.requestId = requestId
        self.decision = decision
        self.learn = learn
    }

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
        case decision
        case learn
    }
}

public struct MetricBatchEntry: Codable, Equatable {
    public let host: String?
    public let port: UInt16
    public let protocolName: String
    public let agentId: String
    public let allowedCount: UInt64
    public let blockedCount: UInt64

    public init(
        host: String?,
        port: UInt16,
        protocolName: String,
        agentId: String,
        allowedCount: UInt64,
        blockedCount: UInt64
    ) {
        self.host = host
        self.port = port
        self.protocolName = protocolName
        self.agentId = agentId
        self.allowedCount = allowedCount
        self.blockedCount = blockedCount
    }

    enum CodingKeys: String, CodingKey {
        case host
        case port
        case protocolName = "protocol"
        case agentId = "agent_id"
        case allowedCount = "allowed_count"
        case blockedCount = "blocked_count"
    }
}

public struct AuditEmitMetricBatchBody: Codable, Equatable {
    public let type: String
    public let windowStart: String
    public let windowEnd: String
    public let byDestination: [MetricBatchEntry]

    public init(windowStart: String, windowEnd: String, byDestination: [MetricBatchEntry]) {
        self.type = "audit_emit_metric_batch"
        self.windowStart = windowStart
        self.windowEnd = windowEnd
        self.byDestination = byDestination
    }

    enum CodingKeys: String, CodingKey {
        case type
        case windowStart = "window_start"
        case windowEnd = "window_end"
        case byDestination = "by_destination"
    }
}

public struct AuditDrainEvent: Codable, Equatable {
    public let seq: UInt64
    public let capturedAtUnixMs: UInt64
    public let priorSha256Hex: String?
    public let eventCanonicalJson: String
    public let critical: Bool

    public init(
        seq: UInt64,
        capturedAtUnixMs: UInt64,
        priorSha256Hex: String?,
        eventCanonicalJson: String,
        critical: Bool
    ) {
        self.seq = seq
        self.capturedAtUnixMs = capturedAtUnixMs
        self.priorSha256Hex = priorSha256Hex
        self.eventCanonicalJson = eventCanonicalJson
        self.critical = critical
    }

    enum CodingKeys: String, CodingKey {
        case seq
        case capturedAtUnixMs = "captured_at_unix_ms"
        case priorSha256Hex = "prior_sha256_hex"
        case eventCanonicalJson = "event_canonical_json"
        case critical
    }
}

public struct AuditDrainResponseBody: Codable, Equatable {
    public let type: String
    public let requestId: String
    public let events: [AuditDrainEvent]
    public let nextAfterSeq: UInt64?
    public let morePending: Bool
    public let walOverflowCount: UInt64

    public init(
        requestId: String,
        events: [AuditDrainEvent],
        nextAfterSeq: UInt64?,
        morePending: Bool,
        walOverflowCount: UInt64
    ) {
        self.type = "audit_drain_response"
        self.requestId = requestId
        self.events = events
        self.nextAfterSeq = nextAfterSeq
        self.morePending = morePending
        self.walOverflowCount = walOverflowCount
    }

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
        case events
        case nextAfterSeq = "next_after_seq"
        case morePending = "more_pending"
        case walOverflowCount = "wal_overflow_count"
    }
}

public struct HandshakeResponseBody: Codable, Equatable {
    public let type: String
    public let fortressId: String
    public let signingKeyId: String
    public let nonceSignatureB64url: String

    public init(fortressId: String, signingKeyId: String, nonceSignatureB64url: String) {
        self.type = "handshake_response"
        self.fortressId = fortressId
        self.signingKeyId = signingKeyId
        self.nonceSignatureB64url = nonceSignatureB64url
    }

    enum CodingKeys: String, CodingKey {
        case type
        case fortressId = "fortress_id"
        case signingKeyId = "signing_key_id"
        case nonceSignatureB64url = "nonce_signature_b64url"
    }
}

// MARK: - Internal envelope-wire bodies for variants without dedicated public structs

private struct StatusRequestEnvelopeBody: Codable {
    let type: String
    let requestId: String

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
    }
}

private struct PolicyReloadRequestEnvelopeBody: Codable {
    let type: String
    let requestId: String
    let manifestPath: String

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
        case manifestPath = "manifest_path"
    }
}

private struct AuditEmitEnvelopeBody: Codable {
    let type: String
    let event: JSONValue
}

private struct AuditDrainRequestEnvelopeBody: Codable {
    let type: String
    let requestId: String
    let afterSeq: UInt64?
    let maxEvents: UInt32

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
        case afterSeq = "after_seq"
        case maxEvents = "max_events"
    }
}

private struct AuditDrainAckEnvelopeBody: Codable {
    let type: String
    let requestId: String
    let lastAckedSeq: UInt64

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
        case lastAckedSeq = "last_acked_seq"
    }
}

private struct UnlockNotificationEnvelopeBody: Codable {
    let type: String
    let fortressId: String
    let unlockedAt: String

    enum CodingKeys: String, CodingKey {
        case type
        case fortressId = "fortress_id"
        case unlockedAt = "unlocked_at"
    }
}

private struct LockNotificationEnvelopeBody: Codable {
    let type: String
    let fortressId: String
    let lockedAt: String

    enum CodingKeys: String, CodingKey {
        case type
        case fortressId = "fortress_id"
        case lockedAt = "locked_at"
    }
}

private struct HandshakeChallengeEnvelopeBody: Codable {
    let type: String
    let nonceB64url: String

    enum CodingKeys: String, CodingKey {
        case type
        case nonceB64url = "nonce_b64url"
    }
}

// MARK: - JSONValue helper for arbitrary audit_emit payloads

public enum JSONValue: Codable, Equatable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let v = try? container.decode(Bool.self) {
            self = .bool(v)
        } else if let v = try? container.decode(Double.self) {
            self = .number(v)
        } else if let v = try? container.decode(String.self) {
            self = .string(v)
        } else if let v = try? container.decode([JSONValue].self) {
            self = .array(v)
        } else if let v = try? container.decode([String: JSONValue].self) {
            self = .object(v)
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "JSONValue: unrecognized JSON token"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null:
            try container.encodeNil()
        case .bool(let v):
            try container.encode(v)
        case .number(let v):
            try container.encode(v)
        case .string(let v):
            try container.encode(v)
        case .array(let v):
            try container.encode(v)
        case .object(let v):
            try container.encode(v)
        }
    }
}
