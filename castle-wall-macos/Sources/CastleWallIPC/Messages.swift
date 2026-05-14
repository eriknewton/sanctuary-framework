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
// Alpha-2 additions (Castle Wall macOS Phase 1 packet filter + manifest
// sync): manifest_subscribe, manifest_updated, flow_decision_recorded,
// flow_pending_approval. Phase 1 ships full-snapshot manifest sync; delta
// patches are reserved for v1.x.
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
    case manifestSubscribe(requestId: String)
    case manifestUpdated(ManifestUpdatedBody)
    case flowDecisionRecorded(FlowDecisionRecordedBody)
    case flowPendingApproval(FlowPendingApprovalBody)

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
        case "manifest_subscribe":
            let inner = try body.decode(ManifestSubscribeEnvelopeBody.self)
            self = .manifestSubscribe(requestId: inner.requestId)
        case "manifest_updated":
            self = .manifestUpdated(try body.decode(ManifestUpdatedBody.self))
        case "flow_decision_recorded":
            self = .flowDecisionRecorded(try body.decode(FlowDecisionRecordedBody.self))
        case "flow_pending_approval":
            self = .flowPendingApproval(try body.decode(FlowPendingApprovalBody.self))
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
        case .manifestSubscribe(let requestId):
            try container.encode(ManifestSubscribeEnvelopeBody(
                type: "manifest_subscribe",
                requestId: requestId
            ))
        case .manifestUpdated(let body):
            try container.encode(body)
        case .flowDecisionRecorded(let body):
            try container.encode(body)
        case .flowPendingApproval(let body):
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

// MARK: - Alpha-2: manifest sync + flow decision telemetry

/// Allowlist rule shape mirroring `server/src/castle-wall/allowlist/schema.ts`.
/// The runtime ships the full snapshot inside `manifest_updated`; the
/// extension's evaluator consumes this shape directly.
public struct ManifestRule: Codable, Equatable {
    public let id: String
    public let schemaVersion: UInt32
    public let createdAt: String
    public let description: String?
    public let match: ManifestRuleMatch
    public let scope: ManifestRuleScope
    public let disposition: String
    public let timeWindow: ManifestRuleTimeWindow?

    public init(
        id: String,
        schemaVersion: UInt32,
        createdAt: String,
        description: String?,
        match: ManifestRuleMatch,
        scope: ManifestRuleScope,
        disposition: String,
        timeWindow: ManifestRuleTimeWindow?
    ) {
        self.id = id
        self.schemaVersion = schemaVersion
        self.createdAt = createdAt
        self.description = description
        self.match = match
        self.scope = scope
        self.disposition = disposition
        self.timeWindow = timeWindow
    }

    enum CodingKeys: String, CodingKey {
        case id
        case schemaVersion = "schema_version"
        case createdAt = "created_at"
        case description
        case match
        case scope
        case disposition
        case timeWindow = "time_window"
    }
}

/// A `host` field that accepts either a single string or an array of strings.
/// Mirrors the TypeScript `string | string[]` union in `schema.ts`.
public enum ManifestRuleHostMatch: Codable, Equatable {
    case single(String)
    case multiple([String])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let one = try? container.decode(String.self) {
            self = .single(one)
            return
        }
        if let many = try? container.decode([String].self) {
            self = .multiple(many)
            return
        }
        throw DecodingError.dataCorruptedError(
            in: container,
            debugDescription: "host must be string or [string]"
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .single(let s):
            try container.encode(s)
        case .multiple(let arr):
            try container.encode(arr)
        }
    }

    /// Iterate the host strings without forcing the caller to switch.
    public var values: [String] {
        switch self {
        case .single(let s): return [s]
        case .multiple(let arr): return arr
        }
    }
}

/// A `port` field that accepts either a single number or an array of numbers.
public enum ManifestRulePortMatch: Codable, Equatable {
    case single(Int)
    case multiple([Int])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let one = try? container.decode(Int.self) {
            self = .single(one)
            return
        }
        if let many = try? container.decode([Int].self) {
            self = .multiple(many)
            return
        }
        throw DecodingError.dataCorruptedError(
            in: container,
            debugDescription: "port must be int or [int]"
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .single(let n):
            try container.encode(n)
        case .multiple(let arr):
            try container.encode(arr)
        }
    }

    public var values: [Int] {
        switch self {
        case .single(let n): return [n]
        case .multiple(let arr): return arr
        }
    }
}

public struct ManifestRuleMatch: Codable, Equatable {
    public let host: ManifestRuleHostMatch?
    public let hostPattern: String?
    public let port: ManifestRulePortMatch?
    public let protocolName: String?

    public init(
        host: ManifestRuleHostMatch?,
        hostPattern: String?,
        port: ManifestRulePortMatch?,
        protocolName: String?
    ) {
        self.host = host
        self.hostPattern = hostPattern
        self.port = port
        self.protocolName = protocolName
    }

    enum CodingKeys: String, CodingKey {
        case host
        case hostPattern = "host_pattern"
        case port
        case protocolName = "protocol"
    }
}

public struct ManifestRuleScope: Codable, Equatable {
    public let agentIds: [String]?
    public let templateIds: [String]?

    public init(agentIds: [String]?, templateIds: [String]?) {
        self.agentIds = agentIds
        self.templateIds = templateIds
    }

    enum CodingKeys: String, CodingKey {
        case agentIds = "agent_ids"
        case templateIds = "template_ids"
    }
}

public struct ManifestRuleTimeWindow: Codable, Equatable {
    public let start: String
    public let end: String

    public init(start: String, end: String) {
        self.start = start
        self.end = end
    }
}

/// One entry in the signed manifest body the extension verifies locally.
/// `sha256` is the hex SHA-256 of the canonical JSON rule bytes shipped in
/// the same `manifest_updated` notification.
public struct ManifestRuleDigestEntry: Codable, Equatable {
    public let ruleId: String
    public let file: String
    public let sha256: String

    public init(ruleId: String, file: String, sha256: String) {
        self.ruleId = ruleId
        self.file = file
        self.sha256 = sha256
    }

    enum CodingKeys: String, CodingKey {
        case ruleId = "rule_id"
        case file
        case sha256
    }
}

/// Signed allowlist manifest body. The extension verifies the Ed25519
/// signature over canonical JSON of this exact shape before trusting rules.
public struct ManifestSignedBody: Codable, Equatable {
    public let schemaVersion: UInt32
    public let fortressId: String
    public let issuedAt: String
    public let rules: [ManifestRuleDigestEntry]

    public init(
        schemaVersion: UInt32,
        fortressId: String,
        issuedAt: String,
        rules: [ManifestRuleDigestEntry]
    ) {
        self.schemaVersion = schemaVersion
        self.fortressId = fortressId
        self.issuedAt = issuedAt
        self.rules = rules
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case fortressId = "fortress_id"
        case issuedAt = "issued_at"
        case rules
    }
}

/// Ed25519 signature envelope for a `ManifestSignedBody`.
public struct ManifestSignatureEnvelope: Codable, Equatable {
    public let signatureScheme: String
    public let signingKeyId: String
    public let signatureB64url: String

    public init(
        signatureScheme: String,
        signingKeyId: String,
        signatureB64url: String
    ) {
        self.signatureScheme = signatureScheme
        self.signingKeyId = signingKeyId
        self.signatureB64url = signatureB64url
    }

    enum CodingKeys: String, CodingKey {
        case signatureScheme = "signature_scheme"
        case signingKeyId = "signing_key_id"
        case signatureB64url = "signature_b64url"
    }
}

/// `manifest_updated` notification body. The rules remain a full parsed
/// snapshot, but the snapshot is accepted only when `manifest` + `signature`
/// verify against the pinned fortress key.
public struct ManifestUpdatedBody: Codable, Equatable {
    public let type: String
    public let manifest: ManifestSignedBody?
    public let signature: ManifestSignatureEnvelope?
    public let rules: [ManifestRule]

    public init(manifestSignatureB64url: String?, rules: [ManifestRule]) {
        self.type = "manifest_updated"
        if let manifestSignatureB64url {
            self.manifest = ManifestSignedBody(
                schemaVersion: CastleWallConstants.schemaVersionV1,
                fortressId: "legacy-unsigned",
                issuedAt: "",
                rules: []
            )
            self.signature = ManifestSignatureEnvelope(
                signatureScheme: CastleWallConstants.signatureSchemeV1,
                signingKeyId: "legacy-unsigned",
                signatureB64url: manifestSignatureB64url
            )
        } else {
            self.manifest = nil
            self.signature = nil
        }
        self.rules = rules
    }

    public init(
        manifest: ManifestSignedBody,
        signature: ManifestSignatureEnvelope,
        rules: [ManifestRule]
    ) {
        self.type = "manifest_updated"
        self.manifest = manifest
        self.signature = signature
        self.rules = rules
    }

    public var manifestSignatureB64url: String? {
        return signature?.signatureB64url
    }

    enum CodingKeys: String, CodingKey {
        case type
        case manifest
        case signature
        case rules
    }
}

/// `flow_decision_recorded` notification body.
public struct FlowDecisionRecordedBody: Codable, Equatable {
    public let type: String
    public let decision: String
    public let destination: IpcDestination
    public let agent: IpcAgentAttribution
    public let matchedRuleId: String?
    public let recordedAt: String

    public init(
        decision: String,
        destination: IpcDestination,
        agent: IpcAgentAttribution,
        matchedRuleId: String?,
        recordedAt: String
    ) {
        self.type = "flow_decision_recorded"
        self.decision = decision
        self.destination = destination
        self.agent = agent
        self.matchedRuleId = matchedRuleId
        self.recordedAt = recordedAt
    }

    enum CodingKeys: String, CodingKey {
        case type
        case decision
        case destination
        case agent
        case matchedRuleId = "matched_rule_id"
        case recordedAt = "recorded_at"
    }
}

/// `flow_pending_approval` notification body.
public struct FlowPendingApprovalBody: Codable, Equatable {
    public let type: String
    public let requestId: String
    public let destination: IpcDestination
    public let agent: IpcAgentAttribution
    public let surface: String
    public let expiresInSeconds: UInt32

    public init(
        requestId: String,
        destination: IpcDestination,
        agent: IpcAgentAttribution,
        surface: String,
        expiresInSeconds: UInt32
    ) {
        self.type = "flow_pending_approval"
        self.requestId = requestId
        self.destination = destination
        self.agent = agent
        self.surface = surface
        self.expiresInSeconds = expiresInSeconds
    }

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
        case destination
        case agent
        case surface
        case expiresInSeconds = "expires_in_seconds"
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

private struct ManifestSubscribeEnvelopeBody: Codable {
    let type: String
    let requestId: String

    enum CodingKeys: String, CodingKey {
        case type
        case requestId = "request_id"
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
