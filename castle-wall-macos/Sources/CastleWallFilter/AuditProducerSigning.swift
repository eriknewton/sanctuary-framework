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
}

public enum AuditProducerSigningConstants {
    public static let keyId = "cw-audit-producer-v1"
    public static let domainPrefix = "sanctuary.castle-wall.audit-producer.v1\n"
}

public protocol AuditProducerSigning {
    func signAuditProducerPayload(
        _ payload: Data,
        reply: @escaping (_ signature: Data?, _ error: String?) -> Void
    )
}

public final class XpcAuditProducerSigner: AuditProducerSigning {
    public init() {}

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

        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            connection.invalidate()
            reply(nil, "audit producer helper unreachable: \(error.localizedDescription)")
        }
        guard let signer = proxy as? CastleWallSignerXPCProtocol else {
            connection.invalidate()
            reply(nil, "audit producer helper proxy unavailable")
            return
        }
        signer.sign(
            payload: payload,
            purpose: SignerConstants.SignPurpose.auditProducer
        ) { signature, error in
            connection.invalidate()
            reply(signature, error)
        }
    }
}

public final class AuditProducerChain {
    private var nextSeq: UInt64
    private var priorHashHex: String?
    private let stateQueue = DispatchQueue(
        label: "ai.sanctuaryprotocol.castle-wall.audit-producer-chain"
    )

    public init(nextSeq: UInt64 = 0, priorHashHex: String? = nil) {
        self.nextSeq = nextSeq
        self.priorHashHex = priorHashHex
    }

    public func buildSignedFlowDecision(
        outcome: EvaluationOutcome,
        flow: FilterFlowDescriptor,
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

        signer.signAuditProducerPayload(pending.signingBytes) { [weak self] signature, error in
            if let error {
                completion(.failure(.signerUnavailable(error)))
                return
            }
            guard let signature, !signature.isEmpty else {
                completion(.failure(.emptySignature))
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
                producer: producer
            )
            self?.stateQueue.sync {
                if self?.nextSeq == pending.seq {
                    self?.nextSeq = pending.seq + 1
                    self?.priorHashHex = pending.eventHashHex
                }
            }
            completion(.success(.flowDecisionRecorded(signedBody)))
        }
    }

    private func buildPendingDecisionLocked(
        outcome: EvaluationOutcome,
        flow: FilterFlowDescriptor,
        recordedAt: Date
    ) throws -> PendingDecision {
        let decision: String
        let matchedRuleId: String?
        let eventType: String
        let operation: String
        let result: String
        switch outcome {
        case .allow(let ruleId):
            decision = "allow"
            matchedRuleId = ruleId
            eventType = "egress_allowed"
            operation = "egress_approved"
            result = "success"
        case .drop(let ruleId):
            decision = "drop"
            matchedRuleId = ruleId
            eventType = "egress_blocked"
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
        let event = JSONValue.object([
            "schema_version": .number(1),
            "layer": .string("l1"),
            "timestamp": .string(recordedAtString),
            "fortress_id": .string(agent.id),
            "event_type": .string(eventType),
            "agent": .object([
                "id": .string(agent.id),
                "template": .string(agent.template),
            ]),
            "destination": .object([
                "host": destination.host.map { .string($0) } ?? .null,
                "ip": .string(destination.ip),
                "port": .number(Double(destination.port)),
                "protocol": .string(destination.protocolName),
            ]),
            "decision": .null,
            "rule_id": matchedRuleId.map { .string($0) } ?? .null,
            "details": .object([
                "seq": .number(Double(seq)),
                "prior_sha256_hex": prior.map { .string($0) } ?? .null,
            ]),
        ])
        let eventCanonical = try canonicalJSONString(event)
        let signedDetails = signedDetailsFor(
            decision: decision,
            destination: destination,
            agent: agent,
            matchedRuleId: matchedRuleId,
            seq: seq,
            priorHashHex: prior
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
                recordedAt: recordedAtString
            ),
            eventCanonicalJson: walCanonical,
            eventHashHex: sha256Hex(Data(eventCanonical.utf8)),
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
        priorHashHex: String?
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
        return details
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

    private struct PendingDecision {
        let body: FlowDecisionRecordedBody
        let eventCanonicalJson: String
        let eventHashHex: String
        let signingBytes: Data
        let capturedAtUnixMs: UInt64
        let seq: UInt64
        let priorHashHex: String?
    }
}
