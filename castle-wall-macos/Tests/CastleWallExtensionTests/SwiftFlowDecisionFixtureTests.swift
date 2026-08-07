import XCTest
import CryptoKit
@testable import CastleWallFilter
@testable import CastleWallIPC

final class SwiftFlowDecisionFixtureTests: XCTestCase {
    private struct Fixture: Decodable {
        let pubkeyB64url: String
        let canonical: String
        let canonicalSha256Hex: String
        let capturedAtUnixMs: UInt64
        let seq: UInt64
        let priorSha256Hex: String?
        let keyId: String
        let sigB64url: String
        let flow: Flow

        struct Flow: Decodable {
            let fortressId: String
            let eventType: String
            let agentId: String
            let agentTemplate: String
            let destHost: String?
            let destIp: String
            let destPort: Int
            let destProtocol: String
            let decision: String
            let matchedRuleId: String?
            let recordedAt: String

            enum CodingKeys: String, CodingKey {
                case fortressId = "fortress_id"
                case eventType = "event_type"
                case agentId = "agent_id"
                case agentTemplate = "agent_template"
                case destHost = "dest_host"
                case destIp = "dest_ip"
                case destPort = "dest_port"
                case destProtocol = "dest_protocol"
                case decision
                case matchedRuleId = "matched_rule_id"
                case recordedAt = "recorded_at"
            }
        }

        enum CodingKeys: String, CodingKey {
            case pubkeyB64url = "pubkey_b64url"
            case canonical
            case canonicalSha256Hex = "canonical_sha256_hex"
            case capturedAtUnixMs = "captured_at_unix_ms"
            case seq
            case priorSha256Hex = "prior_sha256_hex"
            case keyId = "key_id"
            case sigB64url = "sig_b64url"
            case flow
        }
    }

    func testSwiftEmitterStillMatchesCapturedFlowDecisionFixture() throws {
        let fixture = try loadFixture()
        let seed = Data((1...32).map { UInt8($0) })
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let signer = FixtureAuditProducerSigner(privateKey: privateKey)
        let chain = AuditProducerChain(stateStore: VolatileAuditProducerChainStateStore())
        let recordedAt = Date(
            timeIntervalSince1970: TimeInterval(fixture.capturedAtUnixMs) / 1000
        )
        let flow = FilterFlowDescriptor(
            sourceAppIdentifier: "ai.sanctuaryprotocol.fixture",
            agentId: fixture.flow.agentId,
            templateId: fixture.flow.agentTemplate,
            destinationHost: fixture.flow.destHost,
            destinationIp: fixture.flow.destIp,
            destinationPort: fixture.flow.destPort,
            networkProtocol: .tcp,
            hostnameSource: fixture.flow.destHost == nil ? nil : "sni",
            opaqueDestination: fixture.flow.destHost == nil,
            sourceRuid: 503,
            sourceUnattributed: false
        )
        let expectation = expectation(description: "signed flow decision")
        var result: Result<IpcMessage, AuditProducerSigningError>?
        chain.buildSignedFlowDecision(
            outcome: .drop(matchedRuleId: nil),
            flow: flow,
            recordedAt: recordedAt,
            signer: signer
        ) { signed in
            result = signed
            expectation.fulfill()
        }
        wait(for: [expectation], timeout: 1.0)
        guard case .success(.flowDecisionRecorded(let body)) = try XCTUnwrap(result) else {
            return XCTFail("expected signed flow decision")
        }
        let producer = try XCTUnwrap(body.producer)

        XCTAssertEqual(Base64URL.encode(privateKey.publicKey.rawRepresentation), fixture.pubkeyB64url)
        XCTAssertEqual(producer.eventCanonicalJson, fixture.canonical)
        XCTAssertEqual(sha256Hex(Data(producer.eventCanonicalJson.utf8)), fixture.canonicalSha256Hex)
        XCTAssertEqual(producer.capturedAtUnixMs, fixture.capturedAtUnixMs)
        XCTAssertEqual(producer.seq, fixture.seq)
        XCTAssertEqual(producer.priorSha256Hex, fixture.priorSha256Hex)
        XCTAssertEqual(producer.keyId, fixture.keyId)
        XCTAssertTrue(
            privateKey.publicKey.isValidSignature(
                try Base64URL.decode(producer.signatureB64url),
                for: signingBytes(
                    canonical: producer.eventCanonicalJson,
                    capturedAtUnixMs: producer.capturedAtUnixMs,
                    seq: producer.seq
                )
            )
        )
        XCTAssertEqual(body.decision, fixture.flow.decision)
        XCTAssertEqual(body.agent.id, fixture.flow.agentId)
        XCTAssertEqual(body.agent.template, fixture.flow.agentTemplate)
        XCTAssertEqual(body.destination.host, fixture.flow.destHost)
        XCTAssertEqual(body.destination.ip, fixture.flow.destIp)
        XCTAssertEqual(Int(body.destination.port), fixture.flow.destPort)
        XCTAssertEqual(body.destination.protocolName, fixture.flow.destProtocol)
        XCTAssertEqual(body.matchedRuleId, fixture.flow.matchedRuleId)
        XCTAssertEqual(body.recordedAt, fixture.flow.recordedAt)
    }

    func testCapturedFixtureSignatureVerifiesInSwift() throws {
        let fixture = try loadFixture()
        let publicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: Base64URL.decode(fixture.pubkeyB64url)
        )
        let signature = try Base64URL.decode(fixture.sigB64url)
        let signedBytes = signingBytes(
            canonical: fixture.canonical,
            capturedAtUnixMs: fixture.capturedAtUnixMs,
            seq: fixture.seq
        )

        XCTAssertTrue(publicKey.isValidSignature(signature, for: signedBytes))
        XCTAssertFalse(publicKey.isValidSignature(signature, for: Data("tampered".utf8)))
    }

    private func loadFixture() throws -> Fixture {
        let data = try Data(contentsOf: fixtureURL())
        return try JSONDecoder().decode(Fixture.self, from: data)
    }

    private func fixtureURL() -> URL {
        return URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("server")
            .appendingPathComponent("test")
            .appendingPathComponent("castle-wall")
            .appendingPathComponent("fixtures")
            .appendingPathComponent("swift-flow-decision-vector.json")
    }

    private func signingBytes(
        canonical: String,
        capturedAtUnixMs: UInt64,
        seq: UInt64
    ) -> Data {
        return Data(
            "\(AuditProducerSigningConstants.domainPrefix)\(canonical)\n\(capturedAtUnixMs)\n\(seq)".utf8
        )
    }

    private func sha256Hex(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

private final class FixtureAuditProducerSigner: AuditProducerSigning {
    private let privateKey: Curve25519.Signing.PrivateKey

    init(privateKey: Curve25519.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    func signAuditProducerPayload(
        _ payload: Data,
        reply: @escaping (Data?, String?) -> Void
    ) {
        do {
            reply(try privateKey.signature(for: payload), nil)
        } catch {
            reply(nil, "\(error)")
        }
    }
}
