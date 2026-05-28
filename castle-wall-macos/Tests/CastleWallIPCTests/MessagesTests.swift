//
// MessagesTests.swift
//
// JSON envelope decode + re-encode tests. Mirrors the Rust message_test
// suite. Cross-language byte-equivalence is the long-term invariant; this
// suite enforces the Swift side's discriminator behavior + key-name shape.
//

import XCTest
@testable import CastleWallIPC

final class MessagesTests: XCTestCase {
    func testHandshakeChallengeRoundTrip() throws {
        let original = IpcMessage.handshakeChallenge(nonceB64url: "AAAA")
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: encoded)
        XCTAssertEqual(decoded, original)

        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains("\"type\":\"handshake_challenge\""))
        XCTAssertTrue(json.contains("\"nonce_b64url\":\"AAAA\""))
    }

    func testHandshakeResponseRoundTrip() throws {
        let original = IpcMessage.handshakeResponse(HandshakeResponseBody(
            fortressId: "deadbeef",
            signingKeyId: "v1",
            nonceSignatureB64url: "AAAA"
        ))
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: encoded)
        XCTAssertEqual(decoded, original)

        let json = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(json.contains("\"fortress_id\":\"deadbeef\""))
        XCTAssertTrue(json.contains("\"signing_key_id\":\"v1\""))
        XCTAssertTrue(json.contains("\"nonce_signature_b64url\":\"AAAA\""))
    }

    func testStatusRequestRoundTrip() throws {
        let original = IpcMessage.statusRequest(requestId: "req")
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: encoded)
        XCTAssertEqual(decoded, original)
    }

    func testStatusResponseRoundTrip() throws {
        let body = StatusResponseBody(
            requestId: "req",
            uptimeSeconds: 42,
            loadedManifestSignatureB64url: "sig",
            loadedRuleCount: 7,
            noWallEngaged: false
        )
        let original = IpcMessage.statusResponse(body)
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: encoded)
        XCTAssertEqual(decoded, original)
    }

    func testDecisionResponseWithLearnRoundTrip() throws {
        let body = DecisionResponseBody(
            requestId: "req",
            decision: "allow_always",
            learn: LearnedDecisionEnvelope(granularity: "per_template_etld1")
        )
        let original = IpcMessage.decisionResponse(body)
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(IpcMessage.self, from: encoded)
        XCTAssertEqual(decoded, original)
    }

    func testDecisionResponseWithoutLearnOmitsField() throws {
        let body = DecisionResponseBody(
            requestId: "req",
            decision: "deny_once",
            learn: nil
        )
        let original = IpcMessage.decisionResponse(body)
        let encoded = try JSONEncoder().encode(original)
        let json = String(data: encoded, encoding: .utf8) ?? ""
        // Swift's default JSONEncoder emits `null` for nil; we accept either
        // omitted OR null on the wire as long as the round-trip matches the
        // Optional<LearnedDecisionEnvelope> contract on decode. Asserting
        // round-trip equality (above tests) is the load-bearing invariant.
        // Here we simply ensure no `granularity` value leaks when learn is nil.
        XCTAssertFalse(json.contains("granularity"))
    }

    func testFlowDecisionRecordedEncodesNilMatchedRuleIdAsNull() throws {
        let nilRuleBody = FlowDecisionRecordedBody(
            decision: "drop",
            destination: IpcDestination(
                host: nil,
                ip: "203.0.113.4",
                port: 8080,
                protocolName: "tcp",
                hostnameSource: nil,
                opaque: true
            ),
            agent: IpcAgentAttribution(id: "agent-9", template: "ops-runner"),
            matchedRuleId: nil,
            recordedAt: "2026-05-11T12:01:00Z"
        )
        let nilRuleMessage = IpcMessage.flowDecisionRecorded(nilRuleBody)
        let nilRuleEncoded = try JSONEncoder().encode(nilRuleMessage)
        let nilRuleObject = try XCTUnwrap(
            JSONSerialization.jsonObject(with: nilRuleEncoded) as? [String: Any]
        )
        XCTAssertTrue(nilRuleObject.keys.contains("matched_rule_id"))
        XCTAssertTrue(nilRuleObject["matched_rule_id"] is NSNull)
        XCTAssertEqual(
            try JSONDecoder().decode(IpcMessage.self, from: nilRuleEncoded),
            nilRuleMessage
        )

        let matchedRuleBody = FlowDecisionRecordedBody(
            decision: "allow",
            destination: IpcDestination(
                host: "api.anthropic.com",
                ip: "104.18.32.10",
                port: 443,
                protocolName: "tcp",
                hostnameSource: "sni",
                opaque: false
            ),
            agent: IpcAgentAttribution(id: "agent-7", template: "coding-assistant"),
            matchedRuleId: "rule-anthropic",
            recordedAt: "2026-05-11T12:00:00Z"
        )
        let matchedRuleMessage = IpcMessage.flowDecisionRecorded(matchedRuleBody)
        let matchedRuleEncoded = try JSONEncoder().encode(matchedRuleMessage)
        XCTAssertEqual(
            try JSONDecoder().decode(IpcMessage.self, from: matchedRuleEncoded),
            matchedRuleMessage
        )
    }

    func testUnknownTypeFailsToDecode() {
        let raw = "{\"type\":\"bogus\",\"x\":1}".data(using: .utf8)!
        XCTAssertThrowsError(try JSONDecoder().decode(IpcMessage.self, from: raw))
    }

    func testEnvelopeWrapperRoundTrip() throws {
        let inner = IpcMessage.handshakeChallenge(nonceB64url: "AAAA")
        let envelope = MessageEnvelope(
            jsonrpc: "2.0",
            method: "castle-wall.handshake_challenge",
            params: inner
        )
        let encoded = try JSONEncoder().encode(envelope)
        let decoded = try JSONDecoder().decode(MessageEnvelope.self, from: encoded)
        XCTAssertEqual(decoded, envelope)
    }
}
