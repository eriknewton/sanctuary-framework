import XCTest
@testable import CastleWallFilter
@testable import CastleWallIPC

final class ManifestParityVectorTests: XCTestCase {
    private struct Fixture: Decodable {
        let manifestSignedBody: ManifestSignedBody
        let rules: [ManifestRule]
        let expectedCanonicalJsonB64: String
        let expectedCanonicalJsonHex: String
        let testPublicKeyB64url: String
        let testSignatureB64url: String

        enum CodingKeys: String, CodingKey {
            case manifestSignedBody = "manifest_signed_body"
            case rules
            case expectedCanonicalJsonB64 = "expected_canonical_json_b64"
            case expectedCanonicalJsonHex = "expected_canonical_json_hex"
            case testPublicKeyB64url = "test_public_key_b64url"
            case testSignatureB64url = "test_signature_b64url"
        }
    }

    func testCanonicalBytesAndSignatureParityVector() throws {
        let fixture = try loadFixture()
        let expectedBytes = try XCTUnwrap(Data(base64Encoded: fixture.expectedCanonicalJsonB64))

        let actualBytes = try SignedManifestVerifier.canonicalJSONData(fixture.manifestSignedBody)
        XCTAssertEqual(actualBytes, expectedBytes)
        XCTAssertEqual(actualBytes.hexEncodedString(), fixture.expectedCanonicalJsonHex)

        let signature = ManifestSignatureEnvelope(
            signatureScheme: CastleWallConstants.signatureSchemeV1,
            signingKeyId: "parity-test-key",
            signatureB64url: fixture.testSignatureB64url
        )
        let message = ManifestUpdatedBody(
            manifest: fixture.manifestSignedBody,
            signature: signature,
            rules: fixture.rules
        )
        let pinnedPublicKey = try Base64URL.decode(fixture.testPublicKeyB64url)

        let snapshot = try SignedManifestVerifier.verifiedSnapshot(
            from: message,
            pinnedPublicKey: pinnedPublicKey,
            now: Date(timeIntervalSince1970: 0)
        )
        XCTAssertEqual(snapshot.rules.count, fixture.rules.count)
        XCTAssertEqual(snapshot.signatureB64url, fixture.testSignatureB64url)
    }

    /// The 2026-07-12 Mini1 drill regression: rule content containing a
    /// forward slash (every provisioned-hermes description carries
    /// "443/tcp"). The previous JSONSerialization-based canonicalization
    /// escaped "/" as "\/", so the recomputed per-rule digests diverged from
    /// the Node signer's and the extension rejected every egress manifest
    /// while the CLI reported armed. The body is decoded from wire-shaped
    /// JSON so `receivedRules` populates exactly as on the live IPC path.
    func testSlashBearingEgressManifestVerifies() throws {
        let fixture = try loadFixture(named: "manifest-parity-vector-slash")

        let canonicalBody = try SignedManifestVerifier.canonicalJSONData(fixture.manifestSignedBody)
        XCTAssertEqual(canonicalBody.hexEncodedString(), fixture.expectedCanonicalJsonHex)

        // Rebuild the wire notification and decode it, so receivedRules is
        // sourced from the raw "rules" JSON exactly as delivered by the
        // daemon (this is the path the live rejection went through).
        let fixtureJSON = try JSONSerialization.jsonObject(
            with: Data(contentsOf: fixtureURL(named: "manifest-parity-vector-slash"))
        ) as! [String: Any]
        let wire: [String: Any] = [
            "type": "manifest_updated",
            "manifest": fixtureJSON["manifest_signed_body"]!,
            "signature": [
                "signature_scheme": CastleWallConstants.signatureSchemeV1,
                "signing_key_id": "parity-test-key",
                "signature_b64url": fixture.testSignatureB64url,
            ],
            "rules": fixtureJSON["rules"]!,
        ]
        let wireData = try JSONSerialization.data(withJSONObject: wire)
        let message = try JSONDecoder().decode(ManifestUpdatedBody.self, from: wireData)
        XCTAssertNotNil(message.receivedRules)

        let pinnedPublicKey = try Base64URL.decode(fixture.testPublicKeyB64url)
        let snapshot = try SignedManifestVerifier.verifiedSnapshot(
            from: message,
            pinnedPublicKey: pinnedPublicKey,
            now: Date(timeIntervalSince1970: 0)
        )
        XCTAssertEqual(snapshot.rules.count, fixture.rules.count)
    }

    func testCanonicalStringEscapingMatchesNodeEmitter() throws {
        // No "/" escaping; JSON.stringify short escapes; \u00xx lowercase hex
        // for remaining controls; raw non-ASCII.
        let value = JSONValue.object([
            "d": .string("api.venice.ai:443/tcp"),
            "q": .string("a\"b\\c\u{08}\u{09}\u{0A}\u{0C}\u{0D}\u{1F}\u{E9}"),
        ])
        let bytes = try SignedManifestVerifier.canonicalJSONData(value)
        let text = String(data: bytes, encoding: .utf8)!
        XCTAssertEqual(
            text,
            "{\"d\":\"api.venice.ai:443/tcp\",\"q\":\"a\\\"b\\\\c\\b\\t\\n\\f\\r\\u001f\u{E9}\"}"
        )
    }

    func testCanonicalKeyOrderIsUTF16CodeUnitOrder() throws {
        let value = JSONValue.object([
            "a": .integer(1),
            "Z": .integer(2),
            "_": .integer(3),
            "\u{E9}": .integer(4),
        ])
        let bytes = try SignedManifestVerifier.canonicalJSONData(value)
        let text = String(data: bytes, encoding: .utf8)!
        XCTAssertEqual(text, "{\"Z\":2,\"_\":3,\"a\":1,\"\u{E9}\":4}")
    }

    func testCanonicalNumberBounds() {
        XCTAssertThrowsError(
            try SignedManifestVerifier.canonicalJSONData(JSONValue.number(1.5))
        )
        // Integral doubles print like the Node emitter (JSON.stringify(443.0) == "443").
        XCTAssertEqual(
            try SignedManifestVerifier.canonicalJSONData(JSONValue.number(443.0)),
            Data("443".utf8)
        )
    }

    private func loadFixture() throws -> Fixture {
        return try loadFixture(named: "manifest-parity-vector")
    }

    private func loadFixture(named name: String) throws -> Fixture {
        let data = try Data(contentsOf: fixtureURL(named: name))
        return try JSONDecoder().decode(Fixture.self, from: data)
    }

    private func fixtureURL(named name: String) -> URL {
        return URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
            .appendingPathComponent("\(name).json")
    }
}

private extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}
