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

    private func loadFixture() throws -> Fixture {
        let fixtureURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
            .appendingPathComponent("manifest-parity-vector.json")
        let data = try Data(contentsOf: fixtureURL)
        return try JSONDecoder().decode(Fixture.self, from: data)
    }
}

private extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02x", $0) }.joined()
    }
}
