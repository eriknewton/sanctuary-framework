import XCTest
import CryptoKit
@testable import CastleWallFilter
@testable import CastleWallIPC

final class ManifestDerivedDigestFixtureTests: XCTestCase {
    func testRealDerivedDNSManifestVerifiesAgainstPinnedKey() throws {
        let message = try loadCapturedManifest()
        guard case .manifestUpdated(let body) = message.params else {
            return XCTFail("expected manifest_updated")
        }

        let snapshot = try SignedManifestVerifier.verifiedSnapshot(
            from: body,
            pinnedPublicKey: try loadPinnedPublicKey(),
            now: Date(timeIntervalSince1970: 0)
        )

        XCTAssertEqual(snapshot.rules.count, 3)
        XCTAssertTrue(snapshot.rules.contains { $0.id == "derived_dns_for_hostname_rules" })
    }

    func testTypedRuleRoundTripDivergenceIsLimitedToUnknownDerivedField() throws {
        let message = try loadCapturedManifest()
        guard case .manifestUpdated(let body) = message.params else {
            return XCTFail("expected manifest_updated")
        }
        let rawRules = try XCTUnwrap(body.receivedRules)
        guard let rawDerived = rawRules.firstObject(withId: "derived_dns_for_hostname_rules"),
              let typedDerived = body.rules.first(where: { $0.id == "derived_dns_for_hostname_rules" }) else {
            return XCTFail("expected derived DNS rule")
        }

        let typedBytes = try SignedManifestVerifier.canonicalJSONData(typedDerived)
        let typedJSON = try JSONDecoder().decode(JSONValue.self, from: typedBytes)

        XCTAssertEqual(rawDerived.value(at: "match", "ip"), typedJSON.value(at: "match", "ip"))
        XCTAssertEqual(rawDerived.value(at: "match", "port"), typedJSON.value(at: "match", "port"))
        XCTAssertEqual(rawDerived.value(at: "match", "protocol"), typedJSON.value(at: "match", "protocol"))
        XCTAssertEqual(rawDerived.value(at: "derived"), .bool(true))
        XCTAssertNil(typedJSON.value(at: "derived"))
    }

    func testUnknownDeliveredRuleFieldsAreDigestInput() throws {
        let ruleJSON = """
        {
          "id": "rule-with-future-field",
          "schema_version": 1,
          "created_at": "2026-06-11T00:00:00Z",
          "match": { "host": "api.example.com", "port": 443, "protocol": "tcp" },
          "scope": {},
          "disposition": "allow",
          "future_field_absent_from_swift_model": { "enabled": true }
        }
        """
        let rawRule = try JSONDecoder().decode(JSONValue.self, from: Data(ruleJSON.utf8))
        let typedRule = try JSONDecoder().decode(ManifestRule.self, from: Data(ruleJSON.utf8))
        let ruleDigest = try SignedManifestVerifier.sha256Hex(
            SignedManifestVerifier.canonicalJSONData(rawRule)
        )

        let privateKey = Curve25519.Signing.PrivateKey()
        let manifest = ManifestSignedBody(
            schemaVersion: CastleWallConstants.schemaVersionV1,
            fortressId: "fortress-test",
            issuedAt: "2026-06-11T00:00:00Z",
            rules: [
                ManifestRuleDigestEntry(
                    ruleId: typedRule.id,
                    file: "\(typedRule.id).json",
                    sha256: ruleDigest
                )
            ]
        )
        let manifestBytes = try SignedManifestVerifier.canonicalJSONData(manifest)
        let signature = try privateKey.signature(for: manifestBytes)
        let body = ManifestUpdatedBody(
            manifest: manifest,
            signature: ManifestSignatureEnvelope(
                signatureScheme: CastleWallConstants.signatureSchemeV1,
                signingKeyId: "test-key",
                signatureB64url: Base64URL.encode(signature)
            ),
            rules: [typedRule],
            receivedRules: [rawRule]
        )

        XCTAssertNoThrow(try SignedManifestVerifier.verifiedSnapshot(
            from: body,
            pinnedPublicKey: privateKey.publicKey.rawRepresentation,
            now: Date(timeIntervalSince1970: 0)
        ))
    }

    private func loadCapturedManifest() throws -> MessageEnvelope {
        let data = try Data(contentsOf: fixtureURL("manifest-updated-derived-dns-2026-06-11b.json"))
        return try JSONDecoder().decode(MessageEnvelope.self, from: data)
    }

    private func loadPinnedPublicKey() throws -> Data {
        return try Data(contentsOf: fixtureURL("pinned-pubkey-2026-06-11b.bin"))
    }

    private func fixtureURL(_ name: String) -> URL {
        return URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
            .appendingPathComponent(name)
    }
}

private extension Array where Element == JSONValue {
    func firstObject(withId id: String) -> JSONValue? {
        return first { $0.value(at: "id") == .string(id) }
    }
}

private extension JSONValue {
    func value(at path: String...) -> JSONValue? {
        return value(atPath: ArraySlice(path))
    }

    private func value(atPath path: ArraySlice<String>) -> JSONValue? {
        guard let head = path.first else {
            return self
        }
        guard case .object(let object) = self, let value = object[head] else {
            return nil
        }
        return value.value(atPath: path.dropFirst())
    }
}
