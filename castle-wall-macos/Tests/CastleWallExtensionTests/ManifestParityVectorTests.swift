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

    /// #915 follow-up: the u64/large-integer parity class. At
    /// Number.MAX_SAFE_INTEGER (2^53-1) both languages are exact and agree
    /// byte-for-byte (see the TS counterpart
    /// "agrees with Swift at the Number.MAX_SAFE_INTEGER boundary" in
    /// server/test/mesh/canonical-json.test.ts). Beyond that boundary Swift
    /// stays exact -- JSONValue's Codable decode picks `.integer(Int64)` for
    /// any bare JSON integer literal (no decimal point), never routing it
    /// through Double -- while Node's `number` (float64) primitive silently
    /// loses precision with no exception. That divergence is a real,
    /// non-fail-closed finding (documented + skipped, not fixed here, in
    /// the TS suite's "KNOWN GAP" test); this Swift test only proves
    /// Swift's own half is exact, for side-by-side contrast.
    func testCanonicalNumberBoundsAtSafeIntegerAndInt64Max() throws {
        XCTAssertEqual(
            try SignedManifestVerifier.canonicalJSONData(
                JSONValue.integer(9_007_199_254_740_991) // Number.MAX_SAFE_INTEGER
            ),
            Data("9007199254740991".utf8)
        )
        XCTAssertEqual(
            try SignedManifestVerifier.canonicalJSONData(JSONValue.integer(Int64.max)),
            Data("9223372036854775807".utf8)
        )

        // Decoding the same bare integer literal from raw JSON text (the
        // actual production path: JSONDecoder tries Int64 before Double,
        // per JSONValue.init(from:)) preserves full precision too.
        struct WrapBig: Decodable { let v: Int64 }
        let decoded = try JSONDecoder().decode(
            WrapBig.self,
            from: Data("{\"v\":9223372036854775807}".utf8)
        )
        XCTAssertEqual(decoded.v, Int64.max)
    }

    /// #915 follow-up: canonically-equivalent-but-raw-distinct object keys.
    /// "é" (precomposed, U+00E9) and "é" (decomposed, "e" + combining
    /// acute U+0301) are the SAME string under Unicode canonical
    /// equivalence but DIFFERENT raw UTF-16 code-unit sequences.
    ///
    /// This is NOT symmetric with the TS side. Swift's `String` equality
    /// (and therefore `Dictionary` keying) is canonical-equivalence-aware:
    /// a `[String: JSONValue]` dictionary literal built directly from both
    /// forms in Swift source is a compile-time/runtime fatal error
    /// ("Dictionary literal contains duplicate keys"). The realistic attack
    /// surface is decoding raw JSON *text* containing both keys into a
    /// dynamic `[String: JSONValue]` map (the shape `JSONValue.object` uses,
    /// and the shape `receivedRules: [JSONValue]?` decodes into) --
    /// Foundation's JSONDecoder/JSONSerialization do NOT throw there; they
    /// silently keep only the last-decoded key, dropping the other with no
    /// error. This test documents that collapse precisely rather than
    /// asserting parity with the TS test of the same name (see
    /// "keeps canonically-equivalent but raw-distinct object keys as
    /// separate entries" in server/test/mesh/canonical-json.test.ts, which
    /// proves Node keeps all 3 keys).
    ///
    /// Contained today: every field in AllowlistManifest / ManifestRule /
    /// AgentOrigin / OperatorBaseline is a fixed-key Codable struct, not a
    /// dynamic map, so this class cannot reach the manifest signature or
    /// per-rule digest checks silently -- any content that DID differ here
    /// would produce a byte-count mismatch and fail the digest/signature
    /// check (fail-closed). Flagged to the coordinator as a structural
    /// landmine for any future dynamic-map signed field; not fixed here
    /// (test-only build).
    func testCanonicalKeyOrderCollapsesCanonicallyEquivalentKeysOnDecode() throws {
        // "é":1 (decomposed), "é":2 (precomposed), "m":3 -- three
        // distinct JSON keys in the raw text.
        let jsonText = "{\"e\\u0301\":1,\"\\u00e9\":2,\"m\":3}"
        let decoded = try JSONDecoder().decode(JSONValue.self, from: Data(jsonText.utf8))
        guard case .object(let dict) = decoded else {
            return XCTFail("expected .object")
        }
        // Three raw-distinct JSON keys collapsed to two Swift dictionary
        // entries: the decomposed and precomposed "é" forms compare equal
        // under Swift's canonical-equivalence String semantics, so the
        // later-decoded value silently wins.
        XCTAssertEqual(dict.count, 2)
        XCTAssertEqual(dict["m"], .integer(3))
    }

    /// #915 follow-up: deep-but-bounded nesting. Matches the TS test
    /// "matches Swift on deeply nested (but bounded) array recursion" at the
    /// same depth (300) -- both canonicalizers recurse one call frame per
    /// level, and this proves neither overflows nor diverges at that depth.
    func testDeepNestingParityMatchesNodeEmitter() throws {
        let depth = 300
        var value = JSONValue.integer(42)
        for _ in 0..<depth {
            value = .array([value])
        }
        let bytes = try SignedManifestVerifier.canonicalJSONData(value)
        let expected = String(repeating: "[", count: depth) + "42" + String(repeating: "]", count: depth)
        XCTAssertEqual(String(data: bytes, encoding: .utf8), expected)
    }

    /// #915 follow-up: full round-trip parity vector for U+2028 LINE
    /// SEPARATOR, U+2029 PARAGRAPH SEPARATOR, and astral scalar pairs
    /// (single Swift Unicode.Scalar values that are UTF-16 surrogate pairs
    /// in Node). Both languages CAN agree here: JSON grammar does not
    /// require escaping U+2028/U+2029 (only JS *source text* parsing does),
    /// and a well-formed astral codepoint round-trips to the same 4-byte
    /// UTF-8 sequence on both sides. Matches the TS test of the same name.
    ///
    /// Rebuilds the wire notification and decodes it (same as
    /// testSlashBearingEgressManifestVerifies) rather than constructing
    /// ManifestUpdatedBody directly from the typed `rules: [ManifestRule]`,
    /// because these rules carry a `derived` field the typed ManifestRule
    /// struct does not declare -- a direct construction would silently drop
    /// it on re-encode and digest a different (wrong) rule body. The
    /// receivedRules path preserves every field exactly as delivered over
    /// live IPC, which is the actual production digest-verification path.
    func testUnicodeEdgeVectorLineSeparatorsAndAstralPairsMatchNodeEmitter() throws {
        let fixture = try loadFixture(named: "manifest-parity-vector-unicode-edge")
        let expectedBytes = try XCTUnwrap(Data(base64Encoded: fixture.expectedCanonicalJsonB64))

        let actualBytes = try SignedManifestVerifier.canonicalJSONData(fixture.manifestSignedBody)
        XCTAssertEqual(actualBytes, expectedBytes)
        XCTAssertEqual(actualBytes.hexEncodedString(), fixture.expectedCanonicalJsonHex)
        XCTAssertTrue(fixture.manifestSignedBody.fortressId.unicodeScalars.contains(Unicode.Scalar(0x2028)!))
        XCTAssertTrue(fixture.manifestSignedBody.fortressId.unicodeScalars.contains(Unicode.Scalar(0x2029)!))

        let fixtureJSON = try JSONSerialization.jsonObject(
            with: Data(contentsOf: fixtureURL(named: "manifest-parity-vector-unicode-edge"))
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

    /// #915 follow-up: the lone-surrogate fail-closed vector. This fixture's
    /// `fortress_id` carries an unpaired UTF-16 high surrogate (U+D800),
    /// which Node canonicalizes deterministically (see the TS counterpart
    /// "lone-surrogate vector: Node canonicalizes deterministically where
    /// Swift decode fails closed"). Swift's `String` type is
    /// Unicode-scalar-based and structurally cannot hold an unpaired
    /// surrogate, so decoding this fixture must throw -- not a bug to fix,
    /// a structural incompatibility that fails closed by construction.
    func testLoneSurrogateFixtureFailsClosedOnDecode() throws {
        XCTAssertThrowsError(
            try loadFixture(named: "manifest-parity-vector-lone-surrogate")
        ) { error in
            XCTAssertTrue(error is DecodingError, "expected a DecodingError, got \(error)")
        }
    }

    /// S5-0 (2026-07-14 two-confined-uid extension): the new
    /// `agent_origin.gate_uid` field and a rule carrying `scope.uids` inside
    /// the SAME signed body. Proves the Swift canonicalizer + verifier agree
    /// byte-for-byte with the Node signer on the twin-uid shape -- the #1
    /// risk the S5-0 feasibility spike named. See the TS-side half of this
    /// vector ("two-uid vector...") in
    /// server/test/castle-wall/runtime/manifest-parity-vector.test.ts.
    func testTwoUidVectorCanonicalBytesAndSignatureParity() throws {
        let fixture = try loadFixture(named: "manifest-parity-vector-two-uid")
        let expectedBytes = try XCTUnwrap(Data(base64Encoded: fixture.expectedCanonicalJsonB64))

        XCTAssertEqual(fixture.manifestSignedBody.agentOrigin?.gateUid, 601)
        XCTAssertEqual(fixture.rules[1].scope.uids, [601])

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
        XCTAssertEqual(snapshot.agentOrigin?.gateUid, 601)

        // The gate-scoped rule's scope must survive verification intact, and
        // the AllowlistEvaluator must use it to separate the two principals:
        // a gate-uid flow matches the gate-scoped rule, an agent-uid flow to
        // the SAME destination does not.
        let gateRule = try XCTUnwrap(snapshot.rules.first { $0.id == "gate-scoped-endpoint" })
        XCTAssertEqual(gateRule.scope.uids, [601])
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
