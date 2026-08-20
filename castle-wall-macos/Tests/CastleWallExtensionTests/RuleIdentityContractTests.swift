import XCTest
@testable import CastleWallFilter
@testable import CastleWallIPC

final class RuleIdentityContractTests: XCTestCase {
    func testConsumesSharedContractVectors() throws {
        let source = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("castle-wall-daemon/test-vectors/rule-id-filename-v1.json")
        let fixture = try JSONSerialization.jsonObject(with: Data(contentsOf: source)) as! [String: Any]
        for vector in fixture["valid"] as! [[String: String]] {
            let id = vector["id"]!
            XCTAssertTrue(SignedManifestVerifier.validateRuleId(id))
            XCTAssertEqual(SignedManifestVerifier.encodedRuleFilename(for: id), vector["encoded_v1"])
            XCTAssertTrue(SignedManifestVerifier.preflightManifestRuleEntries([
                ManifestRuleDigestEntry(ruleId: id, file: vector["legacy_safe"]!, sha256: "00"),
            ]).isEmpty)
        }
        for id in fixture["invalid_ids"] as! [String] {
            XCTAssertFalse(SignedManifestVerifier.validateRuleId(id))
        }
        for filename in fixture["invalid_filenames"] as! [String] {
            XCTAssertFalse(SignedManifestVerifier.preflightManifestRuleEntries([
                ManifestRuleDigestEntry(ruleId: "a", file: filename, sha256: "00"),
            ]).isEmpty)
        }
    }
    func testPinsEncodedV1AndLegacySafeRelations() throws {
        XCTAssertEqual(
            SignedManifestVerifier.encodedRuleFilename(for: "curated:alpha_1.2-3"),
            "rid1_Y3VyYXRlZDphbHBoYV8xLjItMw.json"
        )
        XCTAssertTrue(SignedManifestVerifier.preflightManifestRuleEntries([
            ManifestRuleDigestEntry(ruleId: "safe-id", file: "safe-id.json", sha256: "00"),
            ManifestRuleDigestEntry(ruleId: "other", file: "rid1_b3RoZXI.json", sha256: "00"),
        ]).isEmpty)
    }

    func testRejectsNonAsciiCanonicalEquivalentAndOverlongIdsBeforeDictionaryInsertion() {
        for value in ["café", "e\u{301}", ".leading", "has space", "a/b", String(repeating: "a", count: 121)] {
            XCTAssertFalse(SignedManifestVerifier.validateRuleId(value), value)
        }
        XCTAssertFalse(SignedManifestVerifier.preflightManifestRuleEntries([
            ManifestRuleDigestEntry(ruleId: "café", file: "café.json", sha256: "00"),
        ]).isEmpty)
    }

    func testRejectsMismatchedAndDuplicatePersistedRelations() {
        XCTAssertFalse(SignedManifestVerifier.preflightManifestRuleEntries([
            ManifestRuleDigestEntry(ruleId: "safe-id", file: "other.json", sha256: "00"),
        ]).isEmpty)
        let duplicateIssues = SignedManifestVerifier.preflightManifestRuleEntries([
            ManifestRuleDigestEntry(ruleId: "safe-id", file: "safe-id.json", sha256: "00"),
            ManifestRuleDigestEntry(ruleId: "safe-id", file: "safe-id.json", sha256: "00"),
        ])
        XCTAssertEqual(duplicateIssues.count, 2)
    }
}
