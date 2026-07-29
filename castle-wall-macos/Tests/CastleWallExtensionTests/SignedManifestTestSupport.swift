import Foundation
import CryptoKit
@testable import CastleWallFilter
@testable import CastleWallIPC

func makeSignedManifestUpdatedBody(
    rules: [ManifestRule],
    privateKey: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey(),
    schemaVersion: UInt32 = CastleWallConstants.schemaVersionV1,
    agentOrigin: AgentOriginWire? = nil,
    operatorBaseline: OperatorBaselineWire? = nil
) throws -> (body: ManifestUpdatedBody, publicKey: Data) {
    let entries = try rules.map { rule -> ManifestRuleDigestEntry in
        let ruleBytes = try SignedManifestVerifier.canonicalJSONData(rule)
        return ManifestRuleDigestEntry(
            ruleId: rule.id,
            file: "\(rule.id).json",
            sha256: SignedManifestVerifier.sha256Hex(ruleBytes)
        )
    }
    let manifest = ManifestSignedBody(
        schemaVersion: schemaVersion,
        fortressId: "fortress-test",
        issuedAt: "2026-05-14T00:00:00Z",
        rules: entries,
        agentOrigin: agentOrigin,
        operatorBaseline: operatorBaseline
    )
    let manifestBytes = try SignedManifestVerifier.canonicalJSONData(manifest)
    let signature = try privateKey.signature(for: manifestBytes)
    let envelope = ManifestSignatureEnvelope(
        signatureScheme: CastleWallConstants.signatureSchemeV1,
        signingKeyId: "test-key",
        signatureB64url: Base64URL.encode(signature)
    )
    return (
        ManifestUpdatedBody(manifest: manifest, signature: envelope, rules: rules),
        privateKey.publicKey.rawRepresentation
    )
}

/// Build a validly-signed `manifest_updated` body from RAW rule JSON strings,
/// decoded through the real wire path so `receivedRules` (and, for the manifest
/// body, `receivedManifest`) carry the exact raw shapes -- including shapes the
/// typed `ManifestRule`/`AgentOriginWire` `Codable` would collapse (e.g. an
/// explicit `"scope": {"uids": null}`). This is the S5-0 HIGH-2 attacker shape:
/// a rule whose raw scope is off-spec but whose digest and manifest signature
/// are valid. The digest is computed over the RAW canonical bytes exactly as
/// `SignedManifestVerifier.verifyRuleDigests` does.
func makeSignedBodyWithRawRules(
    rawRuleJSONs: [String],
    privateKey: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey(),
    agentOrigin: AgentOriginWire? = nil
) throws -> (body: ManifestUpdatedBody, publicKey: Data) {
    var entries: [ManifestRuleDigestEntry] = []
    var rawRuleObjects: [Any] = []
    for rawRuleJSON in rawRuleJSONs {
        let data = Data(rawRuleJSON.utf8)
        let rawValue = try JSONDecoder().decode(JSONValue.self, from: data)
        guard case .object(let obj) = rawValue, case .string(let id)? = obj["id"] else {
            throw NSError(domain: "test", code: 1, userInfo: [NSLocalizedDescriptionKey: "raw rule missing id"])
        }
        let digest = try SignedManifestVerifier.sha256Hex(
            SignedManifestVerifier.canonicalJSONData(rawValue)
        )
        entries.append(ManifestRuleDigestEntry(ruleId: id, file: "\(id).json", sha256: digest))
        rawRuleObjects.append(try JSONSerialization.jsonObject(with: data))
    }
    let manifest = ManifestSignedBody(
        schemaVersion: CastleWallConstants.schemaVersionV1,
        fortressId: "fortress-test",
        issuedAt: "2026-07-14T00:00:00Z",
        rules: entries,
        agentOrigin: agentOrigin
    )
    let manifestBytes = try SignedManifestVerifier.canonicalJSONData(manifest)
    let signature = try privateKey.signature(for: manifestBytes)

    // Assemble the wire JSON and decode it through the real path so
    // receivedRules / receivedManifest populate exactly as on-device.
    let manifestObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(manifest))
    let wire: [String: Any] = [
        "type": "manifest_updated",
        "manifest": manifestObject,
        "signature": [
            "signature_scheme": CastleWallConstants.signatureSchemeV1,
            "signing_key_id": "test-key",
            "signature_b64url": Base64URL.encode(signature),
        ],
        "rules": rawRuleObjects,
    ]
    let wireData = try JSONSerialization.data(withJSONObject: wire)
    let body = try JSONDecoder().decode(ManifestUpdatedBody.self, from: wireData)
    return (body, privateKey.publicKey.rawRepresentation)
}
