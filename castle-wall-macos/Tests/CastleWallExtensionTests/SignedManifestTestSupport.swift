import Foundation
import CryptoKit
@testable import CastleWallFilter
@testable import CastleWallIPC

func makeSignedManifestUpdatedBody(
    rules: [ManifestRule],
    privateKey: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey(),
    schemaVersion: UInt32 = CastleWallConstants.schemaVersionV1,
    agentOrigin: AgentOriginWire? = nil
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
        agentOrigin: agentOrigin
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
