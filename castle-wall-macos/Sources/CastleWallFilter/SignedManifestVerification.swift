//
// SignedManifestVerification.swift
//
// Extension-side trust boundary for IPC-delivered manifest snapshots.
// The extension verifies the signed manifest body against the pinned
// fortress public key, checks schema-version invariants, and verifies the
// delivered rule snapshot against the signed rule digests before the active
// ManifestStore is replaced.
//

import Foundation
import CryptoKit
import CastleWallIPC

public enum SignedManifestVerificationError: Error, Equatable {
    case missingSignedEnvelope
    case unsupportedManifestSchemaVersion(UInt32)
    case unsupportedRuleSchemaVersion(ruleId: String, schemaVersion: UInt32)
    case unsupportedSignatureScheme(String)
    case pinnedKeyLength(expected: Int, actual: Int)
    case pinnedKeyMalformed(String)
    case signatureDecode(String)
    case signatureLength(expected: Int, actual: Int)
    case signatureMismatch
    case canonicalizationFailed(String)
    case ruleDigestCountMismatch(manifest: Int, delivered: Int)
    case duplicateRuleId(String)
    case missingDeliveredRule(String)
    case unexpectedDeliveredRule(String)
    case ruleDigestMismatch(ruleId: String, expected: String, actual: String)
}

public enum SignedManifestVerifier {
    public static func verifiedSnapshot(
        from body: ManifestUpdatedBody,
        pinnedPublicKey: Data,
        now: Date = Date()
    ) throws -> ManifestSnapshot {
        guard let manifest = body.manifest, let signature = body.signature else {
            throw SignedManifestVerificationError.missingSignedEnvelope
        }
        guard manifest.schemaVersion == CastleWallConstants.schemaVersionV1 else {
            throw SignedManifestVerificationError.unsupportedManifestSchemaVersion(manifest.schemaVersion)
        }
        guard signature.signatureScheme == CastleWallConstants.signatureSchemeV1 else {
            throw SignedManifestVerificationError.unsupportedSignatureScheme(signature.signatureScheme)
        }
        guard pinnedPublicKey.count == 32 else {
            throw SignedManifestVerificationError.pinnedKeyLength(expected: 32, actual: pinnedPublicKey.count)
        }

        let payloadBytes: Data
        do {
            payloadBytes = try canonicalJSONData(manifest)
        } catch {
            throw SignedManifestVerificationError.canonicalizationFailed("\(error)")
        }

        let signatureBytes: Data
        do {
            signatureBytes = try Base64URL.decode(signature.signatureB64url)
        } catch {
            throw SignedManifestVerificationError.signatureDecode("\(error)")
        }
        guard signatureBytes.count == 64 else {
            throw SignedManifestVerificationError.signatureLength(
                expected: 64,
                actual: signatureBytes.count
            )
        }

        let key: Curve25519.Signing.PublicKey
        do {
            key = try Curve25519.Signing.PublicKey(rawRepresentation: pinnedPublicKey)
        } catch {
            throw SignedManifestVerificationError.pinnedKeyMalformed("\(error)")
        }
        guard key.isValidSignature(signatureBytes, for: payloadBytes) else {
            throw SignedManifestVerificationError.signatureMismatch
        }

        try verifyRuleDigests(
            manifest: manifest,
            rules: body.rules,
            receivedRules: body.receivedRules
        )
        // `manifest.agentOrigin` is part of the canonical bytes just verified
        // against the pinned key, so it is trusted iff the signature passed.
        // An unsigned / replayed envelope can never inject it.
        return ManifestSnapshot(
            signatureB64url: signature.signatureB64url,
            rules: body.rules,
            updatedAt: now,
            agentOrigin: manifest.agentOrigin,
            operatorBaseline: manifest.operatorBaseline
        )
    }

    public static func canonicalJSONData<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        let encoded = try encoder.encode(value)
        let object = try JSONSerialization.jsonObject(with: encoded)
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    public static func canonicalJSONData(_ value: JSONValue) throws -> Data {
        return try JSONSerialization.data(
            withJSONObject: value.jsonObject(),
            options: [.sortedKeys]
        )
    }

    public static func sha256Hex(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func verifyRuleDigests(
        manifest: ManifestSignedBody,
        rules: [ManifestRule],
        receivedRules: [JSONValue]?
    ) throws {
        guard manifest.rules.count == rules.count else {
            throw SignedManifestVerificationError.ruleDigestCountMismatch(
                manifest: manifest.rules.count,
                delivered: rules.count
            )
        }

        var deliveredById: [String: ManifestRule] = [:]
        var receivedById: [String: JSONValue] = [:]
        for (index, rule) in rules.enumerated() {
            guard rule.schemaVersion == CastleWallConstants.schemaVersionV1 else {
                throw SignedManifestVerificationError.unsupportedRuleSchemaVersion(
                    ruleId: rule.id,
                    schemaVersion: rule.schemaVersion
                )
            }
            if deliveredById[rule.id] != nil {
                throw SignedManifestVerificationError.duplicateRuleId(rule.id)
            }
            deliveredById[rule.id] = rule
            if let receivedRules, receivedRules.count == rules.count {
                receivedById[rule.id] = receivedRules[index]
            }
        }

        var manifestIds = Set<String>()
        for entry in manifest.rules {
            if manifestIds.contains(entry.ruleId) {
                throw SignedManifestVerificationError.duplicateRuleId(entry.ruleId)
            }
            manifestIds.insert(entry.ruleId)
            guard let rule = deliveredById[entry.ruleId] else {
                throw SignedManifestVerificationError.missingDeliveredRule(entry.ruleId)
            }
            let digest = try sha256Hex(
                receivedById[entry.ruleId].map { try canonicalJSONData($0) } ?? canonicalJSONData(rule)
            )
            guard digest == entry.sha256.lowercased() else {
                throw SignedManifestVerificationError.ruleDigestMismatch(
                    ruleId: entry.ruleId,
                    expected: entry.sha256.lowercased(),
                    actual: digest
                )
            }
        }

        for rule in rules where !manifestIds.contains(rule.id) {
            throw SignedManifestVerificationError.unexpectedDeliveredRule(rule.id)
        }
    }
}
