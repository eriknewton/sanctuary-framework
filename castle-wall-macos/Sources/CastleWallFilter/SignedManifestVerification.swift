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

    // Canonicalization parity (2026-07-12 Mini1 egress drill fix).
    //
    // These bytes MUST byte-match the Node signer's canonical JSON
    // (`server/src/mesh/canonical-json.ts`: JSON.stringify escaping, keys
    // sorted by UTF-16 code units, no whitespace). The previous
    // JSONSerialization-based implementation escaped "/" as "\/", so any
    // signed rule whose content contained a forward slash (every
    // provisioned-hermes rule description carries "443/tcp") recomputed a
    // different SHA-256 digest and the extension rejected the whole egress
    // manifest -- the wall silently kept enforcing its prior manifest while
    // the CLI reported armed. Verified live on Mini1: every egress
    // manifest_updated since sysext 1118 booted was rejected; baseline
    // (slash-free) manifests applied.
    //
    // FAIL-CLOSED bounds: non-finite and non-integral numbers are rejected
    // (the Node emitter's shortest-round-trip float formatting is not
    // reproduced here; no signed surface carries floats today), so a future
    // float-bearing manifest surfaces as a loud verifier rejection, never a
    // silently divergent signature.
    public static func canonicalJSONData<T: Encodable>(_ value: T) throws -> Data {
        let encoded = try JSONEncoder().encode(value)
        let jsonValue: JSONValue
        do {
            jsonValue = try JSONDecoder().decode(JSONValue.self, from: encoded)
        } catch {
            throw SignedManifestVerificationError.canonicalizationFailed("\(error)")
        }
        return try canonicalJSONData(jsonValue)
    }

    public static func canonicalJSONData(_ value: JSONValue) throws -> Data {
        var out = ""
        try appendCanonicalJSON(value, to: &out)
        return Data(out.utf8)
    }

    private static func appendCanonicalJSON(_ value: JSONValue, to out: inout String) throws {
        switch value {
        case .null:
            out += "null"
        case .bool(let v):
            out += v ? "true" : "false"
        case .integer(let v):
            out += String(v)
        case .number(let v):
            guard v.isFinite else {
                throw SignedManifestVerificationError.canonicalizationFailed(
                    "non-finite number is not canonicalizable"
                )
            }
            // Integral doubles print like integers in the Node emitter
            // (JSON.stringify(443.0) == "443"); anything else is rejected
            // rather than risk a byte-divergent float rendering.
            guard let integral = Int64(exactly: v) else {
                throw SignedManifestVerificationError.canonicalizationFailed(
                    "non-integral number is not canonicalizable (no float parity contract)"
                )
            }
            out += String(integral)
        case .string(let s):
            appendCanonicalJSONString(s, to: &out)
        case .array(let items):
            out += "["
            var first = true
            for item in items {
                if !first { out += "," }
                first = false
                try appendCanonicalJSON(item, to: &out)
            }
            out += "]"
        case .object(let dict):
            // Node sorts keys by UTF-16 code units (Array.prototype.sort on
            // strings); Swift's default String ordering differs, so compare
            // explicit UTF-16 code-unit sequences.
            //
            // DEBT (#921 follow-up, contained-not-fixed): `dict` here is a
            // genuinely dynamic `[String: JSONValue]` map. Swift's String
            // equality is Unicode canonical-equivalence-aware, so if this
            // dictionary was populated by decoding raw untrusted JSON text
            // (e.g. an IPC-delivered `receivedRules` payload) rather than
            // through a fixed-key Codable struct, two RAW-DISTINCT JSON keys
            // that are NFC/NFD-equivalent (e.g. precomposed "e-acute" vs.
            // "e" + combining acute) silently collapse into ONE dictionary
            // entry (last-decoded wins) before this function ever runs --
            // see testCanonicalKeyOrderCollapsesCanonicallyEquivalentKeysOnDecode
            // in ManifestParityVectorTests.swift, which documents the exact
            // divergence against the TS canonicalizer (which does NOT
            // normalize and treats the two keys as distinct). This is
            // CONTAINED today: every field that reaches this function
            // (AllowlistManifest / ManifestRuleEntry / AgentOrigin /
            // OperatorBaseline) is a fixed-key Codable struct, never a
            // dynamic map, so the per-rule digest / manifest-signature
            // checks fail closed on any resulting byte-count mismatch. If a
            // FUTURE signed field introduces a genuinely dynamic
            // `[String: JSONValue]` map, this collapse becomes live and
            // needs a fix before that field ships -- e.g. decode such maps
            // from an ordered key/value array instead of a Swift
            // Dictionary, or reject decode outright on any UTF-16-distinct
            // keys that compare canonically-equal. Not fixed here (no
            // dynamic-map field exists yet to regress); flagged so it is
            // not rediscovered from scratch.
            let keys = dict.keys.sorted {
                Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16))
            }
            out += "{"
            var first = true
            for key in keys {
                if !first { out += "," }
                first = false
                appendCanonicalJSONString(key, to: &out)
                out += ":"
                try appendCanonicalJSON(dict[key]!, to: &out)
            }
            out += "}"
        }
    }

    /// JSON string literal with exactly JSON.stringify's escaping: quote,
    /// backslash, the short control escapes, \u00xx (lowercase hex) for the
    /// remaining control characters, and EVERYTHING else raw -- no "/"
    /// escaping, no non-ASCII escaping.
    private static func appendCanonicalJSONString(_ s: String, to out: inout String) {
        out += "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{09}": out += "\\t"
            case "\u{0A}": out += "\\n"
            case "\u{0C}": out += "\\f"
            case "\u{0D}": out += "\\r"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
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
