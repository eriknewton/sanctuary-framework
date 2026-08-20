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
    case duplicateRuleFilename(String)
    case invalidRuleIdentity(String)
    case invalidManifestRuleFilename(ruleId: String, filename: String)
    case manifestRuleIdentityPreflight([String])
    case missingDeliveredRule(String)
    case unexpectedDeliveredRule(String)
    case ruleDigestMismatch(ruleId: String, expected: String, actual: String)
    /// S5-0 defense-in-depth (2026-07-14): a signed `agent_origin` descriptor
    /// whose floor invariants do not hold. The signature proves AUTHENTICITY,
    /// not producer VALIDITY, so the enforcement side re-checks and rejects the
    /// WHOLE snapshot (keeping prior policy) rather than trusting the producer.
    case invalidAgentOrigin(String)
    /// S5-0 HIGH-2 (2026-07-14): a signed rule whose RAW scope JSON does not
    /// match the TS `validateRule` shape (e.g. `scope.uids: null`, a scalar, a
    /// fractional/zero/negative/over-`UInt32` uid, or a non-string agent/template
    /// id). Optional `Codable` would silently collapse these to "absent",
    /// widening a scoped rule to all agents -- so the enforcement side rejects
    /// the WHOLE snapshot against the RAW bytes the digest actually binds.
    case invalidRuleSchema(ruleId: String, reason: String)
    /// S5-0 HIGH-5 (2026-07-14): a signed rule carries an axis that TS
    /// `validateRule` ACCEPTS but this macOS evaluator does NOT enforce, so
    /// applying the rule without that axis would be BROADER than the operator
    /// authored (e.g. a `time_window`-bounded allow enforced at all times).
    /// Fail closed: reject the whole snapshot, mirroring the Linux daemon's
    /// `UnenforceableRuleAxis` (`castle-wall-daemon/src/policy.rs`), until the
    /// macOS evaluator grows enforcement for the axis. Distinct from
    /// `invalidRuleSchema` (which validates fields the evaluator DOES consume);
    /// this rejects a field the evaluator does NOT consume.
    case unenforceableRuleAxis(ruleId: String, axis: String)
}

public enum SignedManifestVerifier {
    private static let ruleFilenamePrefix = "rid1_"
    private static let ruleFilenameSuffix = ".json"

    /// MANIFEST-RULEID-PATH-01: the ASCII-only gate avoids Unicode
    /// normalization equivalence before values reach Swift dictionaries.
    static func validateRuleId(_ ruleId: String) -> Bool {
        let bytes = Array(ruleId.utf8)
        guard !bytes.isEmpty, bytes.count <= 120, asciiAlphaNumeric(bytes[0]) else { return false }
        return bytes.allSatisfy { asciiAlphaNumeric($0) || $0 == 46 || $0 == 95 || $0 == 58 || $0 == 45 }
    }

    static func encodedRuleFilename(for ruleId: String) -> String? {
        guard validateRuleId(ruleId) else { return nil }
        return ruleFilenamePrefix + Base64URL.encode(Data(ruleId.utf8)) + ruleFilenameSuffix
    }

    static func legacyRuleFilename(for ruleId: String) -> String? {
        guard validateRuleId(ruleId) else { return nil }
        return ruleId + ruleFilenameSuffix
    }

    private static func asciiAlphaNumeric(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
    }

    /// Pure phase-one scan. It runs before any filename is consumed as a map
    /// key or filesystem path and returns every bounded refusal.
    static func preflightManifestRuleEntries(_ entries: [ManifestRuleDigestEntry]) -> [String] {
        var issues: [String] = []
        var ruleIds = Set<String>()
        var filenames = Set<String>()
        for (index, entry) in entries.enumerated() {
            if !ruleIds.insert(entry.ruleId).inserted {
                issues.append("manifest rule \(index): duplicate rule id")
            }
            if !filenames.insert(entry.file).inserted {
                issues.append("manifest rule \(index): duplicate rule filename")
            }
            guard validateRuleId(entry.ruleId) else {
                issues.append("manifest rule \(index): invalid rule id")
                continue
            }
            let encoded = encodedRuleFilename(for: entry.ruleId)!
            let legacy = legacyRuleFilename(for: entry.ruleId)!
            if entry.file != encoded && entry.file != legacy {
                issues.append("manifest rule \(index): invalid rule filename relation")
            }
        }
        return issues
    }
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
        // ─────────────────────────────────────────────────────────────────
        // S5-0 enforcement-boundary SCHEMA validation (the HIGH-1..HIGH-4
        // chokepoint). A valid signature/digest proves AUTHENTICITY, not that
        // the producer's schema/floor invariants hold. AGENTS.md invariant 4/5
        // forbids trusting across the TS->Swift boundary or silently degrading.
        // So EVERY security-relevant field the TS producer validates is
        // independently re-validated HERE, before the snapshot is constructed;
        // on any violation this THROWS, rejecting the WHOLE snapshot (both
        // `applyManifestUpdated` and `recoverPersistedManifest` funnel through
        // here and keep the prior good snapshot + classifier on throw).
        //
        // COMPLETENESS: `validateSignedRule` is the full mirror of the TS
        // `validateRule` (`server/src/castle-wall/allowlist/schema.ts`) for the
        // security-relevant fields the Swift evaluator/classifier consume --
        // the whole `match` clause (destination axes + the "at least one axis"
        // floor + protocol), the whole `scope` (uids/agent_ids/template_ids),
        // unknown-key rejection at rule/match/scope, and disposition -- plus
        // `validateAgentOriginFloors` for `agent_origin` (the TS
        // `validateAgentOrigin` mirror). The `S5-0_930_parity` anti-regression
        // test enumerates each TS-validated field and asserts the chokepoint
        // rejects a malformed value, so no field can be silently left out again.
        //
        // CRITICAL: validate each field in the representation the crypto
        // actually BINDS.
        //   - RULES: their per-rule DIGEST is computed over the RAW wire bytes
        //     (`verifyRuleDigests` hashes `receivedRules`), and the evaluator
        //     consumes the TYPED `ManifestRule` -- but optional `Codable`
        //     silently collapses an explicit JSON `null` (and other off-shape
        //     values) to "absent". A signed rule whose raw scope is
        //     `{"uids": null}` (HIGH-2) or whose raw `match` is `{}` /
        //     `{"host": null}` (HIGH-3) passes the digest yet decodes to a
        //     widened rule (scope -> all agents, match -> any destination). The
        //     digest binds the RAW bytes, so the RAW bytes are what
        //     `validateSignedRule` schema-validates. On the live IPC + recovery
        //     paths `receivedRules` is ALWAYS populated (decoded from the same
        //     `rules` key as the typed rules, `Messages.swift`), so raw<->typed
        //     correspondence is exact; the `receivedRules == nil` skip is the
        //     in-process typed-constructor path only (digest over the typed
        //     re-encode, so no raw-vs-typed gap exists there).
        //   - AGENT_ORIGIN: the MANIFEST-BODY SIGNATURE is verified over the
        //     re-encoded TYPED `ManifestSignedBody`, so the TYPED struct is the
        //     cryptographically-bound form -- `validateAgentOriginFloors`
        //     validates that same typed form (HIGH-1/HIGH-4). As additional
        //     defense-in-depth against the same Codable-null-collapse class we
        //     ALSO schema-check the RAW `agent_origin` when present.
        // ─────────────────────────────────────────────────────────────────
        try validateSignedRule(
            rules: body.rules,
            receivedRules: body.receivedRules
        )
        if let rawManifest = body.receivedManifest {
            try validateRawAgentOriginShape(rawManifest)
        }
        if let origin = manifest.agentOrigin {
            try validateAgentOriginFloors(origin)
        }
        return ManifestSnapshot(
            signatureB64url: signature.signatureB64url,
            rules: body.rules,
            updatedAt: now,
            agentOrigin: manifest.agentOrigin,
            operatorBaseline: manifest.operatorBaseline
        )
    }

    /// Enforcement-boundary re-validation of a signed `AgentOriginWire`,
    /// mirroring the TS producer's `validateAgentOrigin`
    /// (`server/src/castle-wall/allowlist/agent-origin.ts`) floor invariants so
    /// the macOS consumer independently rejects impossible security state
    /// rather than trusting that the producer enforced them before signing.
    /// Throws `invalidAgentOrigin` (caller rejects the whole snapshot) on any
    /// violation. A `nil` descriptor is not passed here (absent is valid).
    static func validateAgentOriginFloors(_ wire: AgentOriginWire) throws {
        switch wire.mode {
        case .uid:
            // UID mode requires the dedicated agent account uid; without it the
            // classifier would resolve every non-system flow as operator.
            guard let agentUid = wire.agentUid else {
                throw SignedManifestVerificationError.invalidAgentOrigin(
                    "uid mode requires agent_uid"
                )
            }
            // Floor: a real, above-the-system-band account. `agent_uid == 0`
            // (root) or below the system-daemon ceiling is nonsensical/dangerous.
            if agentUid < 1 || agentUid < wire.systemUidAllowCeiling {
                throw SignedManifestVerificationError.invalidAgentOrigin(
                    "agent_uid \(agentUid) below floor (must be >= 1 and >= system_uid_allow_ceiling \(wire.systemUidAllowCeiling))"
                )
            }
            // S5-0: the SECOND confined principal must satisfy the SAME floors
            // AND be distinct from the agent. A colliding gate_uid would let a
            // gate-scoped `uids` rule match the agent's own flows, collapsing
            // the two principals into one at enforcement.
            if let gateUid = wire.gateUid {
                if gateUid < 1 || gateUid < wire.systemUidAllowCeiling {
                    throw SignedManifestVerificationError.invalidAgentOrigin(
                        "gate_uid \(gateUid) below floor (must be >= 1 and >= system_uid_allow_ceiling \(wire.systemUidAllowCeiling))"
                    )
                }
                if gateUid == agentUid {
                    throw SignedManifestVerificationError.invalidAgentOrigin(
                        "gate_uid \(gateUid) collides with agent_uid; the two confined principals must be distinct"
                    )
                }
            }
        case .nat:
            // `gate_uid` is a UID-mode-only concept. A NAT descriptor carrying
            // it is malformed: REJECT the whole snapshot (never silently drop
            // the field, which would be a silent-degrade contract violation).
            if wire.gateUid != nil {
                throw SignedManifestVerificationError.invalidAgentOrigin(
                    "gate_uid is not valid in nat mode (uid-mode-only concept)"
                )
            }
            // HIGH-4 (2026-07-14): a present egress-helper identity must be
            // NON-EMPTY. TS `validateAgentOrigin` (`agent-origin.ts`) treats an
            // empty string as absent (`isNonEmptyString("")` is false); Swift's
            // typed `String?` decode reads `""` as `.some("")` = present. If we
            // accepted `egress_helper_signing_id: ""`, `matchesEgressHelper`
            // would compare the real helper's non-empty signing id against `""`,
            // fail the match, and `classifyNat` would resolve the REAL helper as
            // `.operator` -- earning the allow-all fast-path and bypassing every
            // rule. Reject present-but-empty, then require at least one present
            // (which, after the empty rejection, means at least one NON-empty).
            if let signingId = wire.egressHelperSigningId, signingId.isEmpty {
                throw SignedManifestVerificationError.invalidAgentOrigin(
                    "egress_helper_signing_id must be non-empty when present"
                )
            }
            if let teamId = wire.egressHelperTeamId, teamId.isEmpty {
                throw SignedManifestVerificationError.invalidAgentOrigin(
                    "egress_helper_team_id must be non-empty when present"
                )
            }
            guard wire.egressHelperSigningId != nil || wire.egressHelperTeamId != nil else {
                throw SignedManifestVerificationError.invalidAgentOrigin(
                    "nat mode requires at least one non-empty egress-helper identity"
                )
            }
        }
    }

    /// Largest value the sysext's `UInt32` uid wire type can hold. Mirrors the
    /// TS `UINT32_MAX` cap in `agent-origin.ts` / `schema.ts`.
    private static let uidWireMax: Int64 = 0xFFFF_FFFF

    /// The TS `validateRule` known-key sets (`schema.ts`), mirrored so an
    /// unknown key -- which a conforming producer would never sign, and which
    /// an unknown-only scope/match axis would let widen to all-agents /
    /// any-destination -- is rejected here too (fail closed). Only
    /// `schema_version == 1` rules reach this point (`verifyRuleDigests`
    /// rejects any other version first), so these are the v1 key sets.
    private static let knownRuleKeys: Set<String> = [
        "id", "schema_version", "created_at", "description",
        "match", "scope", "disposition", "time_window", "derived",
    ]
    private static let knownMatchKeys: Set<String> = [
        "host", "host_pattern", "ip", "cidr", "port", "protocol",
    ]
    private static let knownScopeKeys: Set<String> = [
        "agent_ids", "template_ids", "uids",
    ]

    /// Complete enforcement-boundary schema validation of each signed rule,
    /// operating on the RAW `receivedRules` JSON (S5-0 HIGH-2 + HIGH-3). This is
    /// the full mirror of the security-relevant TS `validateRule`
    /// (`server/src/castle-wall/allowlist/schema.ts`) for every field the Swift
    /// `AllowlistEvaluator` consumes:
    ///   - unknown keys at the rule / match / scope level are rejected
    ///     (`rejectUnknownKeys` parity);
    ///   - `match` must be an object with at least one of
    ///     `host`/`host_pattern`/`ip`/`cidr`/`port` present, and every present
    ///     axis is shape/grammar-validated (reject `null`, empty array, empty
    ///     string, malformed IP/CIDR, out-of-range port, invalid protocol) --
    ///     otherwise a null-collapsed or empty `match` widens the rule to ANY
    ///     destination in `matchClauseMatches` (HIGH-3);
    ///   - `scope` axes are validated (HIGH-2): `uids` an array of integers in
    ///     `[1, UInt32.max]`; `agent_ids`/`template_ids` arrays of non-empty
    ///     strings; empty arrays mean "all" (parity with TS + `scopeMatches`);
    ///   - `disposition` is one of `allow`/`prompt`/`deny`.
    ///
    /// Runs against the RAW JSON (not the Codable-parsed `ManifestRule`) so an
    /// explicit `null` / off-type value cannot be silently collapsed to
    /// "absent" before it is checked. When `receivedRules` is absent (the typed
    /// in-process constructor path only, never the wire), the digest was computed
    /// over the typed re-encode, so there is no raw-vs-typed gap and validation
    /// is skipped.
    static func validateSignedRule(
        rules: [ManifestRule],
        receivedRules: [JSONValue]?
    ) throws {
        guard let receivedRules else { return }
        for (index, raw) in receivedRules.enumerated() {
            let fallbackId = index < rules.count ? rules[index].id : "<unknown>"
            let ruleId = ruleIdOf(raw: raw) ?? fallbackId
            guard case .object(let ruleObj) = raw else {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId, reason: "rule is not a JSON object"
                )
            }
            try rejectUnknownRawKeys(ruleObj, known: knownRuleKeys, ruleId: ruleId, label: "rule")

            // match
            guard let matchValue = ruleObj["match"] else {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId, reason: "rule.match missing"
                )
            }
            try validateRawMatch(matchValue, ruleId: ruleId)

            // scope
            guard let scopeValue = ruleObj["scope"] else {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId, reason: "rule.scope missing"
                )
            }
            try validateRawScope(scopeValue, ruleId: ruleId)

            // disposition
            guard case .string(let disposition)? = ruleObj["disposition"] else {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId, reason: "rule.disposition missing or not a string"
                )
            }
            guard disposition == "allow" || disposition == "prompt" || disposition == "deny" else {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId, reason: "rule.disposition must be allow, prompt, or deny (got \(disposition))"
                )
            }

            // UNENFORCEABLE-AXIS gate (S5-0 HIGH-5). DISTINCT from the schema
            // validation above: the checks above validate fields the evaluator
            // DOES consume; this rejects fields the evaluator does NOT consume
            // but TS `validateRule` ACCEPTS. Enforcing such a rule WITHOUT the
            // axis would make it BROADER than the operator authored, so we fail
            // closed (reject the whole snapshot, keep prior policy) exactly like
            // the Linux daemon's `UnenforceableRuleAxis`
            // (`castle-wall-daemon/src/policy.rs`). The daemon's full
            // unenforceable set is a single axis -- `time_window` -- so that is
            // the whole set mirrored here. Do NOT "helpfully" delete this
            // thinking it duplicates schema validation: a future reader who
            // wires ACTUAL time-window enforcement into `AllowlistEvaluator`
            // must remove this reject AND add a parity row (see the guard
            // comment at `AllowlistEvaluator.matches`).
            for axis in unenforceableRuleAxes where ruleObj[axis] != nil {
                throw SignedManifestVerificationError.unenforceableRuleAxis(
                    ruleId: ruleId, axis: axis
                )
            }
        }
    }

    /// Rule axes TS `validateRule` accepts but the macOS `AllowlistEvaluator`
    /// does not enforce -- so a rule carrying one is rejected fail-closed (a
    /// present-but-unenforced constraint would widen the rule). Mirrors the
    /// Linux daemon's `UnenforceableRuleAxis` set, which is exactly
    /// `time_window` today.
    private static let unenforceableRuleAxes: [String] = ["time_window"]

    private static func rejectUnknownRawKeys(
        _ obj: [String: JSONValue], known: Set<String>, ruleId: String, label: String
    ) throws {
        for key in obj.keys where !known.contains(key) {
            throw SignedManifestVerificationError.invalidRuleSchema(
                ruleId: ruleId, reason: "\(label) has unknown field \"\(key)\" (fail closed)"
            )
        }
    }

    /// Validate the RAW `match` object: at least one destination axis present,
    /// each present axis shape/grammar-valid, unknown keys rejected. Mirrors TS
    /// `validateRule`'s match block (`schema.ts:231-286`).
    static func validateRawMatch(_ value: JSONValue, ruleId: String) throws {
        guard case .object(let matchObj) = value else {
            throw SignedManifestVerificationError.invalidRuleSchema(
                ruleId: ruleId, reason: "rule.match must be a JSON object"
            )
        }
        try rejectUnknownRawKeys(matchObj, known: knownMatchKeys, ruleId: ruleId, label: "rule.match")

        // At least one of host/host_pattern/ip/cidr/port must be present (a
        // present key, even null -- but a null value then fails its own axis
        // validation below, so an all-null match is rejected either way).
        let destinationAxes = ["host", "host_pattern", "ip", "cidr", "port"]
        let presentDestinationAxes = destinationAxes.filter { matchObj[$0] != nil }
        if presentDestinationAxes.isEmpty {
            throw SignedManifestVerificationError.invalidRuleSchema(
                ruleId: ruleId,
                reason: "rule.match must specify at least one of host, host_pattern, ip, cidr, or port"
            )
        }
        if let host = matchObj["host"] {
            try validateRawScalarOrArray(host, ruleId: ruleId, axis: "host") { isNonEmptyStringValue($0) }
        }
        if let pattern = matchObj["host_pattern"] {
            guard case .string(let s) = pattern, !s.isEmpty else {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId, reason: "rule.match.host_pattern must be a non-empty string"
                )
            }
        }
        if let ip = matchObj["ip"] {
            try validateRawScalarOrArray(ip, ruleId: ruleId, axis: "ip") { isValidIpValue($0) }
        }
        if let cidr = matchObj["cidr"] {
            try validateRawScalarOrArray(cidr, ruleId: ruleId, axis: "cidr") { isValidCidrValue($0) }
        }
        if let port = matchObj["port"] {
            try validateRawScalarOrArray(port, ruleId: ruleId, axis: "port") { isValidPortValue($0) }
        }
        if let proto = matchObj["protocol"] {
            guard case .string(let p) = proto, p == "tcp" || p == "udp" || p == "tcp+udp" else {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId, reason: "rule.match.protocol must be tcp, udp, or tcp+udp"
                )
            }
        }
    }

    /// Validate a `T | T[]` axis over raw JSON: a single valid scalar, or a
    /// NON-EMPTY array of valid scalars. `null`, an empty array, and any invalid
    /// element all reject -- mirroring TS `validateAxisValues` (`schema.ts:141`).
    private static func validateRawScalarOrArray(
        _ value: JSONValue, ruleId: String, axis: String, element: (JSONValue) -> Bool
    ) throws {
        if case .array(let items) = value {
            if items.isEmpty {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId, reason: "rule.match.\(axis) must not be an empty array"
                )
            }
            for item in items where !element(item) {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId, reason: "rule.match.\(axis) contains an invalid element"
                )
            }
            return
        }
        // Scalar (including null / wrong type): must validate as a single element.
        if !element(value) {
            throw SignedManifestVerificationError.invalidRuleSchema(
                ruleId: ruleId, reason: "rule.match.\(axis) is null, empty, or the wrong type"
            )
        }
    }

    private static func isNonEmptyStringValue(_ v: JSONValue) -> Bool {
        if case .string(let s) = v { return !s.isEmpty }
        return false
    }

    private static func isValidIpValue(_ v: JSONValue) -> Bool {
        guard case .string(let s) = v, !s.isEmpty else { return false }
        // Reuse the evaluator's parser so grammar validation cannot drift from
        // what actually matches at enforcement time.
        return AllowlistEvaluator.parseIP(s) != nil
    }

    private static func isValidCidrValue(_ v: JSONValue) -> Bool {
        guard case .string(let s) = v, !s.isEmpty else { return false }
        let parts = s.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let prefix = Int(parts[1]) else { return false }
        guard let base = AllowlistEvaluator.parseIP(String(parts[0])) else { return false }
        let maxBits = base.bytes.count == 4 ? 32 : 128
        return prefix >= 0 && prefix <= maxBits
    }

    private static func isValidPortValue(_ v: JSONValue) -> Bool {
        guard case .integer(let n) = v else { return false }
        return n >= 1 && n <= 65535
    }

    /// Validate the RAW `scope` object: known keys only, uids/agent_ids/
    /// template_ids axis shapes. Empty arrays are allowed (mean "all", parity
    /// with TS + `scopeMatches`).
    static func validateRawScope(_ value: JSONValue, ruleId: String) throws {
        guard case .object(let scopeObj) = value else {
            throw SignedManifestVerificationError.invalidRuleSchema(
                ruleId: ruleId, reason: "rule.scope must be a JSON object"
            )
        }
        try rejectUnknownRawKeys(scopeObj, known: knownScopeKeys, ruleId: ruleId, label: "rule.scope")
        if let uids = scopeObj["uids"] {
            try validateRawUidScopeAxis(uids, ruleId: ruleId)
        }
        for key in ["agent_ids", "template_ids"] {
            if let ids = scopeObj[key] {
                try validateRawStringIdAxis(ids, ruleId: ruleId, axis: key)
            }
        }
    }

    private static func validateRawUidScopeAxis(_ value: JSONValue, ruleId: String) throws {
        guard case .array(let items) = value else {
            throw SignedManifestVerificationError.invalidRuleSchema(
                ruleId: ruleId,
                reason: "rule.scope.uids must be an array of integers (got a null, scalar, or wrong type)"
            )
        }
        for item in items {
            guard case .integer(let n) = item else {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId,
                    reason: "rule.scope.uids contains a non-integer element"
                )
            }
            if n < 1 || n > uidWireMax {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId,
                    reason: "rule.scope.uids element \(n) out of range [1, \(uidWireMax)]"
                )
            }
        }
    }

    private static func validateRawStringIdAxis(_ value: JSONValue, ruleId: String, axis: String) throws {
        guard case .array(let items) = value else {
            throw SignedManifestVerificationError.invalidRuleSchema(
                ruleId: ruleId,
                reason: "rule.scope.\(axis) must be an array of non-empty strings (got a null, scalar, or wrong type)"
            )
        }
        for item in items {
            guard case .string(let s) = item, !s.isEmpty else {
                throw SignedManifestVerificationError.invalidRuleSchema(
                    ruleId: ruleId,
                    reason: "rule.scope.\(axis) contains a non-string or empty element"
                )
            }
        }
    }

    private static func ruleIdOf(raw: JSONValue) -> String? {
        guard case .object(let obj) = raw, case .string(let id)? = obj["id"] else {
            return nil
        }
        return id
    }

    /// Defense-in-depth schema check of the RAW `agent_origin` object (S5-0
    /// HIGH-2 class). The manifest-body signature already binds the re-encoded
    /// TYPED descriptor (validated by `validateAgentOriginFloors`), but this
    /// additionally rejects a raw `agent_origin` whose uid-family fields are
    /// present as an explicit `null` or a non-integer -- shapes optional
    /// `Codable` would collapse to "absent". Range/floor/cross-field checks stay
    /// in `validateAgentOriginFloors` (which runs on the cryptographically-bound
    /// typed form); here we only ensure the raw uid fields are integers when
    /// present. A `null` or absent `agent_origin` is fine (means no descriptor).
    static func validateRawAgentOriginShape(_ rawManifest: JSONValue) throws {
        guard case .object(let manifestObj) = rawManifest else { return }
        guard let originValue = manifestObj["agent_origin"] else { return }
        if case .null = originValue { return }
        guard case .object(let originObj) = originValue else {
            throw SignedManifestVerificationError.invalidAgentOrigin(
                "agent_origin must be a JSON object when present"
            )
        }
        for field in ["agent_uid", "gate_uid", "system_uid_allow_ceiling"] {
            guard let fieldValue = originObj[field] else { continue }
            guard case .integer = fieldValue else {
                throw SignedManifestVerificationError.invalidAgentOrigin(
                    "agent_origin.\(field) must be an integer when present (raw null / wrong-type collapse rejected)"
                )
            }
        }
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

        let identityIssues = preflightManifestRuleEntries(manifest.rules)
        if !identityIssues.isEmpty {
            throw SignedManifestVerificationError.manifestRuleIdentityPreflight(identityIssues)
        }

        var deliveredById: [String: ManifestRule] = [:]
        var receivedById: [String: JSONValue] = [:]
        for (index, rule) in rules.enumerated() {
            guard validateRuleId(rule.id) else {
                throw SignedManifestVerificationError.invalidRuleIdentity(rule.id)
            }
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
