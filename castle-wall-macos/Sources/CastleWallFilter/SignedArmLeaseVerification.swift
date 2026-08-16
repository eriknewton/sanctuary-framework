//
// SignedArmLeaseVerification.swift
//
// Extension-side trust boundary for daemon-delivered arm-lease frames (O-02).
//
// The arm lease is the single frame that can flip the wall into
// `fail_open_deadman` (operator recovery) or extend the dead-man deadline, and
// the deadline anchors to the EXTENSION's local clock at acceptance
// (`ArmLease.update`). Before this boundary existed, any post-handshake frame
// injection or replay of a captured old lease could therefore re-arm, disarm,
// revoke, or indefinitely extend the wall's lease state with no cryptographic
// check at all — while the manifest, which shares the same channel, got full
// pinned-key re-verification. This verifier gives the lease the same standing:
//   1. AUTHENTICITY — an Ed25519 signature by the pinned fortress key over the
//      canonical signed body. Absent or invalid ⇒ REJECT (never
//      accept-with-warning: silently degrading to an unauthenticated lease is
//      exactly MUST-NEVER #5).
//   2. FRESHNESS — `updated_at` is CONSUMED, not just decoded: it must be
//      strictly newer than the last accepted lease's stamp (in-connection
//      replay of a captured frame) and inside a bounded age/skew window
//      (cross-connection replay of an old frame). Without this, a replayed
//      stale lease re-anchors `leaseExpiresAt`/`heartbeatExpiresAt` to the
//      receiver's `now()` and the dead-man never fires.
//
// Rejection is always fail-SAFE for the wall: the prior lease state stands, so
// a starved lease degrades to `heartbeat_stopped`/missing-lease posture (agents
// fail closed, operator keeps the anti-lockout path) — never to fail-open.
//

import Foundation
import CryptoKit
import CastleWallIPC

public enum SignedArmLeaseVerificationError: Error, Equatable {
    /// The frame carries no signature. An unsigned lease is REJECTED, not
    /// accepted-with-warning (MUST-NEVER #5): "absent" reads as not-proven.
    case missingSignature
    case pinnedKeyLength(expected: Int, actual: Int)
    case pinnedKeyMalformed(String)
    case signatureDecode(String)
    case signatureLength(expected: Int, actual: Int)
    case signatureMismatch
    case canonicalizationFailed(String)
    case updatedAtMalformed(String)
    /// `updated_at` is not strictly newer than the last accepted lease:
    /// a replayed (or reordered) frame inside the current connection.
    case replayedOrStale(receivedMs: Int64, lastAcceptedMs: Int64)
    /// `updated_at` is older than the acceptance window: a captured old frame
    /// replayed across connections (or a wedged producer clock).
    case tooOld(ageSeconds: Int64, maxSeconds: Int64)
    /// `updated_at` is ahead of local time beyond skew tolerance. A hard fail,
    /// not a warning: a future stamp is how a forger would pre-date around the
    /// monotonicity gate, and daemon + extension share one host clock.
    case tooFarInFuture(aheadSeconds: Int64, maxSeconds: Int64)
}

public enum SignedArmLeaseVerifier {

    /// Maximum accepted lease age. Derivation: the daemon re-stamps
    /// `updated_at` at every emission and the default heartbeat interval is
    /// 5s, so a legitimate frame is normally < 1s old; 300s = 60 heartbeat
    /// intervals of slack for a slow root-helper signing round-trip or a
    /// paused daemon, while still bounding cross-connection replay of a
    /// captured frame to a five-minute window (in-connection replay is blocked
    /// by strict monotonicity regardless).
    public static let maxLeaseAgeSeconds: TimeInterval = 300

    /// Maximum accepted forward clock skew. Daemon and extension run on the
    /// SAME host clock, so genuine skew is near zero; 30s tolerates an NTP
    /// step between the daemon's stamp and this check while refusing the
    /// far-future stamps a forger would use to outlive the age window.
    public static let maxFutureSkewSeconds: TimeInterval = 30

    /// Canonical SIGNED BODY of an arm lease: exactly these six fields, always
    /// all present (`revoked` explicit even when false, `ttl_seconds` explicit
    /// null when absent), canonical-JSON serialized (sorted keys, no
    /// whitespace). Reconstructed from the TYPED fields the engine actually
    /// consumes, so everything a decision reads is inside the signature; wire
    /// fields the extension does not consume (e.g. the CLI's diagnostic
    /// `source`) are deliberately outside it.
    ///
    /// Must match `armLeaseSignedBody` in
    /// `server/src/castle-wall/runtime/macos-ipc-listener.ts` byte-for-byte.
    /// A divergence fails CLOSED (every lease rejected, wall degrades to
    /// missing-lease posture), never open — same failure direction as the
    /// manifest canonicalization contract.
    static func canonicalSignedBody(_ body: ArmLeaseBody) throws -> Data {
        let object: JSONValue = .object([
            // `type` doubles as the domain-separation tag against the other
            // payloads the fortress key signs (manifest bodies, handshake
            // nonces): no other signed payload can contain
            // `"type":"arm_lease"` as a top-level canonical field, and a
            // 32-byte raw nonce can never parse as this JSON object.
            "type": .string("arm_lease"),
            "armed": .bool(body.armed),
            "revoked": .bool(body.revoked),
            "ttl_seconds": body.ttlSeconds.map { JSONValue.integer(Int64($0)) } ?? .null,
            "heartbeat_interval_seconds": .integer(Int64(body.heartbeatIntervalSeconds)),
            "updated_at": .string(body.updatedAt),
        ])
        do {
            return try SignedManifestVerifier.canonicalJSONData(object)
        } catch {
            throw SignedArmLeaseVerificationError.canonicalizationFailed("\(error)")
        }
    }

    /// Verify one inbound arm-lease frame. Returns the parsed `updated_at`
    /// instant on success (the caller records it as the new monotonic floor).
    /// Throws on ANY defect — the caller must then leave the lease state, the
    /// `armLeaseReceived` binding flag, and the flow cache untouched.
    public static func verify(
        _ body: ArmLeaseBody,
        pinnedPublicKey: Data,
        lastAcceptedUpdatedAt: Date?,
        now: Date = Date()
    ) throws -> Date {
        // Signature first: freshness fields are attacker-writable until the
        // signature over them has been checked, so nothing below this block
        // may influence accept/reject semantics on unverified content beyond
        // returning a rejection.
        guard let signatureB64url = body.leaseSignatureB64url else {
            throw SignedArmLeaseVerificationError.missingSignature
        }
        guard pinnedPublicKey.count == 32 else {
            throw SignedArmLeaseVerificationError.pinnedKeyLength(
                expected: 32,
                actual: pinnedPublicKey.count
            )
        }

        let signatureBytes: Data
        do {
            signatureBytes = try Base64URL.decode(signatureB64url)
        } catch {
            throw SignedArmLeaseVerificationError.signatureDecode("\(error)")
        }
        // 64 = Ed25519 signature size (RFC 8032), same bound the handshake and
        // manifest verifiers enforce.
        guard signatureBytes.count == 64 else {
            throw SignedArmLeaseVerificationError.signatureLength(
                expected: 64,
                actual: signatureBytes.count
            )
        }

        let key: Curve25519.Signing.PublicKey
        do {
            key = try Curve25519.Signing.PublicKey(rawRepresentation: pinnedPublicKey)
        } catch {
            throw SignedArmLeaseVerificationError.pinnedKeyMalformed("\(error)")
        }

        let payloadBytes = try canonicalSignedBody(body)
        guard key.isValidSignature(signatureBytes, for: payloadBytes) else {
            throw SignedArmLeaseVerificationError.signatureMismatch
        }

        // Freshness: the signature proves the fortress key signed this stamp
        // once; it does NOT prove the frame is current (rule 10 — the relying
        // party bounds the signer's freshness). Both gates are hard fails.
        guard let updatedAt = parseISO8601(body.updatedAt) else {
            throw SignedArmLeaseVerificationError.updatedAtMalformed(body.updatedAt)
        }
        if let lastAcceptedUpdatedAt, updatedAt <= lastAcceptedUpdatedAt {
            throw SignedArmLeaseVerificationError.replayedOrStale(
                receivedMs: epochMs(updatedAt),
                lastAcceptedMs: epochMs(lastAcceptedUpdatedAt)
            )
        }
        let age = now.timeIntervalSince(updatedAt)
        if age > Self.maxLeaseAgeSeconds {
            throw SignedArmLeaseVerificationError.tooOld(
                ageSeconds: Int64(age),
                maxSeconds: Int64(Self.maxLeaseAgeSeconds)
            )
        }
        if age < -Self.maxFutureSkewSeconds {
            throw SignedArmLeaseVerificationError.tooFarInFuture(
                aheadSeconds: Int64(-age),
                maxSeconds: Int64(Self.maxFutureSkewSeconds)
            )
        }

        return updatedAt
    }

    /// Compact, key-material-free label for the unified log. Never includes
    /// signatures, keys, or raw payload bytes.
    public static func rejectLabel(_ error: Error) -> String {
        guard let error = error as? SignedArmLeaseVerificationError else {
            return "unknown(\(String(describing: type(of: error))))"
        }
        switch error {
        case .missingSignature:
            return "missing-signature"
        case .pinnedKeyLength(let expected, let actual):
            return "pinned-key-length(expected=\(expected),actual=\(actual))"
        case .pinnedKeyMalformed:
            return "pinned-key-malformed"
        case .signatureDecode:
            return "signature-decode"
        case .signatureLength(let expected, let actual):
            return "signature-length(expected=\(expected),actual=\(actual))"
        case .signatureMismatch:
            return "signature-mismatch"
        case .canonicalizationFailed:
            return "canonicalization-failed"
        case .updatedAtMalformed:
            return "updated-at-malformed"
        case .replayedOrStale(let receivedMs, let lastAcceptedMs):
            return "replayed-or-stale(received_ms=\(receivedMs),last_accepted_ms=\(lastAcceptedMs))"
        case .tooOld(let ageSeconds, let maxSeconds):
            return "too-old(age_s=\(ageSeconds),max_s=\(maxSeconds))"
        case .tooFarInFuture(let aheadSeconds, let maxSeconds):
            return "too-far-in-future(ahead_s=\(aheadSeconds),max_s=\(maxSeconds))"
        }
    }

    /// The daemon stamps with JavaScript `Date.toISOString()` (always
    /// millisecond-fractional UTC); accept the non-fractional form too so a
    /// hand-provisioned lease from another conforming producer parses. Any
    /// other shape rejects — a malformed stamp must never bypass freshness.
    private static func parseISO8601(_ value: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: value) {
            return date
        }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: value)
    }

    private static func epochMs(_ date: Date) -> Int64 {
        return Int64((date.timeIntervalSince1970 * 1000.0).rounded())
    }
}
