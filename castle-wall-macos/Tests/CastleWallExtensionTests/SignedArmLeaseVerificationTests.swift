//
// SignedArmLeaseVerificationTests.swift
//
// O-02 divergence proofs for the arm-lease trust boundary. Every rejection
// test here is a proof that the corresponding check EXISTS: if
// `SignedArmLeaseVerifier.verify` stopped throwing for that class (check
// disabled or weakened), the XCTAssertThrowsError in that test fails. The
// acceptance tests pin the happy path so the boundary cannot quietly become
// reject-everything either.
//

import XCTest
import CryptoKit
@testable import CastleWallFilter
@testable import CastleWallIPC

final class SignedArmLeaseVerificationTests: XCTestCase {

    private let key = Curve25519.Signing.PrivateKey()
    private var pinned: Data { key.publicKey.rawRepresentation }
    /// Fixed "local clock" for the verifier so age/skew assertions are exact.
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func stamp(_ offsetSeconds: TimeInterval = 0) -> String {
        return isoLeaseStamp(now.addingTimeInterval(offsetSeconds))
    }

    private func expectRejection(
        _ body: ArmLeaseBody,
        lastAccepted: Date? = nil,
        _ check: (SignedArmLeaseVerificationError) -> Bool,
        _ label: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try SignedArmLeaseVerifier.verify(
                body,
                pinnedPublicKey: pinned,
                lastAcceptedUpdatedAt: lastAccepted,
                now: now
            ),
            label,
            file: file,
            line: line
        ) { error in
            guard let error = error as? SignedArmLeaseVerificationError, check(error) else {
                XCTFail("unexpected error for \(label): \(error)", file: file, line: line)
                return
            }
        }
    }

    // MARK: - Acceptance

    func testValidSignedFreshLeaseVerifies() throws {
        let body = try makeSignedArmLeaseBody(
            ttlSeconds: 90,
            updatedAt: stamp(-1),
            privateKey: key
        )
        let accepted = try SignedArmLeaseVerifier.verify(
            body,
            pinnedPublicKey: pinned,
            lastAcceptedUpdatedAt: nil,
            now: now
        )
        XCTAssertEqual(accepted.timeIntervalSince1970, now.timeIntervalSince1970 - 1, accuracy: 0.001)
    }

    func testMonotonicallyNewerStampAccepted() throws {
        let first = try SignedArmLeaseVerifier.verify(
            try makeSignedArmLeaseBody(updatedAt: stamp(-2), privateKey: key),
            pinnedPublicKey: pinned,
            lastAcceptedUpdatedAt: nil,
            now: now
        )
        XCTAssertNoThrow(
            try SignedArmLeaseVerifier.verify(
                try makeSignedArmLeaseBody(updatedAt: stamp(-1), privateKey: key),
                pinnedPublicKey: pinned,
                lastAcceptedUpdatedAt: first,
                now: now
            )
        )
    }

    func testNonFractionalStampAccepted() throws {
        // A conforming non-JS producer may stamp without milliseconds.
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        let body = try makeSignedArmLeaseBody(
            updatedAt: plain.string(from: now),
            privateKey: key
        )
        XCTAssertNoThrow(
            try SignedArmLeaseVerifier.verify(
                body,
                pinnedPublicKey: pinned,
                lastAcceptedUpdatedAt: nil,
                now: now
            )
        )
    }

    func testUnconsumedWireFieldsStayOutsideTheSignature() throws {
        // The CLI's relayed lease carries a diagnostic `source` field the
        // extension never consumes. The signed body binds exactly the consumed
        // fields, so the extra wire field must not break verification.
        let signed = try makeSignedArmLeaseBody(
            ttlSeconds: 90,
            updatedAt: stamp(),
            privateKey: key
        )
        var wire = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(signed)) as? [String: Any]
        )
        wire["source"] = "castle-wall-cli"
        let decoded = try JSONDecoder().decode(
            ArmLeaseBody.self,
            from: JSONSerialization.data(withJSONObject: wire)
        )
        XCTAssertNoThrow(
            try SignedArmLeaseVerifier.verify(
                decoded,
                pinnedPublicKey: pinned,
                lastAcceptedUpdatedAt: nil,
                now: now
            )
        )
    }

    func testRevokedAbsentOnWireBindsAsExplicitFalse() throws {
        // The wire omits `revoked` when false; the signed body pins it to an
        // explicit false. A frame signed that way must verify after a decode
        // that saw no `revoked` key at all.
        // Model the TS producer's wire shape exactly: `revoked` ABSENT (the
        // producer only includes it when true), signature over the normalized
        // body with explicit `revoked:false`.
        let signed = try makeSignedArmLeaseBody(updatedAt: stamp(), privateKey: key)
        let wire: [String: Any] = [
            "type": "arm_lease",
            "armed": true,
            "ttl_seconds": NSNull(),
            "heartbeat_interval_seconds": 5,
            "updated_at": signed.updatedAt,
            "signing_key_id": "test-key",
            "lease_signature_b64url": signed.leaseSignatureB64url as Any,
        ]
        let decoded = try JSONDecoder().decode(
            ArmLeaseBody.self,
            from: JSONSerialization.data(withJSONObject: wire)
        )
        XCTAssertFalse(decoded.revoked)
        XCTAssertNoThrow(
            try SignedArmLeaseVerifier.verify(
                decoded,
                pinnedPublicKey: pinned,
                lastAcceptedUpdatedAt: nil,
                now: now
            )
        )
    }

    // MARK: - Rejections (each one is the divergence proof for its check)

    func testUnsignedLeaseRejected() {
        let body = ArmLeaseBody(
            armed: true,
            ttlSeconds: nil,
            heartbeatIntervalSeconds: 5,
            updatedAt: stamp()
        )
        expectRejection(body, { $0 == .missingSignature }, "unsigned lease must be rejected")
    }

    func testTamperedArmedBitRejected() throws {
        // Signature minted over armed:false; frame delivered with armed:true.
        // The forged flip an attacker actually wants (disarmed -> armed, or
        // the reverse) must invalidate the signature.
        let signedDisarmed = try makeSignedArmLeaseBody(
            armed: false,
            updatedAt: stamp(),
            privateKey: key
        )
        let tampered = ArmLeaseBody(
            armed: true,
            revoked: signedDisarmed.revoked,
            ttlSeconds: signedDisarmed.ttlSeconds,
            heartbeatIntervalSeconds: signedDisarmed.heartbeatIntervalSeconds,
            updatedAt: signedDisarmed.updatedAt,
            signingKeyId: signedDisarmed.signingKeyId,
            leaseSignatureB64url: signedDisarmed.leaseSignatureB64url
        )
        expectRejection(tampered, { $0 == .signatureMismatch }, "tampered armed bit must be rejected")
    }

    func testTamperedTtlRejected() throws {
        let signed = try makeSignedArmLeaseBody(
            ttlSeconds: 90,
            updatedAt: stamp(),
            privateKey: key
        )
        let tampered = ArmLeaseBody(
            armed: signed.armed,
            revoked: signed.revoked,
            ttlSeconds: 86_400,
            heartbeatIntervalSeconds: signed.heartbeatIntervalSeconds,
            updatedAt: signed.updatedAt,
            signingKeyId: signed.signingKeyId,
            leaseSignatureB64url: signed.leaseSignatureB64url
        )
        expectRejection(tampered, { $0 == .signatureMismatch }, "tampered ttl must be rejected")
    }

    func testTamperedUpdatedAtRejected() throws {
        // Re-stamping a captured frame to defeat the freshness gate must
        // invalidate the signature: the stamp is inside the signed body.
        let signed = try makeSignedArmLeaseBody(updatedAt: stamp(-400), privateKey: key)
        let tampered = ArmLeaseBody(
            armed: signed.armed,
            revoked: signed.revoked,
            ttlSeconds: signed.ttlSeconds,
            heartbeatIntervalSeconds: signed.heartbeatIntervalSeconds,
            updatedAt: stamp(),
            signingKeyId: signed.signingKeyId,
            leaseSignatureB64url: signed.leaseSignatureB64url
        )
        expectRejection(tampered, { $0 == .signatureMismatch }, "re-stamped frame must be rejected")
    }

    func testWrongKeyRejected() throws {
        let otherKey = Curve25519.Signing.PrivateKey()
        let body = try makeSignedArmLeaseBody(updatedAt: stamp(), privateKey: otherKey)
        expectRejection(body, { $0 == .signatureMismatch }, "wrong-key signature must be rejected")
    }

    func testReplayedIdenticalStampRejected() throws {
        let body = try makeSignedArmLeaseBody(updatedAt: stamp(-1), privateKey: key)
        let accepted = try SignedArmLeaseVerifier.verify(
            body,
            pinnedPublicKey: pinned,
            lastAcceptedUpdatedAt: nil,
            now: now
        )
        // Identical frame replayed: stamp is EQUAL to the accepted floor.
        expectRejection(
            body,
            lastAccepted: accepted,
            { if case .replayedOrStale = $0 { return true }; return false },
            "identical replay must be rejected"
        )
    }

    func testOlderStampRejectedAgainstNewerFloor() throws {
        let newer = try SignedArmLeaseVerifier.verify(
            try makeSignedArmLeaseBody(updatedAt: stamp(-1), privateKey: key),
            pinnedPublicKey: pinned,
            lastAcceptedUpdatedAt: nil,
            now: now
        )
        let older = try makeSignedArmLeaseBody(updatedAt: stamp(-10), privateKey: key)
        expectRejection(
            older,
            lastAccepted: newer,
            { if case .replayedOrStale = $0 { return true }; return false },
            "older-than-floor stamp must be rejected"
        )
    }

    func testStampOlderThanAgeWindowRejected() throws {
        let body = try makeSignedArmLeaseBody(
            updatedAt: stamp(-(SignedArmLeaseVerifier.maxLeaseAgeSeconds + 1)),
            privateKey: key
        )
        expectRejection(
            body,
            { if case .tooOld = $0 { return true }; return false },
            "stamp beyond the age window must be rejected"
        )
    }

    func testStampWithinAgeWindowAccepted() throws {
        let body = try makeSignedArmLeaseBody(
            updatedAt: stamp(-(SignedArmLeaseVerifier.maxLeaseAgeSeconds - 1)),
            privateKey: key
        )
        XCTAssertNoThrow(
            try SignedArmLeaseVerifier.verify(
                body,
                pinnedPublicKey: pinned,
                lastAcceptedUpdatedAt: nil,
                now: now
            )
        )
    }

    func testStampBeyondFutureSkewRejected() throws {
        let body = try makeSignedArmLeaseBody(
            updatedAt: stamp(SignedArmLeaseVerifier.maxFutureSkewSeconds + 1),
            privateKey: key
        )
        expectRejection(
            body,
            { if case .tooFarInFuture = $0 { return true }; return false },
            "far-future stamp must be a hard fail, not a warning"
        )
    }

    func testStampWithinFutureSkewAccepted() throws {
        let body = try makeSignedArmLeaseBody(
            updatedAt: stamp(SignedArmLeaseVerifier.maxFutureSkewSeconds - 1),
            privateKey: key
        )
        XCTAssertNoThrow(
            try SignedArmLeaseVerifier.verify(
                body,
                pinnedPublicKey: pinned,
                lastAcceptedUpdatedAt: nil,
                now: now
            )
        )
    }

    func testMalformedUpdatedAtRejectedEvenWithValidSignature() throws {
        // A validly-signed frame whose stamp cannot parse must reject: an
        // unparseable stamp must never bypass the freshness gates.
        let body = try makeSignedArmLeaseBody(
            updatedAt: "not-a-timestamp",
            privateKey: key
        )
        expectRejection(
            body,
            { if case .updatedAtMalformed = $0 { return true }; return false },
            "unparseable stamp must be rejected"
        )
    }

    func testGarbageSignatureRejected() throws {
        let body = ArmLeaseBody(
            armed: true,
            ttlSeconds: nil,
            heartbeatIntervalSeconds: 5,
            updatedAt: stamp(),
            signingKeyId: "test-key",
            leaseSignatureB64url: "!!not-base64url!!"
        )
        expectRejection(
            body,
            { if case .signatureDecode = $0 { return true }; return false },
            "undecodable signature must be rejected"
        )
    }

    func testShortSignatureRejected() throws {
        let body = ArmLeaseBody(
            armed: true,
            ttlSeconds: nil,
            heartbeatIntervalSeconds: 5,
            updatedAt: stamp(),
            signingKeyId: "test-key",
            leaseSignatureB64url: Base64URL.encode(Data(repeating: 7, count: 32))
        )
        expectRejection(
            body,
            { $0 == .signatureLength(expected: 64, actual: 32) },
            "wrong-length signature must be rejected"
        )
    }

    func testRejectLabelNeverContainsSignatureMaterial() throws {
        let body = try makeSignedArmLeaseBody(updatedAt: stamp(), privateKey: Curve25519.Signing.PrivateKey())
        do {
            _ = try SignedArmLeaseVerifier.verify(
                body,
                pinnedPublicKey: pinned,
                lastAcceptedUpdatedAt: nil,
                now: now
            )
            XCTFail("expected rejection")
        } catch {
            let label = SignedArmLeaseVerifier.rejectLabel(error)
            XCTAssertEqual(label, "signature-mismatch")
            XCTAssertFalse(label.contains(body.leaseSignatureB64url ?? ""))
        }
    }
}
