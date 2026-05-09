//
// AuthTests.swift
//
// Ed25519 challenge-response handshake vectors. Mirrors the Rust auth
// test suite at `castle-wall-daemon/src/ipc/auth.rs::tests`. The signing
// key generated here is local to the test; cross-language byte equivalence
// of HMAC + signature paths is enforced by the round-trip property
// (sign-and-verify-with-different-keys-or-nonces fails).
//

import XCTest
import CryptoKit
@testable import CastleWallIPC

final class AuthTests: XCTestCase {
    func testNonceIs32BytesAndRandom() {
        let a = Auth.generateChallengeNonce()
        let b = Auth.generateChallengeNonce()
        XCTAssertEqual(a.count, CastleWallConstants.challengeNonceBytes)
        XCTAssertEqual(b.count, CastleWallConstants.challengeNonceBytes)
        XCTAssertNotEqual(a, b)
    }

    func testHappyPathHandshakeVerifies() throws {
        let signing = Curve25519.Signing.PrivateKey()
        let publicKey = signing.publicKey.rawRepresentation
        let nonce = Auth.generateChallengeNonce()
        let signature = try signing.signature(for: nonce)

        let response = IpcMessage.handshakeResponse(HandshakeResponseBody(
            fortressId: "deadbeef",
            signingKeyId: "v1",
            nonceSignatureB64url: Base64URL.encode(signature)
        ))

        let identity = try Auth.verifyHandshakeResponse(
            response,
            expectedNonce: nonce,
            pinnedPublicKey: publicKey
        )
        XCTAssertEqual(identity.fortressId, "deadbeef")
        XCTAssertEqual(identity.signingKeyId, "v1")
    }

    func testSignatureAgainstOtherKeyRejected() throws {
        let pinned = Curve25519.Signing.PrivateKey()
        let other = Curve25519.Signing.PrivateKey()
        let nonce = Auth.generateChallengeNonce()
        let signature = try other.signature(for: nonce)
        let response = IpcMessage.handshakeResponse(HandshakeResponseBody(
            fortressId: "deadbeef",
            signingKeyId: "v1",
            nonceSignatureB64url: Base64URL.encode(signature)
        ))
        XCTAssertThrowsError(try Auth.verifyHandshakeResponse(
            response,
            expectedNonce: nonce,
            pinnedPublicKey: pinned.publicKey.rawRepresentation
        )) { error in
            XCTAssertEqual(error as? AuthError, .signatureMismatch)
        }
    }

    func testSignatureOverWrongNonceRejected() throws {
        let signing = Curve25519.Signing.PrivateKey()
        let issuedNonce = Auth.generateChallengeNonce()
        let attackerNonce = Auth.generateChallengeNonce()
        let signature = try signing.signature(for: attackerNonce)
        let response = IpcMessage.handshakeResponse(HandshakeResponseBody(
            fortressId: "deadbeef",
            signingKeyId: "v1",
            nonceSignatureB64url: Base64URL.encode(signature)
        ))
        XCTAssertThrowsError(try Auth.verifyHandshakeResponse(
            response,
            expectedNonce: issuedNonce,
            pinnedPublicKey: signing.publicKey.rawRepresentation
        )) { error in
            XCTAssertEqual(error as? AuthError, .signatureMismatch)
        }
    }

    func testWrongMessageTypeRejected() throws {
        let signing = Curve25519.Signing.PrivateKey()
        let nonce = Auth.generateChallengeNonce()
        let bogus = IpcMessage.handshakeChallenge(nonceB64url: Base64URL.encode(nonce))
        XCTAssertThrowsError(try Auth.verifyHandshakeResponse(
            bogus,
            expectedNonce: nonce,
            pinnedPublicKey: signing.publicKey.rawRepresentation
        )) { error in
            XCTAssertEqual(error as? AuthError, .wrongMessageType)
        }
    }

    func testMalformedSignatureDecodeRejected() throws {
        let signing = Curve25519.Signing.PrivateKey()
        let nonce = Auth.generateChallengeNonce()
        let response = IpcMessage.handshakeResponse(HandshakeResponseBody(
            fortressId: "deadbeef",
            signingKeyId: "v1",
            nonceSignatureB64url: "!!!not-base64!!!"
        ))
        XCTAssertThrowsError(try Auth.verifyHandshakeResponse(
            response,
            expectedNonce: nonce,
            pinnedPublicKey: signing.publicKey.rawRepresentation
        )) { error in
            if case .signatureDecode = error as? AuthError {
                // ok
            } else {
                XCTFail("expected signatureDecode, got \(String(describing: error))")
            }
        }
    }

    func testSignatureWrongLengthRejected() throws {
        let signing = Curve25519.Signing.PrivateKey()
        let nonce = Auth.generateChallengeNonce()
        // 32 bytes is half the size of an Ed25519 signature.
        let shortSignature = Data(repeating: 0x42, count: 32)
        let response = IpcMessage.handshakeResponse(HandshakeResponseBody(
            fortressId: "deadbeef",
            signingKeyId: "v1",
            nonceSignatureB64url: Base64URL.encode(shortSignature)
        ))
        XCTAssertThrowsError(try Auth.verifyHandshakeResponse(
            response,
            expectedNonce: nonce,
            pinnedPublicKey: signing.publicKey.rawRepresentation
        )) { error in
            XCTAssertEqual(error as? AuthError, .signatureLength(expected: 64, actual: 32))
        }
    }

    func testPinnedKeyWrongLengthRejected() throws {
        let nonce = Auth.generateChallengeNonce()
        let response = IpcMessage.handshakeResponse(HandshakeResponseBody(
            fortressId: "deadbeef",
            signingKeyId: "v1",
            nonceSignatureB64url: Base64URL.encode(Data(repeating: 0x00, count: 64))
        ))
        let shortKey = Data(repeating: 0x00, count: 16)
        XCTAssertThrowsError(try Auth.verifyHandshakeResponse(
            response,
            expectedNonce: nonce,
            pinnedPublicKey: shortKey
        )) { error in
            XCTAssertEqual(error as? AuthError, .pinnedKeyLength(expected: 32, actual: 16))
        }
    }

    func testBase64URLRoundTrip() throws {
        let original = Data([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd])
        let encoded = Base64URL.encode(original)
        XCTAssertFalse(encoded.contains("="))
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        let decoded = try Base64URL.decode(encoded)
        XCTAssertEqual(decoded, original)
    }
}
