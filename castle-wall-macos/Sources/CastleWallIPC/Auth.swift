//
// Auth.swift
//
// Handshake authenticator. Mirrors `castle-wall-daemon/src/ipc/auth.rs` and
// the Sanctuary-main client's signing path. Verification side is exercised
// here; the macOS extension is the "daemon" side that issues the challenge
// and verifies the signed nonce against the TOFU-pinned fortress public key.
//
// Privilege boundary: the extension proves nothing about itself other than
// holding the pinned fortress public key. Sanctuary main proves it controls
// the fortress identity by signing the extension-issued 32-byte nonce with
// the matching Ed25519 private key.
//

import Foundation
import CryptoKit
import Security

/// Errors emitted by the auth layer.
public enum AuthError: Error, Equatable {
    case pinnedKeyIo(String)
    case pinnedKeyLength(expected: Int, actual: Int)
    case wrongMessageType
    case signatureDecode(String)
    case signatureLength(expected: Int, actual: Int)
    case signatureMismatch
    case pinnedKeyMalformed(String)
}

/// Identity asserted by a successful handshake. The extension does not bind
/// `signingKeyId` to authority; it is recorded for audit.
public struct HandshakeIdentity: Equatable {
    public let fortressId: String
    public let signingKeyId: String

    public init(fortressId: String, signingKeyId: String) {
        self.fortressId = fortressId
        self.signingKeyId = signingKeyId
    }
}

public enum Auth {
    /// Generate a fresh 32-byte challenge nonce from the OS RNG.
    public static func generateChallengeNonce() -> Data {
        var bytes = Data(count: CastleWallConstants.challengeNonceBytes)
        let result = bytes.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return -1 }
            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, base)
        }
        precondition(result == errSecSuccess, "SecRandomCopyBytes failed")
        return bytes
    }

    /// Encode a nonce for transport over the wire (base64url, no padding).
    public static func encodeNonceB64url(_ nonce: Data) -> String {
        return Base64URL.encode(nonce)
    }

    /// Load the TOFU-pinned fortress public key from disk. Format: 32 raw
    /// bytes (the Ed25519 verifying-key bytes); installed by Sanctuary main
    /// on first boot.
    public static func loadPinnedPublicKey(at path: URL) throws -> Data {
        let bytes: Data
        do {
            bytes = try Data(contentsOf: path)
        } catch {
            throw AuthError.pinnedKeyIo("\(error)")
        }
        guard bytes.count == 32 else {
            throw AuthError.pinnedKeyLength(expected: 32, actual: bytes.count)
        }
        do {
            _ = try Curve25519.Signing.PublicKey(rawRepresentation: bytes)
        } catch {
            throw AuthError.pinnedKeyMalformed("\(error)")
        }
        return bytes
    }

    /// Verify a handshake response against the original challenge nonce. The
    /// signing input is the raw nonce bytes (NOT the base64url string).
    public static func verifyHandshakeResponse(
        _ response: IpcMessage,
        expectedNonce: Data,
        pinnedPublicKey: Data
    ) throws -> HandshakeIdentity {
        guard case .handshakeResponse(let body) = response else {
            throw AuthError.wrongMessageType
        }
        guard pinnedPublicKey.count == 32 else {
            throw AuthError.pinnedKeyLength(expected: 32, actual: pinnedPublicKey.count)
        }

        let signatureBytes: Data
        do {
            signatureBytes = try Base64URL.decode(body.nonceSignatureB64url)
        } catch {
            throw AuthError.signatureDecode("\(error)")
        }
        guard signatureBytes.count == 64 else {
            throw AuthError.signatureLength(expected: 64, actual: signatureBytes.count)
        }

        let key: Curve25519.Signing.PublicKey
        do {
            key = try Curve25519.Signing.PublicKey(rawRepresentation: pinnedPublicKey)
        } catch {
            throw AuthError.pinnedKeyMalformed("\(error)")
        }

        let valid = key.isValidSignature(signatureBytes, for: expectedNonce)
        if !valid {
            throw AuthError.signatureMismatch
        }

        return HandshakeIdentity(
            fortressId: body.fortressId,
            signingKeyId: body.signingKeyId
        )
    }
}

/// base64url, no-padding (RFC 4648 §5). Mirrors the encoding used on the
/// TS and Rust sides exactly.
public enum Base64URL {
    public enum DecodeError: Error, Equatable {
        case invalidCharacter
        case invalidLength
    }

    public static func encode(_ data: Data) -> String {
        var s = data.base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        while s.hasSuffix("=") {
            s.removeLast()
        }
        return s
    }

    public static func decode(_ s: String) throws -> Data {
        var standard = s
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let pad = (4 - standard.count % 4) % 4
        if pad > 0 {
            standard.append(String(repeating: "=", count: pad))
        }
        guard let data = Data(base64Encoded: standard) else {
            throw DecodeError.invalidCharacter
        }
        return data
    }
}
