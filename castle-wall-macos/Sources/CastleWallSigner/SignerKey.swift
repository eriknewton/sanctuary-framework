//
// SignerKey.swift
//
// The signing primitive at the heart of B2: an Ed25519 key generated and held
// INSIDE the root helper. The private key is stored root-only (0600 root:wheel)
// and never crosses the XPC boundary — the helper returns signatures, never the
// key (hard constraint #6).
//
// The helper signs OPAQUE bytes (§4.3). There is deliberately no manifest
// canonicalizer here: the daemon canonicalizes in TypeScript and hands the
// already-canonical bytes to the shim. Re-implementing a canonicalizer in Swift
// would re-introduce the highest-risk interop surface (two canonicalizers
// diverging → silent signature mismatch).
//
// Private-key custody choice (documented per §4.5 step 2):
//   The Ed25519 private key is stored as raw 32 bytes in a 0600 root:wheel file
//   inside the protected directory. macOS Secure Enclave only protects P-256
//   keys, not Ed25519, so an SE-backed Ed25519 key is not available on the
//   macOS-13 floor without inventing a P-256 wrapping layer. The bankable B2
//   property — the key never materializes in the Node daemon and cannot be read
//   by an operator-UID process — holds with a root-only file. SE/system-keychain
//   wrapping of a wrapping key is a future hardening, noted as such; it is NOT
//   required for the P1 claim.
//

import Foundation
import CryptoKit
import CastleWallIPC

/// Errors from key generation, storage, and signing.
public enum SignerKeyError: Error, Equatable {
    case storageIO(String)
    case insecurePermissions(String)
    case malformedKey(String)
    case keyLength(expected: Int, actual: Int)
}

/// A loaded Ed25519 signing key. Wraps CryptoKit's `Curve25519.Signing`.
public struct SignerKey {
    private let privateKey: Curve25519.Signing.PrivateKey

    /// The 32-byte raw Ed25519 verifying key (safe to share / pin).
    public var publicKeyBytes: Data {
        privateKey.publicKey.rawRepresentation
    }

    /// Wrap an existing CryptoKit private key.
    public init(privateKey: Curve25519.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    /// Generate a fresh Ed25519 keypair.
    public static func generate() -> SignerKey {
        SignerKey(privateKey: Curve25519.Signing.PrivateKey())
    }

    /// Reconstruct from raw 32-byte private-key material.
    public init(rawPrivateKey: Data) throws {
        guard rawPrivateKey.count == 32 else {
            throw SignerKeyError.keyLength(expected: 32, actual: rawPrivateKey.count)
        }
        do {
            self.privateKey = try Curve25519.Signing.PrivateKey(
                rawRepresentation: rawPrivateKey
            )
        } catch {
            throw SignerKeyError.malformedKey("\(error)")
        }
    }

    /// Raw 32-byte private key material. Used only to persist root-only; never
    /// returned over XPC.
    public var rawPrivateKey: Data {
        privateKey.rawRepresentation
    }

    /// Sign opaque bytes. Returns the raw 64-byte Ed25519 signature. The helper
    /// has no concept of what the bytes mean.
    public func sign(_ payload: Data) throws -> Data {
        do {
            return try privateKey.signature(for: payload)
        } catch {
            throw SignerKeyError.malformedKey("sign failed: \(error)")
        }
    }

    /// Verify a signature against this key's public half. Used by tests and by
    /// the shim's optional self-check.
    public func isValidSignature(_ signature: Data, for payload: Data) -> Bool {
        privateKey.publicKey.isValidSignature(signature, for: payload)
    }

    /// Verify a signature against a raw 32-byte public key (no private key
    /// needed). Mirrors the sysext / Auth.swift verification side.
    public static func verify(
        signature: Data,
        payload: Data,
        publicKey: Data
    ) -> Bool {
        guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        else {
            return false
        }
        return pub.isValidSignature(signature, for: payload)
    }
}

/// Persists the helper's private key root-only and loads it back, enforcing
/// that the on-disk file is not readable by group/other. The store is
/// parameterized by directory so unit tests can exercise the read/write/permission
/// logic in a temp dir without root; the production helper points it at the
/// root-owned protected directory.
public struct SignerKeyStore {
    public let directory: String
    public let filename: String
    /// Root-ownership custody enforcer (A2/B2). Default checks the real
    /// filesystem; tests inject a probe so the read/write logic runs without
    /// root. See FileCustody.
    public let custody: FileCustody

    public init(
        directory: String = SignerConstants.protectedDirectory,
        filename: String = SignerConstants.signerPrivateKeyFilename,
        custody: FileCustody = FileCustody()
    ) {
        self.directory = directory
        self.filename = filename
        self.custody = custody
    }

    public var path: String { "\(directory)/\(filename)" }

    /// True iff a private-key file already exists at the configured path.
    public func exists() -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    /// Ensure a key exists: load it if present, otherwise generate + persist a
    /// fresh one. Idempotent — re-running returns the same key.
    public func loadOrCreate() throws -> SignerKey {
        if exists() {
            return try load()
        }
        let key = SignerKey.generate()
        try save(key)
        return key
    }

    /// Persist the key as raw 32 bytes, 0600. Ensures the custody directory
    /// exists ROOT-OWNED and not group/other-writable BEFORE writing — and FAILS
    /// CLOSED if it already exists operator-owned (F-A2-1): a 0600 key inside an
    /// operator-writable directory can still be unlinked + swapped by same-UID
    /// malware (POSIX governs unlink/rename by directory write permission). The
    /// helper runs as root, so a freshly created dir + file are root-owned.
    public func save(_ key: SignerKey) throws {
        do {
            // Root-owned 0755: owner(root) writes; group/other read+traverse but
            // cannot create/unlink/rename here, which is what protects the key.
            try custody.ensureDirectory(directory, mode: 0o755)
        } catch {
            throw SignerKeyError.storageIO("custody dir: \(error)")
        }
        // F-A2-3: create the temp at 0600 BEFORE any bytes are observable, then
        // atomically rename. Never materializes key bytes at a looser mode.
        do {
            try FileCustody.writeAtomicallyPrivate(
                key.rawPrivateKey,
                to: path,
                mode: mode_t(0o600)
            )
        } catch {
            throw SignerKeyError.storageIO("write key: \(error)")
        }
    }

    /// Load the key, asserting the ROOT-OWNS-THE-CUSTODY-CHAIN invariant
    /// (F-A2-1/F-A2-2): the key file must be owned by root and no
    /// group/other-accessible, AND its parent directory must be root-owned and
    /// not group/other-writable. A 0600 file owned by an operator (uid 501) is
    /// rejected exactly like a loose-mode one — owner, not just mode, is checked.
    /// Fail-closed: a custody violation is a defect, not a thing to silently use.
    public func load() throws -> SignerKey {
        // Secret material: forbid ANY group/other access (0o077).
        try custody.assertFile(path, directory: directory, forbiddenFileBits: 0o077)
        guard let data = FileManager.default.contents(atPath: path) else {
            throw SignerKeyError.storageIO("read key: empty/absent at \(path)")
        }
        return try SignerKey(rawPrivateKey: data)
    }
}
