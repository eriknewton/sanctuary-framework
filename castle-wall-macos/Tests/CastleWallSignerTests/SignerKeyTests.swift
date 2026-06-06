//
// SignerKeyTests.swift
//
// Phase A unit coverage for the signer primitive: key gen + raw sign/verify over
// KNOWN opaque bytes (not a manifest — §4.3), and root-only key storage with
// fail-closed permission checks. Runs in CI on macos-latest without root.
//

import XCTest
import CryptoKit
import CastleWallIPC
@testable import CastleWallSigner

final class SignerKeyTests: XCTestCase {

    // Fixed opaque payload: the helper signs bytes blind, so a stable vector is
    // all we need. (Mirrors how the daemon hands already-canonical bytes over.)
    private let fixedPayload = Data("castle-wall-opaque-payload-vector-v1".utf8)

    func testGenerateSignVerifyRoundTrip() throws {
        let key = SignerKey.generate()
        let signature = try key.sign(fixedPayload)
        XCTAssertEqual(signature.count, 64, "Ed25519 signature is 64 bytes")
        XCTAssertTrue(key.isValidSignature(signature, for: fixedPayload))

        // Verifies against the bare public key (the sysext's verification side).
        XCTAssertTrue(
            SignerKey.verify(
                signature: signature,
                payload: fixedPayload,
                publicKey: key.publicKeyBytes
            )
        )
    }

    func testSignatureRejectsTamperedPayload() throws {
        let key = SignerKey.generate()
        let signature = try key.sign(fixedPayload)
        var tampered = fixedPayload
        tampered.append(0x00)
        XCTAssertFalse(key.isValidSignature(signature, for: tampered))
        XCTAssertFalse(
            SignerKey.verify(
                signature: signature,
                payload: tampered,
                publicKey: key.publicKeyBytes
            )
        )
    }

    func testRawPrivateKeyRoundTrip() throws {
        let key = SignerKey.generate()
        let raw = key.rawPrivateKey
        XCTAssertEqual(raw.count, 32)
        let reconstructed = try SignerKey(rawPrivateKey: raw)
        XCTAssertEqual(reconstructed.publicKeyBytes, key.publicKeyBytes)
    }

    func testRawPrivateKeyRejectsWrongLength() {
        XCTAssertThrowsError(try SignerKey(rawPrivateKey: Data(repeating: 0, count: 31))) { err in
            guard case SignerKeyError.keyLength(let expected, let actual) = err else {
                return XCTFail("expected keyLength error, got \(err)")
            }
            XCTAssertEqual(expected, 32)
            XCTAssertEqual(actual, 31)
        }
    }

    func testPublicKeyIsThirtyTwoBytes() {
        XCTAssertEqual(SignerKey.generate().publicKeyBytes.count, 32)
    }

    func testVerifyRejectsMalformedPublicKey() throws {
        let key = SignerKey.generate()
        let signature = try key.sign(fixedPayload)
        XCTAssertFalse(
            SignerKey.verify(
                signature: signature,
                payload: fixedPayload,
                publicKey: Data(repeating: 0, count: 16)
            )
        )
    }
}

final class SignerKeyStoreTests: XCTestCase {
    private var tempDir: String!

    override func setUpWithError() throws {
        tempDir = NSTemporaryDirectory()
            + "castle-signer-store-" + UUID().uuidString
        // Explicit 0o755 so the custody (not group/other-writable) assertion is
        // deterministic regardless of the CI umask.
        try FileManager.default.createDirectory(
            atPath: tempDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: tempDir)
    }

    // CI runs unprivileged: inject a root-simulating probe (real mode, forced
    // uid 0) so save/load exercise the happy custody path without root.
    private func makeStore() -> SignerKeyStore {
        SignerKeyStore(
            directory: tempDir,
            filename: "privkey.bin",
            custody: FileCustody(probe: FileCustody.rootSimulating())
        )
    }

    func testLoadOrCreateGeneratesThenPersists() throws {
        let store = makeStore()
        XCTAssertFalse(store.exists())
        let key = try store.loadOrCreate()
        XCTAssertTrue(store.exists())
        // Second call returns the same persisted key (idempotent).
        let again = try store.loadOrCreate()
        XCTAssertEqual(again.publicKeyBytes, key.publicKeyBytes)
    }

    func testSavedKeyHasOwnerOnlyPermissions() throws {
        let store = makeStore()
        _ = try store.loadOrCreate()
        let attrs = try FileManager.default.attributesOfItem(atPath: store.path)
        let mode = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        XCTAssertEqual(mode & 0o777, 0o600, "private key must be 0600")
    }

    func testLoadRejectsGroupOtherReadableKey() throws {
        let store = makeStore()
        _ = try store.loadOrCreate()
        // Loosen the permissions and confirm the store fails closed. The private
        // key forbids ANY group/other access (0o077), so a 0o644 key is rejected.
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: store.path
        )
        XCTAssertThrowsError(try store.load()) { err in
            guard case FileCustodyError.fileTooPermissive = err else {
                return XCTFail("expected fileTooPermissive, got \(err)")
            }
        }
    }

    func testLoadOrCreateSurvivesProcessRestartSimulation() throws {
        let key = try makeStore().loadOrCreate()
        // A brand-new store object over the same dir = "next boot": same key.
        let reloaded = try makeStore().load()
        XCTAssertEqual(reloaded.publicKeyBytes, key.publicKeyBytes)
        XCTAssertEqual(reloaded.rawPrivateKey, key.rawPrivateKey)
    }
}
