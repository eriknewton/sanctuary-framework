//
// AuditProducerProvisioningTests.swift
//
// Slice M, Piece 1: the root signer helper provisions a DEDICATED macOS
// audit-producer keypair and PUBLISHES its public half where the TypeScript
// server reads it (parallel to the Linux Rust daemon's load_or_generate +
// publish). These tests exercise the exact `SignerService` the helper's
// `main.swift` constructs for the audit-producer Mach service — configured with
// the audit-producer key/pin filenames, NOT the generic manifest-signer
// filenames — by direct call (no listener, no root).
//
// Properties proven:
//   - the audit-producer private key is generate-or-loaded (idempotent) and
//     stored OWNER-ONLY (0600);
//   - installPin PUBLISHES the public half to the audit-producer pin file
//     (`castle-audit-producer.pub`) WORLD-READABLE (0644), where the daemon
//     reads it (TOFU pin);
//   - a signature minted under the audit-producer purpose round-trips against
//     the PUBLISHED public key (so a reader holding only the pin can verify);
//   - the audit-producer key is DISTINCT from the manifest-signer key (a
//     separate Mach service / separate key, per the threat model).
//

import XCTest
import CastleWallIPC
@testable import CastleWallSigner

final class AuditProducerProvisioningTests: XCTestCase {
    private var tempDir: String!
    private var custody: FileCustody!

    override func setUpWithError() throws {
        tempDir = NSTemporaryDirectory() + "castle-audit-producer-" + UUID().uuidString
        try FileManager.default.createDirectory(
            atPath: tempDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        // CI runs unprivileged; the root-simulating probe lets the custody
        // chain exercise the happy path without root.
        custody = FileCustody(probe: FileCustody.rootSimulating())
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: tempDir)
    }

    /// Build the audit-producer `SignerService` exactly as the helper's
    /// `main.swift` does, but rooted at a temp dir with the injected custody.
    private func makeAuditProducerService() -> (service: SignerService, keyStore: SignerKeyStore, pinStore: PinStore) {
        let keyStore = SignerKeyStore(
            directory: tempDir,
            filename: SignerConstants.auditProducerPrivateKeyFilename,
            custody: custody
        )
        let pinStore = PinStore(
            directory: tempDir,
            filename: SignerConstants.auditProducerPublicKeyFilename,
            custody: custody
        )
        let service = SignerService(keyStore: keyStore, pinStore: pinStore)
        return (service, keyStore, pinStore)
    }

    func testInstallPinPublishesAuditProducerPubKeyWorldReadable() throws {
        let (service, _, pinStore) = makeAuditProducerService()

        // The pin file name is the audit-producer pin, not the manifest pin.
        XCTAssertEqual(pinStore.filename, "castle-audit-producer.pub")
        XCTAssertEqual(
            SignerConstants.auditProducerPublicKeyFilename,
            "castle-audit-producer.pub"
        )

        var pinned: Data?
        let exp = expectation(description: "install audit-producer pin")
        service.installPin { pub, err in
            XCTAssertNil(err)
            pinned = pub
            exp.fulfill()
        }
        wait(for: [exp], timeout: 1)
        let pub = try XCTUnwrap(pinned)
        XCTAssertEqual(pub.count, 32, "Ed25519 verifying key is 32 raw bytes")

        // Published to the audit-producer pin path and equals the public key the
        // daemon will TOFU-pin.
        let onDisk = try XCTUnwrap(try pinStore.read())
        XCTAssertEqual(onDisk, pub)

        // 0644: the daemon (and any reader) may READ the pin; only root WRITES.
        let attrs = try FileManager.default.attributesOfItem(atPath: pinStore.path)
        let mode = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        XCTAssertEqual(mode & 0o777, 0o644)
    }

    func testAuditProducerPrivateKeyIsOwnerOnly() throws {
        let (service, keyStore, _) = makeAuditProducerService()

        // Touch the key store (publicKey load-or-creates the private key).
        let exp = expectation(description: "ensure key")
        service.publicKey { pub, err in
            XCTAssertNil(err)
            XCTAssertEqual(pub?.count, 32)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 1)

        XCTAssertEqual(keyStore.filename, "castle-audit-producer.key")
        // 0600: the private key never leaves the helper and is owner-only.
        let attrs = try FileManager.default.attributesOfItem(atPath: keyStore.path)
        let mode = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        XCTAssertEqual(mode & 0o777, 0o600)
    }

    func testAuditProducerSignatureRoundTripsAgainstPublishedPin() throws {
        let (service, _, pinStore) = makeAuditProducerService()

        // Publish the pin (the reader's TOFU anchor).
        var pinned: Data?
        let pinExp = expectation(description: "install")
        service.installPin { pub, _ in pinned = pub; pinExp.fulfill() }
        wait(for: [pinExp], timeout: 1)
        let publishedPub = try XCTUnwrap(pinned)

        // Mint a signature under the audit-producer purpose over opaque bytes
        // (the helper signs opaque bytes; purpose is audit-only).
        let payload = Data("sanctuary.castle-wall.audit-producer.v1\nopaque-flow-bytes".utf8)
        var signature: Data?
        let signExp = expectation(description: "sign")
        service.sign(
            payload: payload,
            purpose: SignerConstants.SignPurpose.auditProducer
        ) { sig, err in
            XCTAssertNil(err)
            signature = sig
            signExp.fulfill()
        }
        wait(for: [signExp], timeout: 1)
        let sig = try XCTUnwrap(signature)
        XCTAssertEqual(sig.count, 64)

        // A reader holding ONLY the published pin verifies the signature — this
        // is the property the TypeScript re-verify side depends on.
        XCTAssertTrue(
            SignerKey.verify(signature: sig, payload: payload, publicKey: publishedPub)
        )

        // The pin read back from disk verifies too (no in-memory shortcut).
        let onDiskPin = try XCTUnwrap(try pinStore.read())
        XCTAssertTrue(
            SignerKey.verify(signature: sig, payload: payload, publicKey: onDiskPin)
        )
    }

    func testLoadOrCreateIsIdempotent() throws {
        let (service, _, _) = makeAuditProducerService()
        var first: Data?
        var second: Data?
        let e1 = expectation(description: "first")
        service.publicKey { p, _ in first = p; e1.fulfill() }
        wait(for: [e1], timeout: 1)
        let e2 = expectation(description: "second")
        service.publicKey { p, _ in second = p; e2.fulfill() }
        wait(for: [e2], timeout: 1)
        XCTAssertEqual(first, second, "re-loading returns the same key, never a fresh one")
    }

    func testAuditProducerKeyIsDistinctFromManifestSignerKey() throws {
        // The manifest-signer service (default filenames) and the audit-producer
        // service (audit-producer filenames) must hold DIFFERENT keys: the
        // audit-producer Mach service is pinned to the extension, and the
        // manifest signer to the signer-client shim, so a compromise of one
        // surface must not yield the other's key.
        let manifestKeyStore = SignerKeyStore(
            directory: tempDir,
            filename: SignerConstants.signerPrivateKeyFilename,
            custody: custody
        )
        let manifestPinStore = PinStore(
            directory: tempDir,
            filename: SignerConstants.pinnedPublicKeyFilename,
            custody: custody
        )
        let manifestService = SignerService(
            keyStore: manifestKeyStore,
            pinStore: manifestPinStore
        )
        let (auditService, _, _) = makeAuditProducerService()

        var manifestPub: Data?
        let e1 = expectation(description: "manifest pub")
        manifestService.publicKey { p, _ in manifestPub = p; e1.fulfill() }
        wait(for: [e1], timeout: 1)

        var auditPub: Data?
        let e2 = expectation(description: "audit pub")
        auditService.publicKey { p, _ in auditPub = p; e2.fulfill() }
        wait(for: [e2], timeout: 1)

        XCTAssertNotEqual(
            try XCTUnwrap(manifestPub),
            try XCTUnwrap(auditPub),
            "audit-producer key must be distinct from the manifest-signer key"
        )
        // And the filenames they persist to are distinct, so they never collide.
        XCTAssertNotEqual(
            SignerConstants.auditProducerPrivateKeyFilename,
            SignerConstants.signerPrivateKeyFilename
        )
        XCTAssertNotEqual(
            SignerConstants.auditProducerPublicKeyFilename,
            SignerConstants.pinnedPublicKeyFilename
        )
    }
}
