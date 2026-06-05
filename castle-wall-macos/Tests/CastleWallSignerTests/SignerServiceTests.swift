//
// SignerServiceTests.swift
//
// Exercises the XPC request-handling core by direct call (no listener, no root):
// signing opaque bytes, public-key retrieval, and the one-time pin install. This
// is the logic the helper executable wires to a mach service in production.
//

import XCTest
@testable import CastleWallSigner

final class SignerServiceTests: XCTestCase {
    private var tempDir: String!
    private var keyStore: SignerKeyStore!
    private var pinStore: PinStore!
    private var service: SignerService!

    override func setUpWithError() throws {
        tempDir = NSTemporaryDirectory() + "castle-signer-svc-" + UUID().uuidString
        try FileManager.default.createDirectory(
            atPath: tempDir, withIntermediateDirectories: true
        )
        keyStore = SignerKeyStore(directory: tempDir, filename: "privkey.bin")
        pinStore = PinStore(directory: tempDir, filename: "pin.bin")
        service = SignerService(keyStore: keyStore, pinStore: pinStore)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: tempDir)
    }

    func testSignOpaqueBytesVerifiesAgainstPublicKey() throws {
        let payload = Data("opaque-canonical-manifest-bytes".utf8)

        var pubKey: Data?
        let pubExp = expectation(description: "pubkey")
        service.publicKey { pub, _ in pubKey = pub; pubExp.fulfill() }
        wait(for: [pubExp], timeout: 1)
        let pub = try XCTUnwrap(pubKey)

        var signature: Data?
        let signExp = expectation(description: "sign")
        service.sign(payload: payload, purpose: SignerConstants.SignPurpose.manifest) { sig, err in
            signature = sig
            XCTAssertNil(err)
            signExp.fulfill()
        }
        wait(for: [signExp], timeout: 1)
        let sig = try XCTUnwrap(signature)
        XCTAssertEqual(sig.count, 64)
        XCTAssertTrue(SignerKey.verify(signature: sig, payload: payload, publicKey: pub))
    }

    func testNonceSignUsesSameKeyAsManifest() throws {
        let nonce = Data((0..<32).map { UInt8($0) })

        var pubKey: Data?
        let pubExp = expectation(description: "pubkey")
        service.publicKey { pub, _ in pubKey = pub; pubExp.fulfill() }
        wait(for: [pubExp], timeout: 1)
        let pub = try XCTUnwrap(pubKey)

        var signature: Data?
        let signExp = expectation(description: "sign-nonce")
        service.sign(payload: nonce, purpose: SignerConstants.SignPurpose.nonce) { sig, _ in
            signature = sig; signExp.fulfill()
        }
        wait(for: [signExp], timeout: 1)
        let sig = try XCTUnwrap(signature)
        XCTAssertTrue(SignerKey.verify(signature: sig, payload: nonce, publicKey: pub))
    }

    func testSignRejectsEmptyPayload() {
        let exp = expectation(description: "empty")
        service.sign(payload: Data(), purpose: "manifest") { sig, err in
            XCTAssertNil(sig)
            XCTAssertNotNil(err)
            exp.fulfill()
        }
        wait(for: [exp], timeout: 1)
    }

    func testInstallPinWritesPinMatchingPublicKey() throws {
        var pinned: Data?
        let exp = expectation(description: "install")
        service.installPin { pub, err in
            XCTAssertNil(err)
            pinned = pub
            exp.fulfill()
        }
        wait(for: [exp], timeout: 1)
        let pub = try XCTUnwrap(pinned)
        XCTAssertEqual(pub.count, 32)

        // The on-disk pin equals the helper's public key.
        let onDisk = try XCTUnwrap(try pinStore.read())
        XCTAssertEqual(onDisk, pub)

        // The pin is 0644 (P2: world-readable, owner-writable; under A2 the
        // owner is root, enforced by the helper running as root).
        let attrs = try FileManager.default.attributesOfItem(atPath: pinStore.path)
        let mode = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        XCTAssertEqual(mode & 0o777, 0o644)
    }

    func testInstallPinIsIdempotent() throws {
        var first: Data?
        var second: Data?
        let exp1 = expectation(description: "install1")
        service.installPin { pub, _ in first = pub; exp1.fulfill() }
        wait(for: [exp1], timeout: 1)
        let exp2 = expectation(description: "install2")
        service.installPin { pub, _ in second = pub; exp2.fulfill() }
        wait(for: [exp2], timeout: 1)
        XCTAssertEqual(first, second, "re-pin re-asserts the same key, not a new rotation")
    }

    func testPublicKeyStableAcrossCalls() throws {
        var a: Data?
        var b: Data?
        let e1 = expectation(description: "a")
        service.publicKey { p, _ in a = p; e1.fulfill() }
        wait(for: [e1], timeout: 1)
        let e2 = expectation(description: "b")
        service.publicKey { p, _ in b = p; e2.fulfill() }
        wait(for: [e2], timeout: 1)
        XCTAssertEqual(a, b)
    }
}
