//
// PinStoreTests.swift
//
// The public pin file is the trust anchor the sysext enforces against. These
// confirm the writer produces the exact on-disk shape the sysext read path
// (Auth.loadPinnedPublicKey) expects: 32 raw bytes, 0644.
//

import XCTest
import CastleWallIPC
@testable import CastleWallSigner

final class PinStoreTests: XCTestCase {
    private var tempDir: String!

    override func setUpWithError() throws {
        tempDir = NSTemporaryDirectory() + "castle-pin-" + UUID().uuidString
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

    // CI runs unprivileged, so the temp dir is operator-owned. Inject a
    // root-simulating probe (real mode, forced uid 0) so the write/read LOGIC is
    // exercised on the happy custody path without actually running as root.
    private func makeStore() -> PinStore {
        PinStore(
            directory: tempDir,
            filename: "pin.bin",
            custody: FileCustody(probe: FileCustody.rootSimulating())
        )
    }

    func testWriteReadRoundTrip() throws {
        let store = makeStore()
        let key = SignerKey.generate().publicKeyBytes
        try store.write(publicKey: key)
        XCTAssertEqual(try store.read(), key)
    }

    func testWriteSetsWorldReadableOwnerWritable() throws {
        let store = makeStore()
        try store.write(publicKey: SignerKey.generate().publicKeyBytes)
        let attrs = try FileManager.default.attributesOfItem(atPath: store.path)
        let mode = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        XCTAssertEqual(mode & 0o777, 0o644)
    }

    func testWriteRejectsWrongLength() {
        let store = makeStore()
        XCTAssertThrowsError(try store.write(publicKey: Data(repeating: 1, count: 16))) { err in
            guard case PinStoreError.keyLength = err else {
                return XCTFail("expected keyLength, got \(err)")
            }
        }
    }

    func testReadReturnsNilWhenAbsent() throws {
        XCTAssertNil(try makeStore().read())
    }

    func testWriteIsIdempotent() throws {
        let store = makeStore()
        let key = SignerKey.generate().publicKeyBytes
        try store.write(publicKey: key)
        try store.write(publicKey: key)
        XCTAssertEqual(try store.read(), key)
    }

    func testRewriteReplacesPin() throws {
        let store = makeStore()
        let k1 = SignerKey.generate().publicKeyBytes
        let k2 = SignerKey.generate().publicKeyBytes
        try store.write(publicKey: k1)
        try store.write(publicKey: k2)
        XCTAssertEqual(try store.read(), k2)
    }
}
