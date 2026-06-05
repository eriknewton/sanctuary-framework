//
// PinStoreTests.swift
//
// The public pin file is the trust anchor the sysext enforces against. These
// confirm the writer produces the exact on-disk shape the sysext read path
// (Auth.loadPinnedPublicKey) expects: 32 raw bytes, 0644.
//

import XCTest
@testable import CastleWallSigner

final class PinStoreTests: XCTestCase {
    private var tempDir: String!

    override func setUpWithError() throws {
        tempDir = NSTemporaryDirectory() + "castle-pin-" + UUID().uuidString
        try FileManager.default.createDirectory(
            atPath: tempDir, withIntermediateDirectories: true
        )
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: tempDir)
    }

    private func makeStore() -> PinStore {
        PinStore(directory: tempDir, filename: "pin.bin")
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
