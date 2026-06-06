//
// SignerCustodyTests.swift
//
// Fix-round coverage for the gauntlet findings F-A2-1 / F-A2-2 / F-A2-3:
// "root owns the whole custody chain." The A2/B2 guarantee is that an
// operator-UID process cannot delete or substitute the helper's private key or
// the public trust-anchor pin. POSIX governs unlink/rename by the *directory's*
// write permission, so a 0600 key inside an operator-owned directory is still
// swappable — these tests reproduce that gap (the store must FAIL CLOSED) and
// pin down the per-file owner check and the F-A2-3 never-loose-mode write.
//
// CI runs unprivileged, so ownership is simulated via an injectable FileFacts
// probe (the production probe stats the real filesystem). The LOGIC under test —
// "reject anything not root-owned" — is identical either way.
//

import XCTest
import CastleWallIPC
@testable import CastleWallSigner

final class SignerCustodyTests: XCTestCase {
    private var tempDir: String!
    private var keyPath: String { "\(tempDir!)/privkey.bin" }
    private var pinPath: String { "\(tempDir!)/pin.bin" }

    override func setUpWithError() throws {
        tempDir = NSTemporaryDirectory() + "castle-custody-" + UUID().uuidString
        try FileManager.default.createDirectory(
            atPath: tempDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: tempDir)
    }

    /// Probe that returns explicit facts for known paths, real facts otherwise.
    private func probe(_ overrides: [String: FileFacts]) -> FileFactsProbe {
        { path in overrides[path] ?? FileCustody.realProbe(path) }
    }

    private func rootStore() -> SignerKeyStore {
        SignerKeyStore(
            directory: tempDir,
            filename: "privkey.bin",
            custody: FileCustody(probe: FileCustody.rootSimulating())
        )
    }

    // MARK: - F-A2-2: load() checks OWNER, not just mode

    func testLoadRejectsOperatorOwnedKeyFile() throws {
        // Persist a key as "root" so the bytes exist on disk.
        _ = try rootStore().loadOrCreate()

        // Now load with a probe that reports the KEY FILE as owned by the
        // operator (uid 501) while the directory is root-owned. A 0600 file owned
        // by uid 501 must be rejected exactly like a loose-mode one.
        let store = SignerKeyStore(
            directory: tempDir,
            filename: "privkey.bin",
            custody: FileCustody(probe: probe([
                tempDir: FileFacts(exists: true, uid: 0, mode: 0o755),
                keyPath: FileFacts(exists: true, uid: 501, mode: 0o600),
            ]))
        )
        XCTAssertThrowsError(try store.load()) { err in
            guard case FileCustodyError.notRootOwned(let path, let uid) = err else {
                return XCTFail("expected notRootOwned, got \(err)")
            }
            XCTAssertEqual(path, self.keyPath)
            XCTAssertEqual(uid, 501)
        }
    }

    func testLoadRejectsNonRootOwnedParentDir() throws {
        _ = try rootStore().loadOrCreate()

        // The key file itself is root-owned 0600, but the PARENT DIR is owned by
        // the operator — so the operator could unlink+replace the key regardless
        // of its mode. Fail closed on the directory.
        let store = SignerKeyStore(
            directory: tempDir,
            filename: "privkey.bin",
            custody: FileCustody(probe: probe([
                tempDir: FileFacts(exists: true, uid: 501, mode: 0o755),
                keyPath: FileFacts(exists: true, uid: 0, mode: 0o600),
            ]))
        )
        XCTAssertThrowsError(try store.load()) { err in
            guard case FileCustodyError.notRootOwned(let path, let uid) = err else {
                return XCTFail("expected notRootOwned (dir), got \(err)")
            }
            XCTAssertEqual(path, self.tempDir)
            XCTAssertEqual(uid, 501)
        }
    }

    func testLoadRejectsGroupOrOtherWritableParentDir() throws {
        _ = try rootStore().loadOrCreate()

        // Root-owned dir, but mode 0o777 (group/other-writable) — an operator can
        // still create/unlink files in it. Reject.
        let store = SignerKeyStore(
            directory: tempDir,
            filename: "privkey.bin",
            custody: FileCustody(probe: probe([
                tempDir: FileFacts(exists: true, uid: 0, mode: 0o777),
                keyPath: FileFacts(exists: true, uid: 0, mode: 0o600),
            ]))
        )
        XCTAssertThrowsError(try store.load()) { err in
            guard case FileCustodyError.dirGroupOrOtherWritable = err else {
                return XCTFail("expected dirGroupOrOtherWritable, got \(err)")
            }
        }
    }

    // MARK: - F-A2-1: save() refuses an operator-owned custody dir

    func testSaveFailsClosedOnOperatorOwnedDirectory() {
        // The directory already exists but is operator-owned: the helper must
        // NOT adopt it (never write a key into a dir an operator can swap).
        let store = SignerKeyStore(
            directory: tempDir,
            filename: "privkey.bin",
            custody: FileCustody(probe: probe([
                tempDir: FileFacts(exists: true, uid: 501, mode: 0o755),
            ]))
        )
        XCTAssertThrowsError(try store.save(SignerKey.generate())) { err in
            guard case SignerKeyError.storageIO = err else {
                return XCTFail("expected storageIO wrapping custody fault, got \(err)")
            }
        }
        // And nothing was written.
        XCTAssertFalse(FileManager.default.fileExists(atPath: keyPath))
    }

    // MARK: - F-A2-2: the pin read path also checks owner

    func testPinReadRejectsOperatorOwnedPin() throws {
        // Write the pin as "root".
        let rootPin = PinStore(
            directory: tempDir,
            filename: "pin.bin",
            custody: FileCustody(probe: FileCustody.rootSimulating())
        )
        try rootPin.write(publicKey: SignerKey.generate().publicKeyBytes)

        // Read with a probe reporting the pin file as operator-owned.
        let store = PinStore(
            directory: tempDir,
            filename: "pin.bin",
            custody: FileCustody(probe: probe([
                tempDir: FileFacts(exists: true, uid: 0, mode: 0o755),
                pinPath: FileFacts(exists: true, uid: 501, mode: 0o644),
            ]))
        )
        XCTAssertThrowsError(try store.read()) { err in
            guard case PinStoreError.storageIO = err else {
                return XCTFail("expected storageIO wrapping custody fault, got \(err)")
            }
        }
    }

    func testPinReadRejectsGroupWritablePin() throws {
        let rootPin = PinStore(
            directory: tempDir,
            filename: "pin.bin",
            custody: FileCustody(probe: FileCustody.rootSimulating())
        )
        try rootPin.write(publicKey: SignerKey.generate().publicKeyBytes)

        // A 0o664 (group-writable) pin is rejected: the operator's group could
        // rewrite the trust anchor.
        let store = PinStore(
            directory: tempDir,
            filename: "pin.bin",
            custody: FileCustody(probe: probe([
                tempDir: FileFacts(exists: true, uid: 0, mode: 0o755),
                pinPath: FileFacts(exists: true, uid: 0, mode: 0o664),
            ]))
        )
        XCTAssertThrowsError(try store.read()) { err in
            guard case PinStoreError.storageIO = err else {
                return XCTFail("expected storageIO wrapping custody fault, got \(err)")
            }
        }
    }

    // MARK: - F-A2-3: the key is never observable at a looser-than-0600 mode

    func testSavedKeyIsNeverGroupOtherReadable() throws {
        let store = rootStore()
        _ = try store.loadOrCreate()
        let attrs = try FileManager.default.attributesOfItem(atPath: store.path)
        let mode = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        XCTAssertEqual(mode & 0o777, 0o600, "key must be exactly 0600 on disk")
        // No stale temp sibling left at a default (looser) mode.
        let tmp = "\(store.path).\(getpid()).tmp"
        XCTAssertFalse(FileManager.default.fileExists(atPath: tmp))
    }
}
