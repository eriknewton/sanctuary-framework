//
// FileCustodyTests.swift
//
// Unit coverage for the root-ownership custody primitive shared by the signer
// helper and the sysext (A2/B2 findings F-A2-1/2/3). Ownership is simulated via
// an injectable probe so the LOGIC runs unprivileged in CI; the F-A2-3 atomic
// private-write is exercised against the real filesystem (it needs no root).
//

import XCTest
@testable import CastleWallIPC

final class FileCustodyTests: XCTestCase {
    private var tempDir: String!

    override func setUpWithError() throws {
        tempDir = NSTemporaryDirectory() + "filecustody-" + UUID().uuidString
        try FileManager.default.createDirectory(
            atPath: tempDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: tempDir)
    }

    private func probe(_ facts: [String: FileFacts]) -> FileFactsProbe {
        { path in facts[path] ?? FileFacts(exists: false, uid: -1, mode: 0) }
    }

    // MARK: - assertDirectory

    func testAssertDirectoryAcceptsRootOwnedRestrictive() throws {
        let c = FileCustody(probe: probe(["/d": FileFacts(exists: true, uid: 0, mode: 0o755)]))
        XCTAssertNoThrow(try c.assertDirectory("/d"))
    }

    func testAssertDirectoryRejectsMissing() {
        let c = FileCustody(probe: probe([:]))
        XCTAssertThrowsError(try c.assertDirectory("/d")) { err in
            guard case FileCustodyError.missing = err else { return XCTFail("got \(err)") }
        }
    }

    func testAssertDirectoryRejectsOperatorOwned() {
        let c = FileCustody(probe: probe(["/d": FileFacts(exists: true, uid: 501, mode: 0o755)]))
        XCTAssertThrowsError(try c.assertDirectory("/d")) { err in
            guard case FileCustodyError.notRootOwned(_, let uid) = err else {
                return XCTFail("got \(err)")
            }
            XCTAssertEqual(uid, 501)
        }
    }

    func testAssertDirectoryRejectsGroupOrOtherWritable() {
        let c = FileCustody(probe: probe(["/d": FileFacts(exists: true, uid: 0, mode: 0o775)]))
        XCTAssertThrowsError(try c.assertDirectory("/d")) { err in
            guard case FileCustodyError.dirGroupOrOtherWritable = err else {
                return XCTFail("got \(err)")
            }
        }
    }

    // MARK: - assertFile

    func testAssertFilePrivkeyRejectsGroupReadable() {
        let c = FileCustody(probe: probe([
            "/d": FileFacts(exists: true, uid: 0, mode: 0o755),
            "/d/k": FileFacts(exists: true, uid: 0, mode: 0o640),
        ]))
        // Privkey forbids ANY group/other access (0o077).
        XCTAssertThrowsError(try c.assertFile("/d/k", directory: "/d", forbiddenFileBits: 0o077)) { err in
            guard case FileCustodyError.fileTooPermissive = err else { return XCTFail("got \(err)") }
        }
    }

    func testAssertFilePinAllowsWorldReadableButNotWritable() throws {
        let c = FileCustody(probe: probe([
            "/d": FileFacts(exists: true, uid: 0, mode: 0o755),
            "/d/pin": FileFacts(exists: true, uid: 0, mode: 0o644),
        ]))
        // Pin (public) only forbids group/other WRITE (0o022): 0644 is fine.
        XCTAssertNoThrow(try c.assertFile("/d/pin", directory: "/d", forbiddenFileBits: 0o022))
    }

    func testAssertFilePinRejectsGroupWritable() {
        let c = FileCustody(probe: probe([
            "/d": FileFacts(exists: true, uid: 0, mode: 0o755),
            "/d/pin": FileFacts(exists: true, uid: 0, mode: 0o664),
        ]))
        XCTAssertThrowsError(try c.assertFile("/d/pin", directory: "/d", forbiddenFileBits: 0o022)) { err in
            guard case FileCustodyError.fileTooPermissive = err else { return XCTFail("got \(err)") }
        }
    }

    func testAssertFileRejectsOperatorOwnedFileInRootDir() {
        let c = FileCustody(probe: probe([
            "/d": FileFacts(exists: true, uid: 0, mode: 0o755),
            "/d/k": FileFacts(exists: true, uid: 501, mode: 0o600),
        ]))
        XCTAssertThrowsError(try c.assertFile("/d/k", directory: "/d", forbiddenFileBits: 0o077)) { err in
            guard case FileCustodyError.notRootOwned(let path, _) = err else {
                return XCTFail("got \(err)")
            }
            XCTAssertEqual(path, "/d/k")
        }
    }

    // MARK: - predicates

    func testFileIsRootOwned() {
        let c = FileCustody(probe: probe([
            "/root": FileFacts(exists: true, uid: 0, mode: 0o644),
            "/op": FileFacts(exists: true, uid: 501, mode: 0o644),
        ]))
        XCTAssertTrue(c.fileIsRootOwned("/root"))
        XCTAssertFalse(c.fileIsRootOwned("/op"))
        XCTAssertFalse(c.fileIsRootOwned("/missing"))
    }

    // MARK: - ensureDirectory

    func testEnsureDirectoryCreatesWhenAbsentThenAsserts() throws {
        let newDir = "\(tempDir!)/child"
        // Real probe: the dir does not exist yet, so ensureDirectory creates it;
        // rootSimulating forces the post-create owner check to pass under CI.
        let c = FileCustody(probe: FileCustody.rootSimulating())
        XCTAssertNoThrow(try c.ensureDirectory(newDir, mode: 0o755))
        XCTAssertTrue(FileManager.default.fileExists(atPath: newDir))
    }

    func testEnsureDirectoryFailsClosedOnOperatorOwnedExisting() {
        let c = FileCustody(probe: probe([tempDir!: FileFacts(exists: true, uid: 501, mode: 0o755)]))
        XCTAssertThrowsError(try c.ensureDirectory(tempDir!, mode: 0o755)) { err in
            guard case FileCustodyError.notRootOwned = err else { return XCTFail("got \(err)") }
        }
    }

    // MARK: - F-A2-3 atomic private write

    func testWriteAtomicallyPrivateMaterializesAtExactMode() throws {
        let path = "\(tempDir!)/secret.bin"
        let payload = Data((0..<32).map { UInt8($0) })
        try FileCustody.writeAtomicallyPrivate(payload, to: path, mode: mode_t(0o600))

        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        let mode = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        XCTAssertEqual(mode & 0o777, 0o600, "bytes must land at exactly 0600, never looser")
        XCTAssertEqual(FileManager.default.contents(atPath: path), payload)
        // The temp sibling must be gone (renamed into place).
        XCTAssertFalse(FileManager.default.fileExists(atPath: "\(path).\(getpid()).tmp"))
    }

    func testWriteAtomicallyPrivateReplacesExisting() throws {
        let path = "\(tempDir!)/secret.bin"
        try FileCustody.writeAtomicallyPrivate(Data([1, 2, 3]), to: path, mode: mode_t(0o600))
        try FileCustody.writeAtomicallyPrivate(Data([9, 9]), to: path, mode: mode_t(0o600))
        XCTAssertEqual(FileManager.default.contents(atPath: path), Data([9, 9]))
    }
}
