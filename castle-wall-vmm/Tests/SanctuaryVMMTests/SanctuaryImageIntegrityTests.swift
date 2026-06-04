import XCTest
@testable import SanctuaryVMM

final class SanctuaryImageIntegrityTests: XCTestCase {

    // MARK: - verifyAndOpen

    func testVerifyAndOpenSucceeds() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sanctuary-integrity-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let content = "test rootfs content for integrity check"
        let fileURL = tempDir.appendingPathComponent("rootfs.ext4")
        try content.write(to: fileURL, atomically: true, encoding: .utf8)

        let digest = try SanctuaryImageIntegrity.computeDigest(at: fileURL)
        let pin = SanctuaryArtifactPin(sha256: digest, artifact: "rootfs.ext4")

        let verified = try SanctuaryImageIntegrity.verifyAndOpen(url: fileURL, pin: pin)
        XCTAssertEqual(verified.url, fileURL)

        // The file handle should be seeked to 0, ready for reading
        let readData = verified.fileHandle.readDataToEndOfFile()
        XCTAssertEqual(String(data: readData, encoding: .utf8), content)
        verified.fileHandle.closeFile()
    }

    func testVerifyAndOpenFailsOnDigestMismatch() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sanctuary-integrity-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let fileURL = tempDir.appendingPathComponent("rootfs.ext4")
        try "original content".write(to: fileURL, atomically: true, encoding: .utf8)

        let wrongPin = SanctuaryArtifactPin(
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            artifact: "rootfs.ext4"
        )

        XCTAssertThrowsError(try SanctuaryImageIntegrity.verifyAndOpen(url: fileURL, pin: wrongPin)) { error in
            guard case SanctuaryImageIntegrityError.digestMismatch(let artifact, let expected, _) = error else {
                XCTFail("Expected digestMismatch, got \(error)")
                return
            }
            XCTAssertEqual(artifact, "rootfs.ext4")
            XCTAssertEqual(expected, wrongPin.sha256)
        }
    }

    func testVerifyAndOpenFailsOnMissingFile() {
        let pin = SanctuaryArtifactPin(sha256: "abc", artifact: "missing.ext4")
        let url = URL(fileURLWithPath: "/nonexistent/path/missing.ext4")

        XCTAssertThrowsError(try SanctuaryImageIntegrity.verifyAndOpen(url: url, pin: pin)) { error in
            guard case SanctuaryImageIntegrityError.fileNotFound = error else {
                XCTFail("Expected fileNotFound, got \(error)")
                return
            }
        }
    }

    // MARK: - computeDigest

    func testComputeDigestIsDeterministic() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sanctuary-integrity-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let fileURL = tempDir.appendingPathComponent("test.bin")
        try Data(repeating: 0x42, count: 1024).write(to: fileURL)

        let digest1 = try SanctuaryImageIntegrity.computeDigest(at: fileURL)
        let digest2 = try SanctuaryImageIntegrity.computeDigest(at: fileURL)
        XCTAssertEqual(digest1, digest2)
        XCTAssertEqual(digest1.count, 64) // SHA-256 hex = 64 chars
    }

    func testComputeDigestChangesWithContent() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sanctuary-integrity-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let fileURL = tempDir.appendingPathComponent("test.bin")
        try "content-a".write(to: fileURL, atomically: true, encoding: .utf8)
        let digestA = try SanctuaryImageIntegrity.computeDigest(at: fileURL)

        try "content-b".write(to: fileURL, atomically: true, encoding: .utf8)
        let digestB = try SanctuaryImageIntegrity.computeDigest(at: fileURL)

        XCTAssertNotEqual(digestA, digestB)
    }

    // MARK: - assertOverlayCannotShadow

    func testOverlayAssertionPassesWhenNoShadow() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sanctuary-overlay-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try SanctuaryImageIntegrity.assertOverlayCannotShadow(
            scratchURL: tempDir,
            protectedPaths: ["/usr/local/bin/node", "/usr/local/bin/claude-code"]
        )
    }

    func testOverlayAssertionFailsWhenShadowDetected() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("sanctuary-overlay-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        // Create a shadow file
        let shadowDir = tempDir.appendingPathComponent("usr/local/bin")
        try FileManager.default.createDirectory(at: shadowDir, withIntermediateDirectories: true)
        try "malicious".write(to: shadowDir.appendingPathComponent("node"), atomically: true, encoding: .utf8)

        XCTAssertThrowsError(
            try SanctuaryImageIntegrity.assertOverlayCannotShadow(
                scratchURL: tempDir,
                protectedPaths: ["/usr/local/bin/node"]
            )
        ) { error in
            guard case SanctuaryImageIntegrityError.overlayShadowDetected(let path) = error else {
                XCTFail("Expected overlayShadowDetected, got \(error)")
                return
            }
            XCTAssertEqual(path, "/usr/local/bin/node")
        }
    }

    // MARK: - ArtifactPin Codable

    func testArtifactPinCodable() throws {
        let pin = SanctuaryArtifactPin(
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            artifact: "rootfs.ext4"
        )
        let data = try JSONEncoder().encode(pin)
        let decoded = try JSONDecoder().decode(SanctuaryArtifactPin.self, from: data)
        XCTAssertEqual(pin, decoded)
    }
}
