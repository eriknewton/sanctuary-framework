import CommonCrypto
import Foundation

public enum SanctuaryImageIntegrityError: Error, Equatable {
    case fileNotFound(path: String)
    case fileOpenFailed(path: String)
    case digestMismatch(artifact: String, expected: String, actual: String)
    case overlayShadowDetected(path: String)
}

/// Pinned digest for a single OCI-assembled artifact (the EXT4 rootfs block file).
///
/// The old model (pre-B1) checked kernel + rootfs + initramfs individually because
/// we built the guest image ourselves. Now Apple's `EXT4Unpacker` + OCI content-addressing
/// handles layer-level integrity. Our check targets the finished EXT4 file:
///   - Post-unpack, pre-VM-boot: hash the assembled rootfs.ext4
///   - The OCI content-addressing already verified per-layer digests
///   - We verify the whole-image digest to catch tampering between unpack and boot
public struct SanctuaryArtifactPin: Equatable, Codable, Sendable {
    public let sha256: String
    public let artifact: String

    public init(sha256: String, artifact: String) {
        self.sha256 = sha256
        self.artifact = artifact
    }
}

/// Result of a successful integrity verification. Holds the fd-pinned file handle
/// so the caller can pass it directly to VM configuration without a TOCTOU gap.
public struct SanctuaryVerifiedArtifact: Equatable {
    public let url: URL
    public let fileHandle: FileHandle

    public init(url: URL, fileHandle: FileHandle) {
        self.url = url
        self.fileHandle = fileHandle
    }

    public static func == (lhs: SanctuaryVerifiedArtifact, rhs: SanctuaryVerifiedArtifact) -> Bool {
        return lhs.url == rhs.url
    }
}

public enum SanctuaryImageIntegrity {

    /// Verify a single artifact (typically the EXT4 rootfs) by opening a file handle,
    /// hashing via the SAME fd, and comparing against the pinned digest.
    ///
    /// SECURITY: The returned file handle is the EXACT handle that was hashed.
    /// The caller MUST use this handle (not re-open the path) when configuring
    /// VZDiskImageStorageDeviceAttachment, or the TOCTOU gap reopens.
    public static func verifyAndOpen(
        url: URL,
        pin: SanctuaryArtifactPin
    ) throws -> SanctuaryVerifiedArtifact {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw SanctuaryImageIntegrityError.fileNotFound(path: url.path)
        }

        guard let handle = FileHandle(forReadingAtPath: url.path) else {
            throw SanctuaryImageIntegrityError.fileOpenFailed(path: url.path)
        }

        let digest = sha256OfFileHandle(handle)

        guard digest == pin.sha256 else {
            handle.closeFile()
            throw SanctuaryImageIntegrityError.digestMismatch(
                artifact: pin.artifact,
                expected: pin.sha256,
                actual: digest
            )
        }

        handle.seek(toFileOffset: 0)
        return SanctuaryVerifiedArtifact(url: url, fileHandle: handle)
    }

    /// Compute the SHA-256 digest of a file at a given URL (for pin generation).
    public static func computeDigest(at url: URL) throws -> String {
        guard let handle = FileHandle(forReadingAtPath: url.path) else {
            throw SanctuaryImageIntegrityError.fileOpenFailed(path: url.path)
        }
        let digest = sha256OfFileHandle(handle)
        handle.closeFile()
        return digest
    }

    /// Assert that the scratch overlay cannot shadow critical paths in the rootfs.
    ///
    /// When using ContainerManager, the rootfs is an EXT4 block device and the
    /// scratch is a separate mount. The scratch CANNOT shadow rootfs paths via
    /// overlayfs because they are separate block devices. This check is defense-
    /// in-depth against future configuration changes that might use overlayfs.
    public static func assertOverlayCannotShadow(
        scratchURL: URL,
        protectedPaths: [String]
    ) throws {
        let fm = FileManager.default
        for path in protectedPaths {
            let relativePath = path.hasPrefix("/") ? String(path.dropFirst()) : path
            let shadowPath = scratchURL.appendingPathComponent(relativePath).path
            if fm.fileExists(atPath: shadowPath) {
                throw SanctuaryImageIntegrityError.overlayShadowDetected(path: path)
            }
        }
    }

    // MARK: - Internal hashing

    static func sha256OfFileHandle(_ handle: FileHandle) -> String {
        var context = CC_SHA256_CTX()
        CC_SHA256_Init(&context)

        let bufferSize = 64 * 1024
        while true {
            let data = handle.readData(ofLength: bufferSize)
            if data.isEmpty { break }
            data.withUnsafeBytes { pointer in
                _ = CC_SHA256_Update(&context, pointer.baseAddress, CC_LONG(data.count))
            }
        }

        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256_Final(&digest, &context)

        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
