//
// PinStore.swift
//
// Owns the PUBLIC trust anchor file (the pinned Ed25519 verifying key the sysext
// trusts). Under A2 this file is root:wheel 0644: the helper is the only writer,
// so operator-UID malware cannot swap the key the wall enforces against (P2).
//
// The sysext read path (CastleWallFilterProvider.loadPinnedPublicKey /
// Auth.loadPinnedPublicKey) is unchanged — it already reads whatever 32 raw
// bytes live at this path. A2 only moves the WRITE to root.
//

import Foundation

public enum PinStoreError: Error, Equatable {
    case storageIO(String)
    case keyLength(expected: Int, actual: Int)
}

/// Writes + reads the root-owned public pin file. Parameterized by directory so
/// the write/read/permission logic is unit-testable in a temp dir without root.
public struct PinStore {
    public let directory: String
    public let filename: String

    public init(
        directory: String = SignerConstants.protectedDirectory,
        filename: String = SignerConstants.pinnedPublicKeyFilename
    ) {
        self.directory = directory
        self.filename = filename
    }

    public var path: String { "\(directory)/\(filename)" }

    /// Write the 32-byte public key as the pin, 0644. Creates the dir (0755) if
    /// absent. Idempotent: writing the same key twice is a no-op re-assert.
    public func write(publicKey: Data) throws {
        guard publicKey.count == 32 else {
            throw PinStoreError.keyLength(expected: 32, actual: publicKey.count)
        }
        let fm = FileManager.default
        do {
            try fm.createDirectory(
                atPath: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755]
            )
        } catch {
            throw PinStoreError.storageIO("create dir: \(error)")
        }
        let tempPath = "\(path).tmp"
        do {
            try publicKey.write(to: URL(fileURLWithPath: tempPath), options: [.atomic])
            try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: tempPath)
            if fm.fileExists(atPath: path) {
                try fm.removeItem(atPath: path)
            }
            try fm.moveItem(atPath: tempPath, toPath: path)
            try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
        } catch {
            try? fm.removeItem(atPath: tempPath)
            throw PinStoreError.storageIO("write pin: \(error)")
        }
    }

    /// Read the current pin (32 raw bytes), or nil if absent.
    public func read() throws -> Data? {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return nil }
        guard let data = fm.contents(atPath: path) else {
            throw PinStoreError.storageIO("read pin: empty at \(path)")
        }
        guard data.count == 32 else {
            throw PinStoreError.keyLength(expected: 32, actual: data.count)
        }
        return data
    }
}
