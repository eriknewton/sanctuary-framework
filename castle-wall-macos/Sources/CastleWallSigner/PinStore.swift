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
import CastleWallIPC

public enum PinStoreError: Error, Equatable {
    case storageIO(String)
    case keyLength(expected: Int, actual: Int)
}

/// Writes + reads the root-owned public pin file. Parameterized by directory so
/// the write/read/permission logic is unit-testable in a temp dir without root.
public struct PinStore {
    public let directory: String
    public let filename: String
    /// Root-ownership custody enforcer (A2/B2). See FileCustody.
    public let custody: FileCustody

    public init(
        directory: String = SignerConstants.protectedDirectory,
        filename: String = SignerConstants.pinnedPublicKeyFilename,
        custody: FileCustody = FileCustody()
    ) {
        self.directory = directory
        self.filename = filename
        self.custody = custody
    }

    public var path: String { "\(directory)/\(filename)" }

    /// Write the 32-byte public key as the pin, 0644. Ensures the custody
    /// directory exists ROOT-OWNED and not group/other-writable BEFORE writing
    /// (F-A2-1) and FAILS CLOSED if it already exists operator-owned — otherwise
    /// same-UID malware could unlink + substitute its own trust anchor (P2).
    /// Idempotent: writing the same key twice is a no-op re-assert.
    public func write(publicKey: Data) throws {
        guard publicKey.count == 32 else {
            throw PinStoreError.keyLength(expected: 32, actual: publicKey.count)
        }
        do {
            try custody.ensureDirectory(directory, mode: 0o755)
        } catch {
            throw PinStoreError.storageIO("custody dir: \(error)")
        }
        // The pin is public (group/other-readable is fine), but route it through
        // the same atomic create-then-rename so it never half-materializes.
        do {
            try FileCustody.writeAtomicallyPrivate(publicKey, to: path, mode: mode_t(0o644))
        } catch {
            throw PinStoreError.storageIO("write pin: \(error)")
        }
    }

    /// Read the current pin (32 raw bytes), or nil if absent. When present, the
    /// pin must satisfy the custody chain (F-A2-2): root-owned file, not
    /// group/other-WRITABLE, inside a root-owned non-writable directory. A pin a
    /// non-root process could have rewritten is rejected (fail-closed), never
    /// silently trusted.
    public func read() throws -> Data? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        do {
            // Public key: group/other may READ (0644) but not WRITE — forbid 0o022.
            try custody.assertFile(path, directory: directory, forbiddenFileBits: 0o022)
        } catch {
            throw PinStoreError.storageIO("custody: \(error)")
        }
        guard let data = FileManager.default.contents(atPath: path) else {
            throw PinStoreError.storageIO("read pin: empty at \(path)")
        }
        guard data.count == 32 else {
            throw PinStoreError.keyLength(expected: 32, actual: data.count)
        }
        return data
    }
}
