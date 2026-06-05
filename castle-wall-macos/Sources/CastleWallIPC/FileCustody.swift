//
// FileCustody.swift
//
// Root-ownership custody checks for Castle Wall's A2/B2 trust chain.
//
// The A2 design says the protected directory, the helper's private signing key,
// and the public trust-anchor pin are ROOT-OWNED and tamper-resistant. POSIX
// governs unlink/rename by the *directory's* write permission, not the file's
// `0600`, so a `0600` privkey inside an operator-owned directory can still be
// deleted and replaced by an operator-UID process — the exact "same-UID malware"
// B2 exists to defeat. These helpers make "root owns the whole custody chain" an
// enforced, fail-closed invariant rather than a comment.
//
// The owner/permission probe is injectable so the read/write/permission LOGIC is
// unit-testable in a temp dir without actually running as root (CI runs
// unprivileged). Production uses `realProbe`, which stats the real filesystem.
//

import Foundation

/// Ownership + permission facts about a single path. `uid` is the owning user id
/// (`-1` when unknown/absent); `mode` is the permission bits masked to `0o7777`.
public struct FileFacts: Equatable {
    public let exists: Bool
    public let uid: Int
    public let mode: UInt16

    public init(exists: Bool, uid: Int, mode: UInt16) {
        self.exists = exists
        self.uid = uid
        self.mode = mode
    }
}

/// A function that reports the ownership/permission facts for a path. Injectable
/// so tests can simulate root-owned / operator-owned files without root.
public typealias FileFactsProbe = (_ path: String) -> FileFacts

/// Why a custody assertion failed. Messages are generic (no secret material).
public enum FileCustodyError: Error, Equatable {
    case missing(String)
    case notRootOwned(path: String, uid: Int)
    case dirGroupOrOtherWritable(path: String, mode: UInt16)
    case fileTooPermissive(path: String, mode: UInt16)
    case writeFailed(path: String, code: Int32)
}

/// Enforces the "root owns the custody chain" invariant for a file and its
/// parent directory.
public struct FileCustody {
    public let probe: FileFactsProbe

    public init(probe: @escaping FileFactsProbe = FileCustody.realProbe) {
        self.probe = probe
    }

    /// Production probe: stat the real filesystem via FileManager.
    public static let realProbe: FileFactsProbe = { path in
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return FileFacts(exists: false, uid: -1, mode: 0)
        }
        let uid = (attrs[.ownerAccountID] as? NSNumber)?.intValue ?? -1
        let mode = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        return FileFacts(exists: true, uid: uid, mode: mode & 0o7777)
    }

    /// Test/helper probe: report the REAL mode but force the owner to root
    /// (uid 0). Lets a unit test exercise the happy custody path against a real
    /// temp dir without running as root. Non-existent paths stay non-existent.
    public static func rootSimulating(
        _ base: @escaping FileFactsProbe = FileCustody.realProbe
    ) -> FileFactsProbe {
        { path in
            let f = base(path)
            return f.exists ? FileFacts(exists: true, uid: 0, mode: f.mode) : f
        }
    }

    // MARK: - Boolean predicates (for skip-not-refuse call sites)

    /// True iff the path exists and is owned by root.
    public func fileIsRootOwned(_ path: String) -> Bool {
        let f = probe(path)
        return f.exists && f.uid == 0
    }

    /// True iff `dir` exists, is root-owned, and is not group/other-writable.
    public func directoryIsRootCustodial(_ dir: String) -> Bool {
        let f = probe(dir)
        return f.exists && f.uid == 0 && (f.mode & 0o022) == 0
    }

    // MARK: - Fail-closed assertions

    /// Assert a directory is root-owned and not group/other-writable. A
    /// group/other-writable directory lets a non-root user unlink/rename the
    /// custody files regardless of their own mode, so it is rejected.
    public func assertDirectory(_ dir: String) throws {
        let f = probe(dir)
        guard f.exists else { throw FileCustodyError.missing(dir) }
        guard f.uid == 0 else {
            throw FileCustodyError.notRootOwned(path: dir, uid: f.uid)
        }
        guard (f.mode & 0o022) == 0 else {
            throw FileCustodyError.dirGroupOrOtherWritable(path: dir, mode: f.mode)
        }
    }

    /// Assert a custody file is root-owned, lives inside a root-custodial
    /// directory, and is no looser than `forbiddenFileBits` allows.
    ///   - privkey (secret): pass `0o077` — no group/other access at all.
    ///   - pin (public, world-readable OK): pass `0o022` — not group/other-writable.
    public func assertFile(
        _ path: String,
        directory: String,
        forbiddenFileBits: UInt16
    ) throws {
        try assertDirectory(directory)
        let f = probe(path)
        guard f.exists else { throw FileCustodyError.missing(path) }
        guard f.uid == 0 else {
            throw FileCustodyError.notRootOwned(path: path, uid: f.uid)
        }
        guard (f.mode & forbiddenFileBits) == 0 else {
            throw FileCustodyError.fileTooPermissive(path: path, mode: f.mode)
        }
    }

    /// Ensure the custody directory exists root-owned + restrictive. Creates it
    /// (root-owned, `mode`) when absent — the caller runs as root in production,
    /// so a freshly created dir is root-owned. When it already EXISTS, assert it
    /// is root-custodial and FAIL CLOSED otherwise: never silently adopt an
    /// operator-owned directory a non-root process may have planted first.
    public func ensureDirectory(_ dir: String, mode: Int = 0o755) throws {
        let f = probe(dir)
        if !f.exists {
            try FileManager.default.createDirectory(
                atPath: dir,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: NSNumber(value: mode)]
            )
        }
        try assertDirectory(dir)
    }

    // MARK: - Atomic private write

    /// Atomically write `data` to `path`, guaranteeing the bytes are NEVER
    /// observable at a looser mode than `mode`. The temp file is created with
    /// `O_CREAT|O_EXCL` AT `mode` BEFORE any bytes are written, then renamed into
    /// place (a same-directory POSIX `rename` is atomic). This closes the F-A2-3
    /// window where Foundation's `Data.write(options: .atomic)` briefly
    /// materialized key bytes at the umask default (typically `0644`) before a
    /// follow-up `chmod` to `0600`. `O_EXCL` also refuses to follow a planted
    /// temp symlink.
    public static func writeAtomicallyPrivate(
        _ data: Data,
        to path: String,
        mode: mode_t
    ) throws {
        let tempPath = "\(path).\(getpid()).tmp"
        // Best-effort clear of a stale temp from a crashed prior run so O_EXCL
        // can succeed. ENOENT is the normal case and is ignored.
        unlink(tempPath)
        let fd = open(tempPath, O_CREAT | O_EXCL | O_WRONLY, mode)
        guard fd >= 0 else {
            throw FileCustodyError.writeFailed(path: tempPath, code: errno)
        }

        var writeErrno: Int32 = 0
        let wrote: Bool = data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
            let total = raw.count
            guard total > 0, let base = raw.baseAddress else { return true }
            var offset = 0
            while offset < total {
                let n = write(fd, base.advanced(by: offset), total - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    writeErrno = errno
                    return false
                }
                offset += n
            }
            return true
        }
        close(fd)

        if !wrote {
            unlink(tempPath)
            throw FileCustodyError.writeFailed(path: tempPath, code: writeErrno)
        }
        if rename(tempPath, path) != 0 {
            let renameErrno = errno
            unlink(tempPath)
            throw FileCustodyError.writeFailed(path: path, code: renameErrno)
        }
    }
}
