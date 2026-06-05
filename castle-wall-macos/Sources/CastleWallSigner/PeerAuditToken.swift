//
// PeerAuditToken.swift
//
// Typed decode of a raw kernel `audit_token_t` (32 bytes) into the fields the
// helper records when a peer connects: real-uid, pid, pid-version. Mirrors the
// non-forgeable-token reasoning in CastleWallFilter/AuditTokenDecode.swift, but
// lives in the signer lib (which does not link NetworkExtension) so the helper
// can use it and the unit suite can exercise it against a synthesized token.
//
// The raw audit-token bytes are kernel-written and user space cannot forge them
// (uid/gid/pid/pidversion are set in `set_security_token_task_internal`).
//
// FAIL-CLOSED: every malformed/short/zero-pid input yields `nil`, which the
// helper records as an unattributed peer. Decode failure never fabricates an
// identity.
//

import Foundation
import Darwin

public enum PeerAuditToken {
    /// Decoded peer identity for the audit trail.
    public struct Peer: Equatable {
        public let ruid: uid_t
        public let pid: pid_t
        public let pidVersion: Int32

        public init(ruid: uid_t, pid: pid_t, pidVersion: Int32) {
            self.ruid = ruid
            self.pid = pid
            self.pidVersion = pidVersion
        }
    }

    /// Number of bytes in a kernel `audit_token_t` (8 × uint32 = 32).
    public static let byteCount = MemoryLayout<audit_token_t>.size

    /// Decode raw audit-token bytes. Returns nil for any malformed input
    /// (wrong length, pid == 0).
    public static func decode(_ tokenData: Data?) -> Peer? {
        guard let tokenData, tokenData.count == byteCount else {
            return nil
        }
        var token = audit_token_t()
        let copied = withUnsafeMutableBytes(of: &token) { dst -> Int in
            _ = tokenData.copyBytes(to: dst.bindMemory(to: UInt8.self))
            return dst.count
        }
        guard copied == byteCount else { return nil }

        let pid = audit_token_to_pid(token)
        guard pid > 0 else { return nil }

        return Peer(
            ruid: audit_token_to_ruid(token),
            pid: pid,
            pidVersion: audit_token_to_pidversion(token)
        )
    }
}
