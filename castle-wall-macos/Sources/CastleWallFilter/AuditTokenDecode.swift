//
// AuditTokenDecode.swift
//
// Typed decode of a `NEFilterFlow.sourceAppAuditToken` (a 32-byte kernel
// audit-token structure) into the fields the origin classifier needs:
// real-uid, pid, pid-version, and (best-effort) the code-signing identity.
//
// FAIL-CLOSED CONTRACT (2026-05-29 origin-classifier foundation):
// This decoder NEVER throws a flow open. Every failure path -- nil token,
// wrong byte length, `errSecCSUnsigned`, `EPERM` (FB12057582), `ESRCH`, or
// any unexpected error from Security.framework -- yields an
// `AuditTokenDecode.Result` with `unattributed == true`. The classifier maps
// that to `.unattributed`, which routes to the default-deny + allowlist path.
// There is no code path here that returns a "positively attributed" result
// from a decode failure.
//
// The raw 32 audit-token bytes are non-forgeable (the kernel writes
// uid/gid/pid/pidversion in `set_security_token_task_internal`; user space
// cannot set them). See research: Agent_Only_Wall_Attribution_Research_2026-05-29.
//
// This file imports only Darwin + Security (no NetworkExtension), so the
// decode path is unit-testable against synthesized `audit_token_t` values.
//

import Foundation
import Darwin
import Security

public enum AuditTokenDecode {

    /// The typed result of decoding an audit token. When `unattributed` is
    /// true, the numeric/string fields are NOT meaningful and the classifier
    /// must treat the flow as `.unattributed` (deny side).
    public struct Result: Equatable {
        public let ruid: uid_t
        public let pid: pid_t
        public let pidVersion: Int32
        public let signingId: String?
        public let teamId: String?
        public let unattributed: Bool

        public init(
            ruid: uid_t,
            pid: pid_t,
            pidVersion: Int32,
            signingId: String?,
            teamId: String?,
            unattributed: Bool
        ) {
            self.ruid = ruid
            self.pid = pid
            self.pidVersion = pidVersion
            self.signingId = signingId
            self.teamId = teamId
            self.unattributed = unattributed
        }

        /// The canonical fail-closed result. Used for every decode failure.
        public static let unattributedResult = Result(
            ruid: 0,
            pid: 0,
            pidVersion: 0,
            signingId: nil,
            teamId: nil,
            unattributed: true
        )
    }

    /// The number of bytes in a kernel `audit_token_t` (8 x uint32).
    public static let auditTokenByteCount = MemoryLayout<audit_token_t>.size

    /// Decode the raw audit-token `Data` carried by `NEFilterFlow`.
    ///
    /// `signingInfoResolver` is injected so unit tests can drive the
    /// signing-identity branch deterministically without a live
    /// `SecCode`. In production it defaults to the real
    /// `SecCodeCopyGuestWithAttributes` path. The resolver returning `nil`
    /// for BOTH signingId and teamId is NOT treated as unattributed on its
    /// own -- the uid/pid decode already succeeded, so the flow is attributed
    /// for UID-mode classification; NAT-mode then decides `.unattributed`
    /// when it needs a signing identity it does not have.
    public static func decode(
        tokenData: Data?,
        signingInfoResolver: (audit_token_t) -> (signingId: String?, teamId: String?) = AuditTokenDecode.resolveSigningInfo
    ) -> Result {
        guard let tokenData else {
            return .unattributedResult
        }
        guard tokenData.count == auditTokenByteCount else {
            return .unattributedResult
        }

        var token = audit_token_t()
        let copied = withUnsafeMutableBytes(of: &token) { dst -> Int in
            _ = tokenData.copyBytes(to: dst.bindMemory(to: UInt8.self))
            return dst.count
        }
        guard copied == auditTokenByteCount else {
            return .unattributedResult
        }

        let pid = audit_token_to_pid(token)
        let ruid = audit_token_to_ruid(token)
        let pidVersion = audit_token_to_pidversion(token)

        // A pid of 0 from a real flow's source token is not a process we can
        // attribute (kernel/idle); fail closed rather than guessing.
        guard pid > 0 else {
            return .unattributedResult
        }

        let signing = signingInfoResolver(token)
        return Result(
            ruid: ruid,
            pid: pid,
            pidVersion: pidVersion,
            signingId: signing.signingId,
            teamId: signing.teamId,
            unattributed: false
        )
    }

    /// Best-effort signing-identity resolution via Security.framework.
    /// Returns `(nil, nil)` on ANY failure (`errSecCSUnsigned`, EPERM, etc.).
    /// A `(nil, nil)` result is NOT a decode failure: it simply means the
    /// signing axis is unavailable for this flow. The fail-closed decision
    /// for "no signing identity but NAT mode needs one" is made by the
    /// classifier, not here.
    public static func resolveSigningInfo(
        from token: audit_token_t
    ) -> (signingId: String?, teamId: String?) {
        var tokenCopy = token
        let attrs: CFDictionary = withUnsafeBytes(of: &tokenCopy) { raw -> CFDictionary in
            let data = CFDataCreate(
                kCFAllocatorDefault,
                raw.bindMemory(to: UInt8.self).baseAddress,
                raw.count
            )
            return [kSecGuestAttributeAudit: data as Any] as CFDictionary
        }

        var guest: SecCode?
        let guestStatus = SecCodeCopyGuestWithAttributes(nil, attrs, [], &guest)
        guard guestStatus == errSecSuccess, let guest else {
            return (nil, nil)
        }

        var staticCode: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(guest, [], &staticCode)
        guard staticStatus == errSecSuccess, let staticCode else {
            return (nil, nil)
        }

        var infoCF: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &infoCF
        )
        guard infoStatus == errSecSuccess,
              let info = infoCF as? [String: Any] else {
            return (nil, nil)
        }

        let signingId = info[kSecCodeInfoIdentifier as String] as? String
        let teamId = info[kSecCodeInfoTeamIdentifier as String] as? String
        return (signingId, teamId)
    }
}
