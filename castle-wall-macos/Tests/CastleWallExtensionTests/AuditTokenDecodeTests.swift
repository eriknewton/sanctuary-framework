//
// AuditTokenDecodeTests.swift
//
// Unit tests for the Data -> audit_token_t -> ruid/pid/pidversion decode
// path (2026-05-29 origin-classifier foundation). Drives a synthesized
// audit token (no live process required) and asserts the fail-closed
// contract: every malformed / nil / zero-pid input yields an
// `unattributed == true` result.
//
// audit_token_t layout (Darwin): val[0]=auid, val[1]=euid, val[2]=egid,
// val[3]=ruid, val[4]=rgid, val[5]=pid, val[6]=asid, val[7]=pidversion.
//

import XCTest
import Darwin
@testable import CastleWallFilter

final class AuditTokenDecodeTests: XCTestCase {

    /// Build a synthesized audit-token Data with the given ruid/pid/pidversion.
    private func synthToken(ruid: UInt32, pid: UInt32, pidVersion: UInt32) -> Data {
        var vals = [UInt32](repeating: 0, count: 8)
        vals[3] = ruid
        vals[5] = pid
        vals[7] = pidVersion
        return vals.withUnsafeBytes { Data($0) }
    }

    /// A resolver that returns no signing identity, so tests of the numeric
    /// path don't touch Security.framework.
    private let noSigning: (audit_token_t) -> (signingId: String?, teamId: String?) = { _ in
        return (nil, nil)
    }

    func testDecodesRuidPidPidversion() {
        let token = synthToken(ruid: 501, pid: 4242, pidVersion: 7)
        let result = AuditTokenDecode.decode(tokenData: token, signingInfoResolver: noSigning)
        XCTAssertFalse(result.unattributed)
        XCTAssertEqual(result.ruid, 501)
        XCTAssertEqual(result.pid, 4242)
        XCTAssertEqual(result.pidVersion, 7)
    }

    func testNilTokenIsUnattributed() {
        let result = AuditTokenDecode.decode(tokenData: nil, signingInfoResolver: noSigning)
        XCTAssertTrue(result.unattributed)
        XCTAssertEqual(result, AuditTokenDecode.Result.unattributedResult)
    }

    func testWrongLengthTokenIsUnattributed() {
        let short = Data([0x00, 0x01, 0x02]) // not 32 bytes
        let result = AuditTokenDecode.decode(tokenData: short, signingInfoResolver: noSigning)
        XCTAssertTrue(result.unattributed)
    }

    func testEmptyTokenIsUnattributed() {
        let result = AuditTokenDecode.decode(tokenData: Data(), signingInfoResolver: noSigning)
        XCTAssertTrue(result.unattributed)
    }

    func testZeroPidIsUnattributed() {
        // pid 0 is the kernel/idle; cannot positively attribute -> fail closed.
        let token = synthToken(ruid: 501, pid: 0, pidVersion: 0)
        let result = AuditTokenDecode.decode(tokenData: token, signingInfoResolver: noSigning)
        XCTAssertTrue(result.unattributed)
    }

    func testSigningResolverFailureLeavesAttributedButNoIdentity() {
        // A failed signing lookup (errSecCSUnsigned, EPERM, etc.) returns
        // (nil, nil) -- it does NOT flip the numeric decode to unattributed.
        // The flow stays attributed for UID-mode; NAT-mode decides
        // .unattributed downstream when it needs the missing identity.
        let token = synthToken(ruid: 600, pid: 100, pidVersion: 1)
        let result = AuditTokenDecode.decode(tokenData: token, signingInfoResolver: noSigning)
        XCTAssertFalse(result.unattributed)
        XCTAssertNil(result.signingId)
        XCTAssertNil(result.teamId)
    }

    func testSigningResolverIdentityIsPlumbedThrough() {
        let token = synthToken(ruid: 600, pid: 100, pidVersion: 1)
        let result = AuditTokenDecode.decode(tokenData: token, signingInfoResolver: { _ in
            return (signingId: "ai.sanctuaryprotocol.egress-helper", teamId: "YFQSWQ9BJN")
        })
        XCTAssertFalse(result.unattributed)
        XCTAssertEqual(result.signingId, "ai.sanctuaryprotocol.egress-helper")
        XCTAssertEqual(result.teamId, "YFQSWQ9BJN")
    }

    func testAuditTokenByteCountIs32() {
        XCTAssertEqual(AuditTokenDecode.auditTokenByteCount, 32)
    }
}
