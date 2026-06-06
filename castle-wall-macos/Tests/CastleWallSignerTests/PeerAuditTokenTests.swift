//
// PeerAuditTokenTests.swift
//
// Decode of a synthesized kernel audit_token_t into ruid/pid/pidversion. The
// libbsm accessors read fixed slots of the 8×uint32 token:
//   val[3] = ruid, val[5] = pid, val[7] = pidversion.
// We build a token at those slots and confirm the decode, plus the fail-closed
// paths (nil / wrong length / pid 0 → nil).
//

import XCTest
import Darwin
@testable import CastleWallSigner

final class PeerAuditTokenTests: XCTestCase {

    /// Build a 32-byte audit-token blob with the given field values placed at the
    /// libbsm-defined uint32 slots (host byte order, as the kernel writes them).
    private func makeToken(ruid: UInt32, pid: UInt32, pidVersion: UInt32) -> Data {
        var words = [UInt32](repeating: 0, count: 8)
        words[3] = ruid
        words[5] = pid
        words[7] = pidVersion
        return words.withUnsafeBytes { Data($0) }
    }

    func testDecodeExtractsFields() throws {
        let token = makeToken(ruid: 503, pid: 1234, pidVersion: 7)
        let peer = try XCTUnwrap(PeerAuditToken.decode(token))
        XCTAssertEqual(peer.ruid, 503)
        XCTAssertEqual(peer.pid, 1234)
        XCTAssertEqual(peer.pidVersion, 7)
    }

    func testDecodeNilTokenFailsClosed() {
        XCTAssertNil(PeerAuditToken.decode(nil))
    }

    func testDecodeWrongLengthFailsClosed() {
        XCTAssertNil(PeerAuditToken.decode(Data(repeating: 0, count: 16)))
        XCTAssertNil(PeerAuditToken.decode(Data(repeating: 0, count: 33)))
    }

    func testDecodeZeroPidFailsClosed() {
        let token = makeToken(ruid: 0, pid: 0, pidVersion: 0)
        XCTAssertNil(PeerAuditToken.decode(token))
    }

    func testByteCountIsThirtyTwo() {
        XCTAssertEqual(PeerAuditToken.byteCount, 32)
    }
}
