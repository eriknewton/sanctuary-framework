import Darwin
import Foundation
import XCTest
@testable import MemoryGrantPeer

final class MemoryGrantPeerTests: XCTestCase {
    private func withPair(type: Int32 = SOCK_STREAM, _ body: (Int32, Int32) throws -> Void) throws {
        var descriptors: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, type, 0, &descriptors) == 0 else {
            XCTFail("Could not create temporary socket pair: \(errno)")
            return
        }
        defer { descriptors.forEach { _ = close($0) } }
        try body(descriptors[0], descriptors[1])
    }

    func testKernelIdentityFromUnixConnection() throws {
        try withPair { first, second in
            for socket in [first, second] {
                let identity = try UnixPeerVerifier.requirePeer(socket: socket, expectedUID: geteuid())
                XCTAssertEqual(identity.effectiveUID, geteuid())
                XCTAssertEqual(identity.effectiveGID, getegid())
            }
        }
    }

    func testWrongUIDAndInvalidUIDAreDenied() throws {
        try withPair { socket, _ in
            let differentUID: uid_t = geteuid() == 0 ? 1 : 0
            XCTAssertThrowsError(try UnixPeerVerifier.requirePeer(socket: socket, expectedUID: differentUID)) {
                XCTAssertEqual($0 as? UnixPeerError, .unexpectedUID)
            }
            XCTAssertThrowsError(try UnixPeerVerifier.requirePeer(socket: socket, expectedUID: .max)) {
                XCTAssertEqual($0 as? UnixPeerError, .invalidExpectedUID)
            }
        }
    }

    func testMissingAndUnconnectedDescriptorsAreDenied() {
        XCTAssertThrowsError(try UnixPeerVerifier.requirePeer(socket: -1, expectedUID: geteuid())) {
            XCTAssertEqual($0 as? UnixPeerError, .inspectionFailed)
        }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer { _ = close(descriptor) }
        XCTAssertThrowsError(try UnixPeerVerifier.requirePeer(socket: descriptor, expectedUID: geteuid())) {
            XCTAssertEqual($0 as? UnixPeerError, .inspectionFailed)
        }
    }

    func testDatagramsCannotSubstituteForStreamPeerIdentity() throws {
        try withPair(type: SOCK_DGRAM) { socket, _ in
            XCTAssertThrowsError(try UnixPeerVerifier.requirePeer(socket: socket, expectedUID: geteuid())) {
                XCTAssertEqual($0 as? UnixPeerError, .unsupportedSocket)
            }
        }
    }

    private func header(_ length: UInt32) -> Data {
        var networkLength = length.bigEndian
        return withUnsafeBytes(of: &networkLength) { Data($0) }
    }

    func testEverySplitPointAndBytewiseInputDecodeExactlyOnceAtEOF() throws {
        let body = Data("{\"uid\":0}".utf8) // Payload claims are opaque and confer no identity.
        let wire = header(UInt32(body.count)) + body
        for split in 0...wire.count {
            var decoder = SingleRequestFrame()
            try decoder.append(Data(wire.prefix(split)))
            try decoder.append(Data(wire.dropFirst(split)))
            XCTAssertEqual(try decoder.finishAtEOF(), body)
            XCTAssertEqual(decoder.bufferedByteCount, 0)
            XCTAssertThrowsError(try decoder.finishAtEOF()) {
                XCTAssertEqual($0 as? SingleRequestFrameError, .terminal)
            }
            XCTAssertThrowsError(try decoder.append(wire))
        }
        var decoder = SingleRequestFrame()
        for byte in wire { try decoder.append(Data([byte])) }
        XCTAssertEqual(try decoder.finishAtEOF(), body)
    }

    func testTruncationAtEveryByteIsTerminal() throws {
        let wire = header(3) + Data([1, 2, 3])
        for length in 0..<wire.count {
            var decoder = SingleRequestFrame()
            try decoder.append(Data(wire.prefix(length)))
            XCTAssertThrowsError(try decoder.finishAtEOF()) {
                XCTAssertEqual($0 as? SingleRequestFrameError, .incomplete)
            }
            XCTAssertEqual(decoder.bufferedByteCount, 0)
            XCTAssertThrowsError(try decoder.append(wire)) {
                XCTAssertEqual($0 as? SingleRequestFrameError, .terminal)
            }
        }
    }

    func testZeroOversizeAndUInt32MaximumLengthsFailBeforeBody() {
        for length: UInt32 in [0, UInt32(SingleRequestFrame.maximumPayloadBytes + 1), .max] {
            var decoder = SingleRequestFrame()
            XCTAssertThrowsError(try decoder.append(header(length))) {
                XCTAssertEqual($0 as? SingleRequestFrameError, length == 0 ? .invalidLength : .tooLarge)
            }
            XCTAssertEqual(decoder.bufferedByteCount, 0)
            XCTAssertThrowsError(try decoder.finishAtEOF()) {
                XCTAssertEqual($0 as? SingleRequestFrameError, .terminal)
            }
        }
    }

    func testTrailingBytesInSameOrLaterReadRejectEntireRequest() throws {
        let wire = header(1) + Data([42])
        for trailing in [Data([0]), wire] {
            var sameRead = SingleRequestFrame()
            XCTAssertThrowsError(try sameRead.append(wire + trailing)) {
                XCTAssertEqual($0 as? SingleRequestFrameError, .trailingBytes)
            }
            var laterRead = SingleRequestFrame()
            try laterRead.append(wire)
            XCTAssertThrowsError(try laterRead.append(trailing)) {
                XCTAssertEqual($0 as? SingleRequestFrameError, .trailingBytes)
            }
            XCTAssertThrowsError(try laterRead.finishAtEOF()) {
                XCTAssertEqual($0 as? SingleRequestFrameError, .terminal)
            }
        }
    }

    func testMaximumRequestAndAdversarialInputRemainBounded() throws {
        var decoder = SingleRequestFrame()
        let limit = SingleRequestFrame.maximumPayloadBytes
        try decoder.append(header(UInt32(limit)))
        // One-byte fragmentation stresses retained memory and repeated admission.
        for _ in 0..<limit {
            try decoder.append(Data([42]))
            XCTAssertLessThanOrEqual(decoder.bufferedByteCount, limit + SingleRequestFrame.headerBytes)
        }
        XCTAssertEqual(try decoder.finishAtEOF().count, limit)
        var oversized = SingleRequestFrame()
        let largeInput = Data(repeating: 0, count: limit * 16)
        XCTAssertThrowsError(try oversized.append(largeInput)) {
            XCTAssertEqual($0 as? SingleRequestFrameError, .tooLarge)
        }
        XCTAssertEqual(oversized.bufferedByteCount, 0)
        for _ in 0..<100 {
            XCTAssertThrowsError(try oversized.append(largeInput)) {
                XCTAssertEqual($0 as? SingleRequestFrameError, .terminal)
            }
            XCTAssertEqual(oversized.bufferedByteCount, 0)
        }
    }
}
