//
// FramingTests.swift
//
// Round-trip and parser-edge tests against fixed byte sequences. Mirrors
// `castle-wall-daemon/src/ipc/framing.rs::tests` and the framing portions
// of `server/test/castle-wall/ipc/framing.test.ts`.
//

import XCTest
@testable import CastleWallIPC

final class FramingTests: XCTestCase {
    func testFrameRoundTripsSimpleBody() {
        let framed = Framing.frame("{\"x\":1}")
        guard case .complete(let body, let consumed) = Framing.parseFrame(framed) else {
            XCTFail("expected complete")
            return
        }
        XCTAssertEqual(body, "{\"x\":1}")
        XCTAssertEqual(consumed, framed.count)
    }

    func testParseSignalsNeedMoreForPartialHeader() {
        let buf = Data("Content-Length: 5\r\n".utf8)
        XCTAssertEqual(Framing.parseFrame(buf), .needMore)
    }

    func testParseSignalsNeedMoreForPartialBody() {
        let buf = Data("Content-Length: 10\r\n\r\nshort".utf8)
        XCTAssertEqual(Framing.parseFrame(buf), .needMore)
    }

    func testParseRejectsNegativeLength() {
        let buf = Data("Content-Length: -1\r\n\r\n".utf8)
        guard case .error(let reason) = Framing.parseFrame(buf) else {
            XCTFail("expected error")
            return
        }
        XCTAssertTrue(reason.contains("invalid Content-Length"))
    }

    func testParseRejectsMissingContentLength() {
        let buf = Data("X-Other: 1\r\n\r\n".utf8)
        guard case .error(let reason) = Framing.parseFrame(buf) else {
            XCTFail("expected error")
            return
        }
        XCTAssertTrue(reason.contains("missing Content-Length"))
    }

    func testHeaderMatchIsCaseInsensitive() {
        let body = "{\"x\":1}"
        let frameStr = "content-length: \(body.utf8.count)\r\n\r\n\(body)"
        let buf = Data(frameStr.utf8)
        guard case .complete(let parsed, _) = Framing.parseFrame(buf) else {
            XCTFail("expected complete")
            return
        }
        XCTAssertEqual(parsed, body)
    }

    func testExtraBytesRemainAfterComplete() {
        var buf = Framing.frame("{}")
        buf.append(contentsOf: "trailing".utf8)
        guard case .complete(_, let consumed) = Framing.parseFrame(buf) else {
            XCTFail("expected complete")
            return
        }
        XCTAssertLessThan(consumed, buf.count)
        let remainder = buf.subdata(in: consumed..<buf.count)
        XCTAssertEqual(remainder, Data("trailing".utf8))
    }

    func testFrameMatchesByteSequenceFromRustFixture() {
        // Fixture: a one-key JSON body whose framed bytes must match
        // the Rust `frame()` output exactly. Concatenated as expected by
        // the `castle-wall-daemon` Rust integration_framing_messages
        // test corpus.
        let body = "{\"jsonrpc\":\"2.0\",\"method\":\"castle-wall.status_request\",\"params\":{\"type\":\"status_request\",\"request_id\":\"abc\"}}"
        let framed = Framing.frame(body)
        let expectedHeader = "Content-Length: \(body.utf8.count)\r\n\r\n"
        XCTAssertEqual(framed.prefix(expectedHeader.utf8.count), Data(expectedHeader.utf8))
        XCTAssertEqual(framed.suffix(body.utf8.count), Data(body.utf8))
    }
}
