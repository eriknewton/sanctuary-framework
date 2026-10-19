import XCTest
@testable import LocalModelGatewayCore

let streamHeader = bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
let event = bytes("data: {\"choices\":[{\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}\n\n")
func responseHeader(_ type: String = "text/event-stream", framing: String = "Transfer-Encoding: chunked\r\n", status: Int = 200) -> [UInt8] {
    bytes("HTTP/1.1 \(status) Response\r\nContent-Type: \(type)\r\n\(framing)\r\n")
}
func feed(_ input: [UInt8], to framer: inout ResponseFramer) -> [UInt8] {
    input.flatMap { framer.receive($0) }
}
func response(_ input: [UInt8], streaming: Bool = true, limits: GatewayLimits = .fixture) throws -> [UInt8] {
    let request = try parse(streaming ? chatField(#""stream":true"#) : basic)
    var framer = ResponseFramer(request: request, limits: limits)
    return feed(input, to: &framer) + framer.endOfInput()
}

final class ResponseTests: XCTestCase {
    func testStreamSuccessAndHeldDone() throws {
        let finish = bytes("data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n\n")
        let usage = bytes("data: {\"choices\":[],\"usage\":{\"completion_tokens\":1}}\n\n")
        let payload = event + finish + usage + GatewayProtocol.done
        for framing in ["Transfer-Encoding: chunked\r\n", "Content-Length: \(payload.count)\r\n", ""] {
            var framer = ResponseFramer(request: try parse(chatField(#""stream":true"#)), limits: .fixture)
            XCTAssertEqual(feed(responseHeader(framing: framing), to: &framer), streamHeader)
            let input = framing.hasPrefix("Transfer") ? chunk(payload) + bytes("0\r\n\r\n") : payload
            XCTAssertEqual(feed(input, to: &framer), chunk(event) + chunk(finish) + chunk(usage))
            XCTAssertFalse(framer.isClosed)
            XCTAssertTrue(framer.isStreamingCommitted)
            XCTAssertEqual(framer.endOfInput(), bytes("e\r\ndata: [DONE]\n\n\r\n0\r\n\r\n"))
            XCTAssertTrue(framer.isClosed)
            XCTAssertEqual(framer.endOfInput(), [])
            XCTAssertEqual(framer.fail(cause: .reset), [])
            XCTAssertEqual(framer.receive(0), [])
        }
        // HTTP chunks deliberately split every SSE byte; event and transfer boundaries are unrelated.
        let split = payload.flatMap { chunk([$0]) } + bytes("0\r\n\r\n")
        XCTAssertEqual(try response(responseHeader() + split), streamHeader + chunk(event) + chunk(finish) + chunk(usage) + chunk(GatewayProtocol.done) + bytes("0\r\n\r\n"))
    }
    func testTruncationEOFResetDeadline() throws {
        for tail in [event, event + bytes("data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n\n"),
                     bytes("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"{\"}}]}}]}\n\n")] {
            for terminator in ["", "0\r\n\r\n"] {
                let out = try response(responseHeader() + chunk(tail) + bytes(terminator))
                XCTAssertTrue(out.suffix(chunk(GatewayProtocol.truncation).count).elementsEqual(chunk(GatewayProtocol.truncation)))
                XCTAssertFalse(out.suffix(5).elementsEqual(bytes("0\r\n\r\n")))
            }
            // Both causes truncate after commitment; their pre-commit responses are tested separately.
            for cause in [ResponseFailureCause.reset, .deadline] {
                var framer = ResponseFramer(request: try parse(chatField(#""stream":true"#)), limits: .fixture)
                _ = feed(responseHeader() + chunk(tail), to: &framer)
                XCTAssertEqual(framer.fail(cause: cause), chunk(GatewayProtocol.truncation))
                XCTAssertEqual(framer.fail(cause: .reset), [])
            }
        }
    }
    func testFalseDoneAndMalformedEvents() throws {
        for bad in ["data: [DONE]suffix\n\n", "data: [DONE] \n\n", "data:[DONE]\n\n", "data:  [DONE]\n\n",
                    "data: [DONE]\r\n\r\n", "data: [DONE]\n", "data: [DONE]\n\ndata: {}\n\n",
                    "event: message\ndata: {}\n\n", "data: {}\ndata: {}\n\n", "data: []\n\n", "data: {bad}\n\n",
                    "data: {\"a\":0,\"a\":1}\n\n", "data: {}{}\n\n", "data: {}\r\n\r\n"] {
            let out = try response(responseHeader() + chunk(bytes(bad)) + bytes("0\r\n\r\n"))
            XCTAssertEqual(out, streamHeader + chunk(GatewayProtocol.truncation), bad)
        }
        let invalid = bytes("data: {\"a\":\"") + [0xff] + bytes("\"}\n\n")
        XCTAssertEqual(try response(responseHeader() + chunk(invalid) + bytes("0\r\n\r\n")), streamHeader + chunk(GatewayProtocol.truncation))
    }
    func testFalseDoneLayer() throws {
        var framer = ResponseFramer(request: try parse(chatField(#""stream":true"#)), limits: .fixture)
        _ = feed(responseHeader() + chunk(bytes("data: [DONE]suffix\n\n")), to: &framer)
        XCTAssertEqual(framer.failure, .falseDone)
    }
    func testHTTPChunkRefusals() throws {
        for body in ["g\r\n", "1;ext=x\r\na\r\n", "-1\r\n", " 1\r\n", "ffffffffffffffffffffffffffffffff\r\n",
                     "1\r\naX\n", "1\r\na\rX", "0\r\nX: x\r\n\r\n", "0\r\n\rX", "0\n\n"] {
            XCTAssertEqual(try response(responseHeader() + bytes(body)), streamHeader + chunk(GatewayProtocol.truncation), body)
        }
        // Valid DONE plus a malformed zero-size line isolates hexadecimal grammar from missing DONE.
        XCTAssertEqual(try response(responseHeader() + chunk(GatewayProtocol.done) + bytes("g\r\n\r\n")), streamHeader + chunk(GatewayProtocol.truncation))
        for suffix in [bytes("junk"), responseHeader()] {
            XCTAssertEqual(try response(responseHeader() + chunk(GatewayProtocol.done) + bytes("0\r\n\r\n") + suffix), streamHeader + chunk(GatewayProtocol.truncation))
        }
        XCTAssertEqual(try response(responseHeader(framing: "Content-Length: 1\r\n") + bytes("ab")), streamHeader + chunk(GatewayProtocol.truncation))
    }
    func testResponseModeHeadersAndRedirects() throws {
        for status in 300...399 {
            XCTAssertEqual(try response(responseHeader("application/json", framing: "Content-Length: 2\r\nLocation: https://example.invalid/\r\n", status: status) + bytes("{}")), FixedResponse.upstream.wire)
        }
        for header in [responseHeader("application/json"), responseHeader(status: 100), responseHeader(status: 201),
                       responseHeader(framing: "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n"),
                       responseHeader(framing: "Content-Length: 0\r\nContent-Length: 0\r\n"),
                       responseHeader(framing: "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n"),
                       responseHeader(framing: "Content-Encoding: gzip\r\n"), responseHeader(framing: "Trailer: x\r\n"),
                       responseHeader(framing: "Upgrade: h2c\r\n"), responseHeader(framing: "Transfer-Encoding: gzip\r\n"),
                       responseHeader(framing: "Content-Type: text/event-stream\r\n"), responseHeader(framing: "Content-Length: 01\r\n")] {
            XCTAssertEqual(try response(header), FixedResponse.upstream.wire)
        }
        XCTAssertEqual(try response(responseHeader(), streaming: false), FixedResponse.upstream.wire)
        XCTAssertEqual(try response(bytes("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{}"), streaming: false), FixedResponse.upstream.wire)
        for status in [400, 401, 413, 429, 500, 599] {
            let output = try response(responseHeader("application/json", framing: "Content-Length: 2\r\n", status: status) + bytes("{}"))
            XCTAssertTrue(output.starts(with: bytes("HTTP/1.1 \(status) Upstream Error\r\n")))
        }
    }
    func testNonstreamCompleteValidation() throws {
        for type in ["application/json", "application/json; charset=utf-8"] {
            for framing in ["Content-Length: 3\r\n", "Transfer-Encoding: chunked\r\n", ""] {
                let body = bytes("{}\n")
                let upstream = framing.hasPrefix("Transfer") ? chunk(body) + bytes("0\r\n\r\n") : body
                var framer = ResponseFramer(request: try parse(), limits: .fixture)
                XCTAssertEqual(feed(responseHeader(type, framing: framing) + upstream, to: &framer), [])
                XCTAssertEqual(framer.endOfInput(), bytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{}\n"))
            }
        }
        for body in ["", "{", "{}{}", "{\"a\":0,\"a\":1}", String(repeating:"[",count:65) + String(repeating:"]",count:65)] {
            XCTAssertEqual(try response(responseHeader("application/json", framing: "") + bytes(body), streaming: false), FixedResponse.upstream.wire)
        }
        XCTAssertEqual(try response(responseHeader("application/json", framing: "Content-Length: 3\r\n") + bytes("{}"), streaming: false), FixedResponse.upstream.wire)
    }
    func testResponseBudgets() throws {
        let header = responseHeader()
        let limits = try GatewayLimits(body: event.count, headers: header.count, response: event.count + GatewayProtocol.done.count)
        XCTAssertEqual(try response(header + chunk(event + GatewayProtocol.done) + bytes("0\r\n\r\n"), limits: limits), streamHeader + chunk(event) + chunk(GatewayProtocol.done) + bytes("0\r\n\r\n"))
        let eventShort = try GatewayLimits(body: event.count - 1, headers: header.count, response: limits.response)
        XCTAssertEqual(try response(header + chunk(event), limits: eventShort), streamHeader + chunk(GatewayProtocol.truncation))
        // One combined chunk exceeds the declared chunk budget before any event is emitted.
        let aggregateShort = try GatewayLimits(body: event.count, headers: header.count, response: limits.response - 1)
        XCTAssertEqual(try response(header + chunk(event + GatewayProtocol.done), limits: aggregateShort), streamHeader + chunk(GatewayProtocol.truncation))
        let headerShort = try GatewayLimits(body: event.count, headers: header.count - 1, response: limits.response)
        XCTAssertEqual(try response(header, limits: headerShort), FixedResponse.upstream.wire)
        let hugeChunkLine = bytes(String(repeating:"0",count:header.count) + "\r\n")
        XCTAssertEqual(try response(header + hugeChunkLine, limits: limits), streamHeader + chunk(GatewayProtocol.truncation))
        XCTAssertEqual(try response(header + chunk(GatewayProtocol.done) + hugeChunkLine + bytes("\r\n"), limits: limits), streamHeader + chunk(GatewayProtocol.truncation))
        // Close-delimited bodies isolate the payload aggregate guard from declared-length guards.
        let tiny = try GatewayLimits(body: event.count, headers: header.count, response: 2)
        XCTAssertEqual(try response(responseHeader("application/json", framing: "") + bytes("{}"), streaming: false, limits: tiny), bytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"))
        XCTAssertEqual(try response(responseHeader("application/json", framing: "") + bytes("{} "), streaming: false, limits: tiny), FixedResponse.upstream.wire)
        var declared = ResponseFramer(request: try parse(), limits: tiny)
        // Oversize declared length must refuse at headers, before waiting for body/EOF.
        XCTAssertEqual(feed(responseHeader("application/json", framing: "Content-Length: 3\r\n"), to: &declared), FixedResponse.upstream.wire)
        var aggregate = ResponseFramer(request: try parse(), limits: tiny)
        XCTAssertEqual(feed(responseHeader("application/json", framing: "") + bytes("{}"), to: &aggregate), [])
        // The extra byte must refuse immediately, before the shared JSON parser is reached.
        XCTAssertEqual(aggregate.receive(32), FixedResponse.upstream.wire)
    }
    func testPrecommitDeadline() throws {
        var framer = ResponseFramer(request: try parse(), limits: .fixture)
        XCTAssertEqual(framer.fail(cause: .deadline), FixedResponse.deadline.wire)
        XCTAssertEqual(framer.fail(cause: .reset), [])
        XCTAssertEqual(framer.endOfInput(), [])
        XCTAssertEqual(framer.receive(0), [])
    }
    func testPrecommitReset() throws {
        var framer = ResponseFramer(request: try parse(), limits: .fixture)
        XCTAssertEqual(framer.fail(cause: .reset), FixedResponse.upstream.wire)
        XCTAssertEqual(framer.fail(cause: .deadline), [])
    }
    func testPrecommitProtocolFailure() throws {
        var framer = ResponseFramer(request: try parse(), limits: .fixture)
        XCTAssertEqual(framer.fail(cause: .protocolViolation), FixedResponse.upstream.wire)
    }
    func testSSECarriageReturnLayer() throws {
        var framer = ResponseFramer(request: try parse(chatField(#""stream":true"#)), limits: .fixture)
        // CR is legal JSON whitespace here, so only the SSE layer can refuse it.
        XCTAssertEqual(feed(responseHeader() + chunk(bytes("data: {}\r\n\n")), to: &framer), streamHeader + chunk(GatewayProtocol.truncation))
        XCTAssertEqual(framer.failure, .protocolViolation)
    }
    func testSSEMultilineLayer() throws {
        var framer = ResponseFramer(request: try parse(chatField(#""stream":true"#)), limits: .fixture)
        // The embedded LF is valid JSON whitespace, isolating the SSE single-line rule.
        XCTAssertEqual(feed(responseHeader() + chunk(bytes("data: {\n}\n\n")), to: &framer), streamHeader + chunk(GatewayProtocol.truncation))
        XCTAssertEqual(framer.failure, .protocolViolation)
    }
    func testNonstreamErrorStatus() throws {
        for status in [400, 401, 413, 429, 500, 599] {
            XCTAssertEqual(try response(responseHeader("application/json", framing: "Content-Length: 2\r\n", status: status) + bytes("{}"), streaming: false), FixedResponse.upstream.wire)
        }
    }
    func testStreamAggregateCapAfterEvent() throws {
        let closeHeader = responseHeader(framing: "")
        let limits = try GatewayLimits(body: event.count, headers: closeHeader.count,
                                       response: event.count + GatewayProtocol.done.count - 1)
        var framer = ResponseFramer(request: try parse(chatField(#""stream":true"#)), limits: limits)
        XCTAssertEqual(feed(closeHeader + event, to: &framer), streamHeader + chunk(event))
        // No declared chunk length can reject early: the last DONE byte crosses the aggregate cap.
        XCTAssertEqual(feed(GatewayProtocol.done, to: &framer), chunk(GatewayProtocol.truncation))
        XCTAssertTrue(framer.isClosed)
        XCTAssertEqual(framer.endOfInput(), [])
    }

}
