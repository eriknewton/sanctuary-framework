import XCTest
@testable import LocalModelGatewayCore

func httpRequest(body: String = basic, method: String = "POST", target: String = "/v1/chat/completions",
                 extra: String = "", length: String? = nil) -> [UInt8] {
    bytes("\(method) \(target) HTTP/1.1\r\nHost: 127.0.0.1:11436\r\nContent-Length: \(length ?? String(body.utf8.count))\r\n\(extra)\r\n\(body)")
}
func wireRefused(_ input: [UInt8], _ reason: Refusal, limits: GatewayLimits = .fixture,
                 file: StaticString = #filePath, line: UInt = #line) {
    var framer = RequestFramer(limits: limits)
    XCTAssertThrowsError(try framer.receive(input), file: file, line: line) {
        XCTAssertEqual($0 as? Refusal, reason, file: file, line: line)
    }
}

final class WireTests: XCTestCase {
    func testRefusedProbeClassification() {
        let probes: [(String, RefusedTarget)] = [("/api/v1/models", .lmstudioProbe), ("/v1/props", .llamacppV1Props),
            ("/props", .llamacppProps), ("/version", .vllmVersion), ("/models", .modelsFallback), ("/other", .other)]
        for (target, classification) in probes {
            var framer = RequestFramer(limits: .fixture)
            XCTAssertThrowsError(try framer.receive(httpRequest(body: "", method: "GET", target: target))) {
                XCTAssertEqual($0 as? Refusal, .route)
            }
            XCTAssertEqual(framer.refusedTarget, classification)
        }
    }
    func testHeaderRegeneration() throws {
        let input = httpRequest(extra: "Authorization: Bearer secret\r\nCookie: secret\r\nX-Stainless-Lang: secret\r\nX-Forwarded-For: secret\r\nX-Real-IP: secret\r\nOrigin: secret\r\nUser-Agent: secret\r\nAccept-Encoding: secret\r\nProxy-Authorization: secret\r\n")
        var framer = RequestFramer(limits: .fixture)
        let request = try XCTUnwrap(framer.receive(input))
        let body = RequestSerializer.body(request)
        for authorization in [RequestSerializer.Authorization.placeholder, .stripAfterCapture] {
            let auth = authorization == .placeholder ? "Authorization: Bearer no-key-required\r\n" : ""
            XCTAssertEqual(RequestSerializer.http(request, authorization: authorization),
                           bytes("POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nAccept: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\nContent-Type: application/json\r\n\(auth)\r\n") + body)
        }
        for route in [Route.tags, .models] {
            let request = try parse("", route: route)
            XCTAssertEqual(RequestSerializer.http(request, authorization: .stripAfterCapture),
                           route.method + bytes(" ") + route.target + bytes(" HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nAccept: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
        }
    }
    func testBytewiseRequestAndSplitPoints() throws {
        let input = httpRequest()
        for split in 0..<input.count {
            var framer = RequestFramer(limits: .fixture)
            XCTAssertNil(try framer.receive(Array(input.prefix(split))))
            XCTAssertEqual(try framer.receive(Array(input.dropFirst(split))), try parse())
        }
        var framer = RequestFramer(limits: .fixture)
        for byte in input.dropLast() { XCTAssertNil(try framer.receive([byte])) }
        XCTAssertEqual(try framer.receive([input.last!]), try parse())
        XCTAssertThrowsError(try framer.receive([32])) { XCTAssertEqual($0 as? Refusal, .extraBytes) }
        for route in [Route.tags, .models] {
            for cl in ["", "Content-Length: 0\r\n"] {
                var f = RequestFramer(limits: .fixture)
                let input = route.method + bytes(" ") + route.target + bytes(" HTTP/1.1\r\nHost: 127.0.0.1:11436\r\n\(cl)\r\n")
                XCTAssertEqual(try f.receive(input)?.route, route)
            }
        }
    }
    func testRequestFramingRefusals() {
        for header in ["Transfer-Encoding: chunked", "transfer-encoding: identity", "Content-Encoding: identity",
                       "Content-Encoding: zstd", "Expect: 100-continue", "Upgrade: websocket", "Trailer: x",
                       "Host: 127.0.0.1:11436", "Content-Length: 0", "Bad Name: x", "Bad : x", " Folded: x", "X:\tx", "X: a\tb", "X: a\u{7f}"] {
            wireRefused(httpRequest(extra: header + "\r\n"), .framing)
        }
        for length in ["+1", "-1", "01", "00", "1,1", "1 ", " 1", "1\t", "", "99999999999999999999999999999"] {
            wireRefused(httpRequest(length: length), .framing)
        }
        let wire = String(decoding: httpRequest(), as: UTF8.self)
        for bad in [wire.replacingOccurrences(of: "HTTP/1.1", with: "HTTP/1.0"),
                    wire.replacingOccurrences(of: "POST /", with: "POST  /"),
                    wire.replacingOccurrences(of: "POST /", with: "POST\t/"),
                    wire.replacingOccurrences(of: "Host: 127.0.0.1:11436\r\n", with: ""),
                    wire.replacingOccurrences(of: "127.0.0.1:11436", with: "localhost:11436"),
                    wire.replacingOccurrences(of: "Content-Length: \(basic.utf8.count)\r\n", with: ""),
                    wire.replacingOccurrences(of: "Host:", with: "Host :"),
                    wire.replacingOccurrences(of: "Host: 127.0.0.1:11436\r\n", with: "Host: 127.0.0.1:11436\n")] {
            wireRefused(bytes(bad), .framing)
        }
        wireRefused(httpRequest(body: "x", method: "GET", target: "/api/tags"), .schema)
        var truncated = RequestFramer(limits: .fixture)
        XCTAssertNoThrow(try truncated.receive(Array(httpRequest().dropLast())))
        XCTAssertThrowsError(try truncated.endOfInput())
    }
    func testPipeliningAndPrecedence() {
        wireRefused(httpRequest() + httpRequest(), .extraBytes)
        wireRefused(httpRequest() + [32], .extraBytes)
        wireRefused(httpRequest(target: "/other", extra: "Transfer-Encoding: chunked\r\n"), .framing)
        wireRefused(httpRequest(target: "/other", length: String(GatewayLimits.fixture.body + 1)), .route)
        wireRefused(httpRequest(body: "{}", length: String(GatewayLimits.fixture.body + 1)), .size)
        for target in ["/v1/chat/completions/", "/v1//chat/completions", "/v1/./chat/completions", "/v1/%63hat/completions", "/V1/chat/completions"] {
            wireRefused(httpRequest(target: target), .route)
        }
    }
    func testHeaderAndDeclaredBodyCaps() throws {
        let input = httpRequest()
        let headerCount = input.count - basic.utf8.count
        let exact = try GatewayLimits(body: 256, headers: headerCount, response: 256)
        var framer = RequestFramer(limits: exact)
        XCTAssertNotNil(try framer.receive(input))
        let short = try GatewayLimits(body: 256, headers: headerCount - 1, response: 256)
        wireRefused(input, .framing, limits: short)
        wireRefused(bytes(String(repeating: "x", count: headerCount)), .framing, limits: short)
        let bodyLimit = try GatewayLimits(body: 256, headers: headerCount + 1, response: 256)
        wireRefused(httpRequest(length: "257"), .size, limits: bodyLimit)
    }
    func testFixedWireBytes() throws {
        // Must match FixedResponse/GatewayProtocol in HTTP.swift/Protocol.swift and SEAM.md.
        let names = ["404", "413", "400", "503", "504", "502"]
        let lengths = [76, 84, 88, 74, 82, 82] // G-r2 fixed body lengths, including LF.
        for (i, response) in FixedResponse.allCases.enumerated() {
            let url = Bundle.module.url(forResource: names[i], withExtension: "http", subdirectory: "Fixtures")!
            XCTAssertEqual(response.wire, Array(try Data(contentsOf: url)))
            XCTAssertTrue(String(decoding: response.wire, as: UTF8.self).contains("Content-Length: \(lengths[i])\r\n"))
        }
        XCTAssertEqual(GatewayProtocol.showBody, bytes(#"{"name":"qwen3.5:9b"}"#))
        XCTAssertEqual(GatewayProtocol.showBody.count, 21)
        XCTAssertEqual(GatewayProtocol.done, bytes("data: [DONE]\n\n"))
        XCTAssertEqual(GatewayProtocol.done.count, 14)
        let error = bytes("data: {\"error\":{\"message\":\"Gateway stream truncated\",\"type\":\"gateway_error\",\"code\":\"stream_truncated\"}}\n\n")
        XCTAssertEqual(GatewayProtocol.truncation, error)
        XCTAssertEqual(error.count, 105)
        XCTAssertEqual(chunk(error), bytes("69\r\n") + error + bytes("\r\n"))
    }
}
