// Pure request fixtures exercise the schema boundary; no runtime or platform assurance is claimed.
import XCTest
@testable import LocalModelGatewayCore

let basic = #"{"model":"qwen3.5:9b","messages":[{"role":"user","content":"hello"}]}"#
func parse(_ body: String = basic, route: Route = .chat, limits: GatewayLimits = .fixture) throws -> ValidatedRequest {
    try ValidatedRequest.parse(route: route, body: bytes(body), limits: limits)
}
func refused(_ body: String, _ reason: Refusal, route: Route = .chat,
             file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertThrowsError(try parse(body, route: route), file: file, line: line) {
        XCTAssertEqual($0 as? Refusal, reason, body, file: file, line: line)
    }
}
func chatField(_ field: String) -> String { String(basic.dropLast()) + "," + field + "}" }

final class RequestTests: XCTestCase {
    func testRouteRegistry() throws {
        for route in Route.allCases {
            XCTAssertEqual(Route.match(method: route.method, target: route.target), route)
            let body = route == .chat ? basic : route == .show ? #"{"name":"qwen3.5:9b"}"# : ""
            let request = try parse(body, route: route)
            XCTAssertTrue(RequestSerializer.http(request, authorization: .placeholder).starts(with: route.method + bytes(" ") + route.target))
        }
        let denied = ["/", "/api/version", "/api/status", "/api/pull", "/api/push", "/api/delete", "/api/me", "/api/signout",
                      "/api/user/keys/key", "/api/create", "/api/blobs/digest", "/api/copy", "/api/experimental/web_search",
                      "/api/experimental/web_fetch", "/api/experimental/model-recommendations", "/api/ps", "/api/generate",
                      "/api/chat", "/api/embed", "/api/embeddings", "/v1/completions", "/v1/embeddings", "/v1/models/qwen3.5:9b",
                      "/v1/responses", "/v1/audio/transcriptions", "/v1/messages", "/api/v1/models/load", "/unknown"]
        for path in denied { for method in ["GET", "HEAD", "POST", "DELETE", "OPTIONS", "PUT", "PATCH", "CONNECT", "TRACE"] {
            XCTAssertNil(Route.match(method: bytes(method), target: bytes(path)), method + path)
        } }
        for route in Route.allCases {
            let path = String(decoding: route.target, as: UTF8.self)
            let variants = [path + "/", "/" + path, path + "?q=1", path + "#fragment", "/./" + path.dropFirst(),
                            "/x/../" + path.dropFirst(), path.replacingOccurrences(of: "/", with: "%2F"),
                            path.replacingOccurrences(of: "/", with: "//"), path.uppercased(), "http://127.0.0.1:11436" + path]
            for target in variants { XCTAssertNil(Route.match(method: route.method, target: bytes(target)), target) }
            for method in ["GET", "POST", "HEAD", "OPTIONS", "PUT", "post"] where bytes(method) != route.method {
                XCTAssertNil(Route.match(method: bytes(method), target: route.target))
            }
        }
        XCTAssertEqual(RefusedTarget.classify(method: bytes("GET"), target: bytes("/models")), .modelsFallback)
        let probes: [(String, RefusedTarget)] = [("/api/v1/models", .lmstudioProbe), ("/v1/props", .llamacppV1Props),
            ("/props", .llamacppProps), ("/version", .vllmVersion)]
        for (path, classification) in probes {
            XCTAssertEqual(RefusedTarget.classify(method: bytes("GET"), target: bytes(path)), classification)
            XCTAssertEqual(RefusedTarget.classify(method: bytes("POST"), target: bytes(path)), .other)
        }
        XCTAssertEqual(RefusedTarget.classify(method: Route.chat.method, target: Route.chat.target), .none)
        XCTAssertEqual(RefusedTarget.classify(method: bytes("GET"), target: bytes("/unknown")), .other)
    }
    func testCaseLayers() {
        // Must match goFold's Go 1.26 ASCII-reaching fold cycles in Protocol.swift.
        for key in ["Model", "MODEL", #"\u004dodel"#] {
            for fields in [#""model":"qwen3.5:9b","\#(key)":"qwen3.5:cloud""#,
                           #""\#(key)":"qwen3.5:cloud","model":"qwen3.5:9b""#] {
                refused("{" + fields + #","messages":[{"role":"user","content":"hello"}]}"#, .caseVariantMember)
            }
        }
        for field in [#""ſtream":true"#, #""thinK":false"#, #""STReam":true"#] { refused(chatField(field), .caseVariantMember) }
        refused(#"{"Name":"qwen3.5:9b"}"#, .caseVariantMember, route: .show)
        refused(chatField(#""tools":[{"type":"function","function":{"Name":"f","parameters":{}}}]"#), .caseVariantMember)
        for fields in [#""model":"qwen3.5:9b","model":"qwen3.5:cloud""#,
                       #""model":"qwen3.5:cloud","model":"qwen3.5:9b""#,
                       #""model":"qwen3.5:9b","mo\u0064el":"qwen3.5:cloud""#] {
            refused("{" + fields + #","messages":[{"role":"user","content":"hello"}]}"#, .duplicate)
        }
        // Case refusal precedes unknown fields even when the unknown appears at an earlier level.
        refused(chatField(#""unknown":0,"options":{"NUM_CTX":131072}"#), .caseVariantMember)
    }
    func testUnknownMembers() {
        for field in ["stop", "functions", "function_call", "max_completion_tokens", "reasoning_effort", "response_format", "name", "extra_body", "seed", "tool_choice"] {
            refused(chatField("\"\(field)\":null"), .unknownMember)
        }
        refused(chatField(#""options":{"num_ctx":131072,"other":0}"#), .unknownMember)
        refused(chatField(#""stream":true,"stream_options":{"include_usage":true,"other":0}"#), .unknownMember)
        refused(#"{"model":"qwen3.5:9b","messages":[{"role":"user","content":"x","extra":0}]}"#, .unknownMember)
    }
    func testModelSuffixLayer() {
        for suffix in [":cloud", ":CLOUD", ":cLoUd", "-cloud", "-ClOuD", ":local", ":LOCAL"] {
            for route in [Route.chat, .show] {
                let body = route == .chat ? basic.replacingOccurrences(of: "qwen3.5:9b", with: "qwen3.5" + suffix)
                    : "{\"name\":\"qwen3.5\(suffix)\"}"
                refused(body, .modelLocalitySuffix, route: route)
            }
        }
    }
    func testModelEqualityLayer() {
        for model in ["", "other:9b", "QWEN3.5:9b", "qwen3.5:9b ", "host/ns/qwen3.5:9b", "registry.ollama.ai/library/qwen3.5:9b", "qwen3.5"] {
            refused(basic.replacingOccurrences(of: "qwen3.5:9b", with: model), .modelMismatch)
            refused("{\"name\":\"\(model)\"}", .modelMismatch, route: .show)
        }
    }
    func testShowVariants() throws {
        XCTAssertEqual(RequestSerializer.body(try parse(" \n{\"na\\u006de\" : \"qwen3.5:9b\"}\t", route: .show)), GatewayProtocol.showBody)
        for body in [#"{"model":"qwen3.5:9b"}"#, #"{"name":"qwen3.5:9b","model":"qwen3.5:cloud"}"#,
                     #"{"name":"qwen3.5:9b","options":{}}"#, #"{"name":"qwen3.5:9b","system":"x"}"#,
                     #"{"name":"qwen3.5:9b","template":"x"}"#, #"{"name":"qwen3.5:9b","verbose":true}"#] {
            refused(body, .unknownMember, route: .show)
        }
        for body in ["{}", #"{"name":null}"#, #"{"name":1}"#, "[]"] { refused(body, .schema, route: .show) }
        refused(#"{"name":"qwen3.5:9b","name":"qwen3.5:cloud"}"#, .duplicate, route: .show)
        refused(#"{"name":"qwen3.5:9b"}{}"#, .syntax, route: .show)
    }
    func testAllowedShapesAndRoundTrip() throws {
        let fixture = try String(contentsOf: Bundle.module.url(forResource: "allowed-chat", withExtension: "json", subdirectory: "Fixtures")!, encoding: .utf8)
        for body in [basic, chatField(#""stream":true,"stream_options":{"include_usage":true}"#), fixture,
                     chatField(#""temperature":2e0,"max_tokens":1,"tools":[],"think":false,"options":{"num_ctx":131072}"#)] {
            let first = try parse(body)
            let canonical = RequestSerializer.body(first)
            XCTAssertEqual(try ValidatedRequest.parse(route: .chat, body: canonical, limits: .fixture), first)
            XCTAssertFalse(canonical.last == 10)
        }
        let canonical = RequestSerializer.body(try parse())
        XCTAssertEqual(canonical, bytes(#"{"max_tokens":65536,"messages":[{"content":"hello","role":"user"}],"model":"qwen3.5:9b","stream":false}"#))
    }
    func testSchemaTypesAndRoles() throws {
        for field in [#""stream":1"#, #""stream_options":{"include_usage":true}"#, #""stream":false,"stream_options":{}"#,
                      #""stream":true,"stream_options":{"include_usage":1}"#, #""options":{}"#, #""options":{"num_ctx":1}"#,
                      #""options":{"num_ctx":131072.0}"#, #""think":true"#, #""tools":null"#, #""tools":[null]"#,
                      #""tools":[{"type":"function","function":{"name":"f","parameters":[]}}]"#,
                      #""tools":[{"type":"function","function":{"name":"f","parameters":{},"strict":1}}]"#] {
            refused(chatField(field), .schema)
        }
        for messages in ["null", "[]", "[null]", #"[{"role":"other","content":"x"}]"#,
                         #"[{"role":"user"}]"#, #"[{"role":"assistant","content":null}]"#,
                         #"[{"role":"assistant","content":null,"tool_calls":[]}]"#,
                         #"[{"role":"user","content":"x","reasoning":"r"}]"#,
                         #"[{"role":"user","content":"x","tool_call_id":"id"}]"#,
                         #"[{"role":"user","content":"x","tool_calls":[]}]"#,
                         #"[{"role":"tool","content":"x"}]"#,
                         #"[{"role":"assistant","content":"x","tool_calls":[null]}]"#,
                         #"[{"role":"assistant","content":"x","tool_calls":[{"id":"i","type":"function","function":{"name":"f","arguments":{}}}]}]"#] {
            refused(#"{"model":"qwen3.5:9b","messages":\#(messages)}"#, .schema)
        }
        for role in ["system", "developer", "user", "assistant"] {
            _ = try parse(#"{"model":"qwen3.5:9b","messages":[{"role":"\#(role)","content":[] }]}"#)
        }
        for count in [0, GatewayProtocol.identifierBytes + 1] {
            refused(#"{"model":"qwen3.5:9b","messages":[{"role":"user","content":"x","name":"\#(String(repeating:"a",count:count))"}]}"#, .schema)
        }
        _ = try parse(#"{"model":"qwen3.5:9b","messages":[{"role":"user","content":"x","name":"\#(String(repeating:"a",count:GatewayProtocol.identifierBytes))"}]}"#)
    }
    func testMediaRefusal() throws {
        let fixtures = try String(contentsOf: Bundle.module.url(forResource: "media-data", withExtension: "txt", subdirectory: "Fixtures")!, encoding: .utf8).split(separator: "\n").map(String.init)
        for type in ["image_url", "video_url", "input_audio", "audio", "other"] {
            for data in fixtures + ["https://example.invalid/image"] {
                refused(#"{"model":"qwen3.5:9b","messages":[{"role":"user","content":[{"type":"\#(type)","\#(type)":{"url":"\#(data)"}}]}]}"#, .mediaRefused)
            }
        }
        refused(#"{"model":"qwen3.5:9b","messages":[{"role":"user","content":[null]}]}"#, .mediaRefused)
    }
    func testNumericFieldRanges() throws {
        for number in ["0", "-1", "65537", "1.0", "1e0", "true", "null", "\"1\"", "9223372036854775808"] {
            refused(chatField("\"max_tokens\":\(number)"), .schema)
        }
        for number in ["-0.1", "2.0000001", "true", "null", "\"1\""] { refused(chatField("\"temperature\":\(number)"), .schema) }
        for number in ["0", "-0", "2", "2e0", "1e-300"] { _ = try parse(chatField("\"temperature\":\(number)")) }
        for number in ["1", "65536"] { _ = try parse(chatField("\"max_tokens\":\(number)")) }
    }
    func testNoCanonicalBytesForRejectedModel() throws {
        // Pure G1 zero-byte oracle: failed parsing cannot issue any serializer input.
        for body in [basic.replacingOccurrences(of: "qwen3.5:9b", with: "qwen3.5:cloud"),
                     chatField(#""Model":"qwen3.5:cloud""#)] {
            var emitted: [UInt8] = []
            if let request = try? parse(body) { emitted = RequestSerializer.http(request, authorization: .placeholder) }
            XCTAssertEqual(emitted, [])
        }
    }
    func testBodyAndRebuildBudgets() throws {
        let output = RequestSerializer.body(try parse())
        let exact = try GatewayLimits(body: output.count, headers: 256, response: 256)
        _ = try ValidatedRequest.parse(route: .chat, body: output, limits: exact)
        let short = try GatewayLimits(body: output.count - 1, headers: 256, response: 256)
        XCTAssertThrowsError(try ValidatedRequest.parse(route: .chat, body: output, limits: short)) { XCTAssertEqual($0 as? Refusal, .size) }
        // Input fits, inserted defaults do not: isolates the canonical-output cap.
        XCTAssertThrowsError(try parse(limits: short)) { XCTAssertEqual($0 as? Refusal, .size) }
        for route in [Route.tags, .models] { refused(" ", .schema, route: route) }
        let small = try GatewayLimits(body: 2, headers: 256, response: 256)
        // GET bypasses the JSON parser, isolating the outer body cap from the JSON cap.
        XCTAssertThrowsError(try ValidatedRequest.parse(route: .tags, body: bytes("   "), limits: small)) {
            XCTAssertEqual($0 as? Refusal, .size)
        }
        for size in [0, -1, Int.max] {
            XCTAssertThrowsError(try GatewayLimits(body: size, headers: 1, response: 1))
            XCTAssertThrowsError(try GatewayLimits(body: 1, headers: size, response: 1))
            XCTAssertThrowsError(try GatewayLimits(body: 1, headers: 1, response: size))
        }
    }
}
