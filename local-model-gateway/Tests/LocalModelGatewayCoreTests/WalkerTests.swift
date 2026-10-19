// Closed protocol objects and bounded traversal are pure parser properties, not runtime assurance.
import XCTest
@testable import LocalModelGatewayCore

final class WalkerTests: XCTestCase {
    struct Fixture {
        let kind: ObjectKind, fields: String, wrap: (String) -> String
        var route: Route { kind == .show ? .show : .chat }
        func body(extra: String = "") -> String { wrap("{" + fields + extra + "}") }
    }
    // Must cover every ObjectKind in Request.swift; parameters deliberately remain opaque data.
    var fixtures: [Fixture] {
        let message: (String) -> String = { #"{"model":"qwen3.5:9b","messages":[\#($0)]}"# }
        let part: (String) -> String = { message(#"{"role":"user","content":[\#($0)]}"#) }
        let call: (String) -> String = { message(#"{"role":"assistant","content":null,"tool_calls":[\#($0)]}"#) }
        let tool: (String) -> String = { chatField(#""tools":[\#($0)]"#) }
        return [
            .init(kind: .chat, fields: String(basic.dropFirst().dropLast()), wrap: { $0 }),
            .init(kind: .show, fields: #""name":"qwen3.5:9b""#, wrap: { $0 }),
            .init(kind: .message, fields: #""role":"user","content":"x""#, wrap: message),
            .init(kind: .part, fields: #""type":"text","text":"x""#, wrap: part),
            .init(kind: .call, fields: #""id":"i","type":"function","function":{"name":"f","arguments":"{}"}"#, wrap: call),
            .init(kind: .callFunction, fields: #""name":"f","arguments":"{}""#,
                  wrap: { call(#"{"id":"i","type":"function","function":\#($0)}"#) }),
            .init(kind: .tool, fields: #""type":"function","function":{"name":"f","parameters":{}}"#, wrap: tool),
            .init(kind: .toolFunction, fields: #""name":"f","parameters":{}"#,
                  wrap: { tool(#"{"type":"function","function":\#($0)}"#) }),
            .init(kind: .options, fields: #""num_ctx":131072"#, wrap: { chatField(#""options":\#($0)"#) }),
            .init(kind: .streamOptions, fields: #""include_usage":true"#,
                  wrap: { chatField(#""stream":true,"stream_options":\#($0)"#) })
        ]
    }
    func testEveryObjectMemberClosure() throws {
        XCTAssertEqual(Set(fixtures.map(\.kind)), Set(ObjectKind.allCases))
        for fixture in fixtures {
            _ = try parse(fixture.body(), route: fixture.route)
            refused(fixture.body(extra: #", "extra":0"#), .unknownMember, route: fixture.route)
            for field in fixture.kind.fields {
                refused(fixture.body(extra: ",\"\(field.uppercased())\":0"), .caseVariantMember, route: fixture.route)
                for (ascii, folded) in [("s", "ſ"), ("k", "K")] where field.contains(ascii) {
                    let variant = field.replacingOccurrences(of: ascii, with: folded)
                    refused(fixture.body(extra: ",\"\(variant)\":0"), .caseVariantMember, route: fixture.route)
                }
            }
        }
    }
    func testUsageRequired() {
        refused(chatField(#""stream":true,"stream_options":{}"#), .schema)
    }
    func testOpaqueParametersRebuild() throws {
        let request = try parse(chatField(#""tools":[{"type":"function","function":{"name":"f","parameters":{"Type":1,"type":2,"ſ":3,"s":4,"K":5,"k":6,"e\u0301":7,"é":8}}}]"#))
        let canonical = RequestSerializer.body(request)
        XCTAssertTrue(String(decoding: canonical, as: UTF8.self).contains(#""parameters":{"Type":1,"é":7,"k":6,"s":4,"type":2,"é":8,"ſ":3,"K":5}"#))
        XCTAssertEqual(try ValidatedRequest.parse(route: .chat, body: canonical, limits: .fixture), request)
    }
    func testAdversarialLinearTraversal() throws {
        // Must match the complexity contract in SEAM.md. G-r2 fixture work budget is 120 s;
        // reserve at most 1/30 for parsing, hence 4 s, well below its 121 s total with reserve.
        let fixtureWorkSeconds = 120.0
        let parseShare = 30.0
        let maximumParseSeconds = fixtureWorkSeconds / parseShare
        // Doubling linear work costs 2; allow another 50% for sorting and debug scheduling.
        let doublingFactor = 2.0 * 1.5
        let repetitions = 3 // Median of three excludes a single scheduler interruption.
        let probeMembers = 2_000 // Small early probe keeps a quadratic mutation bounded before max-B.
        let budget = GatewayLimits.fixture.body
        for fixture in fixtures where [.part, .message, .tool, .call].contains(fixture.kind) {
            // Base-36 keys are a fixed dense vocabulary; no key matches this object's protocol fields.
            var members: [String] = [], used = fixture.wrap("{}").utf8.count, index = 0
            while true {
                let key = String(index, radix: 36); index += 1
                if fixture.kind.fields.contains(key) { continue }
                let member = "\"\(key)\":0"
                let cost = member.utf8.count + (members.isEmpty ? 0 : 1)
                if used + cost > budget { break }
                members.append(member); used += cost
            }
            // Maximum member count for this vocabulary and wrapper: the next member cannot fit.
            XCTAssertGreaterThan(used + "\"\(String(index - 1, radix: 36))\":0".utf8.count + 1, budget)
            func body(_ count: Int, pad: Bool = false) -> [UInt8] {
                var result = bytes(fixture.wrap("{" + members.prefix(count).joined(separator: ",") + "}"))
                if pad { result += Array(repeating: 32, count: budget - result.count) }
                return result
            }
            func measure(_ input: [UInt8]) -> Double {
                var samples: [Double] = []
                for _ in 0..<repetitions {
                    let start = DispatchTime.now().uptimeNanoseconds
                    XCTAssertThrowsError(try ValidatedRequest.parse(route: .chat, body: input, limits: .fixture)) {
                        XCTAssertEqual($0 as? Refusal, fixture.kind == .part ? .mediaRefused : .unknownMember)
                    }
                    samples.append(Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000) // ns per second.
                }
                return samples.sorted()[repetitions / 2]
            }
            let probeN = measure(body(probeMembers)), probe2N = measure(body(probeMembers * 2))
            print("complexity probe \(fixture.kind): N=\(probeMembers), seconds=\(probeN), 2N=\(probe2N)")
            XCTAssertLessThan(probe2N, maximumParseSeconds)
            XCTAssertLessThan(probe2N / probeN, doublingFactor)
            // A failed probe stops the large case so a planted quadratic walker cannot monopolize CI.
            guard probe2N < maximumParseSeconds, probe2N / probeN < doublingFactor else { return }
            let n = members.count / 2
            let small = measure(body(n)), large = measure(body(n * 2))
            let maximum = body(members.count, pad: true)
            XCTAssertEqual(maximum.count, budget)
            let elapsed = measure(maximum)
            print("complexity max \(fixture.kind): members=\(members.count), bytes=\(maximum.count), N=\(small), 2N=\(large), max=\(elapsed)")
            XCTAssertLessThan(elapsed, maximumParseSeconds)
            XCTAssertLessThan(large / small, doublingFactor)
        }
    }
}
