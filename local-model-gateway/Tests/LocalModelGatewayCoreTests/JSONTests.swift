import XCTest
@testable import LocalModelGatewayCore

final class JSONTests: XCTestCase {
    func json(_ raw: [UInt8], budget: Int = GatewayLimits.fixture.body) throws -> JSON {
        var parser = StrictJSON(input: raw, budget: budget); return try parser.parse()
    }
    func testStrictSyntaxAndEOF() throws {
        for raw in ["", " ", "{}{}", "{} false", "{}x", "{\"a\":1,}", "[1,]", "/*x*/{}", "//x\n{}", "NaN", "Infinity", "+1", "01", "-01", "1.", ".1", "1e", "1e+", "1e9999", "--1", "[", "{", "[true false]", "tru", "nil", "\u{feff}{}"] {
            XCTAssertThrowsError(try json(bytes(raw)), raw)
        }
        for raw in ["null", "true", "false", "{} \t\r\n", "[]", "-0", "1.00", "1E+2", "1e-300"] {
            _ = try json(bytes(raw))
        }
    }
    func testUnicodeAndEscapes() throws {
        let malformed: [[UInt8]] = [[34, 0xff, 34], [34, 0xc0, 0x80, 34], [34, 0xed, 0xa0, 0x80, 34], [34, 0xf4, 0x90, 0x80, 0x80, 34], [34, 10, 34]]
        for raw in malformed { XCTAssertThrowsError(try json(raw)) }
        for raw in [#""\uD800""#, #""\uDC00""#, #""\uD800\u0041""#, #""\x20""#, #""\uXXXX""#, #""\u123""#] {
            XCTAssertThrowsError(try json(bytes(raw)), raw)
        }
        XCTAssertEqual(try json(bytes(#""\uD83D\uDE00""#)), .string(bytes("😀")))
        let raw = #"{"z":"\u0000\u0001\b\t\n\f\r\/\\\"","e\u0301":1,"é":2}"#
        let value = try json(bytes(raw)); var out: [UInt8] = []; emitJSON(value, into: &out)
        XCTAssertEqual(out, bytes(#"{"é":1,"z":"\u0000\u0001\b\t\n\f\r/\\\"","é":2}"#))
        XCTAssertEqual(try json(out), value)
    }
    func testRecursiveDecodedDuplicates() {
        for raw in [#"{"a":0,"a":1}"#, #"{"a":0,"\u0061":1}"#, #"{"x":[{"a":0,"a":1}]}"#,
                    #"{"a":null,"a":{}}"#, #"{"é":0,"\u00e9":1}"#] {
            XCTAssertThrowsError(try json(bytes(raw))) { XCTAssertEqual($0 as? Refusal, .duplicate) }
        }
        refused(chatField(#""tools":[{"type":"function","function":{"name":"f","parameters":{"a":0,"a":1}}}]"#), .duplicate)
    }
    func testDepthAndNodes() throws {
        let depth = GatewayProtocol.depth
        _ = try json(bytes(String(repeating: "[", count: depth) + String(repeating: "]", count: depth)))
        XCTAssertThrowsError(try json(bytes(String(repeating: "[", count: depth + 1) + String(repeating: "]", count: depth + 1))))
        _ = try json(bytes(String(repeating: "{\"a\":", count: depth) + "0" + String(repeating: "}", count: depth)))
        XCTAssertThrowsError(try json(bytes(String(repeating: "{\"a\":", count: depth + 1) + "0" + String(repeating: "}", count: depth + 1))))
        // Two-byte minimum nodes: [] at B=2 uses exactly N=1; budget 1 has no node allowance.
        _ = try json(bytes("[]"), budget: 2)
        XCTAssertThrowsError(try json(bytes("0"), budget: 1))
        // Explicitly isolate aggregate node enforcement with a preconsumed parser budget.
        var parser = StrictJSON(input: bytes("[0]"), budget: 4, nodes: 1)
        XCTAssertThrowsError(try parser.parse())
    }
    func testPayloadCap() throws {
        XCTAssertEqual(try json(bytes("{}"), budget: 2), .object([]))
        XCTAssertThrowsError(try json(bytes("{} "), budget: 2)) { XCTAssertEqual($0 as? Refusal, .size) }
    }
    func testNumericLexemesSurvive() throws {
        let value = try json(bytes("[1.00,1E+2,-0,1e-300,9007199254740993]"))
        var out: [UInt8] = []; emitJSON(value, into: &out)
        XCTAssertEqual(out, bytes("[1.00,1E+2,-0,1e-300,9007199254740993]"))
    }
}
