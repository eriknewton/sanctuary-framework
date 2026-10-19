// A JSON string is decoded UTF-8 bytes, never Swift's normalization-aware String identity.
indirect enum JSON: Equatable, Sendable {
    case object([Member]), array([JSON]), string([UInt8]), number([UInt8]), bool(Bool), null
    struct Member: Equatable, Sendable { let key: [UInt8]; let value: JSON }
    var members: [Member]? { if case .object(let m) = self { m } else { nil } }
    var elements: [JSON]? { if case .array(let a) = self { a } else { nil } }
    var string: [UInt8]? { if case .string(let s) = self { s } else { nil } }
    subscript(_ name: String) -> JSON? { members?.first { $0.key == bytes(name) }?.value }
}

struct StrictJSON {
    let input: [UInt8]
    let budget: Int
    var offset = 0
    var nodes = 0
    mutating func parse() throws -> JSON {
        guard input.count <= budget else { throw Refusal.size }
        let value = try value(depth: 0)
        whitespace()
        // A valid first value never authorizes an unchecked second value or trailing garbage.
        guard offset == input.count else { throw Refusal.syntax }
        return value
    }
    mutating func whitespace() {
        while offset < input.count && [9, 10, 13, 32].contains(input[offset]) { offset += 1 }
    }
    mutating func take(_ byte: UInt8) -> Bool {
        if offset < input.count && input[offset] == byte { offset += 1; return true }; return false
    }
    mutating func require(_ byte: UInt8) throws { guard take(byte) else { throw Refusal.syntax } }
    mutating func value(depth: Int) throws -> JSON {
        whitespace(); nodes += 1
        // Counting every value and key bounds aggregate work as well as recursion.
        guard nodes <= budget / 2, depth <= GatewayProtocol.depth, offset < input.count else {
            throw Refusal.syntax
        }
        switch input[offset] {
        case 123: // {
            guard depth < GatewayProtocol.depth else { throw Refusal.syntax }
            offset += 1; whitespace()
            var members: [JSON.Member] = []; var keys = Set<[UInt8]>()
            if take(125) { return .object(members) }
            repeat {
                whitespace(); let key = try string(); nodes += 1
                guard nodes <= budget / 2 else { throw Refusal.syntax }
                // Decoded byte identity catches escaped duplicates without merging distinct Unicode names.
                guard keys.insert(key).inserted else { throw Refusal.duplicate }
                whitespace(); try require(58)
                members.append(.init(key: key, value: try value(depth: depth + 1))); whitespace()
            } while take(44)
            try require(125)
            return .object(members.sorted { $0.key.lexicographicallyPrecedes($1.key) })
        case 91: // [
            guard depth < GatewayProtocol.depth else { throw Refusal.syntax }
            offset += 1; whitespace(); var values: [JSON] = []
            if take(93) { return .array(values) }
            repeat { values.append(try value(depth: depth + 1)); whitespace() } while take(44)
            try require(93); return .array(values)
        case 34: return .string(try string())
        case 116: try literal("true"); return .bool(true)
        case 102: try literal("false"); return .bool(false)
        case 110: try literal("null"); return .null
        default: return .number(try number())
        }
    }
    mutating func literal(_ text: String) throws {
        for b in text.utf8 { try require(b) }
    }
    mutating func string() throws -> [UInt8] {
        try require(34); var result: [UInt8] = []
        while offset < input.count {
            let b = input[offset]; offset += 1
            if b == 34 {
                // String is used only as a UTF-8 validity check, never as a key or ordering operation.
                guard Array(String(decoding: result, as: UTF8.self).utf8) == result else { throw Refusal.syntax }
                return result
            }
            guard b >= 32 else { throw Refusal.syntax } // JSON excludes unescaped C0 controls.
            if b != 92 { result.append(b); continue }
            guard offset < input.count else { throw Refusal.syntax }
            let escape = input[offset]; offset += 1
            switch escape {
            case 34, 47, 92: result.append(escape)
            case 98: result.append(8)
            case 102: result.append(12)
            case 110: result.append(10)
            case 114: result.append(13)
            case 116: result.append(9)
            case 117:
                var scalar = try hexQuad()
                if (0xd800...0xdbff).contains(scalar) {
                    try require(92); try require(117); let low = try hexQuad()
                    guard (0xdc00...0xdfff).contains(low) else { throw Refusal.syntax }
                    // UTF-16 surrogate pair formula from Unicode: 10 low bits per code unit.
                    scalar = 0x10000 + ((scalar - 0xd800) << 10) + low - 0xdc00
                }
                guard let unicode = Unicode.Scalar(scalar) else { throw Refusal.syntax }
                result += String(unicode).utf8
            default: throw Refusal.syntax
            }
        }
        throw Refusal.syntax
    }
    mutating func hexQuad() throws -> UInt32 {
        var value: UInt32 = 0
        for _ in 0..<4 { // JSON \u escapes contain exactly four hexadecimal digits.
            guard offset < input.count, let digit = hexDigit(input[offset]) else { throw Refusal.syntax }
            value = value * 16 + UInt32(digit); offset += 1 // Base 16.
        }
        return value
    }
    mutating func number() throws -> [UInt8] {
        let start = offset; _ = take(45)
        if !take(48) {
            guard offset < input.count, (49...57).contains(input[offset]) else { throw Refusal.syntax }
            digits()
        }
        if take(46) { try someDigits() }
        if take(101) || take(69) { if !take(43) { _ = take(45) }; try someDigits() }
        let lexeme = Array(input[start..<offset])
        // Validation uses binary64 but emission preserves the original validated lexeme.
        guard let number = Double(String(decoding: lexeme, as: UTF8.self)), number.isFinite else {
            throw Refusal.syntax
        }
        return lexeme
    }
    mutating func digits() { while offset < input.count && (48...57).contains(input[offset]) { offset += 1 } }
    mutating func someDigits() throws {
        let start = offset; digits(); guard start != offset else { throw Refusal.syntax }
    }
}

func hexDigit(_ byte: UInt8) -> Int? {
    switch byte {
    case 48...57: Int(byte - 48) // ASCII decimal digits.
    case 65...70: Int(byte - 65) + 10 // A-F.
    case 97...102: Int(byte - 97) + 10 // a-f.
    default: nil
    }
}

func emitJSON(_ value: JSON, into out: inout [UInt8]) {
    switch value {
    case .null: out += bytes("null")
    case .bool(let b): out += bytes(b ? "true" : "false")
    case .number(let n): out += n
    case .string(let s):
        out.append(34)
        for b in s {
            switch b {
            case 34, 92: out += [92, b]
            case 8: out += bytes("\\b")
            case 9: out += bytes("\\t")
            case 10: out += bytes("\\n")
            case 12: out += bytes("\\f")
            case 13: out += bytes("\\r")
            case 0..<32:
                let hex = bytes("0123456789abcdef")
                out += bytes("\\u00") + [hex[Int(b) / 16], hex[Int(b) % 16]]
            default: out.append(b)
            }
        }
        out.append(34)
    case .array(let a):
        out.append(91)
        for (i, v) in a.enumerated() { if i > 0 { out.append(44) }; emitJSON(v, into: &out) }
        out.append(93)
    case .object(let members):
        out.append(123)
        for (i, m) in members.sorted(by: { $0.key.lexicographicallyPrecedes($1.key) }).enumerated() {
            if i > 0 { out.append(44) }; emitJSON(.string(m.key), into: &out)
            out.append(58); emitJSON(m.value, into: &out)
        }
        out.append(125)
    }
}
