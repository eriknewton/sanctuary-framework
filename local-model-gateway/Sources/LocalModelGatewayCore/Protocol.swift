/// Shared wire pins. Must match SEAM.md and WireTests; later slices consume these, never copies.
public enum GatewayProtocol {
    public static let model = Array("qwen3.5:9b".utf8) // B18/B24 runtime tag.
    public static let listenerHost = Array("127.0.0.1:11436".utf8) // B17 listener.
    public static let upstreamHost = Array("127.0.0.1:11434".utf8) // B17 sole destination.
    public static let showBody = Array("{\"name\":\"qwen3.5:9b\"}".utf8) // B18: 21 bytes.
    public static let done = Array("data: [DONE]\n\n".utf8) // G-r2: 14 bytes.
    public static let truncation = Array("data: {\"error\":{\"message\":\"Gateway stream truncated\",\"type\":\"gateway_error\",\"code\":\"stream_truncated\"}}\n\n".utf8) // B27: 105 bytes.
    public static let outputTokens = 65_536 // R:71 output allowance, inserted if absent.
    public static let contextTokens = 131_072 // B28 compatibility input, not runtime proof.
    public static let depth = 64 // G-r2 explicit structural budget.
    public static let identifierBytes = 128 // G-r2 explicit identifier budget.
    static let crlf: [UInt8] = [13, 10] // ASCII CR LF.
    static let headerEnd: [UInt8] = [13, 10, 13, 10] // Empty CRLF line.
}

/// Explicit byte budgets; callers must supply measured production values in later slices.
public struct GatewayLimits: Equatable, Sendable {
    public let body: Int
    public let headers: Int
    public let response: Int
    public var event: Int { body }
    public init(body: Int, headers: Int, response: Int) throws {
        // Half the integer range leaves room to add two independently bounded lengths without overflow.
        guard body > 0, headers > 0, response > 0,
              max(body, headers, response) <= Int.max / 2 else { throw Refusal.size }
        self.body = body; self.headers = headers; self.response = response
    }
    // G-r2 fixture allowances only: 1 MiB body, 64 slots * 256 bytes, 32 MiB response.
    public static let fixture = try! GatewayLimits(body: 1_024 * 1_024, headers: 64 * 256,
                                                   response: 32 * 1_024 * 1_024)
}

/// Closed reasons for later journal consumers. No caller-controlled text is retained.
public enum Refusal: Error, Equatable, Sendable {
    case framing, route, size, syntax, duplicate, caseVariantMember, unknownMember
    case modelLocalitySuffix, modelMismatch, schema, mediaRefused, extraBytes
    case upstreamProtocol
}

/// The single registry for matching and rebuilding the four method/target pairs.
public enum Route: CaseIterable, Sendable {
    case chat, tags, show, models
    public var method: [UInt8] { Array((self == .chat || self == .show ? "POST" : "GET").utf8) }
    public var target: [UInt8] {
        switch self {
        case .chat: Array("/v1/chat/completions".utf8)
        case .tags: Array("/api/tags".utf8)
        case .show: Array("/api/show".utf8)
        case .models: Array("/v1/models".utf8)
        }
    }
    public static func match(method: [UInt8], target: [UInt8]) -> Route? {
        // Raw identity prevents backend path normalization from widening this registry.
        allCases.first { $0.method == method && $0.target == target }
    }
}

/// Probe classifications are exact pairs; wrong methods always remain OTHER.
public enum RefusedTarget: Sendable {
    case none, lmstudioProbe, llamacppV1Props, llamacppProps, vllmVersion, modelsFallback, other
    public static func classify(method: [UInt8], target: [UInt8]) -> Self {
        if Route.match(method: method, target: target) != nil { return .none }
        guard method == bytes("GET") else { return .other }
        let probes: [([UInt8], Self)] = [(bytes("/api/v1/models"), .lmstudioProbe),
            (bytes("/v1/props"), .llamacppV1Props), (bytes("/props"), .llamacppProps),
            (bytes("/version"), .vllmVersion), (bytes("/models"), .modelsFallback)]
        return probes.first { $0.0 == target }?.1 ?? .other
    }
}

func bytes(_ string: String) -> [UInt8] { Array(string.utf8) }
func asciiLower(_ value: [UInt8]) -> [UInt8] {
    value.map { (65...90).contains($0) ? $0 + 32 : $0 } // ASCII A-Z to a-z offset.
}

// Go 1.26 encoding/json foldName: ASCII folding plus the only non-ASCII simple-fold
// cycles reaching ASCII, U+017F long s and U+212A Kelvin sign. Must match RequestTests.testCaseLayers.
func goFold(_ value: [UInt8]) -> [UInt8] {
    var result: [UInt8] = []
    for scalar in String(decoding: value, as: UTF8.self).unicodeScalars {
        switch scalar.value {
        case 0x017f: result.append(115) // long s -> ASCII s
        case 0x212a: result.append(107) // Kelvin -> ASCII k
        default: result += asciiLower(Array(String(scalar).utf8))
        }
    }
    return result
}

// G-r2 defines N = floor(payloadBudget / 2): one minimal scalar byte plus its separator
// amortizes to two bytes. Integer division supplies the floor, shared by node and array checks.
func jsonNodeCap(_ payloadBudget: Int) -> Int { payloadBudget / 2 }
