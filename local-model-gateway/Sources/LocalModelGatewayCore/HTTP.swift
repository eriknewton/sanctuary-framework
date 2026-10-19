struct Header: Sendable { let name: [UInt8]; let value: [UInt8] }
struct HeaderBlock {
    let first: [UInt8]
    let fields: [Header]
    init(_ bytes: [UInt8]) throws {
        let lines = try splitCRLF(bytes)
        guard let first = lines.first, !first.isEmpty else { throw Refusal.framing }
        self.first = first
        var fields: [Header] = []
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: 58), colon > 0,
                  line[..<colon].allSatisfy(isToken), colon + 1 < line.count, line[colon + 1] == 32 else {
                throw Refusal.framing
            }
            let value = Array(line.dropFirst(colon + 2)) // Colon and exactly one conventional SP.
            // Controls and obs-fold cannot create a second interpretation of a header boundary.
            guard value.allSatisfy({ $0 >= 32 && $0 < 127 }) else { throw Refusal.framing }
            fields.append(Header(name: asciiLower(Array(line[..<colon])), value: value))
        }
        self.fields = fields
    }
    func one(_ name: String) throws -> [UInt8]? {
        let matches = fields.filter { $0.name == bytes(name) }
        guard matches.count <= 1 else { throw Refusal.framing }
        return matches.first?.value
    }
    func forbid(_ names: [String]) throws {
        guard !fields.contains(where: { names.map(bytes).contains($0.name) }) else { throw Refusal.framing }
    }
}

func isToken(_ b: UInt8) -> Bool {
    (48...57).contains(b) || (65...90).contains(b) || (97...122).contains(b)
        || bytes("!#$%&'*+-.^_`|~").contains(b)
}
func splitCRLF(_ input: [UInt8]) throws -> [[UInt8]] {
    var result: [[UInt8]] = []; var current: [UInt8] = []; var i = 0
    while i < input.count {
        if input[i] == 13 {
            guard i + 1 < input.count, input[i + 1] == 10 else { throw Refusal.framing }
            result.append(current); current = []; i += 2
        } else {
            guard input[i] != 10 else { throw Refusal.framing }
            current.append(input[i]); i += 1
        }
    }
    result.append(current); return result
}
func decimalLength(_ raw: [UInt8]) throws -> Int {
    guard !raw.isEmpty, raw.allSatisfy({ (48...57).contains($0) }),
          raw.count == 1 || raw.first != 48 else { throw Refusal.framing }
    var n = 0
    for digit in raw {
        let (multiplied, a) = n.multipliedReportingOverflow(by: 10) // Decimal radix.
        let (added, b) = multiplied.addingReportingOverflow(Int(digit - 48))
        guard !a, !b else { throw Refusal.framing }; n = added
    }
    return n
}

/// One connection's pure request framing state. A refusal or completed request is absorbing.
public struct RequestFramer: Sendable {
    private enum State: Sendable { case headers, body, complete, refused }
    private var state = State.headers
    private var header: [UInt8] = [], body: [UInt8] = []
    private var route: Route?, length = 0
    private let limits: GatewayLimits
    /// Closed probe classification for G3; arbitrary target bytes never become journal text.
    public private(set) var refusedTarget = RefusedTarget.other
    public init(limits: GatewayLimits) { self.limits = limits }
    /// Returns nil until complete. Buffered extra bytes refuse before any request escapes.
    public mutating func receive(_ input: [UInt8]) throws -> ValidatedRequest? {
        do {
            for byte in input {
                switch state {
                case .headers:
                    // Check before append so an unterminated header never exceeds H retained bytes.
                    guard header.count < limits.headers else { throw Refusal.framing }
                    header.append(byte)
                    if header.suffix(GatewayProtocol.headerEnd.count).elementsEqual(GatewayProtocol.headerEnd) {
                        try parseHeaders(); header = []
                        state = length == 0 ? .complete : .body
                    }
                case .body:
                    body.append(byte)
                    if body.count == length { state = .complete }
                case .complete, .refused: throw Refusal.extraBytes
                }
            }
            if state == .complete {
                // Only the shared schema can issue the serializer's input type.
                let request = try ValidatedRequest.parse(route: route!, body: body, limits: limits)
                state = .refused; body = []; return request
            }
            return nil
        } catch { state = .refused; header = []; body = []; throw error }
    }
    /// EOF before the declared body is complete is a framing refusal, never a partial request.
    public mutating func endOfInput() throws {
        guard state == .refused else { state = .refused; throw Refusal.framing }
    }
    private mutating func parseHeaders() throws {
        let block = try HeaderBlock(Array(header.dropLast(GatewayProtocol.headerEnd.count)))
        let words = block.first.split(separator: 32, omittingEmptySubsequences: false).map(Array.init)
        guard words.count == 3, !words[0].isEmpty, words[0].allSatisfy(isToken),
              !words[1].isEmpty, words[1].allSatisfy({ $0 > 32 && $0 < 127 }),
              words[2] == bytes("HTTP/1.1") else { throw Refusal.framing }
        try block.forbid(["transfer-encoding", "content-encoding", "expect", "upgrade", "trailer"])
        guard try block.one("host") == GatewayProtocol.listenerHost else { throw Refusal.framing }
        let declared = try block.one("content-length")
        if words[0] == bytes("POST") && declared == nil { throw Refusal.framing }
        length = try declared.map(decimalLength) ?? 0
        // Framing is established before route, and route before declared-size disposition.
        refusedTarget = RefusedTarget.classify(method: words[0], target: words[1])
        guard let matched = Route.match(method: words[0], target: words[1]) else { throw Refusal.route }
        route = matched
        guard length <= limits.body else { throw Refusal.size }
        if matched == .tags || matched == .models { guard length == 0 else { throw Refusal.schema } }
    }
}

/// Fixed wire responses shared with later runtime refusal/drain machinery. Must match WireTests/SEAM.md.
public enum FixedResponse: CaseIterable, Sendable {
    case notFound, tooLarge, invalidRequest, busy, deadline, upstream
    public var wire: [UInt8] {
        let status: String, message: String, code: String
        switch self {
        case .notFound: (status, message, code) = ("404 Not Found", "Not found", "not_found")
        case .tooLarge: (status, message, code) = ("413 Content Too Large", "Request too large", "too_large")
        case .invalidRequest: (status, message, code) = ("400 Bad Request", "Invalid request", "invalid_request")
        case .busy: (status, message, code) = ("503 Service Unavailable", "Gateway busy", "busy")
        case .deadline: (status, message, code) = ("504 Gateway Timeout", "Gateway deadline", "deadline")
        case .upstream: (status, message, code) = ("502 Bad Gateway", "Upstream failure", "upstream")
        }
        let body = bytes("{\"error\":{\"message\":\"\(message)\",\"type\":\"gateway_error\",\"code\":\"\(code)\"}}\n")
        return bytes("HTTP/1.1 \(status)\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n") + body
    }
}

func chunk(_ bytes: [UInt8]) -> [UInt8] {
    Array(String(bytes.count, radix: 16).utf8) + GatewayProtocol.crlf + bytes + GatewayProtocol.crlf
}
