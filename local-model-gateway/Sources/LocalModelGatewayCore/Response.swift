/// Bounded response diagnostics for per-layer witnesses; no upstream content is retained.
public enum ResponseFailure: Error, Equatable, Sendable { case protocolViolation, falseDone, invalidEventJSON }

/// Explicit terminal cause; deadlines have distinct pre-commit HTTP semantics.
public enum ResponseFailureCause: Sendable { case deadline, reset, protocolViolation }

/// Pure upstream HTTP/SSE decoder. Feed one byte only after draining the prior returned output.
/// This keeps the output queue at one event; socket ownership and deadlines belong to G2.
public struct ResponseFramer: Sendable {
    private enum State: Sendable { case headers, length, closeBody, chunkSize, chunkBody, chunkCR, chunkLF, endCR, endLF, framedEnd, closed }
    private var state = State.headers
    private let streaming: Bool, limits: GatewayLimits
    private var header: [UInt8] = [], body: [UInt8] = [], event: [UInt8] = [], sizeLine: [UInt8] = []
    private var remaining = 0, received = 0, status = 0
    private var committed = false, sse = false, sawDone = false
    public private(set) var failure: ResponseFailure?
    /// The runtime closes after draining the final segment; a closed parser never revives.
    public var isClosed: Bool { state == .closed }
    /// Commitment determines whether a failure returns a fixed HTTP response or a B27 chunk.
    public var isStreamingCommitted: Bool { committed }
    public init(request: ValidatedRequest, limits: GatewayLimits) {
        streaming = request.streaming; self.limits = limits
    }
    /// Returns a bounded output segment. Once closed, later completions cannot produce bytes.
    public mutating func receive(_ byte: UInt8) -> [UInt8] {
        guard state != .closed else { return [] }
        do { return try step(byte) } catch {
            failure = (error as? ResponseFailure) ?? .protocolViolation; return fail(cause: .protocolViolation)
        }
    }
    /// Must be called only for genuine transport EOF, never a timeout/reset. Holds DONE until here.
    public mutating func endOfInput() -> [UInt8] {
        guard state != .closed else { return [] }
        guard state == .framedEnd || state == .closeBody else { return fail(cause: .protocolViolation) }
        if sse {
            // HTTP termination and exact DONE are both required; finish_reason alone is not completion.
            guard sawDone, event.isEmpty else { return fail(cause: .protocolViolation) }
            state = .closed
            return chunk(GatewayProtocol.done) + bytes("0\r\n\r\n")
        }
        do {
            var parser = StrictJSON(input: body, budget: limits.response)
            _ = try parser.parse()
            state = .closed
            // Regenerated framing cannot propagate Location, cookies or upstream credentials.
            let reason = status == 200 ? "OK" : "Upstream Error"
            return bytes("HTTP/1.1 \(status) \(reason)\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n") + body
        } catch { return fail(cause: .protocolViolation) }
    }
    /// Reset, deadline, malformed transport or cancellation of upstream work uses this terminal path.
    /// The writer must never splice it into a partially delivered event (G2 terminal-reserve contract).
    public mutating func fail(cause: ResponseFailureCause) -> [UInt8] {
        guard state != .closed else { return [] }
        state = .closed; body = []; event = []; header = []; sizeLine = []
        // Incomplete chunking is intentional; never emit a zero chunk on truncation (B27).
        if committed { return chunk(GatewayProtocol.truncation) }
        return cause == .deadline ? FixedResponse.deadline.wire : FixedResponse.upstream.wire
    }
    private mutating func step(_ byte: UInt8) throws -> [UInt8] {
        switch state {
        case .headers:
            guard header.count < limits.headers else { throw Refusal.upstreamProtocol }
            header.append(byte)
            if header.suffix(GatewayProtocol.headerEnd.count).elementsEqual(GatewayProtocol.headerEnd) {
                try parseHeaders(); header = []
                if sse {
                    committed = true
                    return bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n")
                }
            }
        case .length, .chunkBody:
            let wasLength = state == .length
            let output = try payload(byte); remaining -= 1
            if remaining == 0 { state = wasLength ? .framedEnd : .chunkCR }
            return output
        case .closeBody: return try payload(byte)
        case .chunkSize:
            guard sizeLine.count < limits.headers else { throw Refusal.upstreamProtocol }
            sizeLine.append(byte)
            if sizeLine.suffix(GatewayProtocol.crlf.count).elementsEqual(GatewayProtocol.crlf) {
                let digits = sizeLine.dropLast(GatewayProtocol.crlf.count)
                guard !digits.isEmpty else { throw Refusal.upstreamProtocol }
                var n = 0
                for d in digits {
                    guard let digit = hexDigit(d) else { throw Refusal.upstreamProtocol }
                    let (m, a) = n.multipliedReportingOverflow(by: 16)
                    let (v, b) = m.addingReportingOverflow(digit)
                    guard !a, !b else { throw Refusal.upstreamProtocol }; n = v
                }
                guard n <= limits.response - received else { throw Refusal.upstreamProtocol }
                remaining = n; sizeLine = []; state = n == 0 ? .endCR : .chunkBody
            }
        case .chunkCR: guard byte == 13 else { throw Refusal.upstreamProtocol }; state = .chunkLF
        case .chunkLF: guard byte == 10 else { throw Refusal.upstreamProtocol }; state = .chunkSize
        case .endCR: guard byte == 13 else { throw Refusal.upstreamProtocol }; state = .endLF
        case .endLF: guard byte == 10 else { throw Refusal.upstreamProtocol }; state = .framedEnd
        case .framedEnd: throw Refusal.upstreamProtocol // No payload or second response after termination.
        case .closed: break
        }
        return []
    }
    private mutating func parseHeaders() throws {
        let block = try HeaderBlock(Array(header.dropLast(GatewayProtocol.headerEnd.count)))
        let words = block.first.split(separator: 32, omittingEmptySubsequences: false)
        guard words.count >= 3, Array(words[0]) == bytes("HTTP/1.1"), words[1].count == 3,
              block.first.allSatisfy({ $0 >= 32 && $0 < 127 }) else { throw Refusal.upstreamProtocol }
        status = try decimalLength(Array(words[1]))
        // Redirects and informational statuses cannot escape or trigger another destination.
        guard status == 200 || (streaming && (400...599).contains(status)) else { throw Refusal.upstreamProtocol }
        try block.forbid(["content-encoding", "trailer", "upgrade"])
        let contentType = try block.one("content-type")
        sse = status == 200 && streaming
        if sse { guard contentType == bytes("text/event-stream") else { throw Refusal.upstreamProtocol } }
        else {
            guard contentType == bytes("application/json") || contentType == bytes("application/json; charset=utf-8") else {
                throw Refusal.upstreamProtocol
            }
        }
        let length = try block.one("content-length"), transfer = try block.one("transfer-encoding")
        // TE/CL ambiguity is refused rather than resolved with a parser-specific precedence.
        guard length == nil || transfer == nil else { throw Refusal.upstreamProtocol }
        if let length {
            remaining = try decimalLength(length)
            guard remaining <= limits.response else { throw Refusal.upstreamProtocol }
            state = remaining == 0 ? .framedEnd : .length
        } else if let transfer {
            guard transfer == bytes("chunked") else { throw Refusal.upstreamProtocol }; state = .chunkSize
        } else { state = .closeBody }
    }
    private mutating func payload(_ byte: UInt8) throws -> [UInt8] {
        // Aggregate decoded bytes, not transfer framing, consume the response budget.
        guard received < limits.response else { throw Refusal.upstreamProtocol }; received += 1
        if !sse { body.append(byte); return [] }
        guard !sawDone, event.count < limits.event, byte != 13 else { throw Refusal.upstreamProtocol }
        event.append(byte)
        if event.suffix(2).elementsEqual([10, 10]) { // SSE's two-LF event terminator.
            let complete = event; event = []
            if complete == GatewayProtocol.done { sawDone = true; return [] }
            let prefix = bytes("data: ")
            guard complete.starts(with: prefix) else { throw Refusal.upstreamProtocol }
            let data = Array(complete.dropFirst(prefix.count).dropLast(2))
            // Prefix DONE variants, multiline data and other SSE fields cannot reach the SDK.
            guard !data.starts(with: bytes("[DONE]")) else { throw ResponseFailure.falseDone }
            guard !data.contains(10) else { throw Refusal.upstreamProtocol }
            do {
                var parser = StrictJSON(input: data, budget: limits.event)
                guard try parser.parse().members != nil else { throw ResponseFailure.invalidEventJSON }
            } catch { throw ResponseFailure.invalidEventJSON }
            return chunk(complete)
        }
        return []
    }
}
