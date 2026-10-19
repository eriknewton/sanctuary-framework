/// Parser-issued capability for serialization. No public/memberwise constructor accepts unchecked data.
public struct ValidatedRequest: Equatable, Sendable {
    public let route: Route
    public let streaming: Bool
    fileprivate let body: [UInt8]
    private init(route: Route, streaming: Bool, body: [UInt8]) {
        self.route = route; self.streaming = streaming; self.body = body
    }

    /// Parse a complete route body. HTTP callers first use RequestFramer to establish its boundary.
    public static func parse(route: Route, body: [UInt8], limits: GatewayLimits) throws -> Self {
        guard body.count <= limits.body else { throw Refusal.size }
        if route == .tags || route == .models {
            guard body.isEmpty else { throw Refusal.schema }
            return Self(route: route, streaming: false, body: [])
        }
        var parser = StrictJSON(input: body, budget: limits.body)
        var value = try parser.parse()
        guard value.members != nil else { throw Refusal.schema }
        var names = MemberScan()
        names.scan(value, kind: route == .show ? .show : .chat)
        // Name errors are resolved across the whole protocol tree before semantic/model checks.
        if names.caseVariant { throw Refusal.caseVariantMember }
        if names.unknown { throw Refusal.unknownMember }
        try validateModel(value[route == .show ? "name" : "model"])
        if route == .show {
            return Self(route: route, streaming: false, body: GatewayProtocol.showBody)
        }
        let schema = RequestSchema(budget: limits.body)
        try schema.chat(value)
        // Defaults are explicit canonical fields, so reparse produces the same typed value.
        var members = value.members!
        if value["max_tokens"] == nil {
            members.append(.init(key: bytes("max_tokens"), value: .number(bytes(String(GatewayProtocol.outputTokens)))))
        }
        if value["stream"] == nil { members.append(.init(key: bytes("stream"), value: .bool(false))) }
        value = .object(members)
        var rebuilt: [UInt8] = []; emitJSON(value, into: &rebuilt)
        // Rebuilding can insert defaults; the output budget is independent of the input check.
        guard rebuilt.count <= limits.body else { throw Refusal.size }
        return Self(route: route, streaming: value["stream"] == .bool(true), body: rebuilt)
    }
}

/// Only the validated type can enter the canonical-body serializer.
public enum RequestSerializer {
    public static func body(_ request: ValidatedRequest) -> [UInt8] { request.body }
    /// Select stripping only after the B18 capture comparison; placeholder is the conservative mode.
    public enum Authorization: Sendable { case placeholder, stripAfterCapture }
    public static func http(_ request: ValidatedRequest, authorization: Authorization) -> [UInt8] {
        // No inbound header map crosses this boundary; every emitted header is freshly selected.
        var out = request.route.method + bytes(" ") + request.route.target + bytes(" HTTP/1.1\r\nHost: ")
        out += GatewayProtocol.upstreamHost + bytes("\r\nAccept: application/json\r\n")
        out += bytes("Content-Length: \(request.body.count)\r\nConnection: close\r\n")
        if request.route == .chat || request.route == .show { out += bytes("Content-Type: application/json\r\n") }
        if authorization == .placeholder { out += bytes("Authorization: Bearer no-key-required\r\n") }
        return out + GatewayProtocol.crlf + request.body
    }
}

private func validateModel(_ value: JSON?) throws {
    guard let model = value?.string else { throw Refusal.schema }
    // Suffix refusal is independently observable even when exact pinning would also refuse.
    let folded = asciiLower(model)
    if [":cloud", "-cloud", ":local"].contains(where: { folded.suffix($0.utf8.count).elementsEqual($0.utf8) }) {
        throw Refusal.modelLocalitySuffix
    }
    guard model == GatewayProtocol.model else { throw Refusal.modelMismatch }
}

private enum ObjectKind {
    case chat, show, message, part, call, callFunction, tool, toolFunction, options, streamOptions
    var fields: [String] {
        switch self {
        case .chat: ["model", "messages", "max_tokens", "temperature", "stream", "stream_options", "options", "think", "tools"]
        case .show: ["name"]
        case .message: ["role", "content", "name", "reasoning", "tool_call_id", "tool_calls"]
        case .part: ["type", "text"]
        case .call: ["id", "type", "function"]
        case .callFunction: ["name", "arguments"]
        case .tool: ["type", "function"]
        case .toolFunction: ["name", "description", "parameters", "strict"]
        case .options: ["num_ctx"]
        case .streamOptions: ["include_usage"]
        }
    }
}

private struct MemberScan {
    var caseVariant = false
    var unknown = false
    mutating func scan(_ value: JSON, kind: ObjectKind) {
        guard let members = value.members else { return }
        let allowed = kind.fields.map(bytes)
        for member in members {
            // Case folding is a separate guard from the closed accepted-member list (B24).
            if allowed.contains(goFold(member.key)) && !allowed.contains(member.key) { caseVariant = true }
            if !allowed.contains(member.key) {
                // A media part has its own refusal, before any image decoding could occur.
                if kind != .part || value["type"] == .string(bytes("text")) { unknown = true }
            }
        }
        switch kind {
        case .chat:
            each(value["messages"], .message); each(value["tools"], .tool)
            if let v = value["options"] { scan(v, kind: .options) }
            if let v = value["stream_options"] { scan(v, kind: .streamOptions) }
        case .message:
            each(value["content"], .part); each(value["tool_calls"], .call)
        case .call: if let v = value["function"] { scan(v, kind: .callFunction) }
        case .tool: if let v = value["function"] { scan(v, kind: .toolFunction) }
        default: break // Tool parameters are opaque data, not protocol member names.
        }
    }
    mutating func each(_ value: JSON?, _ kind: ObjectKind) {
        for v in value?.elements ?? [] { scan(v, kind: kind) }
    }
}

private struct RequestSchema {
    let budget: Int
    func need(_ condition: Bool) throws { guard condition else { throw Refusal.schema } }
    func text(_ value: JSON?, min: Int = 0, max: Int? = nil) throws {
        guard let s = value?.string, s.count >= min, s.count <= (max ?? budget) else { throw Refusal.schema }
    }
    func id(_ value: JSON?) throws { try text(value, min: 1, max: GatewayProtocol.identifierBytes) }
    func integer(_ value: JSON?, min: Int, max: Int) throws {
        guard case .number(let n) = value,
              !n.contains(46), !n.contains(101), !n.contains(69),
              let i = Int(String(decoding: n, as: UTF8.self)), i >= min, i <= max else { throw Refusal.schema }
    }
    func array(_ value: JSON?, min: Int) throws -> [JSON] {
        guard let a = value?.elements, a.count >= min, a.count <= budget / 2 else { throw Refusal.schema }
        return a
    }
    func boolean(_ value: JSON?) throws { guard case .bool = value else { throw Refusal.schema } }
    func chat(_ value: JSON) throws {
        for message in try array(value["messages"], min: 1) { try self.message(message) }
        if let v = value["max_tokens"] { try integer(v, min: 1, max: GatewayProtocol.outputTokens) }
        if let v = value["temperature"] {
            guard case .number(let n) = v, let d = Double(String(decoding: n, as: UTF8.self)),
                  d.isFinite, d >= 0, d <= 2 else { throw Refusal.schema }
        }
        if let v = value["stream"] { try boolean(v) }
        if let v = value["stream_options"] {
            try need(value["stream"] == .bool(true) && v.members != nil)
            try boolean(v["include_usage"])
        }
        if let v = value["options"] {
            try need(v.members != nil)
            try integer(v["num_ctx"], min: GatewayProtocol.contextTokens, max: GatewayProtocol.contextTokens)
        }
        if let v = value["think"] { try need(v == .bool(false)) }
        if let tools = value["tools"] { for tool in try array(tools, min: 0) { try self.tool(tool) } }
    }
    func message(_ v: JSON) throws {
        guard v.members != nil, let role = v["role"]?.string,
              ["system", "developer", "user", "assistant", "tool"].map(bytes).contains(role) else { throw Refusal.schema }
        let assistant = role == bytes("assistant"), tool = role == bytes("tool")
        if let n = v["name"] { try id(n) }
        if let r = v["reasoning"] { try need(assistant); try text(r) }
        if let calls = v["tool_calls"] {
            try need(assistant)
            for c in try array(calls, min: 1) { try call(c) }
        }
        if tool { try id(v["tool_call_id"]) } else { try need(v["tool_call_id"] == nil) }
        if v["content"] == .null { try need(assistant && !(v["tool_calls"]?.elements?.isEmpty ?? true)) }
        else if let parts = v["content"]?.elements {
            try need(parts.count <= budget / 2)
            for part in parts {
                // All non-text shapes refuse without decoding media or dereferencing URLs.
                guard part.members != nil, part["type"] == .string(bytes("text")) else { throw Refusal.mediaRefused }
                guard part.members!.allSatisfy({ [bytes("type"), bytes("text")].contains($0.key) }) else {
                    throw Refusal.unknownMember
                }
                try text(part["text"])
            }
        } else { try text(v["content"]) }
    }
    func call(_ v: JSON) throws {
        try need(v.members != nil && v["type"] == .string(bytes("function")))
        try id(v["id"])
        guard let f = v["function"], f.members != nil else { throw Refusal.schema }
        try id(f["name"]); try text(f["arguments"])
    }
    func tool(_ v: JSON) throws {
        try need(v.members != nil && v["type"] == .string(bytes("function")))
        guard let f = v["function"], f.members != nil else { throw Refusal.schema }
        try id(f["name"]); try need(f["parameters"]?.members != nil)
        if let d = f["description"] { try text(d) }
        if let s = f["strict"] { try boolean(s) }
    }
}
