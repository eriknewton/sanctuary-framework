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
        let value = try parser.parse()
        var schema = RequestSchema(budget: limits.body)
        let accepted = schema.request(value, route: route)
        try schema.finish()
        if route == .show {
            return Self(route: route, streaming: false, body: GatewayProtocol.showBody)
        }
        // Only typed accepted fields generate protocol objects; the parsed input tree is never emitted.
        var rebuilt: [UInt8] = []; emitJSON(accepted.json, into: &rebuilt)
        // Rebuilding can insert defaults; the output budget is independent of the input check.
        guard rebuilt.count <= limits.body else { throw Refusal.size }
        return Self(route: route, streaming: accepted.stream, body: rebuilt)
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

// Must match the complete fixture set in WalkerTests.testEveryObjectMemberClosure.
enum ObjectKind: CaseIterable {
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

// These private values can be constructed only by the one schema walker below. Numeric fields
// retain validated lexemes; parameters alone retain opaque JSON data (B24).
private struct AcceptedCall {
    let id: [UInt8], name: [UInt8], arguments: [UInt8]
    var json: JSON { object([("id", .string(id)), ("type", .string(bytes("function"))),
        ("function", object([("name", .string(name)), ("arguments", .string(arguments))]))]) }
}
private struct AcceptedTool {
    let name: [UInt8], description: [UInt8]?, parameters: JSON, strict: Bool?
    var json: JSON { object([("type", .string(bytes("function"))), ("function", object([
        ("name", .string(name)), ("description", description.map(JSON.string)),
        ("parameters", parameters), ("strict", strict.map(JSON.bool))]))]) }
}
private struct AcceptedPart {
    let text: [UInt8]
    var json: JSON { object([("type", .string(bytes("text"))), ("text", .string(text))]) }
}
private enum AcceptedContent {
    case text([UInt8]), parts([AcceptedPart]), null
    var json: JSON {
        switch self {
        case .text(let text): .string(text)
        case .parts(let parts): .array(parts.map(\.json))
        case .null: .null
        }
    }
}
private struct AcceptedMessage {
    let role: [UInt8], content: AcceptedContent, name: [UInt8]?, reasoning: [UInt8]?
    let toolCallID: [UInt8]?, calls: [AcceptedCall]?
    var json: JSON { object([("role", .string(role)), ("content", content.json),
        ("name", name.map(JSON.string)), ("reasoning", reasoning.map(JSON.string)),
        ("tool_call_id", toolCallID.map(JSON.string)), ("tool_calls", calls.map { .array($0.map(\.json)) })]) }
}
private struct AcceptedChat {
    var messages: [AcceptedMessage] = []
    var maxTokens = bytes(String(GatewayProtocol.outputTokens))
    var temperature: [UInt8]?, stream = false, includeUsage: Bool?, context: [UInt8]?, think: Bool?
    var tools: [AcceptedTool]?
    var json: JSON { object([("model", .string(GatewayProtocol.model)),
        ("messages", .array(messages.map(\.json))), ("max_tokens", .number(maxTokens)),
        ("temperature", temperature.map(JSON.number)), ("stream", .bool(stream)),
        ("stream_options", includeUsage.map { object([("include_usage", .bool($0))]) }),
        ("options", context.map { object([("num_ctx", .number($0))]) }),
        ("think", think.map(JSON.bool)), ("tools", tools.map { .array($0.map(\.json)) })]) }
}
private func object(_ fields: [(String, JSON?)]) -> JSON {
    .object(fields.compactMap { key, value in value.map { .init(key: bytes(key), value: $0) } })
}

private struct Fields {
    var values: [[UInt8]: JSON] = [:]
    subscript(_ name: String) -> JSON? { values[bytes(name)] }
}

private struct RequestSchema {
    let budget: Int
    var caseVariant = false, unknown = false
    var semanticFailure: Refusal?, modelFailure: Refusal?

    mutating func record(_ reason: Refusal) { if semanticFailure == nil { semanticFailure = reason } }
    mutating func need(_ condition: Bool) { if !condition { record(.schema) } }
    func finish() throws {
        // Resolve names across every visited object before model and semantic failures (G-r2).
        if caseVariant { throw Refusal.caseVariantMember }
        if unknown { throw Refusal.unknownMember }
        if let modelFailure { throw modelFailure }
        if let semanticFailure { throw semanticFailure }
    }
    mutating func fields(_ value: JSON, kind: ObjectKind) -> Fields {
        guard let members = value.members else { record(kind == .part ? .mediaRefused : .schema); return Fields() }
        let allowed = kind.fields.map(bytes)
        // This lookup must stay outside the member loop: untrusted objects may fill the entire body.
        let textPart = kind == .part && value["type"] == .string(bytes("text"))
        var result = Fields()
        for member in members {
            // Case equivalence is checked separately from exact membership, before any value is accepted.
            if allowed.contains(goFold(member.key)) && !allowed.contains(member.key) { caseVariant = true }
            if !allowed.contains(member.key) {
                // Non-text parts have a dedicated media refusal; none can become an accepted part.
                if kind != .part || textPart { unknown = true }
            } else {
                result.values[member.key] = member.value
            }
        }
        return result
    }
    mutating func text(_ value: JSON?, min: Int = 0, max: Int? = nil) -> [UInt8] {
        guard let s = value?.string, s.count >= min, s.count <= (max ?? budget) else { record(.schema); return [] }
        return s
    }
    mutating func id(_ value: JSON?) -> [UInt8] { text(value, min: 1, max: GatewayProtocol.identifierBytes) }
    mutating func integer(_ value: JSON?, min: Int, max: Int) -> [UInt8] {
        guard case .number(let n) = value,
              !n.contains(46), !n.contains(101), !n.contains(69),
              let i = Int(String(decoding: n, as: UTF8.self)), i >= min, i <= max else { record(.schema); return [] }
        return n
    }
    mutating func array(_ value: JSON?, min: Int) -> [JSON] {
        guard let a = value?.elements, a.count >= min, a.count <= jsonNodeCap(budget) else { record(.schema); return [] }
        return a
    }
    mutating func boolean(_ value: JSON?) -> Bool {
        guard case .bool(let b) = value else { record(.schema); return false }; return b
    }
    mutating func request(_ value: JSON, route: Route) -> AcceptedChat {
        let f = fields(value, kind: route == .show ? .show : .chat)
        do { try validateModel(f[route == .show ? "name" : "model"]) }
        catch { modelFailure = error as? Refusal }
        var accepted = AcceptedChat()
        if route == .show { return accepted }
        accepted.messages = array(f["messages"], min: 1).map { message($0) }
        if let v = f["max_tokens"] { accepted.maxTokens = integer(v, min: 1, max: GatewayProtocol.outputTokens) }
        if let v = f["temperature"] {
            if case .number(let n) = v, let d = Double(String(decoding: n, as: UTF8.self)),
               d.isFinite, d >= 0, d <= 2 { accepted.temperature = n }
            else { record(.schema) }
        }
        if let v = f["stream"] { accepted.stream = boolean(v) }
        if let v = f["stream_options"] {
            let options = fields(v, kind: .streamOptions)
            need(accepted.stream)
            accepted.includeUsage = boolean(options["include_usage"])
        }
        if let v = f["options"] {
            let options = fields(v, kind: .options)
            accepted.context = integer(options["num_ctx"], min: GatewayProtocol.contextTokens, max: GatewayProtocol.contextTokens)
        }
        if let v = f["think"] { need(v == .bool(false)); accepted.think = false }
        if let v = f["tools"] { accepted.tools = array(v, min: 0).map { tool($0) } }
        return accepted
    }
    mutating func message(_ value: JSON) -> AcceptedMessage {
        let f = fields(value, kind: .message)
        let role = text(f["role"])
        need(["system", "developer", "user", "assistant", "tool"].map(bytes).contains(role))
        let assistant = role == bytes("assistant"), isTool = role == bytes("tool")
        let name = f["name"].map { id($0) }
        let reasoning = f["reasoning"].map { v in need(assistant); return text(v) }
        let calls = f["tool_calls"].map { v in
            need(assistant); return array(v, min: 1).map { call($0) }
        }
        var toolCallID: [UInt8]?
        if isTool { toolCallID = id(f["tool_call_id"]) } else { need(f["tool_call_id"] == nil) }
        let content: AcceptedContent
        if f["content"] == .null { need(assistant && !(calls?.isEmpty ?? true)); content = .null }
        else if let parts = f["content"]?.elements {
            need(parts.count <= jsonNodeCap(budget)); content = .parts(parts.map { part($0) })
        } else { content = .text(text(f["content"])) }
        return AcceptedMessage(role: role, content: content, name: name, reasoning: reasoning, toolCallID: toolCallID, calls: calls)
    }
    mutating func part(_ value: JSON) -> AcceptedPart {
        let f = fields(value, kind: .part)
        // Non-text parts never reach media decoding, URL resolution or typed output.
        guard f["type"] == .string(bytes("text")) else { record(.mediaRefused); return AcceptedPart(text: []) }
        return AcceptedPart(text: text(f["text"]))
    }
    mutating func call(_ value: JSON) -> AcceptedCall {
        let f = fields(value, kind: .call)
        need(f["type"] == .string(bytes("function")))
        let id = id(f["id"])
        let function = fields(f["function"] ?? .null, kind: .callFunction)
        return AcceptedCall(id: id, name: self.id(function["name"]), arguments: text(function["arguments"]))
    }
    mutating func tool(_ value: JSON) -> AcceptedTool {
        let f = fields(value, kind: .tool)
        need(f["type"] == .string(bytes("function")))
        let function = fields(f["function"] ?? .null, kind: .toolFunction)
        let name = id(function["name"])
        // Opaque schema names remain data; only this field may retain a parsed input subtree.
        need(function["parameters"]?.members != nil)
        let description = function["description"].map { text($0) }
        let strict = function["strict"].map { boolean($0) }
        return AcceptedTool(name: name, description: description, parameters: function["parameters"] ?? .null, strict: strict)
    }
}
