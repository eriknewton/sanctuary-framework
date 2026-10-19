import Darwin
import Foundation
import MemoryGrantPeer

public enum RelayProtocolConstants {
    // These values must match the Values block in hermes-memory-relay/SEAM.md.
    // 4 bytes = the fixed big-endian length prefix shared by public and inherited-fd frames.
    public static let frameLengthPrefixBytes = 4
    // 24/16/8 are the byte offsets for decoding a 32-bit big-endian length prefix.
    public static let byteShift24 = 24
    public static let byteShift16 = 16
    public static let byteShift8 = 8
    // 1024 bytes = one KiB; all protocol caps are specified in KiB in DESIGN-r6.
    public static let bytesPerKiB = 1024
    // 64 KiB is the public MCP frame cap from DESIGN-r6 "Frame caps".
    public static let maxPublicFrameBytes = 64 * bytesPerKiB
    // 64 KiB is the public result frame cap from DESIGN-r6 "Frame caps".
    public static let maxResultFrameBytes = 64 * bytesPerKiB
    // 128 ASCII bytes keeps the request id exact because the allowed charset contains no JSON-escaped characters.
    public static let maxRequestIDBytes = 128
    // 32 lowercase hex characters carry 128 bits of probe nonce entropy without giving Node an unbounded echo string.
    public static let probeNonceBytes = 32
    // 21 bytes = "c" plus the 20 decimal digits of UInt64.max; relay-minted ids never need more.
    public static let maxConnectionIDBytes = 1 + String(UInt64.max).count
    private struct EmptyPrivateResponseEnvelope: Encodable {
        let type = "response"
        let connectionID = ""
        let requestID = ""
        let resultB64 = ""

        enum CodingKeys: String, CodingKey {
            case type
            case connectionID = "connection_id"
            case requestID = "request_id"
            case resultB64 = "result_b64"
        }
    }

    public static let privateResponseEnvelopeSyntaxBytes: Int = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return (try? encoder.encode(EmptyPrivateResponseEnvelope()).count) ?? Int.max
    }()
    // 256 bytes is explicit slack beyond the longest private response envelope fields.
    public static let privateResponseFrameHeadroomBytes = 256
    // The private response envelope carries connection_id, request_id, result_b64, and named headroom.
    public static let maxFrameOverheadBytes = privateResponseEnvelopeSyntaxBytes
        + maxConnectionIDBytes
        + maxRequestIDBytes
        + privateResponseFrameHeadroomBytes
    // Base64 emits 4 bytes for each 3 input bytes; padding is included by Foundation's standard base64 encoder.
    public static let maxPrivateFrameBytes = 4 * ((maxPublicFrameBytes + 2) / 3) + maxFrameOverheadBytes
    // Each response class inherits the 64 KiB cap from DESIGN-r6 "Frame caps".
    public static let maxInsertResponseFrameBytes = 64 * bytesPerKiB
    public static let maxGetResponseFrameBytes = 64 * bytesPerKiB
    public static let maxSearchResponseFrameBytes = 64 * bytesPerKiB
    // One incomplete frame can retain only its 4-byte prefix plus the public payload cap.
    public static let maxPartialFrameBytes = maxPublicFrameBytes + frameLengthPrefixBytes
    // 4 public connections is the LaunchAgent slice cap; the fifth fd is closed before Node sees accepted.
    public static let maxPublicConnections = 4
    // 8 events is the per-connection control queue depth from r5c N5.
    public static let controlQueueDepthPerConnection = 8
    // 2 client control responses = one pong in flight plus one write-completion grace slot.
    public static let controlResponseAllowancePerConnection = 2
    // 4 client-bound frames = one result/error, one busy denial, plus two control responses.
    public static let maxClientOutboundFramesPerConnection = 1 + 1 + controlResponseAllowancePerConnection
    // 64 KiB per read caps scanner work to one public frame's byte budget per socket read.
    public static let maxPublicReadChunkBytes = maxPublicFrameBytes
    // 131076 = one retained partial frame plus one public read chunk.
    public static let probeDrainMaxBytes = maxPartialFrameBytes + maxPublicReadChunkBytes
    // 12 public frames: one primary hello/tools_list/tools_call, one busy-denied call, eight
    // forwarded controls (cancel or terminal shutdown), and two pings producing the pong allowance.
    // Responses and accepted/closed/probe frames travel on the private side and do not consume this budget.
    // Must match PROBE_DRAIN_MAX_FRAMES in hermes-memory-relay/SEAM.md.
    public static let probeDrainMaxFrames = 1 + 1 + controlQueueDepthPerConnection + controlResponseAllowancePerConnection
    // 1000 ms covers scheduler latency after uncatchable SIGKILL; this is not a durable-write bound.
    // Must match RELAY_CHILD_REAP_BOUND_MS in server/src/hermes-memory-bridge/process-shell.ts.
    public static let relayChildReapBoundMilliseconds = 1_000
    // 64 levels is deeper than any allowlisted public frame needs; the fixed bound keeps scanning iterative and stack-bounded.
    public static let maxJSONNestingDepth = 64
    // 2000 ms is the r6 probe bound that keeps commit checks below the tool deadline.
    public static let probeReplyBoundMilliseconds = 2_000
    // Must match CHILD_READY_TIMEOUT_MS in server/src/hermes-memory-bridge/process-shell.ts.
    // 5000 ms is the child composition readiness budget.
    public static let childReadyTimeoutMilliseconds = 5_000
    // Must match RELAY_CHILD_SIGTERM_GRACE_MS in server/src/hermes-memory-bridge/process-shell.ts.
    // 3000 ms is the SIGTERM grace after the bounded probe drain.
    public static let childSigtermGraceMilliseconds = 3_000
    // Must match RELAY_CHILD_EXIT_BOUND_MS in server/src/hermes-memory-bridge/process-shell.ts.
    public static let relayChildExitBoundMilliseconds = probeReplyBoundMilliseconds + childSigtermGraceMilliseconds
    // 3 is the fixed inherited fd named by S9 and passed through --relay-fd.
    public static let childInheritedRelayFD = Int32(3)
    // Installation v1 fixes the owner and Hermes account UIDs; neither comes from public bytes.
    public static let ownerUID = uid_t(501)
    public static let hermesUID = uid_t(502)
    public static let rootUid = uid_t(0)
    // 80 is the standard macOS admin group id returned by Directory Services.
    public static let macOSAdminGroupID = gid_t(80)
    public static let publicSocketMode = mode_t(0o660)
    public static let socketDirectoryMode = mode_t(0o710)
    public static let privateDirectoryMode = mode_t(0o700)
    public static let permissionBitsMask = mode_t(0o777)
    public static let setuidBit = mode_t(0o4000)
    public static let setgidBit = mode_t(0o2000)
    public static let stickyBit = mode_t(0o1000)
    public static let groupWriteBit = mode_t(0o020)
    public static let worldWriteBit = mode_t(0o002)
    // 1024 is a named ceiling for macOS supplemental groups; lookup failure below this ceiling refuses startup.
    static let maxSupplementalGroupLookupCount = 1024
}

public enum JSONValue: Codable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "unsupported JSON value")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value):
            try container.encode(value)
        case .number(let value):
            try container.encode(value)
        case .bool(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .null:
            try container.encodeNil()
        }
    }
}

public struct RelayFrame: Codable, Equatable {
    public var type: String
    public var fields: [String: JSONValue]

    public init(type: String, fields: [String: JSONValue] = [:]) {
        self.type = type
        self.fields = fields
    }

    enum CodingKeys: String, CodingKey {
        case type
    }

    public init(from decoder: Decoder) throws {
        let keyed = try decoder.container(keyedBy: DynamicCodingKey.self)
        guard let typeKey = DynamicCodingKey(stringValue: "type"),
              let decodedType = try keyed.decodeIfPresent(String.self, forKey: typeKey)
        else {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "frame type is required")
            )
        }
        type = decodedType
        var decodedFields: [String: JSONValue] = [:]
        for key in keyed.allKeys where key.stringValue != "type" {
            decodedFields[key.stringValue] = try keyed.decode(JSONValue.self, forKey: key)
        }
        fields = decodedFields
    }

    public func encode(to encoder: Encoder) throws {
        var keyed = encoder.container(keyedBy: DynamicCodingKey.self)
        try keyed.encode(type, forKey: DynamicCodingKey(stringValue: "type")!)
        for (name, value) in fields {
            try keyed.encode(value, forKey: DynamicCodingKey(stringValue: name)!)
        }
    }
}

public struct DynamicCodingKey: CodingKey {
    public let stringValue: String
    public let intValue: Int?

    public init?(stringValue: String) {
        self.stringValue = stringValue
        intValue = nil
    }

    public init?(intValue: Int) {
        stringValue = "\(intValue)"
        self.intValue = intValue
    }
}

public enum FrameStreamError: Error, Equatable {
    case overlargeLength(UInt32)
    case partialRetentionExceeded(Int)
    case malformedJSON
    case duplicateJSONKey
    case poisoned
}

private enum TopLevelJSONFrameScanner {
    enum ScanError: Error {
        case duplicateKey
        case malformed
    }

    static func scan(_ data: Data, capturedStringKeys: Set<String>) throws -> RelayFrame {
        var scanner = Scanner(bytes: Array(data), capturedStringKeys: capturedStringKeys)
        return try scanner.scanTopLevelObject()
    }

    private struct Scanner {
        var bytes: [UInt8]
        var capturedStringKeys: Set<String>
        var index = 0

        var isAtEnd: Bool {
            index >= bytes.count
        }

        mutating func skipWhitespace() {
            while !isAtEnd, [UInt8(ascii: " "), UInt8(ascii: "\n"), UInt8(ascii: "\r"), UInt8(ascii: "\t")].contains(bytes[index]) {
                index += 1
            }
        }

        mutating func scanTopLevelObject() throws -> RelayFrame {
            skipWhitespace()
            guard try consumeIf(UInt8(ascii: "{")) else { throw ScanError.malformed }
            var fields: [String: JSONValue] = [:]
            var type: String?
            var seenCapturedDecodedKeys = Set<[UInt8]>()
            skipWhitespace()
            if try consumeIf(UInt8(ascii: "}")) {
                throw ScanError.malformed
            }
            while true {
                skipWhitespace()
                guard !isAtEnd, bytes[index] == UInt8(ascii: "\"") else { throw ScanError.malformed }
                let parsedKey = try parseString()
                let capturesKey = capturedStringKeys.contains(parsedKey.decoded)
                if capturesKey, !seenCapturedDecodedKeys.insert(Array(parsedKey.decoded.utf8)).inserted {
                    // Relay-read keys compare decoded UTF-8 bytes so escaped spelling cannot create a second routing identity.
                    throw ScanError.duplicateKey
                }
                skipWhitespace()
                guard try consumeIf(UInt8(ascii: ":")) else { throw ScanError.malformed }
                let valueKind = try parseValueSkippingNested()
                if capturesKey {
                    guard case .string(let stringValue) = valueKind else { throw ScanError.malformed }
                    if parsedKey.decoded == "type" {
                        type = stringValue
                    } else {
                        fields[parsedKey.decoded] = .string(stringValue)
                    }
                } else if parsedKey.decoded != "type" {
                    fields[parsedKey.decoded] = valueKind.placeholder
                }
                skipWhitespace()
                if try consumeIf(UInt8(ascii: "}")) {
                    skipWhitespace()
                    guard isAtEnd, let type else { throw ScanError.malformed }
                    return RelayFrame(type: type, fields: fields)
                }
                guard try consumeIf(UInt8(ascii: ",")) else { throw ScanError.malformed }
            }
        }

        mutating func parseValueSkippingNested() throws -> TopLevelValueKind {
            skipWhitespace()
            guard !isAtEnd else { throw ScanError.malformed }
            switch bytes[index] {
            case UInt8(ascii: "{"):
                try skipComposite(opening: UInt8(ascii: "{"), closing: UInt8(ascii: "}"))
                return .object
            case UInt8(ascii: "["):
                try skipComposite(opening: UInt8(ascii: "["), closing: UInt8(ascii: "]"))
                return .array
            case UInt8(ascii: "\""):
                return .string(try parseString().decoded)
            case UInt8(ascii: "t"):
                try consumeLiteral("true")
                return .bool
            case UInt8(ascii: "f"):
                try consumeLiteral("false")
                return .bool
            case UInt8(ascii: "n"):
                try consumeLiteral("null")
                return .null
            case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"):
                try parseNumber()
                return .number
            default:
                throw ScanError.malformed
            }
        }

        mutating func skipComposite(opening: UInt8, closing: UInt8) throws {
            guard try consumeIf(opening) else { throw ScanError.malformed }
            var stack: [UInt8] = [closing]
            while !stack.isEmpty {
                guard !isAtEnd else { throw ScanError.malformed }
                let byte = bytes[index]
                if byte == UInt8(ascii: "\"") {
                    _ = try parseString()
                    continue
                }
                if byte == UInt8(ascii: "{") {
                    guard stack.count < RelayProtocolConstants.maxJSONNestingDepth else { throw ScanError.malformed }
                    stack.append(UInt8(ascii: "}"))
                    index += 1
                    continue
                }
                if byte == UInt8(ascii: "[") {
                    guard stack.count < RelayProtocolConstants.maxJSONNestingDepth else { throw ScanError.malformed }
                    stack.append(UInt8(ascii: "]"))
                    index += 1
                    continue
                }
                if byte == stack.last {
                    stack.removeLast()
                    index += 1
                    continue
                }
                index += 1
            }
        }

        mutating func parseString() throws -> ParsedString {
            guard try consumeIf(UInt8(ascii: "\"")) else { throw ScanError.malformed }
            var output: [UInt8] = []
            let rawStart = index
            while !isAtEnd {
                let byte = bytes[index]
                index += 1
                if byte == UInt8(ascii: "\"") {
                    let raw = Array(bytes[rawStart..<(index - 1)])
                    guard let decoded = String(data: Data(output), encoding: .utf8) else { throw ScanError.malformed }
                    return ParsedString(decoded: decoded, rawBytes: raw)
                }
                if byte == UInt8(ascii: "\\") {
                    guard !isAtEnd else { throw ScanError.malformed }
                    let escaped = bytes[index]
                    index += 1
                    switch escaped {
                    case UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "/"):
                        output.append(escaped)
                    case UInt8(ascii: "b"):
                        output.append(0x08)
                    case UInt8(ascii: "f"):
                        output.append(0x0c)
                    case UInt8(ascii: "n"):
                        output.append(UInt8(ascii: "\n"))
                    case UInt8(ascii: "r"):
                        output.append(UInt8(ascii: "\r"))
                    case UInt8(ascii: "t"):
                        output.append(UInt8(ascii: "\t"))
                    case UInt8(ascii: "u"):
                        let scalar = try parseUnicodeScalar()
                        output.append(contentsOf: String(scalar).utf8)
                    default:
                        throw ScanError.malformed
                    }
                } else {
                    guard byte >= 0x20 else { throw ScanError.malformed }
                    output.append(byte)
                }
            }
            throw ScanError.malformed
        }

        mutating func parseUnicodeScalar() throws -> UnicodeScalar {
            // JSON unicode escapes carry exactly four hex digits per scalar.
            let first = try consumeFourHexDigits()
            if first >= 0xd800, first <= 0xdbff {
                guard index + 6 <= bytes.count,
                      bytes[index] == UInt8(ascii: "\\"),
                      bytes[index + 1] == UInt8(ascii: "u")
                else {
                    throw ScanError.malformed
                }
                index += 2
                let second = try consumeFourHexDigits()
                guard second >= 0xdc00, second <= 0xdfff else {
                    throw ScanError.malformed
                }
                let scalarValue = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                guard let scalar = UnicodeScalar(scalarValue) else {
                    throw ScanError.malformed
                }
                return scalar
            }
            guard let scalar = UnicodeScalar(first), !(first >= 0xdc00 && first <= 0xdfff) else {
                throw ScanError.malformed
            }
            return scalar
        }

        mutating func consumeFourHexDigits() throws -> UInt32 {
            let hexDigitCount = 4
            guard index + hexDigitCount <= bytes.count else { throw ScanError.malformed }
            var value: UInt32 = 0
            for _ in 0..<hexDigitCount {
                let byte = bytes[index]
                index += 1
                let digit: UInt32
                switch byte {
                case UInt8(ascii: "0")...UInt8(ascii: "9"):
                    digit = UInt32(byte - UInt8(ascii: "0"))
                case UInt8(ascii: "a")...UInt8(ascii: "f"):
                    digit = UInt32(byte - UInt8(ascii: "a")) + 10
                case UInt8(ascii: "A")...UInt8(ascii: "F"):
                    digit = UInt32(byte - UInt8(ascii: "A")) + 10
                default:
                    throw ScanError.malformed
                }
                value = (value << 4) | digit
            }
            return value
        }

        mutating func parseNumber() throws {
            if try consumeIf(UInt8(ascii: "-")), isAtEnd {
                throw ScanError.malformed
            }
            try consumeDigits()
            if try consumeIf(UInt8(ascii: ".")) {
                try consumeDigits()
            }
            if !isAtEnd, bytes[index] == UInt8(ascii: "e") || (!isAtEnd && bytes[index] == UInt8(ascii: "E")) {
                index += 1
                _ = try consumeIf(UInt8(ascii: "+")) || consumeIf(UInt8(ascii: "-"))
                try consumeDigits()
            }
        }

        mutating func consumeDigits() throws {
            let start = index
            while !isAtEnd, bytes[index] >= UInt8(ascii: "0"), bytes[index] <= UInt8(ascii: "9") {
                index += 1
            }
            guard index > start else { throw ScanError.malformed }
        }

        mutating func consumeLiteral(_ literal: String) throws {
            for byte in literal.utf8 {
                guard !isAtEnd, bytes[index] == byte else { throw ScanError.malformed }
                index += 1
            }
        }

        mutating func consumeIf(_ byte: UInt8) throws -> Bool {
            guard !isAtEnd, bytes[index] == byte else {
                return false
            }
            index += 1
            return true
        }
    }

    private struct ParsedString {
        var decoded: String
        var rawBytes: [UInt8]
    }

    private enum TopLevelValueKind {
        case string(String)
        case object
        case array
        case number
        case bool
        case null

        var placeholder: JSONValue {
            switch self {
            case .string(let value):
                return .string(value)
            case .object:
                return .object([:])
            case .array:
                return .array([])
            case .number:
                return .number(0)
            case .bool:
                return .bool(false)
            case .null:
                return .null
            }
        }
    }
}

public struct BoundedFrameStream {
    private let maxFrameBytes: Int
    private let maxPartialBytes: Int
    private var buffer = Data()
    private var poisoned = false

    public init(
        maxFrameBytes: Int = RelayProtocolConstants.maxPublicFrameBytes,
        maxFrameOverheadBytes: Int = RelayProtocolConstants.maxFrameOverheadBytes
    ) {
        self.maxFrameBytes = maxFrameBytes
        _ = maxFrameOverheadBytes
        maxPartialBytes = maxFrameBytes + RelayProtocolConstants.frameLengthPrefixBytes
    }

    public var hasPartialFrame: Bool {
        !buffer.isEmpty
    }

    public var isPoisoned: Bool {
        poisoned
    }

    public mutating func append(_ bytes: Data) throws -> [RelayFrame] {
        try appendDecoded(bytes).map(\.frame)
    }

    public mutating func appendDecoded(_ bytes: Data, maximumFrames: Int = Int.max) throws -> [DecodedRelayFrame] {
        guard !poisoned else {
            throw FrameStreamError.poisoned
        }
        buffer.append(bytes)

        var frames: [DecodedRelayFrame] = []
        while buffer.count >= RelayProtocolConstants.frameLengthPrefixBytes {
            // A barrier cannot spend unbounded work parsing even a single bounded read chunk.
            if frames.count >= maximumFrames {
                poisoned = true
                buffer.removeAll(keepingCapacity: false)
                return frames
            }
            let length = Self.decodeLengthPrefix(buffer)
            if length > UInt32(maxFrameBytes) {
                // Length is checked before slicing payload bytes so a peer cannot make the relay allocate an over-cap frame.
                poisoned = true
                buffer.removeAll(keepingCapacity: false)
                if frames.isEmpty {
                    throw FrameStreamError.overlargeLength(length)
                }
                return frames
            }
            let totalFrameBytes = RelayProtocolConstants.frameLengthPrefixBytes + Int(length)
            guard buffer.count >= totalFrameBytes else {
                break
            }
            let payloadRange = RelayProtocolConstants.frameLengthPrefixBytes..<totalFrameBytes
            let payload = buffer.subdata(in: payloadRange)
            do {
                let frame = try TopLevelJSONFrameScanner.scan(payload, capturedStringKeys: Self.capturedStringKeys)
                frames.append(DecodedRelayFrame(frame: frame, payloadBytes: payload))
                buffer.removeSubrange(0..<totalFrameBytes)
                continue
            } catch TopLevelJSONFrameScanner.ScanError.duplicateKey {
                poisoned = true
                buffer.removeAll(keepingCapacity: false)
                if frames.isEmpty {
                    throw FrameStreamError.duplicateJSONKey
                }
                return frames
            } catch {
                poisoned = true
                buffer.removeAll(keepingCapacity: false)
                if frames.isEmpty {
                    throw FrameStreamError.malformedJSON
                }
                return frames
            }
        }
        if buffer.count > maxPartialBytes {
            let retainedBytes = buffer.count
            poisoned = true
            buffer.removeAll(keepingCapacity: false)
            if frames.isEmpty {
                throw FrameStreamError.partialRetentionExceeded(retainedBytes)
            }
        }
        return frames
    }

    public mutating func markPoisoned() {
        poisoned = true
        buffer.removeAll(keepingCapacity: false)
    }

    public mutating func discard() {
        buffer.removeAll(keepingCapacity: false)
    }

    public static func encode(_ frame: RelayFrame) throws -> Data {
        let payload = try encodedPayload(frame)
        var output = Data()
        let length = UInt32(payload.count)
        output.append(UInt8((length >> RelayProtocolConstants.byteShift24) & 0xff))
        output.append(UInt8((length >> RelayProtocolConstants.byteShift16) & 0xff))
        output.append(UInt8((length >> RelayProtocolConstants.byteShift8) & 0xff))
        output.append(UInt8(length & 0xff))
        output.append(payload)
        return output
    }

    public static func encodedPayload(_ frame: RelayFrame) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return try encoder.encode(frame)
    }

    public static func encodeLengthOnly(_ length: UInt32) -> Data {
        var output = Data()
        output.append(UInt8((length >> RelayProtocolConstants.byteShift24) & 0xff))
        output.append(UInt8((length >> RelayProtocolConstants.byteShift16) & 0xff))
        output.append(UInt8((length >> RelayProtocolConstants.byteShift8) & 0xff))
        output.append(UInt8(length & 0xff))
        return output
    }

    private static func decodeLengthPrefix(_ buffer: Data) -> UInt32 {
        let prefix = Array(buffer.prefix(RelayProtocolConstants.frameLengthPrefixBytes))
        return (UInt32(prefix[0]) << RelayProtocolConstants.byteShift24)
            | (UInt32(prefix[1]) << RelayProtocolConstants.byteShift16)
            | (UInt32(prefix[2]) << RelayProtocolConstants.byteShift8)
            | UInt32(prefix[3])
    }

    private static let capturedStringKeys: Set<String> = [
        "type",
        "request_id",
        "mcp_request_id",
        "connection_id",
        "nonce",
        "result_b64"
    ]
}

public struct DecodedRelayFrame: Equatable {
    public var frame: RelayFrame
    public var payloadBytes: Data
}

public enum FrameDirection: String {
    case publicInbound
    case nodeToRelay
    case relayToNode
    case clientOutbound
}

public enum AllowlistError: Error, Equatable {
    case unknownFrame(String)
    case unexpectedField(String)
    case missingField(String)
    case wrongType(String)
}

public enum FieldType: Sendable {
    case string
    case object
}

public struct FrameAllowlist {
    public static let publicInbound: [String: [String: FieldType]] = [
        "hello": ["request_id": .string, "protocol_version": .string, "client_name": .string],
        "tools_list": ["request_id": .string],
        "tools_call": ["request_id": .string, "name": .string, "arguments": .object],
        "cancel": ["mcp_request_id": .string],
        "ping": [:],
        "shutdown": [:]
    ]

    public static let nodeToRelay: [String: [String: FieldType]] = [
        "ready": [:],
        "probe": ["connection_id": .string, "nonce": .string],
        "response": ["connection_id": .string, "request_id": .string, "result_b64": .string],
        "close": ["connection_id": .string]
    ]

    public static let relayToNode: [String: [String: FieldType]] = [
        "accepted": ["connection_id": .string],
        "frame": ["connection_id": .string, "frame_b64": .string],
        "closed": ["connection_id": .string],
        "probe_reply": ["connection_id": .string, "nonce": .string],
        "relay_shutdown": [:]
    ]

    public static let clientOutbound: [String: [String: FieldType]] = [
        "result": ["request_id": .string, "payload": .object],
        "error": ["request_id": .string, "message": .string],
        "pong": [:]
    ]

    public static func validate(_ frame: RelayFrame, direction: FrameDirection) throws {
        let table: [String: [String: FieldType]]
        switch direction {
        case .publicInbound:
            table = publicInbound
        case .nodeToRelay:
            table = nodeToRelay
        case .relayToNode:
            table = relayToNode
        case .clientOutbound:
            table = clientOutbound
        }
        guard let expectedFields = table[frame.type] else {
            throw AllowlistError.unknownFrame(frame.type)
        }
        for key in frame.fields.keys where expectedFields[key] == nil {
            throw AllowlistError.unexpectedField(key)
        }
        for (key, type) in expectedFields {
            guard let value = frame.fields[key] else {
                throw AllowlistError.missingField(key)
            }
            switch (type, value) {
            case (.string, .string), (.object, .object):
                continue
            default:
                throw AllowlistError.wrongType(key)
            }
        }
        if direction == .publicInbound {
            try validatePublicRequestIDBounds(frame)
        }
        if direction == .nodeToRelay, frame.type == "probe" {
            try validateProbeNonce(frame)
        }
    }

    private static func validatePublicRequestIDBounds(_ frame: RelayFrame) throws {
        let fieldName: String?
        switch frame.type {
        case "hello", "tools_list", "tools_call":
            fieldName = "request_id"
        case "cancel":
            fieldName = "mcp_request_id"
        default:
            fieldName = nil
        }
        guard let fieldName,
              case .string(let requestID)? = frame.fields[fieldName]
        else {
            return
        }
        // Ids are restricted to characters JSON never escapes, so encoded and decoded lengths are equal and the frame budget is exact.
        let bytes = Array(requestID.utf8)
        if bytes.isEmpty
            || bytes.count > RelayProtocolConstants.maxRequestIDBytes
            || !bytes.allSatisfy(isAllowedRequestIDByte) {
            throw AllowlistError.wrongType(fieldName)
        }
    }

    private static func isAllowedRequestIDByte(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"),
             UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"),
             UInt8(ascii: "."),
             UInt8(ascii: "_"),
             UInt8(ascii: ":"),
             UInt8(ascii: "-"):
            return true
        default:
            return false
        }
    }

    private static func validateProbeNonce(_ frame: RelayFrame) throws {
        guard case .string(let nonce)? = frame.fields["nonce"] else {
            throw AllowlistError.missingField("nonce")
        }
        let bytes = Array(nonce.utf8)
        guard bytes.count == RelayProtocolConstants.probeNonceBytes,
              bytes.allSatisfy(isLowercaseHexByte)
        else {
            throw AllowlistError.wrongType("nonce")
        }
    }

    private static func isLowercaseHexByte(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"),
             UInt8(ascii: "a")...UInt8(ascii: "f"):
            return true
        default:
            return false
        }
    }
}

public enum PeerCheckError: Error, Equatable {
    case expectedUidUnavailable
    case expectedUidIsRoot
    case expectedUidIsOwner
    case expectedUidIsRelayUid
    case expectedUidIsAdmin
    case peerUidMismatch(expected: uid_t, actual: uid_t)
    case peerInspectionFailed
    case peerSocketNotStream
    case peerSocketNotConnectedUnix
    case peerUidUnavailable
    case installUidUnavailable
    case installUidMismatch(pinned: uid_t, account: uid_t)
}

public protocol PeerCredentialProvider {
    func peerUid(forFileDescriptor fd: Int32) throws -> uid_t
}

public protocol AdminGroupMembership {
    func isAdmin(uid: uid_t) throws -> Bool
}

public struct DarwinPeerCredentialProvider: PeerCredentialProvider {
    private let expectedUID: uid_t
    public init(expectedUID: uid_t = RelayProtocolConstants.hermesUID) { self.expectedUID = expectedUID }

    public func peerUid(forFileDescriptor fd: Int32) throws -> uid_t {
        // Must match UnixPeerVerifier.requirePeer in castle-wall-macos/Sources/MemoryGrantPeer/UnixPeer.swift.
        // The canonical verifier establishes socket shape and the protected install UID together.
        return try UnixPeerVerifier.requirePeer(socket: fd, expectedUID: expectedUID).effectiveUID
    }
}

public struct DarwinAdminGroupMembership: AdminGroupMembership {
    private let maxSupplementalGroupLookupCount: Int32

    init(maxSupplementalGroupLookupCount: Int32 = Int32(RelayProtocolConstants.maxSupplementalGroupLookupCount)) {
        self.maxSupplementalGroupLookupCount = maxSupplementalGroupLookupCount
    }

    public func isAdmin(uid: uid_t) throws -> Bool {
        guard let passwd = getpwuid(uid), let name = passwd.pointee.pw_name else {
            throw PeerCheckError.peerInspectionFailed
        }
        var capacity = Int32(16)
        let primaryGroup = Int32(bitPattern: UInt32(passwd.pointee.pw_gid))
        let adminGroup = Int32(bitPattern: UInt32(RelayProtocolConstants.macOSAdminGroupID))
        while capacity <= maxSupplementalGroupLookupCount {
            var groupCount = capacity
            var groups = [Int32](repeating: 0, count: Int(capacity))
            let result = groups.withUnsafeMutableBufferPointer { buffer in
                getgrouplist(name, primaryGroup, buffer.baseAddress, &groupCount)
            }
            if result >= 0 {
                return groups.prefix(Int(groupCount)).contains(adminGroup)
            }
            capacity = max(capacity * 2, groupCount)
        }
        throw PeerCheckError.peerInspectionFailed
    }
}

public protocol AccountUIDLookup {
    func uid(forAccountName accountName: String) throws -> uid_t
}

public struct DarwinAccountUIDLookup: AccountUIDLookup {
    public init() {}

    public func uid(forAccountName accountName: String) throws -> uid_t {
        guard let passwd = getpwnam(accountName), passwd.pointee.pw_uid != uid_t.max else {
            throw PeerCheckError.installUidUnavailable
        }
        return passwd.pointee.pw_uid
    }
}

public struct HermesInstallIdentity {
    public var pinnedUID: uid_t
    public var accountName: String

    public init(pinnedUID: uid_t, accountName: String) {
        self.pinnedUID = pinnedUID
        self.accountName = accountName
    }

    public func validate(lookup: AccountUIDLookup) throws -> ValidatedHermesInstallIdentity {
        let accountUID = try lookup.uid(forAccountName: accountName)
        guard accountUID == pinnedUID else {
            throw PeerCheckError.installUidMismatch(pinned: pinnedUID, account: accountUID)
        }
        return ValidatedHermesInstallIdentity(pinnedUID: pinnedUID, accountName: accountName)
    }
}

public struct ValidatedHermesInstallIdentity: Equatable {
    public let pinnedUID: uid_t
    public let accountName: String

    fileprivate init(pinnedUID: uid_t, accountName: String) {
        self.pinnedUID = pinnedUID
        self.accountName = accountName
    }
}

public enum RelayConnectionIDError: Error, Equatable {
    case exhausted
}

public struct RelayConnectionIDMinter {
    private var nextCounter: UInt64 = 1

    public init() {}

    public mutating func mint() throws -> String {
        guard nextCounter < UInt64.max else {
            throw RelayConnectionIDError.exhausted
        }
        defer { nextCounter += 1 }
        return "c\(nextCounter)"
    }
}

public struct RelayAdmissionController {
    private var minter = RelayConnectionIDMinter()
    private var activeConnectionIDs: Set<String> = []

    public init() {}

    public mutating func acceptPeer() throws -> [RelayOutput] {
        guard activeConnectionIDs.count < RelayProtocolConstants.maxPublicConnections else {
            return [.closePublicConnection]
        }
        let connectionID = try minter.mint()
        activeConnectionIDs.insert(connectionID)
        return [.toNode(RelayFrame(type: "accepted", fields: ["connection_id": .string(connectionID)]), completion: nil)]
    }

    public mutating func markClosed(connectionID: String) {
        activeConnectionIDs.remove(connectionID)
    }
}

public enum RelayShutdownModel {
    public static func gracefulShutdownFrame() -> RelayFrame {
        RelayFrame(type: "relay_shutdown")
    }
}

public enum PrivateFrameError: Error, Equatable {
    case fatalRelayError
}

public struct PrivateFrameReceiver {
    private var stream = BoundedFrameStream(maxFrameBytes: RelayProtocolConstants.maxPrivateFrameBytes, maxFrameOverheadBytes: 0)
    private var readySeen = false

    public init() {}

    public mutating func receiveFromNode(_ data: Data) throws -> [RelayFrame] {
        do {
            let frames = try stream.append(data)
            if stream.isPoisoned {
                throw PrivateFrameError.fatalRelayError
            }
            for frame in frames {
                try FrameAllowlist.validate(frame, direction: .nodeToRelay)
                // Ready is the private lifecycle gate; accepting work before it would publish a half-composed bridge.
                if !readySeen {
                    guard frame.type == "ready" else { throw PrivateFrameError.fatalRelayError }
                    readySeen = true
                } else if frame.type == "ready" {
                    throw PrivateFrameError.fatalRelayError
                }
            }
            return frames
        } catch {
            throw PrivateFrameError.fatalRelayError
        }
    }
}

public struct PeerVerifier {
    private let expectedUid: uid_t
    private let relayUid: uid_t
    private let credentials: PeerCredentialProvider
    private let adminMembership: AdminGroupMembership

    public init(
        installIdentity: ValidatedHermesInstallIdentity,
        ownerUid: uid_t,
        relayUid: uid_t = getuid(),
        credentials: PeerCredentialProvider,
        adminMembership: AdminGroupMembership
    ) throws {
        let expectedUid = installIdentity.pinnedUID
        if expectedUid == uid_t.max {
            throw PeerCheckError.expectedUidUnavailable
        }
        if expectedUid == RelayProtocolConstants.rootUid {
            throw PeerCheckError.expectedUidIsRoot
        }
        if expectedUid == ownerUid {
            throw PeerCheckError.expectedUidIsOwner
        }
        if expectedUid == relayUid {
            throw PeerCheckError.expectedUidIsRelayUid
        }
        let isAdmin = (try? adminMembership.isAdmin(uid: expectedUid)) ?? true
        if isAdmin {
            throw PeerCheckError.expectedUidIsAdmin
        }
        self.expectedUid = expectedUid
        self.relayUid = relayUid
        self.credentials = credentials
        self.adminMembership = adminMembership
    }

    public func requirePeer(fileDescriptor fd: Int32) throws {
        let peerUid = try credentials.peerUid(forFileDescriptor: fd)
        // The relay authenticates the kernel peer uid before parsing so untrusted bytes cannot influence protocol state.
        guard peerUid == expectedUid else {
            throw PeerCheckError.peerUidMismatch(expected: expectedUid, actual: peerUid)
        }
    }
}

public enum RelayOutput: Equatable {
    case toNode(RelayFrame, completion: NodeWriteKind?)
    case toClient(RelayFrame, completion: ClientWriteKind)
    case toClientPayload(Data, completion: ClientWriteKind)
    case closePublicConnection
    case fatalRelayError
}

public enum NodeWriteKind {
    case forwardedControlFrame
}

public enum ClientWriteKind {
    case pong
    case busyDenial
    case result
}

public enum RelayConnectionState: Equatable {
    case state_SERVING
    case state_IN_FLIGHT
    case state_POISONED
    case state_CLOSED
}

public struct RelayConnection {
    public let connectionID: String
    private(set) public var state: RelayConnectionState = .state_SERVING
    private var stream = BoundedFrameStream()
    private(set) var queuedControlCount = 0
    private(set) var reservedControlCount = 0
    private var busyDenialOutstanding = false
    private var resultFramesOutstanding = 0
    private var controlResponsesOutstanding = 0
    private var currentRequestID: String?
    private var closedSent = false
    private var lastDecodedFrameCount = 0

    public init(connectionID: String) {
        self.connectionID = connectionID
        _ = Self.longestAllowedDenialFrameFitsResultCap
        _ = Self.longestAllowedFullResultPrivateResponseFitsFrameCap
    }

    public mutating func receivePublicBytes(_ data: Data, maximumFrames: Int = Int.max) -> [RelayOutput] {
        lastDecodedFrameCount = 0
        guard state != .state_CLOSED else {
            return []
        }
        do {
            let frames = try stream.appendDecoded(data, maximumFrames: maximumFrames)
            lastDecodedFrameCount = frames.count
            var output = frames.flatMap { handlePublicFrame($0.frame, payloadBytes: $0.payloadBytes) }
            if stream.isPoisoned {
                output.append(contentsOf: closeOnce(closePublic: true))
            }
            return output
        } catch {
            return closeOnce(closePublic: true)
        }
    }

    mutating func handlePublicFrame(_ frame: RelayFrame) -> [RelayOutput] {
        let payloadBytes = (try? Self.publicPayloadBytes(for: frame)) ?? Data()
        return handlePublicFrame(frame, payloadBytes: payloadBytes)
    }

    private mutating func handlePublicFrame(_ frame: RelayFrame, payloadBytes: Data) -> [RelayOutput] {
        do {
            try FrameAllowlist.validate(frame, direction: .publicInbound)
        } catch {
            return poisonAndClose()
        }

        switch state {
        case .state_SERVING:
            if frame.type == "ping" {
                return recordControlResponse(Self.pongFrame())
            }
            if frame.type == "cancel" {
                return enqueueControl(frame, payloadBytes: payloadBytes)
            }
            if frame.type == "shutdown" {
                return forwardShutdown(payloadBytes: payloadBytes)
            }
            if Self.isCallFrame(frame) {
                if hasUnwrittenCallBlockingOutput {
                    return queueBusyDenial(for: frame)
                }
                state = .state_IN_FLIGHT
                currentRequestID = Self.requestID(from: frame)
            }
            return envelopeOutput(for: frame, payloadBytes: payloadBytes)
        case .state_IN_FLIGHT:
            if frame.type == "ping" {
                return recordControlResponse(Self.pongFrame())
            }
            if Self.isForwardedControlFrame(frame) {
                if frame.type == "shutdown" {
                    return enqueueControl(frame, payloadBytes: payloadBytes) + closeOnce(closePublic: true)
                }
                return enqueueControl(frame, payloadBytes: payloadBytes)
            }
            if Self.isCallFrame(frame) {
                return queueBusyDenial(for: frame)
            }
            return poisonAndClose()
        case .state_POISONED:
            return []
        case .state_CLOSED:
            return []
        }
    }

    public mutating func peerClosed() -> [RelayOutput] {
        closeOnce(closePublic: true)
    }

    private mutating func recordResponseQueued() {
        resultFramesOutstanding += 1
    }

    public mutating func finishInFlight() {
        guard state != .state_CLOSED && state != .state_POISONED else {
            return
        }
        state = .state_SERVING
        currentRequestID = nil
    }

    /// Confirm transport acceptance before treating a decoded control reservation as queued work.
    public mutating func markNodeFrameQueued(_ kind: NodeWriteKind?) {
        if kind == .forwardedControlFrame && reservedControlCount > 0 {
            reservedControlCount -= 1
            queuedControlCount += 1
        }
    }

    /// Release a control reservation when the transport refuses to enqueue its frame.
    public mutating func cancelNodeFrameReservation(_ kind: NodeWriteKind?) {
        if kind == .forwardedControlFrame && reservedControlCount > 0 { reservedControlCount -= 1 }
    }

    public mutating func markNodeFrameWritten(_ kind: NodeWriteKind?) {
        if kind == .forwardedControlFrame && queuedControlCount > 0 {
            queuedControlCount -= 1
        }
    }

    public mutating func markClientFrameWritten(_ kind: ClientWriteKind) {
        switch kind {
        case .pong:
            if controlResponsesOutstanding > 0 {
                controlResponsesOutstanding -= 1
            }
        case .busyDenial:
            busyDenialOutstanding = false
        case .result:
            if resultFramesOutstanding > 0 {
                resultFramesOutstanding -= 1
            }
        }
    }

    public mutating func handleNodeFrame(_ frame: RelayFrame) -> [RelayOutput] {
        do {
            try FrameAllowlist.validate(frame, direction: .nodeToRelay)
        } catch {
            return [.fatalRelayError]
        }
        guard case .string(let frameConnectionID) = frame.fields["connection_id"] ?? .string(connectionID),
              frameConnectionID == connectionID else {
            return [.fatalRelayError]
        }
        if state == .state_CLOSED {
            return frame.type == "response" || frame.type == "close" ? [] : [.fatalRelayError]
        }
        switch frame.type {
        case "response":
            guard state == .state_IN_FLIGHT,
                  case .string(let requestID)? = frame.fields["request_id"],
                  let currentRequestID,
                  case .string(let resultB64)? = frame.fields["result_b64"]
            else {
                return [.fatalRelayError]
            }
            guard requestID == currentRequestID,
                  let resultPayload = Self.strictStandardBase64Payload(resultB64),
                  resultPayload.count <= RelayProtocolConstants.maxResultFrameBytes,
                  Self.isAllowedNodeResultPayload(resultPayload, requestID: currentRequestID)
            else {
                let denial = Self.denialFrame(requestID: currentRequestID)
                recordResponseQueued()
                finishInFlight()
                return [.toClient(denial, completion: .result)]
            }
            recordResponseQueued()
            finishInFlight()
            return [.toClientPayload(resultPayload, completion: .result)]
        case "close":
            return closeOnce(closePublic: true)
        default:
            return [.fatalRelayError]
        }
    }

    public mutating func handleProbe(_ probe: RelayFrame, publicFD: PublicFDProbeSource) -> [RelayOutput] {
        guard case .string(let nonce) = probe.fields["nonce"],
              case .string(let probeConnectionID) = probe.fields["connection_id"]
        else {
            return [.fatalRelayError]
        }
        do {
            try FrameAllowlist.validate(probe, direction: .nodeToRelay)
        } catch {
            return [.fatalRelayError]
        }
        guard probeConnectionID == connectionID else {
            return [.fatalRelayError]
        }
        if state == .state_CLOSED {
            return [.toNode(RelayFrame(type: "probe_reply", fields: [
                "connection_id": .string(probeConnectionID),
                "nonce": .string(nonce)
            ]), completion: nil)]
        }
        var output: [RelayOutput] = []
        var remainingBytes = RelayProtocolConstants.probeDrainMaxBytes
        var remainingFrames = RelayProtocolConstants.probeDrainMaxFrames
        while state != .state_CLOSED, remainingBytes > 0, remainingFrames > 0,
              let event = publicFD.next(maximumBytes: min(remainingBytes, RelayProtocolConstants.maxPublicReadChunkBytes)) {
            switch event {
            case .data(let bytes):
                guard !bytes.isEmpty, bytes.count <= remainingBytes else {
                    output.append(contentsOf: closeOnce(closePublic: true))
                    break
                }
                remainingBytes -= bytes.count
                output.append(contentsOf: receivePublicBytes(bytes, maximumFrames: remainingFrames))
                remainingFrames -= lastDecodedFrameCount
            case .eof, .hangup:
                output.append(contentsOf: closeOnce(closePublic: true))
            }
        }
        // Exhausting either budget with readable data cannot establish the drained decision boundary.
        if (remainingBytes == 0 || remainingFrames == 0) && publicFD.isReadable {
            output.append(contentsOf: closeOnce(closePublic: true))
        }
        if stream.hasPartialFrame || stream.isPoisoned {
            output.append(contentsOf: closeOnce(closePublic: true))
        }
        output.append(.toNode(RelayFrame(type: "probe_reply", fields: [
            "connection_id": .string(probeConnectionID),
            "nonce": .string(nonce)
        ]), completion: nil))
        return output
    }

    private mutating func enqueueControl(_ frame: RelayFrame, payloadBytes: Data) -> [RelayOutput] {
        // Reservations bound decoding; only a successful transport enqueue becomes queued work.
        reservedControlCount += 1
        // Control events are capped per connection so a caller cannot grow retained state while a tool call is outstanding.
        if queuedControlCount + reservedControlCount > RelayProtocolConstants.controlQueueDepthPerConnection {
            return poisonAndClose()
        }
        return envelopeOutput(for: frame, payloadBytes: payloadBytes)
    }

    private mutating func closeOnce(closePublic: Bool = false) -> [RelayOutput] {
        guard !closedSent else {
            return []
        }
        state = .state_CLOSED
        closedSent = true
        stream.discard()
        var output: [RelayOutput] = [.toNode(RelayFrame(type: "closed", fields: ["connection_id": .string(connectionID)]), completion: nil)]
        if closePublic {
            output.append(.closePublicConnection)
        }
        return output
    }

    private mutating func envelopeOutput(for frame: RelayFrame, payloadBytes: Data) -> [RelayOutput] {
        let envelope = RelayFrame(type: "frame", fields: [
            "connection_id": .string(connectionID),
            "frame_b64": .string(payloadBytes.base64EncodedString())
        ])
        guard ((try? BoundedFrameStream.encodedPayload(envelope).count) ?? (RelayProtocolConstants.maxPrivateFrameBytes + 1)) <= RelayProtocolConstants.maxPrivateFrameBytes else {
            return [.fatalRelayError]
        }
        let completion: NodeWriteKind? = Self.isForwardedControlFrame(frame) ? .forwardedControlFrame : nil
        return [.toNode(envelope, completion: completion)]
    }

    private var hasUnwrittenCallBlockingOutput: Bool {
        resultFramesOutstanding > 0 || busyDenialOutstanding
    }

    private mutating func queueBusyDenial(for frame: RelayFrame) -> [RelayOutput] {
        if busyDenialOutstanding {
            return poisonAndClose()
        }
        busyDenialOutstanding = true
        return [.toClient(Self.busyDenialFrame(for: frame), completion: .busyDenial)]
    }

    private mutating func poisonAndClose() -> [RelayOutput] {
        state = .state_POISONED
        stream.markPoisoned()
        return closeOnce(closePublic: true)
    }

    private mutating func recordControlResponse(_ frame: RelayFrame) -> [RelayOutput] {
        controlResponsesOutstanding += 1
        if controlResponsesOutstanding > RelayProtocolConstants.controlResponseAllowancePerConnection {
            return poisonAndClose()
        }
        return [.toClient(frame, completion: .pong)]
    }

    private mutating func forwardShutdown(payloadBytes: Data) -> [RelayOutput] {
        enqueueControl(RelayFrame(type: "shutdown"), payloadBytes: payloadBytes) + closeOnce(closePublic: true)
    }

    private static func isForwardedControlFrame(_ frame: RelayFrame) -> Bool {
        frame.type == "cancel" || frame.type == "shutdown"
    }

    private static func isCallFrame(_ frame: RelayFrame) -> Bool {
        frame.type == "tools_call" || frame.type == "hello" || frame.type == "tools_list"
    }

    private static func busyDenialFrame(for frame: RelayFrame) -> RelayFrame {
        denialFrame(requestID: requestID(from: frame))
    }

    private static func denialFrame(requestID: String) -> RelayFrame {
        RelayFrame(type: "error", fields: [
            "request_id": .string(requestID),
            "message": .string("Memory request denied.")
        ])
    }

    private static let longestAllowedDenialFrameFitsResultCap: Bool = {
        let payloadBytes = (try? BoundedFrameStream.encodedPayload(denialFrame(requestID: String(repeating: "x", count: RelayProtocolConstants.maxRequestIDBytes))).count)
            ?? (RelayProtocolConstants.maxResultFrameBytes + 1)
        precondition(payloadBytes <= RelayProtocolConstants.maxResultFrameBytes, "longest allowed denial frame shape exceeds result cap")
        return true
    }()

    private static let longestAllowedFullResultPrivateResponseFitsFrameCap: Bool = {
        let response = RelayFrame(type: "response", fields: [
            "connection_id": .string("c" + String(UInt64.max)),
            "request_id": .string(String(repeating: "x", count: RelayProtocolConstants.maxRequestIDBytes)),
            "result_b64": .string(Data(repeating: UInt8(ascii: "a"), count: RelayProtocolConstants.maxResultFrameBytes).base64EncodedString())
        ])
        let payloadBytes = (try? BoundedFrameStream.encodedPayload(response).count)
            ?? (RelayProtocolConstants.maxPrivateFrameBytes + 1)
        precondition(payloadBytes <= RelayProtocolConstants.maxPrivateFrameBytes, "longest allowed private response exceeds private frame cap")
        return true
    }()

    private static func requestID(from frame: RelayFrame) -> String {
        guard case .string(let requestID)? = frame.fields["request_id"] else {
            return ""
        }
        return requestID
    }

    private static func strictStandardBase64Payload(_ encoded: String) -> Data? {
        guard encoded.count.isMultiple(of: 4),
              encoded.allSatisfy({ character in
                  character.isASCII
                      && (character.isLetter || character.isNumber || character == "+" || character == "/" || character == "=")
              })
        else {
            return nil
        }
        if let firstPadding = encoded.firstIndex(of: "=") {
            // Standard base64 padding is terminal; accepting stripped or mid-string padding would drift from Node's fixture contract.
            guard encoded[firstPadding...].allSatisfy({ $0 == "=" }),
                  encoded.distance(from: firstPadding, to: encoded.endIndex) <= 2
            else {
                return nil
            }
        }
        return Data(base64Encoded: encoded)
    }

    private static func pongFrame() -> RelayFrame {
        RelayFrame(type: "pong")
    }

    private static func publicPayloadBytes(for frame: RelayFrame) throws -> Data {
        Data(try BoundedFrameStream.encode(frame).dropFirst(RelayProtocolConstants.frameLengthPrefixBytes))
    }

    private static func isAllowedNodeResultPayload(_ payload: Data, requestID: String) -> Bool {
        guard let frame = try? TopLevelJSONFrameScanner.scan(payload, capturedStringKeys: ["type", "request_id"]),
              (frame.type == "result" || frame.type == "error"),
              case .string(let payloadRequestID)? = frame.fields["request_id"],
              payloadRequestID == requestID
        else {
            return false
        }
        return true
    }
}

public enum PublicFDProbeEvent: Equatable {
    case data(Data)
    case eof
    case hangup
}

public protocol PublicFDProbeSource {
    var isReadable: Bool { get }
    func next(maximumBytes: Int) -> PublicFDProbeEvent?
}

public struct PathMetadata: Equatable {
    public var owner: uid_t
    public var group: gid_t
    public var mode: mode_t
    public var isDirectory: Bool
    public var isSymlink: Bool
    public var isSocket: Bool

    public init(owner: uid_t, group: gid_t, mode: mode_t, isDirectory: Bool, isSymlink: Bool, isSocket: Bool = false) {
        self.owner = owner
        self.group = group
        self.mode = mode
        self.isDirectory = isDirectory
        self.isSymlink = isSymlink
        self.isSocket = isSocket
    }
}

public protocol RelayFileSystem {
    func lstat(_ path: String) throws -> PathMetadata
    func unlink(_ path: String) throws
    func chmod(_ path: String, _ mode: mode_t) throws
}

public enum SocketPathCheckError: Error, Equatable {
    case emptyPath
    case rootPath
    case symlink(String)
    case notDirectory(String)
    case wrongOwner(String)
    case writableAncestor(String)
    case unsafeAncestorMode(String)
    case wrongSocketDirectoryMode(String)
    case leftoverNotSocket(String)
    case leftoverWrongOwner(String)
}

public enum RelayFileSystemError: Error, Equatable {
    case noEntry(String)
}

public struct SocketPathValidator {
    public let socketDirectory: String
    public let expectedSocketDirectoryOwner: uid_t
    public let expectedSocketDirectoryGroup: gid_t

    public init(socketDirectory: String, expectedSocketDirectoryOwner: uid_t, expectedSocketDirectoryGroup: gid_t) {
        self.socketDirectory = socketDirectory
        self.expectedSocketDirectoryOwner = expectedSocketDirectoryOwner
        self.expectedSocketDirectoryGroup = expectedSocketDirectoryGroup
    }

    public func validate(fileSystem: RelayFileSystem) throws {
        if socketDirectory.isEmpty {
            throw SocketPathCheckError.emptyPath
        }
        if socketDirectory == "/" {
            throw SocketPathCheckError.rootPath
        }
        let components = socketDirectory.split(separator: "/").map(String.init)
        var path = ""
        for (index, component) in components.enumerated() {
            path += "/" + component
            let metadata = try fileSystem.lstat(path)
            if metadata.isSymlink {
                // Every component is checked with lstat so the relay binds only inside the verified socket tree.
                throw SocketPathCheckError.symlink(path)
            }
            guard metadata.isDirectory else {
                throw SocketPathCheckError.notDirectory(path)
            }
            let isFinalDirectory = index == components.count - 1
            if isFinalDirectory {
                if metadata.owner != expectedSocketDirectoryOwner || metadata.group != expectedSocketDirectoryGroup {
                    throw SocketPathCheckError.wrongOwner(path)
                }
                let checkedBits = RelayProtocolConstants.permissionBitsMask
                    | RelayProtocolConstants.setuidBit
                    | RelayProtocolConstants.setgidBit
                    | RelayProtocolConstants.stickyBit
                if metadata.mode & checkedBits != RelayProtocolConstants.socketDirectoryMode {
                    throw SocketPathCheckError.wrongSocketDirectoryMode(path)
                }
            } else {
                if metadata.owner != RelayProtocolConstants.rootUid {
                    throw SocketPathCheckError.wrongOwner(path)
                }
                let unsafeBits = RelayProtocolConstants.setuidBit
                    | RelayProtocolConstants.setgidBit
                    | RelayProtocolConstants.stickyBit
                if metadata.mode & unsafeBits != 0 {
                    throw SocketPathCheckError.unsafeAncestorMode(path)
                }
                if metadata.mode & (RelayProtocolConstants.groupWriteBit | RelayProtocolConstants.worldWriteBit) != 0 {
                    throw SocketPathCheckError.writableAncestor(path)
                }
            }
        }
    }
}

public protocol RelayInstanceLock {
    func tryLock(_ path: String) -> Bool
}

public final class DarwinInstanceLock: RelayInstanceLock {
    private var heldFD: Int32?

    deinit { if let fd = heldFD { close(fd) } }

    public init() {}

    public func tryLock(_ path: String) -> Bool {
        guard heldFD == nil else { return false }
        let fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, RuntimeConfiguration.protectedFileMode)
        guard fd >= 0 else {
            return false
        }
        var info = stat()
        if fstat(fd, &info) != 0 || (info.st_mode & S_IFMT) != S_IFREG
            || info.st_uid != getuid() || info.st_mode & 0o7777 != RuntimeConfiguration.protectedFileMode {
            close(fd)
            return false
        }
        if flock(fd, LOCK_EX | LOCK_NB) != 0 {
            close(fd)
            return false
        }
        heldFD = fd
        return true
    }
}

public enum InstanceLockError: Error, Equatable {
    case unavailable(lockPath: String, operatorMessage: String)
}

public final class RelaySocketLifecycle {
    private let lockPath: String
    private let socketPath: String
    private let lock: RelayInstanceLock
    private let fileSystem: RelayFileSystem
    private let relayUid: uid_t
    private(set) public var didAcquireLock = false
    private(set) public var didUnlinkSocket = false

    public init(lockPath: String, socketPath: String, lock: RelayInstanceLock, fileSystem: RelayFileSystem, relayUid: uid_t = getuid()) {
        self.lockPath = lockPath
        self.socketPath = socketPath
        self.lock = lock
        self.fileSystem = fileSystem
        self.relayUid = relayUid
    }

    public func acquireBeforeSocketWork() throws {
        guard lock.tryLock(lockPath) else {
            throw InstanceLockError.unavailable(
                lockPath: lockPath,
                operatorMessage: "Hermes memory relay could not acquire \(lockPath)."
            )
        }
        didAcquireLock = true
    }

    public func unlinkLeftoverSocketWhileLocked() throws {
        guard didAcquireLock else {
            throw InstanceLockError.unavailable(
                lockPath: lockPath,
                operatorMessage: "Hermes memory relay requires \(lockPath) before socket reclaim."
            )
        }
        let metadata: PathMetadata
        do {
            metadata = try fileSystem.lstat(socketPath)
        } catch RelayFileSystemError.noEntry {
            didUnlinkSocket = false
            return
        }
        guard metadata.isSocket else {
            throw SocketPathCheckError.leftoverNotSocket(socketPath)
        }
        guard metadata.owner == relayUid else {
            throw SocketPathCheckError.leftoverWrongOwner(socketPath)
        }
        // Leftover sockets are reclaimed only under the process-lifetime flock so two relays cannot race bind ownership.
        try fileSystem.unlink(socketPath)
        didUnlinkSocket = true
    }
}

public struct ChildSpawnPlan: Equatable {
    public enum RelayFDAction: Equatable {
        case duplicate(source: Int32, target: Int32)
        // The fd-3 case is modeled as posix_spawn_file_actions_addinherit_np under POSIX_SPAWN_CLOEXEC_DEFAULT.
        case inherit(Int32)
    }

    public var executablePath: String
    public var arguments: [String]
    public var environment: [String: String]
    public var cloexecDefault: Bool
    public var relayFDAction: RelayFDAction
    public var stdinPath: String
    public var stdoutLogPath: String
    public var stderrLogPath: String

    // Must match validateHermesBridgeEnvironment in server/src/hermes-memory-bridge/process-shell.ts.
    // CoreFoundation may add its encoding hint after exec; the actual spawn array still contains exactly six configured keys.
    var environmentEntries: [String] { environment.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" } }

    public init(
        executablePath: String,
        arguments: [String],
        environment: [String: String],
        cloexecDefault: Bool,
        relayFDAction: RelayFDAction,
        stdinPath: String,
        stdoutLogPath: String,
        stderrLogPath: String
    ) {
        self.executablePath = executablePath
        self.arguments = arguments
        self.environment = environment
        self.cloexecDefault = cloexecDefault
        self.relayFDAction = relayFDAction
        self.stdinPath = stdinPath
        self.stdoutLogPath = stdoutLogPath
        self.stderrLogPath = stderrLogPath
    }
}

public enum ChildSupervisorError: Error, Equatable {
    case executablePathMustBeAbsolute
    case childReadyTimeout
    case childExitedBeforeReady
    case unexpectedReadyFrame
}

public struct ChildSupervisorConfig {
    public var executablePath: String
    public var bridgeEntryPath: String
    public var bridgeLogPath: String
    public var relayFD: Int32
    public var baseEnvironment: [String: String]
    public var bridgeIdentity: String
    public var agentID: String
    public var fortressID: String

    public init(
        executablePath: String,
        bridgeEntryPath: String,
        bridgeLogPath: String,
        relayFD: Int32,
        baseEnvironment: [String: String],
        bridgeIdentity: String,
        agentID: String,
        fortressID: String
    ) {
        self.executablePath = executablePath
        self.bridgeEntryPath = bridgeEntryPath
        self.bridgeLogPath = bridgeLogPath
        self.relayFD = relayFD
        self.baseEnvironment = baseEnvironment
        self.bridgeIdentity = bridgeIdentity
        self.agentID = agentID
        self.fortressID = fortressID
    }
}

public struct ChildSupervisor {
    public static let relayFDArgumentName = "--relay-fd"

    public static func spawnPlan(config: ChildSupervisorConfig) throws -> ChildSpawnPlan {
        guard config.executablePath.hasPrefix("/"), config.bridgeEntryPath.hasPrefix("/"), config.bridgeLogPath.hasPrefix("/") else {
            throw ChildSupervisorError.executablePathMustBeAbsolute
        }
        let sanitized = configuredEnvironment(
            baseEnvironment: config.baseEnvironment,
            bridgeIdentity: config.bridgeIdentity,
            agentID: config.agentID,
            fortressID: config.fortressID
        )
        let fdAction: ChildSpawnPlan.RelayFDAction = config.relayFD == RelayProtocolConstants.childInheritedRelayFD
            ? .inherit(config.relayFD)
            : .duplicate(source: config.relayFD, target: RelayProtocolConstants.childInheritedRelayFD)
        return ChildSpawnPlan(
            executablePath: config.executablePath,
            arguments: [
                config.executablePath,
                config.bridgeEntryPath,
                "hermes-memory-bridge",
                "run",
                relayFDArgumentName,
                "\(RelayProtocolConstants.childInheritedRelayFD)"
            ],
            environment: sanitized,
            cloexecDefault: true,
            relayFDAction: fdAction,
            stdinPath: "/dev/null",
            stdoutLogPath: config.bridgeLogPath,
            stderrLogPath: config.bridgeLogPath
        )
    }

    public static func configuredEnvironment(
        baseEnvironment input: [String: String],
        bridgeIdentity: String,
        agentID: String,
        fortressID: String
    ) -> [String: String] {
        // Must match HERMES_BRIDGE_ENV_ALLOWLIST in server/src/hermes-memory-bridge/process-shell.ts.
        let allowedKeys = Set([
            "HOME",
            "LANG",
            "TMPDIR"
        ])
        var output = input.filter { key, _ in allowedKeys.contains(key) }
        // Identity variables come from install configuration, never from inherited process environment.
        output["HERMES_MEMORY_BRIDGE_IDENTITY"] = bridgeIdentity
        output["HERMES_MEMORY_AGENT_ID"] = agentID
        output["HERMES_MEMORY_FORTRESS_ID"] = fortressID
        return output
    }

    public static func validateReadyFrame(_ frame: RelayFrame) throws {
        if frame.type != "ready" || !frame.fields.isEmpty {
            throw ChildSupervisorError.unexpectedReadyFrame
        }
        try FrameAllowlist.validate(frame, direction: .nodeToRelay)
    }
}

public enum RelayStartupState: Equatable {
    case state_AWAIT_LOCK
    case state_AWAIT_CHILD_READY
    case state_SERVING
}

public protocol RelayStartupOperations {
    func acquireInstanceLock() throws
    func validateSocketPathUnderLock() throws
    func spawnChild() throws
    func waitForChildReady(timeoutMilliseconds: Int) throws
    func unlinkLeftoverSocketWhileLocked() throws
    func bindPublicSocket() throws
    func chmodPublicSocket() throws
    func verifyPublicSocket() throws
    func killChild()
    func reapChild()
}

public struct RelayStartupCoordinator {
    private let operations: RelayStartupOperations
    private(set) public var state: RelayStartupState = .state_AWAIT_LOCK

    public init(operations: RelayStartupOperations) {
        self.operations = operations
    }

    public mutating func start() throws {
        try operations.acquireInstanceLock()
        try operations.validateSocketPathUnderLock()
        var childStarted = false
        do {
            try operations.spawnChild()
            childStarted = true
            state = .state_AWAIT_CHILD_READY
            try operations.waitForChildReady(timeoutMilliseconds: RelayProtocolConstants.childReadyTimeoutMilliseconds)
            try operations.unlinkLeftoverSocketWhileLocked()
            // The public socket is bound only after Node reports ready so failed composition never exposes a callable socket.
            try operations.bindPublicSocket()
            try operations.chmodPublicSocket()
            try operations.verifyPublicSocket()
            state = .state_SERVING
        } catch {
            if childStarted {
                operations.killChild()
                operations.reapChild()
            }
            throw error
        }
    }
}

public enum HermesMemoryRelayEntrypoint {
    public static func run(_ arguments: [String]) -> Never {
        run(arguments, main: RelayRuntime.main)
    }

    // Tests supply required filesystem/uid composition through the same entrypoint, never a runtime flag.
    static func run(_ arguments: [String], main: ([String]) -> Int32) -> Never {
        exit(main(arguments))
    }
}
