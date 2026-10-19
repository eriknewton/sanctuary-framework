import Darwin
import Foundation

/// Protected installation inputs for scoped memory search and get; writes not yet available.
public struct RuntimeConfiguration: Equatable {
    public let nodeExecutable: String
    public let nodeEntry: String
    public let bridgeLog: String
    public let relayLog: String
    public let publicSocket: String
    public let privateDirectory: String
    public let ownerUID: uid_t
    public let hermesAccount: String
    public let hermesUID: uid_t
    public let group: String
    public let fortressID: String
    public let agentID: String
    public let identityFingerprint: String

    // PATH_MAX bounds each of six paths; remaining identifiers fit in one additional path budget.
    static let maximumConfigBytes = Int(PATH_MAX) * 7
    // Darwin sun_path has 104 bytes, including its terminating NUL.
    static let maximumSocketPathBytes = MemoryLayout.size(ofValue: sockaddr_un().sun_path) - 1
    static let protectedFileMode = mode_t(0o600)
    static let schemaVersion = 1
    static let keys: Set<String> = [
        "schema_version", "node_executable", "node_entry", "bridge_log", "relay_log",
        "public_socket", "private_dir", "owner_uid", "hermes_account", "hermes_uid", "group",
        "fortress_id", "agent_id", "identity_fingerprint"
    ]

    /// Parse the exact v1 schema. Validation does not grant permission to spawn or bind.
    public static func parse(_ bytes: Data) throws -> RuntimeConfiguration {
        guard bytes.count <= maximumConfigBytes else { throw RuntimeFailure.configuration }
        var parser = FlatConfigurationParser(bytes: Array(bytes))
        let fields = try parser.parse()
        guard Set(fields.keys) == keys else { throw RuntimeFailure.configuration }
        func text(_ key: String) throws -> String {
            guard case .string(let value)? = fields[key], !value.isEmpty,
                  !value.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else {
                throw RuntimeFailure.configuration
            }
            return value
        }
        func integer(_ key: String) throws -> UInt32 {
            guard case .integer(let value)? = fields[key] else { throw RuntimeFailure.configuration }
            return value
        }
        guard try integer("schema_version") == schemaVersion,
              try integer("owner_uid") == RelayProtocolConstants.ownerUID,
              try integer("hermes_uid") == RelayProtocolConstants.hermesUID else { throw RuntimeFailure.configuration }
        let result = try RuntimeConfiguration(
            nodeExecutable: text("node_executable"), nodeEntry: text("node_entry"),
            bridgeLog: text("bridge_log"), relayLog: text("relay_log"), publicSocket: text("public_socket"),
            privateDirectory: text("private_dir"), ownerUID: integer("owner_uid"),
            hermesAccount: text("hermes_account"), hermesUID: integer("hermes_uid"), group: text("group"),
            fortressID: text("fortress_id"), agentID: text("agent_id"), identityFingerprint: text("identity_fingerprint")
        )
        for path in [result.nodeExecutable, result.nodeEntry, result.bridgeLog, result.relayLog,
                     result.publicSocket, result.privateDirectory] { try normalizedAbsolute(path) }
        guard result.publicSocket.utf8.count <= maximumSocketPathBytes,
              result.identityFingerprint.utf8.count == 64,
              result.identityFingerprint.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              validID(result.fortressID), validID(result.agentID) else { throw RuntimeFailure.configuration }
        return result
    }

    /// Open one owner-only config without following links, then validate its protected inputs.
    public static func load(path: String) throws -> RuntimeConfiguration {
        try normalizedAbsolute(path)
        try validateChain(parent(path), owner: RelayProtocolConstants.ownerUID)
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw RuntimeFailure.configuration }
        defer { close(fd) }
        var info = stat()
        // Descriptor metadata binds the bytes being parsed, rather than a prior path observation.
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == RelayProtocolConstants.ownerUID,
              info.st_mode & 0o7777 == protectedFileMode,
              info.st_size > 0, info.st_size <= maximumConfigBytes else { throw RuntimeFailure.configuration }
        var bytes = Data()
        var buffer = [UInt8](repeating: 0, count: maximumConfigBytes + 1)
        while bytes.count <= maximumConfigBytes {
            let count = read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw RuntimeFailure.configuration }
            if count == 0 { break }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        let config = try parse(bytes)
        guard path == config.privateDirectory + "/relay-config.json" else { throw RuntimeFailure.configuration }
        try config.validateProtectedInputs()
        return config
    }

    func validateProtectedInputs() throws {
        guard getuid() == ownerUID, geteuid() == ownerUID else { throw RuntimeFailure.configuration }
        try Self.validateChain(privateDirectory, owner: ownerUID)
        let directory = try Self.metadata(privateDirectory)
        guard directory.st_uid == ownerUID, directory.st_mode & 0o7777 == RelayProtocolConstants.privateDirectoryMode else {
            throw RuntimeFailure.configuration
        }
        for path in [nodeExecutable, nodeEntry] {
            try Self.validateChain(Self.parent(path), owner: ownerUID)
            let info = try Self.metadata(path)
            guard info.st_mode & S_IFMT == S_IFREG,
                  info.st_uid == 0 || info.st_uid == ownerUID,
                  info.st_mode & 0o022 == 0 else { throw RuntimeFailure.configuration }
        }
        guard access(nodeExecutable, X_OK) == 0 else { throw RuntimeFailure.configuration }
        for path in [bridgeLog, relayLog] {
            try Self.validateChain(Self.parent(path), owner: ownerUID)
        }
        let identity = try HermesInstallIdentity(pinnedUID: hermesUID, accountName: hermesAccount)
            .validate(lookup: DarwinAccountUIDLookup())
        _ = try PeerVerifier(installIdentity: identity, ownerUid: ownerUID,
                            credentials: DarwinPeerCredentialProvider(), adminMembership: DarwinAdminGroupMembership())
        guard getgrnam(group) != nil else { throw RuntimeFailure.configuration }
        // Public socket metadata is intentionally inspected only after acquiring the instance flock.
    }

    static func normalizedAbsolute(_ path: String) throws {
        guard path.hasPrefix("/"), !path.contains("\0"), path != "/", !path.hasSuffix("/"),
              !path.split(separator: "/", omittingEmptySubsequences: false).dropFirst().contains(where: {
                  $0.isEmpty || $0 == "." || $0 == ".."
              }), path.utf8.count < Int(PATH_MAX) else { throw RuntimeFailure.configuration }
    }

    static func parent(_ path: String) -> String { URL(fileURLWithPath: path).deletingLastPathComponent().path }

    static func metadata(_ path: String) throws -> stat {
        var info = stat()
        guard lstat(path, &info) == 0 else { throw RuntimeFailure.configuration }
        return info
    }

    static func validateChain(_ path: String, owner: uid_t) throws {
        var current = ""
        for part in path.split(separator: "/") {
            current += "/" + part
            let info = try metadata(current)
            // Every traversed component must remain an owner/root-controlled directory, never a symlink.
            guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == 0 || info.st_uid == owner,
                  info.st_mode & 0o022 == 0 else { throw RuntimeFailure.configuration }
        }
    }

    private static func validID(_ value: String) -> Bool {
        // Must match ID_GRAMMAR in server/src/hermes-memory-bridge/process-shell.ts: at most 63 ASCII bytes.
        let bytes = Array(value.utf8)
        let alphanumeric: (UInt8) -> Bool = { (48...57).contains($0) || (97...122).contains($0) }
        return !bytes.isEmpty && bytes.count <= 63 && alphanumeric(bytes[0])
            && bytes.allSatisfy { alphanumeric($0) || $0 == 45 }
    }
}

/// Fixed operator classifications; arbitrary exception text never reaches logs.
public enum RuntimeFailure: Error {
    case configuration, lock, spawn, readiness, transport, socket, reapTimeout
}

private enum ConfigurationValue {
    case string(String)
    case integer(UInt32)
}

/// V1 is a flat object of strings and unsigned integers; duplicates are rejected before decoding.
private struct FlatConfigurationParser {
    let bytes: [UInt8]
    var index = 0

    mutating func whitespace() {
        while index < bytes.count && [UInt8(32), 9, 10, 13].contains(bytes[index]) { index += 1 }
    }

    mutating func consume(_ byte: UInt8) throws {
        whitespace()
        guard index < bytes.count, bytes[index] == byte else { throw RuntimeFailure.configuration }
        index += 1
    }

    mutating func string() throws -> String {
        whitespace()
        let start = index
        try consume(UInt8(ascii: "\""))
        var escaped = false
        while index < bytes.count {
            let byte = bytes[index]
            index += 1
            if escaped { escaped = false; continue }
            if byte == UInt8(ascii: "\\") { escaped = true; continue }
            if byte == UInt8(ascii: "\"") {
                return try JSONDecoder().decode(String.self, from: Data(bytes[start..<index]))
            }
        }
        throw RuntimeFailure.configuration
    }

    mutating func parse() throws -> [String: ConfigurationValue] {
        try consume(UInt8(ascii: "{"))
        var result: [String: ConfigurationValue] = [:]
        while true {
            let key = try string()
            // The exact field set also bounds parser state and disallows future unreviewed knobs.
            guard RuntimeConfiguration.keys.contains(key), result[key] == nil else { throw RuntimeFailure.configuration }
            try consume(UInt8(ascii: ":"))
            whitespace()
            guard index < bytes.count else { throw RuntimeFailure.configuration }
            if bytes[index] == UInt8(ascii: "\"") { result[key] = .string(try string()) }
            else {
                let start = index
                while index < bytes.count && (48...57).contains(bytes[index]) { index += 1 }
                guard index > start, index - start == 1 || bytes[start] != UInt8(ascii: "0"),
                      let number = UInt32(String(decoding: bytes[start..<index], as: UTF8.self)) else {
                    throw RuntimeFailure.configuration
                }
                result[key] = .integer(number)
            }
            whitespace()
            guard index < bytes.count else { throw RuntimeFailure.configuration }
            if bytes[index] == UInt8(ascii: "}") { index += 1; break }
            try consume(UInt8(ascii: ","))
        }
        whitespace()
        guard index == bytes.count else { throw RuntimeFailure.configuration }
        return result
    }
}
