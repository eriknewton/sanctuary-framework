import Darwin
import Foundation
import XCTest
@testable import HermesMemoryRelayCore

final class RuntimeTests: XCTestCase {
    private func fixture(_ changes: [String: Any] = [:]) throws -> Data {
        var fields: [String: Any] = [
            "schema_version": 1, "node_executable": "/opt/node", "node_entry": "/opt/bridge.js",
            "bridge_log": "/private/bridge.log", "relay_log": "/private/relay.log",
            "public_socket": "/Library/memory.sock", "private_dir": "/private/bridge",
            "owner_uid": 501, "hermes_account": "hermes", "hermes_uid": 502, "group": "hermes",
            "fortress_id": "hermes-memory", "agent_id": "hermes", "identity_fingerprint": String(repeating: "a", count: 64)
        ]
        fields.merge(changes) { _, replacement in replacement }
        return try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
    }

    func testInvalidConfigNeverSpawnsOrBinds() throws {
        XCTAssertNoThrow(try RuntimeConfiguration.parse(fixture()), "validConfiguration")
        for changes: [String: Any] in [
            ["owner_uid": 0], ["hermes_uid": 501], ["schema_version": 2], ["unexpected": true],
            ["public_socket": "/" + String(repeating: "s", count: 104)], ["node_entry": "/opt/../entry.js"],
            ["node_executable": "/opt//node"], ["agent_id": ""], ["identity_fingerprint": "no"]
        ] {
            XCTAssertThrowsError(try RuntimeConfiguration.parse(fixture(changes)), "invalidConfigNeverSpawnsOrBinds")
            var composed = false
            let code = RelayRuntime.main(["relay", "--config", "/tmp/relay-config.json"], loadConfiguration: { _ in
                try RuntimeConfiguration.parse(self.fixture(changes))
            }, compose: { _ in
                composed = true
                throw RuntimeFailure.configuration
            })
            XCTAssertEqual(code, EX_CONFIG, "invalidConfigNeverSpawnsOrBinds")
            XCTAssertFalse(composed, "invalidConfigNeverSpawnsOrBinds")
        }
        let original = String(decoding: try fixture(), as: UTF8.self)
        for duplicate in ["owner_uid", "schema_version", "node_entry"] {
            let bytes = Data(("{\"" + duplicate + "\":1," + original.dropFirst()).utf8)
            XCTAssertThrowsError(try RuntimeConfiguration.parse(bytes), "duplicateConfigurationRefuses")
        }
        XCTAssertThrowsError(try RuntimeConfiguration.parse(Data(original.replacingOccurrences(of: "501", with: "true").utf8)))
    }

    func testPeerAdmissionRejectsUnsafeDescriptors() throws {
        let verifier = DarwinPeerCredentialProvider()
        var streams = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &streams), 0)
        defer { streams.forEach { close($0) } }
        // The developer account is not the configured Hermes principal.
        XCTAssertNotEqual(getuid(), RelayProtocolConstants.hermesUID)
        XCTAssertThrowsError(try verifier.peerUid(forFileDescriptor: streams[0]), "peerAdmissionRejectsUnsafeDescriptors")
        let unconnected = socket(AF_UNIX, SOCK_STREAM, 0)
        defer { close(unconnected) }
        XCTAssertThrowsError(try verifier.peerUid(forFileDescriptor: unconnected), "unconnectedPeerRefuses")
        var datagrams = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_DGRAM, 0, &datagrams), 0)
        defer { datagrams.forEach { close($0) } }
        XCTAssertThrowsError(try verifier.peerUid(forFileDescriptor: datagrams[0]), "nonStreamPeerRefuses")
    }

    func testProbeDrainSeesCancelBeforeReply() throws {
        var connection = RelayConnection(connectionID: "c1")
        _ = connection.receivePublicBytes(try BoundedFrameStream.encode(RelayFrame(type: "tools_list", fields: ["request_id": .string("r1")])))
        let cancel = try BoundedFrameStream.encode(RelayFrame(type: "cancel", fields: ["mcp_request_id": .string("r1")]))
        let source = IncrementalProbe([.data(cancel)])
        let result = connection.handleProbe(probe(), publicFD: source)
        XCTAssertEqual(result.compactMap(nodeType), ["frame", "probe_reply"], "probeDrainSeesCancelBeforeReply")
    }

    func testRuntimeFloodRetentionIsBounded() throws {
        let runtime = RelayRuntime(configuration: try RuntimeConfiguration.parse(fixture()), environment: [:],
                                   socketGroup: getgid(), instanceLock: DarwinInstanceLock(),
                                   verifySocketPath: { throw RuntimeFailure.socket },
                                   verifyPeer: { _ in throw RuntimeFailure.socket }, ordinaryReadsEnabled: { false })
        // Four live slots each reserve accepted, call, eight controls, closed, probe reply; one shutdown slot.
        let requiredPrivateQueueCap = 4 * (1 + 1 + 8 + 1 + 1) + 1
        for _ in 0..<requiredPrivateQueueCap {
            try runtime.enqueueNode(RelayFrame(type: "closed", fields: ["connection_id": .string("c1")]), id: nil, kind: nil)
        }
        XCTAssertThrowsError(try runtime.enqueueNode(RelayFrame(type: "closed", fields: ["connection_id": .string("c1")]), id: nil, kind: nil), "runtimeFloodRetentionIsBounded")
        var connection = RelayConnection(connectionID: "c1")
        let cancel = try BoundedFrameStream.encode(RelayFrame(type: "cancel", fields: ["mcp_request_id": .string("r1")]))
        let source = IncrementalProbe(Array(repeating: .data(cancel), count: 100))
        let output = connection.handleProbe(probe(), publicFD: source)
        let types = output.compactMap(nodeType)
        XCTAssertEqual(types.suffix(2), ["closed", "probe_reply"], "runtimeFloodRetentionIsBounded")
        XCTAssertLessThanOrEqual(source.reads, RelayProtocolConstants.probeDrainMaxFrames)
        XCTAssertEqual(RelayProtocolConstants.probeDrainMaxBytes, 131076)
    }

    func testControlSlotsRetireOnExactWrite() throws {
        var connection = RelayConnection(connectionID: "c1")
        let cancel = try BoundedFrameStream.encode(RelayFrame(type: "cancel", fields: ["mcp_request_id": .string("r1")]))
        for _ in 0..<RelayProtocolConstants.controlQueueDepthPerConnection { _ = connection.receivePublicBytes(cancel) }
        connection.markNodeFrameWritten(nil)
        XCTAssertTrue(connection.receivePublicBytes(cancel).compactMap(nodeType).contains("closed"), "controlSlotsRetireOnExactWrite")
    }

    func testNativeControlSlotsRetireOnExactWrite() throws {
        let runtime = RelayRuntime(configuration: try RuntimeConfiguration.parse(fixture()), environment: [:],
                                   socketGroup: getgid(), instanceLock: DarwinInstanceLock(),
                                   verifySocketPath: { throw RuntimeFailure.socket },
                                   verifyPeer: { _ in throw RuntimeFailure.socket }, ordinaryReadsEnabled: { false })
        var sockets = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { sockets.forEach { close($0) } }
        for fd in sockets { XCTAssertEqual(fcntl(fd, F_SETFL, O_NONBLOCK), 0) }
        // A one-KiB requested send buffer forces a partial write of the 64-KiB frame on Darwin.
        var capacity = Int32(RelayProtocolConstants.bytesPerKiB)
        XCTAssertEqual(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &capacity, socklen_t(MemoryLayout.size(ofValue: capacity))), 0)
        let payload = Data(repeating: UInt8(ascii: "x"), count: RelayProtocolConstants.maxPublicFrameBytes)
        var queue = [QueuedWrite(bytes: payload, connectionID: "c1", nodeCompletion: .forwardedControlFrame, clientCompletion: nil)]
        XCTAssertNil(try runtime.writeHead(&queue, fd: sockets[0]), "controlSlotsRetireOnExactWrite partial write")
        XCTAssertEqual(queue.count, 1, "controlSlotsRetireOnExactWrite")
        guard !queue.isEmpty else { return }
        let partial = queue[0].offset
        XCTAssertGreaterThan(partial, 0, "controlSlotsRetireOnExactWrite")
        XCTAssertLessThan(partial, payload.count, "controlSlotsRetireOnExactWrite")
        XCTAssertNil(try runtime.writeHead(&queue, fd: sockets[0]), "controlSlotsRetireOnExactWrite EAGAIN")
        XCTAssertEqual(queue[0].offset, partial, "controlSlotsRetireOnExactWrite EAGAIN")
        var received = Data(), buffer = [UInt8](repeating: 0, count: payload.count)
        var completed: QueuedWrite?
        // At least one byte must progress per successful turn; this bound also detects a stalled writer.
        for _ in 0...payload.count {
            let count = read(sockets[1], &buffer, buffer.count)
            if count > 0 { received.append(contentsOf: buffer.prefix(count)) }
            if !queue.isEmpty { completed = try runtime.writeHead(&queue, fd: sockets[0]) ?? completed }
            if received.count == payload.count && queue.isEmpty { break }
        }
        XCTAssertEqual(received, payload, "controlSlotsRetireOnExactWrite exact bytes")
        XCTAssertEqual(completed?.connectionID, "c1", "controlSlotsRetireOnExactWrite")
        if case .forwardedControlFrame? = completed?.nodeCompletion {} else { XCTFail("controlSlotsRetireOnExactWrite token") }
        XCTAssertTrue(queue.isEmpty, "controlSlotsRetireOnExactWrite")
    }

    func testControlResponseAllowanceWaitsForWrite() throws {
        var connection = RelayConnection(connectionID: "c1")
        let ping = try BoundedFrameStream.encode(RelayFrame(type: "ping"))
        // Two pongs is the wire-contract allowance, independent of the product counter.
        let requiredPongAllowance = 2
        for _ in 0..<requiredPongAllowance { _ = connection.receivePublicBytes(ping) }
        XCTAssertTrue(connection.receivePublicBytes(ping).compactMap(nodeType).contains("closed"), "controlResponseAllowanceWaitsForWrite")
    }

    func testFifthConnectionNeverReachesNode() throws {
        var admission = RelayAdmissionController()
        for _ in 0..<4 { XCTAssertEqual(try admission.acceptPeer().compactMap(nodeType), ["accepted"]) }
        XCTAssertEqual(try admission.acceptPeer(), [.closePublicConnection], "fifthConnectionNeverReachesNode")
    }

    func testSpawnUsesOnlyConfiguredEnvironment() throws {
        let output = ChildSupervisor.configuredEnvironment(baseEnvironment: [
            "HOME": "/fixture", "LANG": "C", "TMPDIR": "/fixture/tmp", "NODE_OPTIONS": "sensitive",
            "SANCTUARY_PASSPHRASE": "fixture-only", "HERMES_MEMORY_AGENT_ID": "untrusted"
        ], bridgeIdentity: "pin", agentID: "hermes", fortressID: "hermes-memory")
        XCTAssertEqual(Set(output.keys), Set(["HOME", "LANG", "TMPDIR", "HERMES_MEMORY_BRIDGE_IDENTITY", "HERMES_MEMORY_AGENT_ID", "HERMES_MEMORY_FORTRESS_ID"]), "spawnUsesOnlyConfiguredEnvironment")
        XCTAssertEqual(output["HERMES_MEMORY_AGENT_ID"], "hermes")
        let plan = try ChildSupervisor.spawnPlan(config: ChildSupervisorConfig(
            executablePath: "/opt/node", bridgeEntryPath: "/opt/cli.js", bridgeLogPath: "/tmp/log",
            relayFD: 4, baseEnvironment: ["HOME": "/tmp/home", "LANG": "C", "TMPDIR": "/tmp/tmp", "SECRET": "excluded"],
            bridgeIdentity: "pin", agentID: "hermes", fortressID: "hermes-memory"))
        // These are the entries materialized by posix_spawn, before the OS initializes the child.
        XCTAssertEqual(Set(plan.environmentEntries), Set([
            "HOME=/tmp/home", "LANG=C", "TMPDIR=/tmp/tmp", "HERMES_MEMORY_BRIDGE_IDENTITY=pin",
            "HERMES_MEMORY_AGENT_ID=hermes", "HERMES_MEMORY_FORTRESS_ID=hermes-memory"
        ]), "spawnUsesOnlyConfiguredEnvironment")
    }

    func testFlockPrecedesEverySocketOperation() throws {
        var pattern = Array("/tmp/hmr-XXXXXX".utf8CString)
        guard let pointer = mkdtemp(&pattern) else { throw RuntimeFailure.configuration }
        let root = String(cString: pointer)
        defer { try? FileManager.default.removeItem(atPath: root) }
        let lock = DarwinInstanceLock()
        XCTAssertTrue(lock.tryLock(root + "/relay.lock"))
        let socketPath = root + "/memory.sock"
        let serving = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(serving, 0)
        defer { close(serving) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: socketPath.utf8CString.map { UInt8(bitPattern: $0) })
        }
        func usingAddress(_ action: (UnsafePointer<sockaddr>, socklen_t) -> Int32) -> Int32 {
            withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    action($0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
        }
        XCTAssertEqual(usingAddress { Darwin.bind(serving, $0, $1) }, 0)
        XCTAssertEqual(listen(serving, 1), 0)
        XCTAssertEqual(fcntl(serving, F_SETFL, O_NONBLOCK), 0)
        var original = stat()
        XCTAssertEqual(lstat(socketPath, &original), 0)
        let config = try RuntimeConfiguration.parse(fixture([
            "private_dir": root, "public_socket": socketPath,
            "bridge_log": root + "/bridge.log", "relay_log": root + "/relay.log"
        ]))
        var socketWork = false
        let runtime = RelayRuntime(configuration: config, environment: [:], socketGroup: getgid(),
                                   instanceLock: DarwinInstanceLock(), verifySocketPath: { socketWork = true },
                                   verifyPeer: { _ in throw RuntimeFailure.socket }, ordinaryReadsEnabled: { true })
        XCTAssertEqual(runtime.run(), EX_CONFIG, "flockPrecedesEverySocketOperation")
        XCTAssertFalse(socketWork, "flockPrecedesEverySocketOperation")
        var retained = stat()
        XCTAssertEqual(lstat(socketPath, &retained), 0, "flockPrecedesEverySocketOperation")
        XCTAssertEqual(retained.st_ino, original.st_ino, "flockPrecedesEverySocketOperation")
        let client = socket(AF_UNIX, SOCK_STREAM, 0)
        defer { close(client) }
        XCTAssertEqual(usingAddress { connect(client, $0, $1) }, 0, "flockPrecedesEverySocketOperation")
        let accepted = accept(serving, nil, nil)
        XCTAssertGreaterThanOrEqual(accepted, 0, "flockPrecedesEverySocketOperation")
        if accepted >= 0 { close(accepted) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: config.bridgeLog), "flockPrecedesEverySocketOperation")
        withExtendedLifetime(lock) {}
    }

    func testRuntimeSeparatesChannelAllowlists() throws {
        let privateOnly = RelayFrame(type: "ready")
        XCTAssertThrowsError(try FrameAllowlist.validate(privateOnly, direction: .publicInbound), "runtimeSeparatesChannelAllowlists")
        let publicOnly = RelayFrame(type: "ping")
        XCTAssertThrowsError(try FrameAllowlist.validate(publicOnly, direction: .nodeToRelay), "runtimeSeparatesChannelAllowlists")
    }

    private func probe() -> RelayFrame {
        RelayFrame(type: "probe", fields: ["connection_id": .string("c1"), "nonce": .string(String(repeating: "a", count: 32))])
    }
    private func nodeType(_ output: RelayOutput) -> String? {
        if case .toNode(let frame, _) = output { return frame.type }
        return nil
    }
}

private final class IncrementalProbe: PublicFDProbeSource {
    var events: [PublicFDProbeEvent]
    var reads = 0
    init(_ events: [PublicFDProbeEvent]) { self.events = events }
    var isReadable: Bool { !events.isEmpty }
    func next(maximumBytes: Int) -> PublicFDProbeEvent? {
        guard !events.isEmpty else { return nil }
        reads += 1
        return events.removeFirst()
    }
}
