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
                                   verifyPeer: { _ in throw RuntimeFailure.socket }, ordinaryReadsEnabled: { false }, reapChild: Darwin.waitpid)
        // Four live or draining slots each reserve accepted, call, eight controls, closed, probe reply; one shutdown slot.
        let requiredPrivateQueueCap = 4 * (1 + 1 + 8 + 1 + 1) + 1
        for _ in 0..<(requiredPrivateQueueCap - 1) {
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
                                   verifyPeer: { _ in throw RuntimeFailure.socket }, ordinaryReadsEnabled: { false }, reapChild: Darwin.waitpid)
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
        // Six entries plus the terminating null pointer are inspected before the OS initializes the child.
        let materialized = RelayRuntime.withSpawnEnvironment(plan) { values in
            XCTAssertEqual(values.count, 7, "spawnUsesOnlyConfiguredEnvironment actual array")
            XCTAssertNil(values.last!, "spawnUsesOnlyConfiguredEnvironment terminator")
            return values.compactMap { $0.map { String(cString: $0) } }
        }
        XCTAssertEqual(Set(materialized), Set([
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
                                   verifyPeer: { _ in throw RuntimeFailure.socket }, ordinaryReadsEnabled: { true }, reapChild: Darwin.waitpid)
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

    func testProtectedConfigThroughBothEntrypoints() throws {
        // Darwin's per-user temp root has protected ancestors even when a runner sets TMPDIR=/tmp.
        var temporaryPath = [CChar](repeating: 0, count: Int(PATH_MAX))
        XCTAssertGreaterThan(confstr(_CS_DARWIN_USER_TEMP_DIR, &temporaryPath, temporaryPath.count), 0)
        // realpath resolves /var to /private/var before the production no-symlink ancestor walk.
        let resolvedTemporaryPath = try XCTUnwrap(realpath(temporaryPath, nil))
        defer { free(resolvedTemporaryPath) }
        let temporaryRoot = String(cString: resolvedTemporaryPath)
        let cases = ["valid", "mode", "owner", "leaf-link", "ancestor-link", "group-write", "other-write", "oversize", "oversize-stat",
                     "wrong-name", "private-mode", "exec-group-write", "exec-other-write", "entry-group-write", "entry-other-write",
                     "exec-no-x", "admin-member"]
        for scenario in cases {
            var template = Array((temporaryRoot + "/hmr-XXXXXX").utf8CString)
            let root = try XCTUnwrap(mkdtemp(&template)).withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
            defer { try? FileManager.default.removeItem(atPath: root) }
            let privateDir = root + "/private"
            try FileManager.default.createDirectory(atPath: privateDir, withIntermediateDirectories: false,
                                                   attributes: [.posixPermissions: 0o700])
            let node = root + "/node", entry = root + "/entry.js", path = privateDir + "/relay-config.json"
            try Data("#!/bin/sh\nexit 0\n".utf8).write(to: URL(fileURLWithPath: node))
            XCTAssertEqual(chmod(node, 0o700), 0)
            try Data("fixture".utf8).write(to: URL(fileURLWithPath: entry))
            let bytes = try fixture(["node_executable": node, "node_entry": entry,
                "private_dir": privateDir, "bridge_log": privateDir + "/bridge.log", "relay_log": privateDir + "/relay.log"])
            try bytes.write(to: URL(fileURLWithPath: path))
            XCTAssertEqual(chmod(path, 0o600), 0)
            var input = path
            switch scenario {
            case "mode": XCTAssertEqual(chmod(path, 0o644), 0)
            case "wrong-name":
                input = privateDir + "/other.json"
                try FileManager.default.copyItem(atPath: path, toPath: input)
            case "private-mode": XCTAssertEqual(chmod(privateDir, 0o750), 0) // Adds group read and search.
            case "exec-group-write": XCTAssertEqual(chmod(node, 0o720), 0) // Owner executable plus group write.
            case "exec-other-write": XCTAssertEqual(chmod(node, 0o702), 0) // Owner executable plus other write.
            case "entry-group-write": XCTAssertEqual(chmod(entry, 0o620), 0) // Owner read/write plus group write.
            case "entry-other-write": XCTAssertEqual(chmod(entry, 0o602), 0) // Owner read/write plus other write.
            case "exec-no-x": XCTAssertEqual(chmod(node, 0o600), 0) // Owner read/write without execute.
            case "leaf-link":
                try FileManager.default.moveItem(atPath: path, toPath: privateDir + "/actual")
                XCTAssertEqual(symlink(privateDir + "/actual", path), 0)
            case "ancestor-link":
                XCTAssertEqual(symlink(root, root + "/alias"), 0)
                input = root + "/alias/private/relay-config.json"
                let linked = try fixture(["node_executable": node, "node_entry": entry,
                    "private_dir": root + "/alias/private", "bridge_log": privateDir + "/bridge.log", "relay_log": privateDir + "/relay.log"])
                try linked.write(to: URL(fileURLWithPath: path))
            case "group-write": XCTAssertEqual(chmod(root, 0o720), 0)
            case "other-write": XCTAssertEqual(chmod(root, 0o702), 0)
            case "oversize":
                // Legal JSON plus whitespace isolates the size check from the schema parser.
                let oversized = bytes + Data(repeating: UInt8(ascii: " "), count: RuntimeConfiguration.maximumConfigBytes)
                try oversized.write(to: URL(fileURLWithPath: path))
                XCTAssertThrowsError(try RuntimeConfiguration.parse(oversized), "protectedConfig oversize parser")
            default: break
            }
            for option in ["--check-config", "--config"] {
                var composed = false, observedStat = false
                let code = RelayRuntime.main(["relay", option, input], loadConfiguration: { file in
                    try RuntimeConfiguration.load(path: file, descriptorMetadata: { fd in
                        var info = try RuntimeConfiguration.descriptorMetadata(fd)
                        observedStat = true
                        // Unprivileged host cannot chown to another uid; preserve every real stat field except owner.
                        if scenario == "owner" { info.st_uid = RelayProtocolConstants.hermesUID }
                        if scenario == "oversize-stat" { info.st_size = off_t(RuntimeConfiguration.maximumConfigBytes + 1) }
                        return info
                    }, lookup: RuntimeFixtureAccount(), admin: RuntimeFixtureAdmin(member: scenario == "admin-member"), groupExists: { _ in true })
                }, compose: { _ in composed = true; throw RuntimeFailure.readiness })
                XCTAssertEqual(code, scenario == "valid" && option == "--check-config" ? EX_OK : EX_CONFIG,
                               "protectedConfig \(scenario) \(option)")
                XCTAssertEqual(composed, scenario == "valid" && option == "--config", "protectedConfig \(scenario) \(option)")
                if scenario == "owner" { XCTAssertTrue(observedStat, "protectedConfig owner real stat") }
            }
        }
    }

    private func twoMaximumCalls() throws -> Data {
        func largeCall(_ id: String) throws -> Data {
            let empty = RelayFrame(type: "tools_call", fields: ["request_id": .string(id), "name": .string("memory_search"),
                "arguments": .object(["query": .string("")])])
            let padding = RelayProtocolConstants.maxPublicFrameBytes - (try BoundedFrameStream.encodedPayload(empty).count)
            var full = empty
            full.fields["arguments"] = .object(["query": .string(String(repeating: "x", count: padding))])
            return try BoundedFrameStream.encode(full)
        }
        return try largeCall("r1") + largeCall("r2")
    }

    func testProbeDrainRejectsSingleOverBudgetRead() throws {
        var connection = RelayConnection(connectionID: "c1")
        // This deliberately nonconforming source isolates the defensive per-read check.
        let source = OversizedProbe(bytes: try twoMaximumCalls())
        let result = connection.handleProbe(probe(), publicFD: source)
        XCTAssertEqual(result.compactMap(nodeType), ["closed", "probe_reply"], "singleReadByteBudget")
        XCTAssertEqual(source.reads, 1, "singleReadByteBudget")
    }

    func testProbeDrainEnforcesCumulativeByteBudget() throws {
        var connection = RelayConnection(connectionID: "c1")
        let bytes = try twoMaximumCalls()
        // Two legal payloads plus their four-byte prefixes: 2 x (65536 + 4) = 131080.
        let requiredInputBytes = 131080
        // One retained partial frame plus one read chunk: (65536 + 4) + 65536 = 131076.
        let requiredConsumedBytes = 131076
        let expectedReadSizes = [65536, 65536, 4] // Two full reads and the four remaining budget bytes.
        XCTAssertEqual(bytes.count, requiredInputBytes, "cumulativeByteBudget")
        let source = IncrementalProbe([.data(bytes)])
        let result = connection.handleProbe(probe(), publicFD: source)
        XCTAssertEqual(result.compactMap(nodeType).suffix(2), ["closed", "probe_reply"], "cumulativeByteBudget")
        XCTAssertEqual(source.consumedBytes, requiredConsumedBytes, "cumulativeByteBudget")
        XCTAssertEqual(source.readSizes, expectedReadSizes, "cumulativeByteBudget")
        XCTAssertEqual(source.reads, expectedReadSizes.count, "cumulativeByteBudget")
    }

    func testFullConformingProbeGrammar() throws {
        var connection = RelayConnection(connectionID: "c1")
        struct DrainVector: Decodable { let frame: RelayFrame; let probe_drain_repeat: Int? }
        struct Fixture: Decodable { let valid: [DrainVector] }
        let url = try XCTUnwrap(Bundle.module.url(forResource: "relay-frames", withExtension: "json"))
        let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: url))
        let frames = fixture.valid.flatMap { Array(repeating: $0.frame, count: $0.probe_drain_repeat ?? 0) }
        XCTAssertEqual(frames.count, RelayProtocolConstants.probeDrainMaxFrames, "fullConformingProbeGrammar shared pin")
        let source = IncrementalProbe(try frames.map { .data(try BoundedFrameStream.encode($0)) })
        let result = connection.handleProbe(probe(), publicFD: source)
        XCTAssertFalse(result.contains(.closePublicConnection), "fullConformingProbeGrammar")
        XCTAssertEqual(result.compactMap(nodeType).last, "probe_reply", "fullConformingProbeGrammar")
        XCTAssertEqual(source.reads, RelayProtocolConstants.probeDrainMaxFrames, "fullConformingProbeGrammar")
    }

    func testShutdownSlotCannotBeUsedByTraffic() throws {
        let runtime = RelayRuntime(configuration: try RuntimeConfiguration.parse(fixture()), environment: [:],
            socketGroup: getgid(), instanceLock: DarwinInstanceLock(), verifySocketPath: {}, verifyPeer: { _ in },
            ordinaryReadsEnabled: { false }, reapChild: Darwin.waitpid)
        let traffic = RelayFrame(type: "closed", fields: ["connection_id": .string("c1")])
        for _ in 0..<(RuntimeLimits.privateQueueFrames - 1) { try runtime.enqueueNode(traffic, id: nil, kind: nil) }
        XCTAssertThrowsError(try runtime.enqueueNode(traffic, id: nil, kind: nil), "reservedShutdownSlot")
        XCTAssertNoThrow(try runtime.enqueueNode(RelayShutdownModel.gracefulShutdownFrame(), id: nil, kind: nil), "reservedShutdownSlot")
    }

    func testControlReservationTracksActualEnqueue() throws {
        let runtime = RelayRuntime(configuration: try RuntimeConfiguration.parse(fixture()), environment: [:],
            socketGroup: getgid(), instanceLock: DarwinInstanceLock(), verifySocketPath: {}, verifyPeer: { _ in },
            ordinaryReadsEnabled: { false }, reapChild: Darwin.waitpid)
        let traffic = RelayFrame(type: "closed", fields: ["connection_id": .string("c1")])
        var core = RelayConnection(connectionID: "c1")
        let cancel = try BoundedFrameStream.encode(RelayFrame(type: "cancel", fields: ["mcp_request_id": .string("r1")]))
        let output = core.receivePublicBytes(cancel)
        guard case .toNode(let frame, let kind) = try XCTUnwrap(output.first) else { return XCTFail("controlEnqueueAccounting") }
        XCTAssertEqual(core.queuedControlCount, 0, "controlEnqueueAccounting before queue")
        try runtime.enqueueReservedNode(frame, id: "c1", kind: kind, core: &core)
        XCTAssertEqual(core.queuedControlCount, 1, "controlEnqueueAccounting accepted")
        XCTAssertEqual(core.reservedControlCount, 0, "controlEnqueueAccounting accepted")
        for _ in 1..<(RuntimeLimits.privateQueueFrames - 1) { try runtime.enqueueNode(traffic, id: nil, kind: nil) }
        _ = core.receivePublicBytes(cancel)
        XCTAssertThrowsError(try runtime.enqueueReservedNode(frame, id: "c1", kind: kind, core: &core), "controlEnqueueAccounting refused")
        XCTAssertEqual(core.queuedControlCount, 1, "controlEnqueueAccounting refused")
        XCTAssertEqual(core.reservedControlCount, 0, "controlEnqueueAccounting refused")
        core.markNodeFrameWritten(kind)
        XCTAssertEqual(core.queuedControlCount, 0, "controlEnqueueAccounting written")
    }

    func testSpawnChildEndpointClosesAndDeliversEOF() throws {
        var pattern = Array("/tmp/hmr-XXXXXX".utf8CString)
        let root = String(cString: try XCTUnwrap(mkdtemp(&pattern)))
        defer { try? FileManager.default.removeItem(atPath: root) }
        let script = root + "/eof.cjs"
        try """
        const fs=require('node:fs');const channel=new(require('node:net').Socket)({fd:3});
        channel.on('end',()=>{fs.writeFileSync(process.env.HOME+'/eof','observed');process.exit(0);});
        channel.on('error',()=>process.exit(1));channel.resume();
        setTimeout(()=>process.exit(2),2000);
        """.write(toFile: script, atomically: false, encoding: .utf8)
        let node = try XCTUnwrap(["/usr/local/bin/node", "/opt/homebrew/bin/node"].first { FileManager.default.isExecutableFile(atPath: $0) })
        let config = try RuntimeConfiguration.parse(fixture(["node_executable": node, "node_entry": script,
            "bridge_log": root + "/bridge.log", "relay_log": root + "/relay.log", "private_dir": root, "public_socket": root + "/memory.sock"]))
        let runtime = RelayRuntime(configuration: config, environment: ["HOME": root, "LANG": "C", "TMPDIR": "/tmp"],
            socketGroup: getgid(), instanceLock: DarwinInstanceLock(), verifySocketPath: {}, verifyPeer: { _ in },
            ordinaryReadsEnabled: { false }, reapChild: Darwin.waitpid)
        try runtime.state_SPAWN_CHILD()
        let pid = try XCTUnwrap(runtime.child)
        var reaped = false
        defer { if !reaped { _ = kill(pid, SIGKILL); var status: Int32 = 0; _ = waitpid(pid, &status, 0) } }
        XCTAssertEqual(runtime.childEndpointFlags & FD_CLOEXEC, FD_CLOEXEC, "childEndpointCLOEXEC")
        runtime.closePrivateChannel()
        var status: Int32 = 0
        XCTAssertEqual(waitpid(pid, &status, 0), pid, "childEndpointEOF")
        reaped = true
        XCTAssertEqual(status, 0, "childEndpointEOF")
        XCTAssertEqual(try String(contentsOfFile: root + "/eof", encoding: .utf8), "observed", "childEndpointEOF")
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
    var readSizes: [Int] = []
    var consumedBytes: Int { readSizes.reduce(0, +) }
    init(_ events: [PublicFDProbeEvent]) { self.events = events }
    var isReadable: Bool { !events.isEmpty }
    func next(maximumBytes: Int) -> PublicFDProbeEvent? {
        guard !events.isEmpty else { return nil }
        reads += 1
        let event = events.removeFirst()
        guard case .data(let bytes) = event else { return event }
        // Preserve the unread tail so the fixture obeys the same maximumBytes contract as native reads.
        let chunk = Data(bytes.prefix(maximumBytes))
        if bytes.count > chunk.count { events.insert(.data(Data(bytes.dropFirst(chunk.count))), at: 0) }
        readSizes.append(chunk.count)
        return .data(chunk)
    }
}

private final class OversizedProbe: PublicFDProbeSource {
    let bytes: Data
    var reads = 0
    init(bytes: Data) { self.bytes = bytes }
    var isReadable: Bool { reads == 0 }
    func next(maximumBytes: Int) -> PublicFDProbeEvent? {
        guard isReadable else { return nil }
        reads += 1
        return .data(bytes)
    }
}

struct RuntimeFixtureAccount: AccountUIDLookup {
    func uid(forAccountName name: String) throws -> uid_t { RelayProtocolConstants.hermesUID }
}
struct RuntimeFixtureAdmin: AdminGroupMembership {
    var member = false
    func isAdmin(uid: uid_t) throws -> Bool { member }
}
