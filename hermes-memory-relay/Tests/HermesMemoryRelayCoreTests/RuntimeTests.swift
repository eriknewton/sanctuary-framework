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
