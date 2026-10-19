import XCTest
@testable import HermesMemoryRelayCore

private let testExpectedUid = uid_t(502)
private let testRelayUid = uid_t(501)
private let testOwnerUid = uid_t(500)
private let testAdminUid = uid_t(504)
private let testFD = Int32(9)
private let testRootGroup = gid_t(0)
private let testGroup = gid_t(210)
private let testRootAncestorMode = mode_t(0o755)
private let testSocketDirectory = "/Library/Application Support/Sanctuary/HermesMemoryBridge/sockets"
private let testSocketPath = testSocketDirectory + "/memory.sock"
private let testLockPath = "/Users/owner/Library/Application Support/Sanctuary/hermes-memory-bridge/private/relay.lock"
private let testBridgeLogPath = "/Users/owner/Library/Logs/Sanctuary/hermes-memory-bridge.log"
private let testProbeNonce = "0123456789abcdef0123456789abcdef"

final class BoundedFrameStreamTests: XCTestCase {
    func testDuplicateTopLevelReadKeysPoisonPublicJSON() throws {
        var stream = BoundedFrameStream()
        let duplicateTop = #"{"type":"cancel","mcp_request_id":"a","mcp_request_id":"b"}"#

        XCTAssertThrowsError(try stream.append(Self.prefixedJSON(duplicateTop)))
        XCTAssertTrue(stream.isPoisoned)
    }

    func testTopLevelDuplicatePoisonsButNestedDuplicateIsForwarded() throws {
        var topLevelStream = BoundedFrameStream()
        let duplicateTop = #"{"type":"cancel","mcp_request_id":"a","mcp_request_id":"b"}"#
        XCTAssertThrowsError(try topLevelStream.append(Self.prefixedJSON(duplicateTop)))
        XCTAssertTrue(topLevelStream.isPoisoned)

        var nestedStream = BoundedFrameStream()
        let duplicateNested = #"{"type":"tools_call","request_id":"r","name":"memory_search","arguments":{"query":"a","query":"b"}}"#
        let frames = try nestedStream.append(Self.prefixedJSON(duplicateNested))
        XCTAssertEqual(frames.map(\.type), ["tools_call"])
        XCTAssertFalse(nestedStream.isPoisoned)
    }

    func testEscapedDuplicateTopLevelReadKeyPoisonsPublicJSON() throws {
        var stream = BoundedFrameStream()
        let duplicateType = #"{"type":"ping","\u0074ype":"shutdown"}"#

        XCTAssertThrowsError(try stream.append(Self.prefixedJSON(duplicateType)))
        XCTAssertTrue(stream.isPoisoned)
    }

    func testNestedStringDelimitersAndTrailingBytesAreChecked() throws {
        var nestedStringStream = BoundedFrameStream()
        let nestedString = #"{"type":"tools_call","request_id":"mcp-1","name":"memory_search","arguments":{"query":"]}\"[{","items":["}\""]}}"#
        XCTAssertEqual(try nestedStringStream.append(Self.prefixedJSON(nestedString)).map(\.type), ["tools_call"])

        var trailingStream = BoundedFrameStream()
        let trailing = #"{"type":"ping"}x"#
        XCTAssertThrowsError(try trailingStream.append(Self.prefixedJSON(trailing)))
        XCTAssertTrue(trailingStream.isPoisoned)

        var controlStream = BoundedFrameStream()
        let unescapedControl = Data(#"{"type":"tools_list","request_id":"a"#.utf8)
            + Data([0x01])
            + Data(#"b"}"#.utf8)
        XCTAssertThrowsError(try controlStream.append(Self.prefixed(unescapedControl)))
        XCTAssertTrue(controlStream.isPoisoned)
    }

    func testDeepNestingPoisonsOnSmallStack() throws {
        let prefix = #"{"type":"tools_call","request_id":"mcp-deep","name":"memory_search","arguments":"#
        let suffix = "}"
        let payload = Data(
            (prefix
                + String(repeating: "[", count: RelayProtocolConstants.maxPublicFrameBytes - Data(prefix.utf8).count - Data(suffix.utf8).count)
                + suffix).utf8
        )
        let done = expectation(description: "bounded scanner returns")
        let thread = Thread {
            var connection = RelayConnection(connectionID: "conn-deep")
            let outputs = connection.receivePublicBytes(Self.prefixed(payload))
            XCTAssertEqual(Self.closedCount(in: outputs), 1)
            XCTAssertTrue(outputs.contains(.closePublicConnection))
            done.fulfill()
        }
        thread.stackSize = 512 * RelayProtocolConstants.bytesPerKiB
        thread.start()
        wait(for: [done], timeout: 30)
    }

    func testNestingDepthIsBoundedBeforeAllowlist() throws {
        let excessiveDepth = RelayProtocolConstants.maxJSONNestingDepth + 1
        let payload = #"{"type":"ping","pad":"# + String(repeating: "[", count: excessiveDepth)
            + String(repeating: "]", count: excessiveDepth) + "}"
        var stream = BoundedFrameStream()

        XCTAssertThrowsError(try stream.append(Self.prefixedJSON(payload)))
        XCTAssertTrue(stream.isPoisoned)
    }

    func testNestingDepthBoundaryAllowsNamedLimitBelowTopLevelObject() throws {
        let allowedDepth = RelayProtocolConstants.maxJSONNestingDepth
        let allowedPayload = #"{"type":"ping","pad":"# + String(repeating: "[", count: allowedDepth)
            + String(repeating: "]", count: allowedDepth) + "}"
        var allowedStream = BoundedFrameStream()
        XCTAssertEqual(try allowedStream.append(Self.prefixedJSON(allowedPayload)).map(\.type), ["ping"])

        let refusedDepth = RelayProtocolConstants.maxJSONNestingDepth + 1
        let refusedPayload = #"{"type":"ping","pad":"# + String(repeating: "[", count: refusedDepth)
            + String(repeating: "]", count: refusedDepth) + "}"
        var refusedStream = BoundedFrameStream()
        XCTAssertThrowsError(try refusedStream.append(Self.prefixedJSON(refusedPayload)))
    }

    func testPrivateEnvelopeForMaxPublicSlashPayloadStaysWithinCap() throws {
        let publicPayload = Data(repeating: 0xff, count: RelayProtocolConstants.maxPublicFrameBytes)
        let envelope = RelayFrame(type: "frame", fields: [
            "connection_id": .string("c1"),
            "frame_b64": .string(publicPayload.base64EncodedString())
        ])
        let privatePayloadBytes = try BoundedFrameStream.encodedPayload(envelope).count

        XCTAssertLessThanOrEqual(privatePayloadBytes, RelayProtocolConstants.maxPrivateFrameBytes)
    }

    func testMultiFrameStreamAcceptsSecondValidFrame() throws {
        var stream = BoundedFrameStream()
        let first = RelayFrame(type: "ping")
        let second = RelayFrame(type: "shutdown")
        let data = try BoundedFrameStream.encode(first) + BoundedFrameStream.encode(second)

        let frames = try stream.append(data)

        XCTAssertEqual(frames.map(\.type), ["ping", "shutdown"])
        XCTAssertFalse(stream.hasPartialFrame)
    }

    func testLargeCompleteFramesDecodeBeforePartialCap() throws {
        var stream = BoundedFrameStream()
        let payload = String(repeating: "a", count: 48 * RelayProtocolConstants.bytesPerKiB)
        let first = RelayFrame(type: "hello", fields: ["request_id": .string("mcp-large-hello"), "protocol_version": .string("2026-10-12"), "client_name": .string(payload)])
        let second = RelayFrame(type: "tools_list", fields: ["request_id": .string("mcp-large")])
        let data = try BoundedFrameStream.encode(first) + BoundedFrameStream.encode(second)

        let frames = try stream.append(data)

        XCTAssertEqual(frames.map(\.type), ["hello", "tools_list"])
        XCTAssertFalse(stream.hasPartialFrame)
    }

    func testCompleteFramePlusLargeIncompleteTailKeepsDecodedPrefix() throws {
        var stream = BoundedFrameStream(
            maxFrameBytes: RelayProtocolConstants.bytesPerKiB,
            maxFrameOverheadBytes: RelayProtocolConstants.bytesPerKiB
        )
        let complete = RelayFrame(type: "ping")
        let partialTailBytes = RelayProtocolConstants.frameLengthPrefixBytes
            + RelayProtocolConstants.bytesPerKiB
            + RelayProtocolConstants.bytesPerKiB
            + 1
        let partial = BoundedFrameStream.encodeLengthOnly(UInt32(RelayProtocolConstants.bytesPerKiB))
            + Data(repeating: UInt8(ascii: "x"), count: partialTailBytes)
        let frames = try stream.append(try BoundedFrameStream.encode(complete) + partial)

        XCTAssertEqual(frames.map(\.type), ["ping"])
        XCTAssertTrue(stream.isPoisoned)
    }

    func testOverlargeLengthRejectedBeforePayloadAllocation() throws {
        var stream = BoundedFrameStream(maxFrameBytes: RelayProtocolConstants.bytesPerKiB)
        let overlargeLength = UInt32(RelayProtocolConstants.bytesPerKiB + 1)

        XCTAssertThrowsError(try stream.append(BoundedFrameStream.encodeLengthOnly(overlargeLength))) { error in
            XCTAssertEqual(error as? FrameStreamError, .overlargeLength(overlargeLength))
        }
        XCTAssertTrue(stream.isPoisoned)
    }

    func testPartialRetentionIsBounded() throws {
        var stream = BoundedFrameStream(
            maxFrameBytes: RelayProtocolConstants.bytesPerKiB,
            maxFrameOverheadBytes: RelayProtocolConstants.bytesPerKiB
        )
        let retainedBytes = RelayProtocolConstants.frameLengthPrefixBytes
            + RelayProtocolConstants.bytesPerKiB
            + RelayProtocolConstants.bytesPerKiB
            + 1
        let partial = BoundedFrameStream.encodeLengthOnly(UInt32(RelayProtocolConstants.bytesPerKiB))
            + Data(repeating: UInt8(ascii: "x"), count: retainedBytes)

        XCTAssertThrowsError(try stream.append(partial))
        XCTAssertTrue(stream.isPoisoned)
    }

    private static func prefixedJSON(_ json: String) -> Data {
        prefixed(Data(json.utf8))
    }

    private static func prefixed(_ payload: Data) -> Data {
        var output = BoundedFrameStream.encodeLengthOnly(UInt32(payload.count))
        output.append(payload)
        return output
    }

    private static func closedCount(in outputs: [RelayOutput]) -> Int {
        outputs.filter { output in
            guard case .toNode(let frame, _) = output else { return false }
            return frame.type == "closed"
        }.count
    }
}

final class FrameFixtureTests: XCTestCase {
    func testRelayFrameFixtureMatchesAllowlists() throws {
        let fixture = try RelayFixture.load()
        let expectedValidNames: Set<String> = [
            "public hello",
            "public tools list",
            "public tool call",
            "public cancel",
            "public ping",
            "public shutdown",
            "node ready",
            "node probe",
            "node response",
            "node close",
            "relay accepted",
            "relay frame envelope",
            "relay closed",
            "relay probe reply",
            "relay shutdown",
            "client result",
            "client error",
            "client pong"
        ]
        XCTAssertEqual(Set(fixture.valid.map(\.name)), expectedValidNames)

        for vector in fixture.valid + fixture.malformed + fixture.wrongAllowlist {
            try vector.assertExpectedAction()
        }

        XCTAssertEqual(Set(fixture.streamCases.map(\.name)), [
            "overlarge length",
            "partial frame",
            "two 48 KiB frames",
            "max public frame plus partial tail",
            "duplicate public key",
            "nested duplicate public key",
            "escaped duplicate public key",
            "node result valid",
            "node result over cap",
            "node result mismatched id",
            "node result lone surrogate",
            "node result over depth",
            "refused cancel",
            "node close then late response",
            "node result padded base64",
            "node result unpadded base64",
            "request id over cap",
            "request id disallowed character",
            "request id escaped legal character",
            "node response private cap exact",
            "node response private cap over",
            "relay accepted bytes",
            "relay frame bytes",
            "relay closed bytes",
            "relay probe reply bytes",
            "relay closed then late probe reply",
            "relay probe reply after timeout",
            "relay shutdown bytes",
            "relay bad json",
            "relay unknown type",
            "relay missing field",
            "relay duplicate key",
            "relay over cap length",
            "relay probe reply never accepted connection"
        ])

        var streamActionByChannelAndBytes: [String: (name: String, action: String)] = [:]
        for streamCase in fixture.streamCases {
            try Self.assertNoConflictingAction(
                channel: streamCase.channel,
                bytesHex: streamCase.bytesHex,
                action: streamCase.expectedAction,
                name: streamCase.name,
                seen: &streamActionByChannelAndBytes
            )
        }

        let expectedBytesHexByName = try StreamVector.expectedBytesHexByName()
        for streamCase in fixture.streamCases {
            XCTAssertEqual(streamCase.bytesHex, expectedBytesHexByName[streamCase.name], streamCase.name)
            XCTAssertEqual(streamCase.thenBytesHex, StreamVector.expectedThenBytesHexByName[streamCase.name], streamCase.name)
            try streamCase.assertExpectedAction()
        }
    }

    private static func assertNoConflictingAction(
        channel: String,
        bytesHex: String,
        action: String,
        name: String,
        seen: inout [String: (name: String, action: String)]
    ) throws {
        let key = "\(channel)\u{0}\(bytesHex)"
        if let existing = seen[key] {
            XCTAssertEqual(existing.action, action, "\(existing.name) and \(name) share bytes on \(channel)")
        } else {
            seen[key] = (name, action)
        }
    }
}

final class PeerVerifierTests: XCTestCase {
    func testConnectionIdsAreRelayMintedAndMonotonic() throws {
        var minter = RelayConnectionIDMinter()

        XCTAssertEqual(try minter.mint(), "c1")
        XCTAssertEqual(try minter.mint(), "c2")
        XCTAssertEqual(try minter.mint(), "c3")
    }

    func testPeerVerifierRefusesUnsafeExpectedUidsAtStartup() throws {
        let credentials = StubCredentials(peerUid: testExpectedUid)
        let admin = StubAdminMembership(adminUIDs: [testAdminUid])

        XCTAssertThrowsError(try PeerVerifier(installIdentity: try Self.validatedIdentity(uid: RelayProtocolConstants.rootUid), ownerUid: testOwnerUid, relayUid: testRelayUid, credentials: credentials, adminMembership: admin))
        XCTAssertThrowsError(try PeerVerifier(installIdentity: try Self.validatedIdentity(uid: testOwnerUid), ownerUid: testOwnerUid, relayUid: testRelayUid, credentials: credentials, adminMembership: admin))
        XCTAssertThrowsError(try PeerVerifier(installIdentity: try Self.validatedIdentity(uid: testRelayUid), ownerUid: testOwnerUid, relayUid: testRelayUid, credentials: credentials, adminMembership: admin))
        XCTAssertThrowsError(try PeerVerifier(installIdentity: try Self.validatedIdentity(uid: testExpectedUid), ownerUid: testOwnerUid, relayUid: testExpectedUid, credentials: credentials, adminMembership: admin))
        XCTAssertThrowsError(try PeerVerifier(installIdentity: try Self.validatedIdentity(uid: testAdminUid), ownerUid: testOwnerUid, relayUid: testRelayUid, credentials: credentials, adminMembership: admin))
    }

    func testPeerVerifierTreatsAdminLookupFailureAsRefusal() throws {
        XCTAssertThrowsError(try PeerVerifier(
            installIdentity: try Self.validatedIdentity(uid: testExpectedUid),
            ownerUid: testOwnerUid,
            relayUid: testRelayUid,
            credentials: StubCredentials(peerUid: testExpectedUid),
            adminMembership: StubAdminMembership(adminUIDs: [], lookupError: PeerCheckError.peerInspectionFailed)
        )) { error in
            XCTAssertEqual(error as? PeerCheckError, .expectedUidIsAdmin)
        }
    }

    func testInstallIdentityRequiresPinnedAccountUID() throws {
        let lookup = StubAccountLookup(accounts: ["_hermes-memory": testExpectedUid])

        XCTAssertNoThrow(try HermesInstallIdentity(pinnedUID: testExpectedUid, accountName: "_hermes-memory").validate(lookup: lookup))
        XCTAssertThrowsError(try HermesInstallIdentity(pinnedUID: testExpectedUid + 1, accountName: "_hermes-memory").validate(lookup: lookup)) { error in
            XCTAssertEqual(error as? PeerCheckError, .installUidMismatch(pinned: testExpectedUid + 1, account: testExpectedUid))
        }
    }

    func testPeerVerifierRequiresValidatedInstallIdentity() throws {
        let lookup = StubAccountLookup(accounts: ["_hermes-memory": testExpectedUid])
        let identity = try HermesInstallIdentity(pinnedUID: testExpectedUid, accountName: "_hermes-memory").validate(lookup: lookup)

        XCTAssertNoThrow(try PeerVerifier(
            installIdentity: identity,
            ownerUid: testOwnerUid,
            relayUid: testRelayUid,
            credentials: StubCredentials(peerUid: testExpectedUid),
            adminMembership: StubAdminMembership(adminUIDs: [])
        ))
    }

    func testPeerVerifierUsesSuppliedOwnerUID() throws {
        XCTAssertThrowsError(try PeerVerifier(
            installIdentity: try Self.validatedIdentity(uid: testExpectedUid),
            ownerUid: testExpectedUid,
            relayUid: testRelayUid,
            credentials: StubCredentials(peerUid: testExpectedUid),
            adminMembership: StubAdminMembership(adminUIDs: [])
        )) { error in
            XCTAssertEqual(error as? PeerCheckError, .expectedUidIsOwner)
        }
    }

    func testDarwinAdminGroupDetectsCurrentAdminUser() throws {
        var groupCount = Int32(0)
        _ = getgroups(0, nil)
        groupCount = getgroups(0, nil)
        guard groupCount > 0 else {
            throw XCTSkip("current supplemental groups unavailable")
        }
        var groups = [gid_t](repeating: 0, count: Int(groupCount))
        let readCount = groups.withUnsafeMutableBufferPointer { buffer in
            getgroups(groupCount, buffer.baseAddress)
        }
        guard readCount > 0, groups.prefix(Int(readCount)).contains(RelayProtocolConstants.macOSAdminGroupID) else {
            throw XCTSkip("current user is not in macOS admin group")
        }
        XCTAssertTrue(try DarwinAdminGroupMembership().isAdmin(uid: getuid()))
    }

    func testDarwinAdminGroupHandlesSystemNogroupAccount() throws {
        guard let passwd = getpwnam("_ftp") else {
            throw XCTSkip("system account fixture unavailable")
        }

        XCTAssertNoThrow(try DarwinAdminGroupMembership().isAdmin(uid: passwd.pointee.pw_uid))
    }

    func testDarwinAdminGroupRefusesLookupFailures() throws {
        // uid_t.max - 1 is Darwin's _unknown/nobody value, so use the adjacent high value as an absent account fixture.
        XCTAssertThrowsError(try DarwinAdminGroupMembership().isAdmin(uid: uid_t.max - 2))
        XCTAssertThrowsError(try DarwinAdminGroupMembership(maxSupplementalGroupLookupCount: 0).isAdmin(uid: getuid()))
    }

    func testPeerVerifierChecksKernelUidBeforeParse() throws {
        let credentials = StubCredentials(peerUid: testExpectedUid + 1)
        let verifier = try PeerVerifier(
            installIdentity: try Self.validatedIdentity(uid: testExpectedUid),
            ownerUid: testOwnerUid,
            relayUid: testRelayUid,
            credentials: credentials,
            adminMembership: StubAdminMembership(adminUIDs: [])
        )

        XCTAssertThrowsError(try verifier.requirePeer(fileDescriptor: testFD)) { error in
            XCTAssertEqual(error as? PeerCheckError, .peerUidMismatch(expected: testExpectedUid, actual: testExpectedUid + 1))
        }
    }

    private static func validatedIdentity(uid: uid_t) throws -> ValidatedHermesInstallIdentity {
        try HermesInstallIdentity(pinnedUID: uid, accountName: "_hermes-memory").validate(lookup: StubAccountLookup(accounts: ["_hermes-memory": uid]))
    }
}

final class ProbeBarrierTests: XCTestCase {
    func testProbeForwardsCurrentPublicEventsBeforeReplyAcrossRuns() throws {
        let runCount = 3
        for index in 0..<runCount {
            var connection = RelayConnection(connectionID: "conn-\(index)")
            _ = connection.handlePublicFrame(RelayFrame(
                type: "tools_call",
                fields: ["request_id": .string("mcp-\(index)"), "name": .string("memory_insert"), "arguments": .object([:])]
            ))
            let cancel = try BoundedFrameStream.encode(RelayFrame(type: "cancel", fields: ["mcp_request_id": .string("mcp-\(index)")]))
            let probe = RelayFrame(type: "probe", fields: ["connection_id": .string("conn-\(index)"), "nonce": .string(testProbeNonce)])

            let outputs = connection.handleProbe(probe, publicFD: StubProbeSource(events: [.data(cancel), .eof]))

            let expectedReply = RelayOutput.toNode(RelayFrame(
                type: "probe_reply",
                fields: ["connection_id": .string("conn-\(index)"), "nonce": .string(testProbeNonce)]
            ), completion: nil)
            let expectedClosed = RelayOutput.toNode(RelayFrame(
                type: "closed",
                fields: ["connection_id": .string("conn-\(index)")]
            ), completion: nil)
            XCTAssertEqual(outputs.last, expectedReply)
            XCTAssertTrue(outputs.dropLast().contains(expectedClosed))
            XCTAssertTrue(outputs.dropLast().contains { output in
                guard case .toNode(let frame, _) = output else { return false }
                return frame.publicFrameTypeFromEnvelope() == "cancel"
            })
        }
    }

    func testPartialAtProbeBecomesClosedBeforeReply() throws {
        var connection = RelayConnection(connectionID: "conn-partial")
        let partial = BoundedFrameStream.encodeLengthOnly(UInt32(RelayProtocolConstants.bytesPerKiB))
        _ = connection.receivePublicBytes(partial)

        let outputs = connection.handleProbe(
            RelayFrame(type: "probe", fields: ["connection_id": .string("conn-partial"), "nonce": .string(testProbeNonce)]),
            publicFD: StubProbeSource(events: [])
        )

        let expectedClosed = RelayOutput.toNode(RelayFrame(
            type: "closed",
            fields: ["connection_id": .string("conn-partial")]
        ), completion: nil)
        let expectedReply = RelayOutput.toNode(RelayFrame(
            type: "probe_reply",
            fields: ["connection_id": .string("conn-partial"), "nonce": .string(testProbeNonce)]
        ), completion: nil)
        XCTAssertEqual(outputs.first, expectedClosed)
        XCTAssertEqual(outputs.last, expectedReply)

        let laterOutputs = connection.receivePublicBytes(Data(repeating: UInt8(ascii: "{"), count: RelayProtocolConstants.frameLengthPrefixBytes))
        XCTAssertTrue(laterOutputs.isEmpty)
        XCTAssertEqual(connection.peerClosed(), [])
    }

    func testProbeForDifferentConnectionIsFatalToPrivateProtocol() throws {
        var connection = RelayConnection(connectionID: "conn-owned")
        let outputs = connection.handleProbe(
            RelayFrame(type: "probe", fields: ["connection_id": .string("conn-requested"), "nonce": .string(testProbeNonce)]),
            publicFD: StubProbeSource(events: [])
        )

        XCTAssertEqual(outputs, [.fatalRelayError])
    }

    func testBusyDenialDuringProbeIsDeliveredToClient() throws {
        var connection = RelayConnection(connectionID: "conn-probe-busy")
        _ = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))
        let secondCall = try BoundedFrameStream.encode(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-2"), "name": .string("memory_get"), "arguments": .object([:])]
        ))

        let outputs = connection.handleProbe(
            RelayFrame(type: "probe", fields: ["connection_id": .string("conn-probe-busy"), "nonce": .string(testProbeNonce)]),
            publicFD: StubProbeSource(events: [.data(secondCall)])
        )

        XCTAssertTrue(outputs.contains(.toClient(RelayFrame(
            type: "error",
            fields: ["request_id": .string("mcp-2"), "message": .string("Memory request denied.")]
        ), completion: .busyDenial)))
    }
}

final class InFlightRuleTests: XCTestCase {
    func testBusyDenialThenFurtherNonControlPoisons() throws {
        var connection = RelayConnection(connectionID: "conn-busy")
        _ = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))

        let busy = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-2"), "name": .string("memory_get"), "arguments": .object([:])]
        ))
        XCTAssertEqual(busy, [.toClient(RelayFrame(
            type: "error",
            fields: ["request_id": .string("mcp-2"), "message": .string("Memory request denied.")]
        ), completion: .busyDenial)])
        XCTAssertEqual(connection.state, .state_IN_FLIGHT)

        let poison = connection.handlePublicFrame(RelayFrame(type: "tools_list", fields: ["request_id": .string("mcp-3")]))
        XCTAssertTrue(poison.contains(.closePublicConnection))
        XCTAssertEqual(connection.state, .state_CLOSED)
    }

    func testHelloAndToolsListEnterInFlight() throws {
        for frame in [
            RelayFrame(type: "hello", fields: ["request_id": .string("mcp-hello"), "protocol_version": .string("2026-10-12"), "client_name": .string("hermes")]),
            RelayFrame(type: "tools_list", fields: ["request_id": .string("mcp-list")])
        ] {
            var connection = RelayConnection(connectionID: "conn-\(frame.type)")
            _ = connection.handlePublicFrame(frame)

            let busy = connection.handlePublicFrame(RelayFrame(
                type: "tools_call",
                fields: ["request_id": .string("mcp-2"), "name": .string("memory_get"), "arguments": .object([:])]
            ))

            XCTAssertEqual(connection.state, .state_IN_FLIGHT)
            XCTAssertTrue(busy.contains(.toClient(RelayFrame(
                type: "error",
                fields: ["request_id": .string("mcp-2"), "message": .string("Memory request denied.")]
            ), completion: .busyDenial)))
        }
    }

    func testPingIsAnsweredByRelay() throws {
        var connection = RelayConnection(connectionID: "conn-ping")

        XCTAssertEqual(connection.handlePublicFrame(RelayFrame(type: "ping")), [.toClient(RelayFrame(type: "pong"), completion: .pong)])
    }

    func testControlQueueCapPoisonsOnlyThatConnection() throws {
        var connection = RelayConnection(connectionID: "conn-controls")
        _ = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))

        for index in 0..<RelayProtocolConstants.controlQueueDepthPerConnection {
            let outputs = connection.handlePublicFrame(RelayFrame(type: "cancel", fields: ["mcp_request_id": .string("mcp-\(index)")]))
            XCTAssertFalse(outputs.contains(.closePublicConnection), "control \(index)")
        }
        let overflow = connection.handlePublicFrame(RelayFrame(type: "shutdown"))
        XCTAssertTrue(overflow.contains(.closePublicConnection))
        XCTAssertEqual(connection.state, .state_CLOSED)
    }

    func testIdleCancelCountsAgainstControlQueue() throws {
        var connection = RelayConnection(connectionID: "conn-idle-controls")
        for index in 0..<RelayProtocolConstants.controlQueueDepthPerConnection {
            let outputs = connection.handlePublicFrame(RelayFrame(type: "cancel", fields: ["mcp_request_id": .string("mcp-\(index)")]))
            XCTAssertFalse(outputs.contains(.closePublicConnection), "control \(index)")
        }

        let overflow = connection.handlePublicFrame(RelayFrame(type: "cancel", fields: ["mcp_request_id": .string("mcp-overflow")]))
        XCTAssertTrue(overflow.contains(.closePublicConnection))
        XCTAssertEqual(connection.state, .state_CLOSED)
    }

    func testFinishInFlightDoesNothingAfterClosedOrPoisoned() throws {
        var closed = RelayConnection(connectionID: "conn-closed")
        _ = closed.peerClosed()
        closed.finishInFlight()
        XCTAssertTrue(closed.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp"), "name": .string("memory_search"), "arguments": .object([:])]
        )).isEmpty)

        var poisoned = RelayConnection(connectionID: "conn-poisoned")
        _ = poisoned.handlePublicFrame(RelayFrame(type: "probe"))
        poisoned.finishInFlight()
        XCTAssertEqual(poisoned.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp"), "name": .string("memory_search"), "arguments": .object([:])]
        )), [])
    }
}

final class SocketAndLockTests: XCTestCase {
    func testSocketPathValidatorRejectsSymlinkAndWritableAncestor() throws {
        let fs = StubFileSystem.standardSocketTree()
        fs.metadata["/Library/Application Support"]?.mode |= RelayProtocolConstants.groupWriteBit
        let validator = SocketPathValidator(socketDirectory: testSocketDirectory, expectedSocketDirectoryOwner: testOwnerUid, expectedSocketDirectoryGroup: testGroup)
        XCTAssertThrowsError(try validator.validate(fileSystem: fs)) { error in
            XCTAssertEqual(error as? SocketPathCheckError, .writableAncestor("/Library/Application Support"))
        }

        let symlinkFS = StubFileSystem.standardSocketTree()
        symlinkFS.metadata[testSocketDirectory]?.isSymlink = true
        XCTAssertThrowsError(try validator.validate(fileSystem: symlinkFS)) { error in
            XCTAssertEqual(error as? SocketPathCheckError, .symlink(testSocketDirectory))
        }
    }

    func testSocketPathValidatorRejectsEmptyRootSetidAndWrongFinalGroup() throws {
        let empty = SocketPathValidator(socketDirectory: "", expectedSocketDirectoryOwner: testOwnerUid, expectedSocketDirectoryGroup: testGroup)
        XCTAssertThrowsError(try empty.validate(fileSystem: StubFileSystem.standardSocketTree()))

        let root = SocketPathValidator(socketDirectory: "/", expectedSocketDirectoryOwner: testOwnerUid, expectedSocketDirectoryGroup: testGroup)
        XCTAssertThrowsError(try root.validate(fileSystem: StubFileSystem.standardSocketTree()))

        let setidFS = StubFileSystem.standardSocketTree()
        setidFS.metadata["/Library/Application Support"]?.mode = testRootAncestorMode | RelayProtocolConstants.setgidBit
        let validator = SocketPathValidator(socketDirectory: testSocketDirectory, expectedSocketDirectoryOwner: testOwnerUid, expectedSocketDirectoryGroup: testGroup)
        XCTAssertThrowsError(try validator.validate(fileSystem: setidFS))

        let wrongAncestorOwnerFS = StubFileSystem.standardSocketTree()
        wrongAncestorOwnerFS.metadata["/Library/Application Support"]?.owner = testOwnerUid
        XCTAssertThrowsError(try validator.validate(fileSystem: wrongAncestorOwnerFS))

        let wrongGroupFS = StubFileSystem.standardSocketTree()
        wrongGroupFS.metadata[testSocketDirectory]?.group = testGroup + 1
        XCTAssertThrowsError(try validator.validate(fileSystem: wrongGroupFS))

        let finalSetidFS = StubFileSystem.standardSocketTree()
        finalSetidFS.metadata[testSocketDirectory]?.mode = RelayProtocolConstants.socketDirectoryMode | RelayProtocolConstants.setgidBit
        XCTAssertThrowsError(try validator.validate(fileSystem: finalSetidFS))
    }

    func testSocketReclaimRequiresLockFirst() throws {
        let fs = StubFileSystem.standardSocketTree()
        let lifecycle = RelaySocketLifecycle(lockPath: testLockPath, socketPath: testSocketPath, lock: StubLock(available: false), fileSystem: fs)

        XCTAssertThrowsError(try lifecycle.acquireBeforeSocketWork()) { error in
            guard case .unavailable(let lockPath, let message) = error as? InstanceLockError else {
                return XCTFail("unexpected error \(error)")
            }
            XCTAssertEqual(lockPath, testLockPath)
            XCTAssertTrue(message.contains(testLockPath))
        }

        let unordered = RelaySocketLifecycle(lockPath: testLockPath, socketPath: testSocketPath, lock: StubLock(available: true), fileSystem: fs)
        XCTAssertThrowsError(try unordered.unlinkLeftoverSocketWhileLocked())

        fs.metadata[testSocketPath] = PathMetadata(owner: testRelayUid, group: testGroup, mode: RelayProtocolConstants.publicSocketMode, isDirectory: false, isSymlink: false, isSocket: true)
        let locked = RelaySocketLifecycle(lockPath: testLockPath, socketPath: testSocketPath, lock: StubLock(available: true), fileSystem: fs, relayUid: testRelayUid)
        try locked.acquireBeforeSocketWork()
        try locked.unlinkLeftoverSocketWhileLocked()
        XCTAssertTrue(locked.didUnlinkSocket)

        let firstBoot = RelaySocketLifecycle(lockPath: testLockPath, socketPath: testSocketPath, lock: StubLock(available: true), fileSystem: StubFileSystem.standardSocketTree(), relayUid: testRelayUid)
        try firstBoot.acquireBeforeSocketWork()
        XCTAssertNoThrow(try firstBoot.unlinkLeftoverSocketWhileLocked())
        XCTAssertFalse(firstBoot.didUnlinkSocket)

        let notSocketFS = StubFileSystem.standardSocketTree()
        notSocketFS.metadata[testSocketPath] = PathMetadata(owner: testRelayUid, group: testGroup, mode: RelayProtocolConstants.publicSocketMode, isDirectory: false, isSymlink: false, isSocket: false)
        let notSocket = RelaySocketLifecycle(lockPath: testLockPath, socketPath: testSocketPath, lock: StubLock(available: true), fileSystem: notSocketFS, relayUid: testRelayUid)
        try notSocket.acquireBeforeSocketWork()
        XCTAssertThrowsError(try notSocket.unlinkLeftoverSocketWhileLocked()) { error in
            XCTAssertEqual(error as? SocketPathCheckError, .leftoverNotSocket(testSocketPath))
        }

        let wrongOwnerFS = StubFileSystem.standardSocketTree()
        wrongOwnerFS.metadata[testSocketPath] = PathMetadata(owner: testRelayUid + 1, group: testGroup, mode: RelayProtocolConstants.publicSocketMode, isDirectory: false, isSymlink: false, isSocket: true)
        let wrongOwner = RelaySocketLifecycle(lockPath: testLockPath, socketPath: testSocketPath, lock: StubLock(available: true), fileSystem: wrongOwnerFS, relayUid: testRelayUid)
        try wrongOwner.acquireBeforeSocketWork()
        XCTAssertThrowsError(try wrongOwner.unlinkLeftoverSocketWhileLocked()) { error in
            XCTAssertEqual(error as? SocketPathCheckError, .leftoverWrongOwner(testSocketPath))
        }
    }
}

final class ChildSupervisorTests: XCTestCase {
    func testPrivateNodeFramesUseDerivedCapAndFatalError() throws {
        var receiver = PrivateFrameReceiver()
        let frame = RelayFrame(type: "ready")

        XCTAssertEqual(try receiver.receiveFromNode(BoundedFrameStream.encode(frame)), [frame])

        var overCap = BoundedFrameStream.encodeLengthOnly(UInt32(RelayProtocolConstants.maxPrivateFrameBytes + 1))
        overCap.append(UInt8(ascii: "{"))
        XCTAssertThrowsError(try receiver.receiveFromNode(overCap)) { error in
            XCTAssertEqual(error as? PrivateFrameError, .fatalRelayError)
        }
    }

    func testPrivateLifecycleRequiresReadyFirstAndOnlyOnce() throws {
        var firstFrameReceiver = PrivateFrameReceiver()
        let probe = RelayFrame(type: "probe", fields: ["connection_id": .string("c1"), "nonce": .string(testProbeNonce)])
        XCTAssertThrowsError(try firstFrameReceiver.receiveFromNode(BoundedFrameStream.encode(probe)))

        var secondReadyReceiver = PrivateFrameReceiver()
        XCTAssertEqual(try secondReadyReceiver.receiveFromNode(BoundedFrameStream.encode(RelayFrame(type: "ready"))), [RelayFrame(type: "ready")])
        XCTAssertThrowsError(try secondReadyReceiver.receiveFromNode(BoundedFrameStream.encode(RelayFrame(type: "ready"))))
    }

    func testPrivateLifecycleRejectsNonPrivateFrameAfterReady() throws {
        var receiver = PrivateFrameReceiver()
        XCTAssertEqual(try receiver.receiveFromNode(BoundedFrameStream.encode(RelayFrame(type: "ready"))), [RelayFrame(type: "ready")])

        XCTAssertThrowsError(try receiver.receiveFromNode(BoundedFrameStream.encode(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_search"), "arguments": .object([:])]
        )))) { error in
            XCTAssertEqual(error as? PrivateFrameError, .fatalRelayError)
        }

        XCTAssertThrowsError(try receiver.receiveFromNode(BoundedFrameStream.encode(RelayFrame(
            type: "error",
            fields: ["request_id": .string("mcp-1"), "message": .string("Memory request denied.")]
        )))) { error in
            XCTAssertEqual(error as? PrivateFrameError, .fatalRelayError)
        }
    }

    func testPrivateMalformedFrameAfterValidPrefixIsFatalInSameRead() throws {
        var receiver = PrivateFrameReceiver()
        let ready = try BoundedFrameStream.encode(RelayFrame(type: "ready"))
        let malformedPayload = Data(#"{"type":"probe""#.utf8)
        let malformed = BoundedFrameStream.encodeLengthOnly(UInt32(malformedPayload.count)) + malformedPayload

        XCTAssertThrowsError(try receiver.receiveFromNode(ready + malformed)) { error in
            XCTAssertEqual(error as? PrivateFrameError, .fatalRelayError)
        }
    }

    func testSpawnPlanUsesAbsoluteExecutableAndSanitizedEnvironment() throws {
        XCTAssertThrowsError(try ChildSupervisor.spawnPlan(config: ChildSupervisorConfig(
            executablePath: "node",
            bridgeEntryPath: "/opt/sanctuary/bin/hermes-memory-bridge.js",
            bridgeLogPath: testBridgeLogPath,
            relayFD: 12,
            baseEnvironment: [:],
            bridgeIdentity: "bridge-install",
            agentID: "agent-install",
            fortressID: "fortress-install"
        )))

        let plan = try ChildSupervisor.spawnPlan(config: ChildSupervisorConfig(
            executablePath: "/opt/sanctuary/bin/node",
            bridgeEntryPath: "/opt/sanctuary/bin/hermes-memory-bridge.js",
            bridgeLogPath: testBridgeLogPath,
            relayFD: 12,
            baseEnvironment: [
                "SANCTUARY_TOKEN": "x",
                "NODE_OPTIONS": "--inspect",
                "NODE_ENV": "test",
                "DYLD_LIBRARY_PATH": "x",
                "PATH": "/bin",
                "LANG": "en_US.UTF-8",
                "HOME": "/Users/owner",
                "TMPDIR": "/tmp",
                "HERMES_MEMORY_BRIDGE_IDENTITY": "caller-bridge"
            ],
            bridgeIdentity: "bridge-install",
            agentID: "agent-install",
            fortressID: "fortress-install"
        ))

        XCTAssertTrue(plan.cloexecDefault)
        XCTAssertEqual(plan.relayFDAction, .duplicate(source: 12, target: 3))
        XCTAssertEqual(plan.stdinPath, "/dev/null")
        XCTAssertEqual(plan.stdoutLogPath, testBridgeLogPath)
        XCTAssertEqual(plan.stderrLogPath, testBridgeLogPath)
        XCTAssertEqual(plan.arguments, [
            "/opt/sanctuary/bin/node",
            "/opt/sanctuary/bin/hermes-memory-bridge.js",
            "hermes-memory-bridge",
            "run",
            "--relay-fd",
            "3"
        ])
        XCTAssertEqual(plan.environment, [
            "HOME": "/Users/owner",
            "LANG": "en_US.UTF-8",
            "TMPDIR": "/tmp",
            "HERMES_MEMORY_BRIDGE_IDENTITY": "bridge-install",
            "HERMES_MEMORY_AGENT_ID": "agent-install",
            "HERMES_MEMORY_FORTRESS_ID": "fortress-install"
        ])
    }

    func testSpawnPlanInheritsRelayFDWhenSourceIsAlreadyChildFD() throws {
        let plan = try ChildSupervisor.spawnPlan(config: ChildSupervisorConfig(
            executablePath: "/opt/sanctuary/bin/node",
            bridgeEntryPath: "/opt/sanctuary/bin/hermes-memory-bridge.js",
            bridgeLogPath: testBridgeLogPath,
            relayFD: RelayProtocolConstants.childInheritedRelayFD,
            baseEnvironment: [:],
            bridgeIdentity: "bridge-install",
            agentID: "agent-install",
            fortressID: "fortress-install"
        ))

        XCTAssertEqual(plan.relayFDAction, .inherit(RelayProtocolConstants.childInheritedRelayFD))
    }

    func testReadyFrameIsRequiredBeforeBind() throws {
        XCTAssertNoThrow(try ChildSupervisor.validateReadyFrame(RelayFrame(type: "ready")))
        XCTAssertThrowsError(try ChildSupervisor.validateReadyFrame(RelayFrame(type: "response", fields: ["connection_id": .string("c"), "request_id": .string("r"), "result_b64": .string("e30=")])))
    }
}

final class RelayStartupCoordinatorTests: XCTestCase {
    func testPublicSocketBindsOnlyAfterChildReady() throws {
        let operations = StubStartupOperations()
        var coordinator = RelayStartupCoordinator(operations: operations)

        try coordinator.start()

        XCTAssertEqual(operations.events, [
            "lock",
            "validate",
            "spawn",
            "ready:\(RelayProtocolConstants.childReadyTimeoutMilliseconds)",
            "unlink",
            "bind",
            "chmod",
            "verify"
        ])
        XCTAssertEqual(coordinator.state, .state_SERVING)
    }

    func testReadyFailureLeavesPublicSocketUnbound() throws {
        let operations = StubStartupOperations(readyError: ChildSupervisorError.childReadyTimeout)
        var coordinator = RelayStartupCoordinator(operations: operations)

        XCTAssertThrowsError(try coordinator.start())
        XCTAssertEqual(operations.events, [
            "lock",
            "validate",
            "spawn",
            "ready:\(RelayProtocolConstants.childReadyTimeoutMilliseconds)",
            "kill",
            "reap"
        ])
    }
}

final class RelayConnectionLifecycleTests: XCTestCase {
    func testPoisonThenLaterCloseEmitsOneClosed() throws {
        var connection = RelayConnection(connectionID: "conn-once")
        let malformed = BoundedFrameStream.encodeLengthOnly(UInt32(RelayProtocolConstants.bytesPerKiB))
            + Data(repeating: UInt8(ascii: "{"), count: RelayProtocolConstants.bytesPerKiB)

        let first = connection.receivePublicBytes(malformed)
        let second = connection.peerClosed()

        XCTAssertEqual(Self.closedCount(in: first + second), 1)
    }

    func testClosedBypassesControlQueueAtTerminal() throws {
        var connection = RelayConnection(connectionID: "conn-terminal")
        _ = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))
        for index in 0..<RelayProtocolConstants.controlQueueDepthPerConnection {
            _ = connection.handlePublicFrame(RelayFrame(type: "cancel", fields: ["mcp_request_id": .string("mcp-\(index)")]))
        }

        let outputs = connection.peerClosed()

        XCTAssertEqual(Self.closedCount(in: outputs), 1)
    }

    func testPoisonAfterDecodedPrefixClosesInSameRead() throws {
        var connection = RelayConnection(connectionID: "conn-prefix")
        let valid = try BoundedFrameStream.encode(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))
        let malformedPayload = Data(#"{"type":"cancel""#.utf8)
        var malformed = BoundedFrameStream.encodeLengthOnly(UInt32(malformedPayload.count))
        malformed.append(malformedPayload)

        let outputs = connection.receivePublicBytes(valid + malformed)

        XCTAssertTrue(outputs.contains { output in
            guard case .toNode(let frame, _) = output else { return false }
            return frame.publicFrameTypeFromEnvelope() == "tools_call"
        })
        XCTAssertEqual(Self.closedCount(in: outputs), 1)
        XCTAssertTrue(outputs.contains(.closePublicConnection))
    }

    func testOverCapLengthAfterDecodedPrefixStillForwardsPrefix() throws {
        var connection = RelayConnection(connectionID: "conn-overcap-prefix")
        let valid = try BoundedFrameStream.encode(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))
        let overCapLength = BoundedFrameStream.encodeLengthOnly(UInt32(RelayProtocolConstants.maxPublicFrameBytes + 1))

        let outputs = connection.receivePublicBytes(valid + overCapLength)

        XCTAssertTrue(outputs.contains { output in
            guard case .toNode(let frame, _) = output else { return false }
            return frame.publicFrameTypeFromEnvelope() == "tools_call"
        })
        XCTAssertEqual(Self.closedCount(in: outputs), 1)
        XCTAssertTrue(outputs.contains(.closePublicConnection))
    }

    func testPeerClosedRequestsPublicClose() throws {
        var connection = RelayConnection(connectionID: "conn-peer-closed")
        let outputs = connection.peerClosed()

        XCTAssertEqual(Self.closedCount(in: outputs), 1)
        XCTAssertTrue(outputs.contains(.closePublicConnection))
    }

    func testShutdownForwardsAndClosesCaller() throws {
        var connection = RelayConnection(connectionID: "conn-shutdown")
        let outputs = connection.handlePublicFrame(RelayFrame(type: "shutdown"))

        XCTAssertTrue(outputs.contains { output in
            guard case .toNode(let frame, _) = output else { return false }
            return frame.publicFrameTypeFromEnvelope() == "shutdown"
        })
        XCTAssertEqual(Self.closedCount(in: outputs), 1)
        XCTAssertTrue(outputs.contains(.closePublicConnection))
    }

    func testMatchingResponseProducesResultAndEndsInFlight() throws {
        var connection = RelayConnection(connectionID: "conn-response")
        _ = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))
        let resultPayload = try Self.publicPayload(RelayFrame(
            type: "result",
            fields: ["request_id": .string("mcp-1"), "payload": .object(["content": .array([])])]
        ))

        let outputs = connection.handleNodeFrame(RelayFrame(
            type: "response",
            fields: [
                "connection_id": .string("conn-response"),
                "request_id": .string("mcp-1"),
                "result_b64": .string(resultPayload.base64EncodedString())
            ]
        ))

        XCTAssertEqual(outputs, [.toClientPayload(resultPayload, completion: .result)])
        XCTAssertEqual(connection.state, .state_SERVING)
    }

    func testPublicFrameEnvelopeCarriesExactPayloadBytes() throws {
        let payload = Data(#"{"type":"tools_call","request_id":"mcp-raw","name":"memory_insert","arguments":{"text":"secret","n":5}}"#.utf8)
        var connection = RelayConnection(connectionID: "conn-raw")

        let outputs = connection.receivePublicBytes(Self.prefixed(payload))

        guard case .toNode(let envelope, _)? = outputs.first,
              case .string(let encoded)? = envelope.fields["frame_b64"],
              let decoded = Data(base64Encoded: encoded)
        else {
            return XCTFail("expected relay frame envelope")
        }
        XCTAssertEqual(decoded, payload)
    }

    func testResultPayloadBoundaryAndTopLevelChecksAreIndependent() throws {
        let exactCapHead = #"{"type":"result","request_id":"mcp-1","payload":{"text":""#
        let exactCapTail = #""}}"#
        let exactPad = RelayProtocolConstants.maxResultFrameBytes - Data(exactCapHead.utf8).count - Data(exactCapTail.utf8).count
        let exactCap = Data((exactCapHead + String(repeating: "a", count: exactPad) + exactCapTail).utf8)
        XCTAssertEqual(exactCap.count, RelayProtocolConstants.maxResultFrameBytes)

        let cases: [(String, String, Data, RelayOutput)] = [
            ("exact cap", "mcp-1", exactCap, .toClientPayload(exactCap, completion: .result)),
            ("inner id", "mcp-1", Data(#"{"type":"result","request_id":"mcp-other","payload":{}}"#.utf8), Self.denial("mcp-1")),
            ("duplicate inner id", "mcp-1", Data(#"{"type":"result","request_id":"mcp-other","request_id":"mcp-1","payload":{}}"#.utf8), Self.denial("mcp-1")),
            ("escaped duplicate inner id", "mcp-1", Data(#"{"type":"result","request_id":"mcp-other","\u0072equest_id":"mcp-1","payload":{}}"#.utf8), Self.denial("mcp-1")),
            ("outer id", "mcp-other", Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8), Self.denial("mcp-1")),
            ("type", "mcp-1", Data(#"{"type":"pong","request_id":"mcp-1"}"#.utf8), Self.denial("mcp-1")),
            ("closed type", "mcp-1", Data(#"{"type":"closed","request_id":"mcp-1"}"#.utf8), Self.denial("mcp-1")),
            ("error type", "mcp-1", Data(#"{"type":"error","request_id":"mcp-1","message":"Memory request denied."}"#.utf8), .toClientPayload(Data(#"{"type":"error","request_id":"mcp-1","message":"Memory request denied."}"#.utf8), completion: .result)),
            ("escaped duplicate type", "mcp-1", Data(#"{"type":"result","\u0074ype":"pong","request_id":"mcp-1"}"#.utf8), Self.denial("mcp-1")),
            ("lone surrogate", "mcp-1", Data(#"{"type":"result","request_id":"mcp-1","payload":{"text":"\ud83d"}}"#.utf8), Self.denial("mcp-1")),
            ("lone low surrogate", "mcp-1", Data(#"{"type":"result","request_id":"mcp-1","payload":{"text":"\udc00"}}"#.utf8), Self.denial("mcp-1")),
            ("bad surrogate pair", "mcp-1", Data(#"{"type":"result","request_id":"mcp-1","payload":{"text":"\ud83dA"}}"#.utf8), Self.denial("mcp-1")),
            ("non-low surrogate partner", "mcp-1", Data(#"{"type":"result","request_id":"mcp-1","payload":{"text":"\ud83d\u0041"}}"#.utf8), Self.denial("mcp-1")),
            ("over depth", "mcp-1", Data((#"{"type":"result","request_id":"mcp-1","payload":"# + String(repeating: "[", count: RelayProtocolConstants.maxJSONNestingDepth + 1) + String(repeating: "]", count: RelayProtocolConstants.maxJSONNestingDepth + 1) + "}").utf8), Self.denial("mcp-1"))
        ]

        for (name, outerRequestID, resultPayload, expected) in cases {
            var connection = Self.connectionWithCall("conn-\(name.replacingOccurrences(of: " ", with: "-"))", requestID: "mcp-1")
            let outputs = connection.handleNodeFrame(RelayFrame(
                type: "response",
                fields: [
                    "connection_id": .string(connection.connectionID),
                    "request_id": .string(outerRequestID),
                    "result_b64": .string(resultPayload.base64EncodedString())
                ]
            ))

            XCTAssertEqual(outputs.first, expected, name)
        }
    }

    func testResponseMismatchSendsFixedErrorAndClosedResponseIsDiscarded() throws {
        var connection = RelayConnection(connectionID: "conn-response")
        _ = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))
        let mismatchedPayload = try Self.publicPayload(RelayFrame(
            type: "result",
            fields: ["request_id": .string("mcp-2"), "payload": .object([:])]
        ))

        XCTAssertEqual(connection.handleNodeFrame(RelayFrame(
            type: "response",
            fields: [
                "connection_id": .string("conn-response"),
                "request_id": .string("mcp-2"),
                "result_b64": .string(mismatchedPayload.base64EncodedString())
            ]
        )), [.toClient(RelayFrame(type: "error", fields: [
            "request_id": .string("mcp-1"),
            "message": .string("Memory request denied.")
        ]), completion: .result)])

        var closed = RelayConnection(connectionID: "conn-closed-response")
        _ = closed.peerClosed()
        XCTAssertEqual(closed.handleNodeFrame(RelayFrame(
            type: "response",
            fields: [
                "connection_id": .string("conn-closed-response"),
                "request_id": .string("mcp-1"),
                "result_b64": .string(try Self.publicPayload(RelayFrame(type: "result", fields: ["request_id": .string("mcp-1"), "payload": .object([:])])).base64EncodedString())
            ]
        )), [])

        XCTAssertEqual(closed.handleNodeFrame(RelayFrame(
            type: "close",
            fields: ["connection_id": .string("conn-closed-response")]
        )), [])
    }

    func testBusyDenialRetiresOnlyWhenBusyDenialIsWritten() throws {
        var connection = RelayConnection(connectionID: "conn-busy-write")
        _ = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))
        _ = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-2"), "name": .string("memory_get"), "arguments": .object([:])]
        ))

        connection.markClientFrameWritten(.pong)
        let outputs = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-3"), "name": .string("memory_search"), "arguments": .object([:])]
        ))

        XCTAssertTrue(outputs.contains(.closePublicConnection))
    }

    func testResultAndBusyOutputsRemainOutstandingUntilTheirOwnWriteCompletes() throws {
        var connection = Self.connectionWithCall("conn-outstanding", requestID: "mcp-1")
        let resultPayload = Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)
        XCTAssertEqual(connection.handleNodeFrame(RelayFrame(
            type: "response",
            fields: [
                "connection_id": .string("conn-outstanding"),
                "request_id": .string("mcp-1"),
                "result_b64": .string(resultPayload.base64EncodedString())
            ]
        )), [.toClientPayload(resultPayload, completion: .result)])

        let busy = connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-2"))
        XCTAssertEqual(busy, [.toClient(RelayFrame(type: "error", fields: [
            "request_id": .string("mcp-2"),
            "message": .string("Memory request denied.")
        ]), completion: .busyDenial)])

        let poison = connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-3"))
        XCTAssertTrue(poison.contains(.closePublicConnection))
        XCTAssertEqual(connection.state, .state_CLOSED)
    }

    func testWrittenResultAndBusyDenialAllowNextCall() throws {
        var connection = Self.connectionWithCall("conn-written", requestID: "mcp-1")
        let resultPayload = Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)
        _ = connection.handleNodeFrame(Self.nodeResponse(connectionID: "conn-written", requestID: "mcp-1", resultPayload: resultPayload))
        _ = connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-2"))

        connection.markClientFrameWritten(.result)
        connection.markClientFrameWritten(.busyDenial)
        let next = connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-3"))

        XCTAssertEqual(Self.forwardedFrameCount(in: next), 1)
        XCTAssertEqual(connection.state, .state_IN_FLIGHT)
    }

    func testWrittenRelayDenialAllowsNextCall() throws {
        var connection = Self.connectionWithCall("conn-written-denial", requestID: "mcp-1")
        let mismatchedPayload = Data(#"{"type":"result","request_id":"mcp-other","payload":{}}"#.utf8)
        let denial = connection.handleNodeFrame(Self.nodeResponse(connectionID: "conn-written-denial", requestID: "mcp-1", resultPayload: mismatchedPayload))
        XCTAssertEqual(Self.clientWriteKind(denial.first), .result)

        connection.markClientFrameWritten(.result)
        let next = connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-2"))
        XCTAssertEqual(Self.forwardedFrameCount(in: next), 1)
        XCTAssertEqual(connection.state, .state_IN_FLIGHT)
    }

    func testResultAndBusyWritesDrainOnlyTheirOwnSlots() throws {
        var resultFirst = Self.connectionWithCall("conn-result-first", requestID: "mcp-1")
        let resultPayload = Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)
        _ = resultFirst.handleNodeFrame(Self.nodeResponse(connectionID: "conn-result-first", requestID: "mcp-1", resultPayload: resultPayload))
        _ = resultFirst.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-2"))
        resultFirst.markClientFrameWritten(.result)
        XCTAssertTrue(resultFirst.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-3")).contains(.closePublicConnection))

        var busyFirst = Self.connectionWithCall("conn-busy-first", requestID: "mcp-1")
        _ = busyFirst.handleNodeFrame(Self.nodeResponse(connectionID: "conn-busy-first", requestID: "mcp-1", resultPayload: resultPayload))
        _ = busyFirst.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-2"))
        busyFirst.markClientFrameWritten(.busyDenial)
        let stillBlocked = busyFirst.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-3"))
        XCTAssertEqual(stillBlocked.first, .toClient(RelayFrame(type: "error", fields: [
            "request_id": .string("mcp-3"),
            "message": .string("Memory request denied.")
        ]), completion: .busyDenial))
    }

    func testNodeResponseDoesNotRetireEarlierBusyDenial() throws {
        var connection = Self.connectionWithCall("conn-busy-before-response", requestID: "mcp-1")
        _ = connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-2"))
        let resultPayload = Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)
        _ = connection.handleNodeFrame(Self.nodeResponse(connectionID: "conn-busy-before-response", requestID: "mcp-1", resultPayload: resultPayload))

        XCTAssertTrue(connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-3")).contains(.closePublicConnection))
    }

    func testNodeResponseDoesNotRetireEarlierPongs() throws {
        var connection = Self.connectionWithCall("conn-pongs-before-response", requestID: "mcp-1")
        XCTAssertFalse(connection.receivePublicBytes(Self.pingBytes()).contains(.closePublicConnection))
        XCTAssertFalse(connection.receivePublicBytes(Self.pingBytes()).contains(.closePublicConnection))
        let resultPayload = Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)
        _ = connection.handleNodeFrame(Self.nodeResponse(connectionID: "conn-pongs-before-response", requestID: "mcp-1", resultPayload: resultPayload))

        XCTAssertTrue(connection.receivePublicBytes(Self.pingBytes()).contains(.closePublicConnection))
    }

    func testNoReadScheduleCapsClientFramesAndCloses() throws {
        var connection = RelayConnection(connectionID: "conn-no-read")
        var queuedClientFrames = 0
        for index in 0..<100 {
            let call = connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-\(index)"))
            queuedClientFrames += Self.clientFrameCount(in: call)
            if call.contains(.closePublicConnection) { break }
            let response = connection.handleNodeFrame(Self.nodeResponse(
                connectionID: "conn-no-read",
                requestID: "mcp-\(index)",
                resultPayload: Data(#"{"type":"result","request_id":"mcp-\#(index)","payload":{}}"#.utf8)
            ))
            queuedClientFrames += Self.clientFrameCount(in: response)
            if response.contains(.closePublicConnection) { break }
            for _ in 0..<RelayProtocolConstants.controlResponseAllowancePerConnection {
                let pong = connection.receivePublicBytes(Self.pingBytes())
                queuedClientFrames += Self.clientFrameCount(in: pong)
                if pong.contains(.closePublicConnection) { break }
            }
        }

        XCTAssertLessThanOrEqual(queuedClientFrames, RelayProtocolConstants.maxClientOutboundFramesPerConnection)
        XCTAssertEqual(connection.state, .state_CLOSED)
    }

    func testDenialPathNoReadScheduleCapsClientFramesAndCloses() throws {
        var connection = RelayConnection(connectionID: "conn-denial-no-read")
        var queuedClientFrames = 0
        for index in 0..<100 {
            let call = connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-\(index)"))
            queuedClientFrames += Self.clientFrameCount(in: call)
            if call.contains(.closePublicConnection) { break }
            let denial = connection.handleNodeFrame(Self.nodeResponse(
                connectionID: "conn-denial-no-read",
                requestID: "mcp-\(index)",
                resultPayload: Data()
            ))
            queuedClientFrames += Self.clientFrameCount(in: denial)
            if denial.contains(.closePublicConnection) { break }
        }

        XCTAssertLessThanOrEqual(queuedClientFrames, RelayProtocolConstants.maxClientOutboundFramesPerConnection)
        XCTAssertEqual(connection.state, .state_CLOSED)
    }

    func testPongWritesDrainOneAtATime() throws {
        var connection = RelayConnection(connectionID: "conn-pongs")
        XCTAssertFalse(connection.receivePublicBytes(Self.pingBytes()).contains(.closePublicConnection))
        XCTAssertFalse(connection.receivePublicBytes(Self.pingBytes()).contains(.closePublicConnection))
        connection.markClientFrameWritten(.pong)
        XCTAssertFalse(connection.receivePublicBytes(Self.pingBytes()).contains(.closePublicConnection))
        XCTAssertTrue(connection.receivePublicBytes(Self.pingBytes()).contains(.closePublicConnection))
    }

    func testNodeControlWritesDrainOneAtATime() throws {
        var connection = Self.connectionWithCall("conn-node-controls", requestID: "mcp-1")
        for index in 0..<RelayProtocolConstants.controlQueueDepthPerConnection {
            XCTAssertFalse(connection.receivePublicBytes(Self.cancelBytes(requestID: "mcp-\(index)")).contains(.closePublicConnection))
        }
        connection.markNodeFrameWritten(.forwardedControlFrame)
        XCTAssertFalse(connection.receivePublicBytes(Self.cancelBytes(requestID: "mcp-extra")).contains(.closePublicConnection))
        XCTAssertTrue(connection.receivePublicBytes(Self.cancelBytes(requestID: "mcp-overflow")).contains(.closePublicConnection))
    }

    func testNodeWriteKindOnlyRetiresForwardedControlFrames() throws {
        var connection = Self.connectionWithCall("conn-node-kind", requestID: "mcp-1")
        for index in 0..<RelayProtocolConstants.controlQueueDepthPerConnection {
            let cancel = connection.receivePublicBytes(Self.cancelBytes(requestID: "mcp-\(index)"))
            XCTAssertEqual(Self.nodeWriteKind(cancel.first), .forwardedControlFrame, "control \(index)")
        }

        connection.markNodeFrameWritten(nil)
        XCTAssertTrue(connection.receivePublicBytes(Self.cancelBytes(requestID: "mcp-overflow")).contains(.closePublicConnection))

        var mapped = RelayConnection(connectionID: "conn-node-kind-mapped")
        let forwardedCall = mapped.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-call"))
        XCTAssertNil(Self.nodeWriteKind(forwardedCall.first))
        for index in 0..<RelayProtocolConstants.controlQueueDepthPerConnection {
            _ = mapped.receivePublicBytes(Self.cancelBytes(requestID: "mcp-mapped-\(index)"))
        }
        mapped.markNodeFrameWritten(Self.nodeWriteKind(forwardedCall.first))
        XCTAssertTrue(mapped.receivePublicBytes(Self.cancelBytes(requestID: "mcp-mapped-overflow")).contains(.closePublicConnection))
    }

    func testMaximumClientOutboundMixIsAccepted() throws {
        var connection = Self.connectionWithCall("conn-max-mix", requestID: "mcp-1")
        XCTAssertFalse(connection.receivePublicBytes(Self.pingBytes()).contains(.closePublicConnection))
        XCTAssertFalse(connection.receivePublicBytes(Self.pingBytes()).contains(.closePublicConnection))
        let resultPayload = Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)
        XCTAssertFalse(connection.handleNodeFrame(Self.nodeResponse(connectionID: "conn-max-mix", requestID: "mcp-1", resultPayload: resultPayload)).contains(.closePublicConnection))
        XCTAssertFalse(connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-2")).contains(.closePublicConnection))
    }

    func testRequestIDCapClosesOnlyTheCurrentConnection() throws {
        let longestAllowed = String(repeating: "x", count: RelayProtocolConstants.maxRequestIDBytes)
        var allowed = RelayConnection(connectionID: "conn-id-allowed")
        XCTAssertEqual(Self.forwardedFrameCount(in: allowed.receivePublicBytes(Self.toolsCallBytes(requestID: longestAllowed))), 1)

        let tooLong = longestAllowed + "x"
        for (name, bytes) in [
            ("hello", Self.helloBytes(requestID: tooLong)),
            ("tools_list", Self.toolsListBytes(requestID: tooLong)),
            ("tools_call", Self.toolsCallBytes(requestID: tooLong)),
            ("cancel", Self.cancelBytes(requestID: tooLong))
        ] {
            var refused = RelayConnection(connectionID: "conn-id-refused-\(name)")
            let outputs = refused.receivePublicBytes(bytes)
            XCTAssertTrue(outputs.contains(.closePublicConnection), name)
            XCTAssertEqual(refused.state, .state_CLOSED, name)
        }

        var other = RelayConnection(connectionID: "conn-id-other")
        XCTAssertEqual(Self.forwardedFrameCount(in: other.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-other"))), 1)
    }

    func testRequestIDCharsetRefusesEscapingAndNonASCII() throws {
        let badIDs = [
            "",
            String(repeating: "x", count: RelayProtocolConstants.maxRequestIDBytes + 1),
            "é",
            "Ł",
            #"quote""#,
            #"slash\"#,
            "control\u{0001}",
            "nul\u{0000}"
        ]
        for badID in badIDs {
            var connection = RelayConnection(connectionID: "conn-bad-id")
            let outputs = connection.receivePublicBytes(Self.publicFrameBytes(RelayFrame(
                type: "tools_call",
                fields: ["request_id": .string(badID), "name": .string("memory_search"), "arguments": .object([:])]
            )))
            XCTAssertTrue(outputs.contains(.closePublicConnection), "id \(badID.debugDescription)")
            XCTAssertEqual(connection.state, .state_CLOSED)
        }
    }

    func testRequestIDCharsetIsExhaustiveForAllIDBearingFrames() throws {
        let allowed = Set(("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-").utf8)
        let builders: [(String, (Data) -> Data)] = [
            ("hello", Self.helloBytes(rawRequestID:)),
            ("tools_list", Self.toolsListBytes(rawRequestID:)),
            ("tools_call", Self.toolsCallBytes(rawRequestID:)),
            ("cancel", Self.cancelBytes(rawRequestID:))
        ]

        for byteValue in 0...255 {
            let byte = UInt8(byteValue)
            let encodedByte = Self.jsonStringContentBytes(for: byte)
            for (shape, idBytes) in [
                ("single", encodedByte),
                ("middle", Data("a".utf8) + encodedByte + Data("b".utf8))
            ] {
                for (frameType, builder) in builders {
                    var connection = RelayConnection(connectionID: "conn-id-\(byteValue)-\(shape)-\(frameType)")
                    let outputs = connection.receivePublicBytes(builder(idBytes))
                    if allowed.contains(byte) {
                        XCTAssertEqual(Self.forwardedFrameCount(in: outputs), 1, "\(frameType) \(shape) 0x\(String(byteValue, radix: 16))")
                        XCTAssertFalse(outputs.contains(.closePublicConnection), "\(frameType) \(shape) 0x\(String(byteValue, radix: 16))")
                    } else {
                        XCTAssertTrue(outputs.contains(.closePublicConnection), "\(frameType) \(shape) 0x\(String(byteValue, radix: 16))")
                        XCTAssertEqual(connection.state, .state_CLOSED, "\(frameType) \(shape) 0x\(String(byteValue, radix: 16))")
                    }
                }
            }
        }
    }

    func testProbeNonceFormatIsExactLowercaseHex() throws {
        var valid = RelayConnection(connectionID: "conn-valid-probe")
        let validOutputs = valid.handleProbe(
            RelayFrame(type: "probe", fields: ["connection_id": .string("conn-valid-probe"), "nonce": .string(testProbeNonce)]),
            publicFD: StubProbeSource(events: [])
        )
        XCTAssertEqual(validOutputs.last, .toNode(RelayFrame(type: "probe_reply", fields: [
            "connection_id": .string("conn-valid-probe"),
            "nonce": .string(testProbeNonce)
        ]), completion: nil))

        for badNonce in [
            String(repeating: "a", count: RelayProtocolConstants.probeNonceBytes - 1),
            String(repeating: "a", count: RelayProtocolConstants.probeNonceBytes + 1),
            "0123456789ABCDEF0123456789abcdef",
            "0123456789abcdef0123456789abcdeg"
        ] {
            var refused = RelayConnection(connectionID: "conn-bad-probe")
            XCTAssertEqual(refused.handleProbe(
                RelayFrame(type: "probe", fields: ["connection_id": .string("conn-bad-probe"), "nonce": .string(badNonce)]),
                publicFD: StubProbeSource(events: [])
            ), [.fatalRelayError], badNonce)
        }
    }

    func testSEAMValuesMatchRelayConstants() throws {
        let seamURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("SEAM.md")
        let seam = try String(contentsOf: seamURL)
        let expectedValues = [
            "MAX_PUBLIC_FRAME_BYTES": RelayProtocolConstants.maxPublicFrameBytes,
            "MAX_RESULT_FRAME_BYTES": RelayProtocolConstants.maxResultFrameBytes,
            "MAX_REQUEST_ID_BYTES": RelayProtocolConstants.maxRequestIDBytes,
            "PROBE_NONCE_BYTES": RelayProtocolConstants.probeNonceBytes,
            "MAX_CONNECTION_ID_BYTES": RelayProtocolConstants.maxConnectionIDBytes,
            "PRIVATE_RESPONSE_ENVELOPE_SYNTAX_BYTES": RelayProtocolConstants.privateResponseEnvelopeSyntaxBytes,
            "PRIVATE_RESPONSE_FRAME_HEADROOM_BYTES": RelayProtocolConstants.privateResponseFrameHeadroomBytes,
            "MAX_FRAME_OVERHEAD_BYTES": RelayProtocolConstants.maxFrameOverheadBytes,
            "MAX_PRIVATE_FRAME_BYTES": RelayProtocolConstants.maxPrivateFrameBytes,
            "MAX_PARTIAL_FRAME_BYTES": RelayProtocolConstants.maxPartialFrameBytes,
            "CONTROL_QUEUE_DEPTH_PER_CONNECTION": RelayProtocolConstants.controlQueueDepthPerConnection,
            "CONTROL_RESPONSE_ALLOWANCE_PER_CONNECTION": RelayProtocolConstants.controlResponseAllowancePerConnection,
            "MAX_CLIENT_OUTBOUND_FRAMES_PER_CONNECTION": RelayProtocolConstants.maxClientOutboundFramesPerConnection,
            "MAX_JSON_NESTING_DEPTH": RelayProtocolConstants.maxJSONNestingDepth,
            "MAX_PUBLIC_READ_CHUNK_BYTES": RelayProtocolConstants.maxPublicReadChunkBytes,
            "PROBE_REPLY_BOUND_MS": RelayProtocolConstants.probeReplyBoundMilliseconds,
            "CHILD_READY_TIMEOUT_MS": RelayProtocolConstants.childReadyTimeoutMilliseconds,
            "RELAY_CHILD_EXIT_BOUND_MS": RelayProtocolConstants.relayChildExitBoundMilliseconds,
            "MAX_PUBLIC_CONNECTIONS": RelayProtocolConstants.maxPublicConnections
        ]
        for (name, expected) in expectedValues {
            let line = seam.split(separator: "\n").first { $0.hasPrefix("\(name) = ") }
            guard let line else {
                return XCTFail("missing \(name) in SEAM.md")
            }
            let numbers = line.matches(of: /\d+/).compactMap { Int($0.output) }
            XCTAssertEqual(numbers.last, expected, name)
        }

        assertAllSEAMValueCopies(
            seam,
            name: "RELAY_CHILD_EXIT_BOUND_MS",
            expected: RelayProtocolConstants.relayChildExitBoundMilliseconds
        )
        assertAllSEAMValueCopies(
            seam,
            name: "PROBE_NONCE_BYTES",
            expected: RelayProtocolConstants.probeNonceBytes
        )
        XCTAssertTrue(
            seam.contains(#"^[A-Za-z0-9._:-]{1,\#(RelayProtocolConstants.maxRequestIDBytes)}$"#),
            "SEAM.md request id regex must keep the relay-owned max id length"
        )
    }

    private func assertAllSEAMValueCopies(_ seam: String, name: String, expected: Int) {
        let marker = "`\(name) = "
        let values = seam.ranges(of: marker).compactMap { range -> Int? in
            let suffix = seam[range.upperBound...]
            let digits = suffix.prefix { $0.isNumber }
            guard !digits.isEmpty else { return nil }
            return Int(digits)
        }
        XCTAssertFalse(values.isEmpty, "missing prose copies of \(name) in SEAM.md")
        for value in values {
            XCTAssertEqual(value, expected, name)
        }
    }

    func testLongestAllowedIDFullResultFitsPrivateResponseCap() throws {
        _ = RelayConnection(connectionID: "conn-assertion-probe")

        let requestID = String(repeating: "r", count: RelayProtocolConstants.maxRequestIDBytes)
        let resultPayload = Self.exactResultPayload(requestID: requestID, exactPayloadBytes: RelayProtocolConstants.maxResultFrameBytes)
        XCTAssertEqual(resultPayload.count, RelayProtocolConstants.maxResultFrameBytes)

        let response = Self.nodeResponse(connectionID: Self.maximumConnectionID, requestID: requestID, resultPayload: resultPayload)
        let measuredSkeleton = try BoundedFrameStream.encodedPayload(RelayFrame(type: "response", fields: [
            "connection_id": .string(""),
            "request_id": .string(""),
            "result_b64": .string("")
        ])).count
        XCTAssertEqual(RelayProtocolConstants.privateResponseEnvelopeSyntaxBytes, measuredSkeleton)
        XCTAssertEqual(RelayProtocolConstants.maxFrameOverheadBytes, measuredSkeleton
            + RelayProtocolConstants.maxConnectionIDBytes
            + RelayProtocolConstants.maxRequestIDBytes
            + RelayProtocolConstants.privateResponseFrameHeadroomBytes)
        XCTAssertLessThanOrEqual(try BoundedFrameStream.encodedPayload(response).count, RelayProtocolConstants.maxPrivateFrameBytes)
    }

    func testForwardedControlDoesNotConsumeCallResponse() throws {
        var connection = Self.connectionWithCall("conn-control-drop", requestID: "mcp-1")
        XCTAssertEqual(Self.forwardedFrameCount(in: connection.receivePublicBytes(Self.cancelBytes(requestID: "mcp-unknown"))), 1)
        let resultPayload = Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)

        XCTAssertEqual(connection.handleNodeFrame(Self.nodeResponse(connectionID: "conn-control-drop", requestID: "mcp-1", resultPayload: resultPayload)), [
            .toClientPayload(resultPayload, completion: .result)
        ])
    }

    func testNodeCloseForParsedRefusalClosesOnlyNamedConnection() throws {
        var refused = Self.connectionWithCall("conn-refused", requestID: "mcp-1")
        XCTAssertTrue(refused.handleNodeFrame(RelayFrame(type: "close", fields: ["connection_id": .string("conn-refused")])).contains(.closePublicConnection))

        var other = RelayConnection(connectionID: "conn-other")
        let outputs = other.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-2"))
        XCTAssertEqual(Self.forwardedFrameCount(in: outputs), 1)
        XCTAssertEqual(other.state, .state_IN_FLIGHT)
    }

    func testClientOutputsCarryWriteCompletionKinds() throws {
        var connection = Self.connectionWithCall("conn-kinds", requestID: "mcp-1")
        XCTAssertEqual(Self.clientWriteKind(connection.receivePublicBytes(Self.pingBytes()).first), .pong)

        let busy = connection.receivePublicBytes(Self.toolsCallBytes(requestID: "mcp-2"))
        XCTAssertEqual(Self.clientWriteKind(busy.first), .busyDenial)

        let resultPayload = Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)
        let result = connection.handleNodeFrame(RelayFrame(
            type: "response",
            fields: [
                "connection_id": .string("conn-kinds"),
                "request_id": .string("mcp-1"),
                "result_b64": .string(resultPayload.base64EncodedString())
            ]
        ))
        XCTAssertEqual(Self.clientWriteKind(result.first), .result)
    }

    func testControlQueueIsNotClearedByNodeResponse() throws {
        var connection = Self.connectionWithCall("conn-control-reset", requestID: "mcp-1")
        for index in 0..<(RelayProtocolConstants.controlQueueDepthPerConnection - 1) {
            let outputs = connection.receivePublicBytes(Self.cancelBytes(requestID: "mcp-\(index)"))
            XCTAssertFalse(outputs.contains(.closePublicConnection), "control \(index)")
        }
        let resultPayload = Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)
        _ = connection.handleNodeFrame(RelayFrame(
            type: "response",
            fields: [
                "connection_id": .string("conn-control-reset"),
                "request_id": .string("mcp-1"),
                "result_b64": .string(resultPayload.base64EncodedString())
            ]
        ))

        XCTAssertFalse(connection.receivePublicBytes(Self.cancelBytes(requestID: "mcp-last")).contains(.closePublicConnection))
        XCTAssertTrue(connection.receivePublicBytes(Self.cancelBytes(requestID: "mcp-overflow")).contains(.closePublicConnection))
    }

    func testControlAllowancesDrainOnWriteCompletion() throws {
        var connection = RelayConnection(connectionID: "conn-drain")
        _ = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))
        for index in 0..<(RelayProtocolConstants.controlQueueDepthPerConnection * 2) {
            let outputs = connection.handlePublicFrame(RelayFrame(type: "cancel", fields: ["mcp_request_id": .string("mcp-\(index)")]))
            XCTAssertFalse(outputs.contains(.closePublicConnection), "control \(index)")
            connection.markNodeFrameWritten(.forwardedControlFrame)
        }

        var pings = RelayConnection(connectionID: "conn-ping-drain")
        for _ in 0..<(RelayProtocolConstants.controlResponseAllowancePerConnection * 3) {
            XCTAssertEqual(pings.handlePublicFrame(RelayFrame(type: "ping")), [.toClient(RelayFrame(type: "pong"), completion: .pong)])
            pings.markClientFrameWritten(.pong)
        }
    }

    func testResultPayloadOverCapSendsFixedErrorAndContinues() throws {
        var connection = RelayConnection(connectionID: "conn-result-cap")
        _ = connection.handlePublicFrame(RelayFrame(
            type: "tools_call",
            fields: ["request_id": .string("mcp-1"), "name": .string("memory_insert"), "arguments": .object([:])]
        ))
        let resultPayload = try Self.publicPayload(RelayFrame(
            type: "result",
            fields: [
                "request_id": .string("mcp-1"),
                "payload": .object(["text": .string(String(repeating: "a", count: RelayProtocolConstants.maxResultFrameBytes))])
            ]
        ))

        let outputs = connection.handleNodeFrame(RelayFrame(
            type: "response",
            fields: [
                "connection_id": .string("conn-result-cap"),
                "request_id": .string("mcp-1"),
                "result_b64": .string(resultPayload.base64EncodedString())
            ]
        ))

        XCTAssertEqual(outputs, [.toClient(RelayFrame(type: "error", fields: [
            "request_id": .string("mcp-1"),
            "message": .string("Memory request denied.")
        ]), completion: .result)])
        XCTAssertEqual(connection.state, .state_SERVING)
    }

    func testWrongConnectionAndMalformedProbeAreFatalPrivateEvents() throws {
        var connection = Self.connectionWithCall("conn-private-check", requestID: "mcp-1")
        let resultPayload = Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)
        XCTAssertEqual(connection.handleNodeFrame(RelayFrame(
            type: "response",
            fields: [
                "connection_id": .string("conn-other"),
                "request_id": .string("mcp-1"),
                "result_b64": .string(resultPayload.base64EncodedString())
            ]
        )), [.fatalRelayError])

        XCTAssertEqual(connection.handleProbe(
            RelayFrame(type: "probe", fields: ["connection_id": .string("conn-private-check")]),
            publicFD: StubProbeSource(events: [])
        ), [.fatalRelayError])
        XCTAssertEqual(connection.handleProbe(
            RelayFrame(type: "probe", fields: ["connection_id": .string("conn-other"), "nonce": .string(testProbeNonce)]),
            publicFD: StubProbeSource(events: [])
        ), [.fatalRelayError])
    }

    func testPoisonThenProbeEOFEmitsClosedOnlyOnce() throws {
        var connection = RelayConnection(connectionID: "conn-poison-probe")
        let first = connection.receivePublicBytes(Self.prefixed(Data("{".utf8)))
        let second = connection.handleProbe(
            RelayFrame(type: "probe", fields: ["connection_id": .string("conn-poison-probe"), "nonce": .string(testProbeNonce)]),
            publicFD: StubProbeSource(events: [.eof, .hangup])
        )

        XCTAssertEqual(Self.closedCount(in: first + second), 1)
    }

    func testProbeEOFAndHangupEmitsClosedOnlyOnce() throws {
        var connection = RelayConnection(connectionID: "conn-live-probe")
        let outputs = connection.handleProbe(
            RelayFrame(type: "probe", fields: ["connection_id": .string("conn-live-probe"), "nonce": .string(testProbeNonce)]),
            publicFD: StubProbeSource(events: [.eof, .hangup])
        )

        XCTAssertEqual(Self.closedCount(in: outputs), 1)
    }

    private static func publicPayload(_ frame: RelayFrame) throws -> Data {
        Data(try BoundedFrameStream.encode(frame).dropFirst(RelayProtocolConstants.frameLengthPrefixBytes))
    }

    private static func prefixed(_ payload: Data) -> Data {
        BoundedFrameStream.encodeLengthOnly(UInt32(payload.count)) + payload
    }

    private static func toolsCallBytes(requestID: String) -> Data {
        prefixed(Data(#"{"type":"tools_call","request_id":"\#(requestID)","name":"memory_search","arguments":{"query":"x"}}"#.utf8))
    }

    private static func toolsCallBytes(rawRequestID: Data) -> Data {
        prefixed(Data(#"{"type":"tools_call","request_id":""#.utf8)
            + rawRequestID
            + Data(#"","name":"memory_search","arguments":{"query":"x"}}"#.utf8))
    }

    private static func toolsListBytes(requestID: String) -> Data {
        prefixed(Data(#"{"type":"tools_list","request_id":"\#(requestID)"}"#.utf8))
    }

    private static func toolsListBytes(rawRequestID: Data) -> Data {
        prefixed(Data(#"{"type":"tools_list","request_id":""#.utf8)
            + rawRequestID
            + Data(#""}"#.utf8))
    }

    private static func helloBytes(requestID: String) -> Data {
        prefixed(Data(#"{"type":"hello","request_id":"\#(requestID)","protocol_version":"2026-10-12","client_name":"hermes"}"#.utf8))
    }

    private static func helloBytes(rawRequestID: Data) -> Data {
        prefixed(Data(#"{"type":"hello","request_id":""#.utf8)
            + rawRequestID
            + Data(#"","protocol_version":"2026-10-12","client_name":"hermes"}"#.utf8))
    }

    private static func cancelBytes(requestID: String) -> Data {
        prefixed(Data(#"{"type":"cancel","mcp_request_id":"\#(requestID)"}"#.utf8))
    }

    private static func cancelBytes(rawRequestID: Data) -> Data {
        prefixed(Data(#"{"type":"cancel","mcp_request_id":""#.utf8)
            + rawRequestID
            + Data(#""}"#.utf8))
    }

    private static func jsonStringContentBytes(for byte: UInt8) -> Data {
        switch byte {
        case 0x00...0x1f:
            return Data(String(format: "\\u%04x", byte).utf8)
        case UInt8(ascii: "\""):
            return Data(#"\""#.utf8)
        case UInt8(ascii: "\\"):
            return Data(#"\\"#.utf8)
        default:
            return Data([byte])
        }
    }

    private static func pingBytes() -> Data {
        prefixed(Data(#"{"type":"ping"}"#.utf8))
    }

    private static func publicFrameBytes(_ frame: RelayFrame) -> Data {
        try! BoundedFrameStream.encode(frame)
    }

    private static func clientWriteKind(_ output: RelayOutput?) -> ClientWriteKind? {
        switch output {
        case .toClient(_, let completion):
            return completion
        case .toClientPayload(_, let completion):
            return completion
        default:
            return nil
        }
    }

    private static func nodeWriteKind(_ output: RelayOutput?) -> NodeWriteKind? {
        switch output {
        case .toNode(_, let completion):
            return completion
        default:
            return nil
        }
    }

    private static func nodeResponse(connectionID: String, requestID: String, resultPayload: Data) -> RelayFrame {
        RelayFrame(type: "response", fields: [
            "connection_id": .string(connectionID),
            "request_id": .string(requestID),
            "result_b64": .string(resultPayload.base64EncodedString())
        ])
    }

    private static var maximumConnectionID: String {
        "c" + String(UInt64.max)
    }

    private static func exactResultPayload(requestID: String, exactPayloadBytes: Int) -> Data {
        let head = #"{"type":"result","request_id":"\#(requestID)","payload":{"text":""#
        let tail = #""}}"#
        let pad = exactPayloadBytes - Data(head.utf8).count - Data(tail.utf8).count
        precondition(pad >= 0)
        return Data((head + String(repeating: "a", count: pad) + tail).utf8)
    }

    private static func clientFrameCount(in outputs: [RelayOutput]) -> Int {
        outputs.filter { output in
            if case .toClient = output { return true }
            if case .toClientPayload = output { return true }
            return false
        }.count
    }

    private static func forwardedFrameCount(in outputs: [RelayOutput]) -> Int {
        outputs.filter { output in
            guard case .toNode(let frame, _) = output else { return false }
            return frame.type == "frame"
        }.count
    }

    private static func connectionWithCall(_ connectionID: String, requestID: String) -> RelayConnection {
        var connection = RelayConnection(connectionID: connectionID)
        _ = connection.receivePublicBytes(toolsCallBytes(requestID: requestID))
        return connection
    }

    private static func denial(_ requestID: String) -> RelayOutput {
        .toClient(RelayFrame(type: "error", fields: [
            "request_id": .string(requestID),
            "message": .string("Memory request denied.")
        ]), completion: .result)
    }

    private static func closedCount(in outputs: [RelayOutput]) -> Int {
        outputs.filter { output in
            guard case .toNode(let frame, _) = output else { return false }
            return frame.type == "closed"
        }.count
    }
}

final class RelayAdmissionTests: XCTestCase {
    func testAdmissionEmitsAcceptedAndClosesFifthConnectionBeforeNode() throws {
        var admission = RelayAdmissionController()
        for index in 1...RelayProtocolConstants.maxPublicConnections {
            XCTAssertEqual(try admission.acceptPeer(), [
                .toNode(RelayFrame(type: "accepted", fields: ["connection_id": .string("c\(index)")]), completion: nil)
            ])
        }

        XCTAssertEqual(try admission.acceptPeer(), [.closePublicConnection])
    }

    func testClosedConnectionFreesAdmissionSlot() throws {
        var admission = RelayAdmissionController()
        for index in 1...RelayProtocolConstants.maxPublicConnections {
            _ = try admission.acceptPeer()
            admission.markClosed(connectionID: "c\(index)")
        }

        XCTAssertEqual(try admission.acceptPeer(), [
            .toNode(RelayFrame(type: "accepted", fields: ["connection_id": .string("c5")]), completion: nil)
        ])
    }

    func testShutdownModelEmitsRelayShutdown() {
        XCTAssertEqual(RelayShutdownModel.gracefulShutdownFrame(), RelayFrame(type: "relay_shutdown"))
    }
}

private struct RelayFixture: Decodable {
    var valid: [RelayVector]
    var malformed: [RelayVector]
    var wrongAllowlist: [RelayVector]
    var streamCases: [StreamVector]

    enum CodingKeys: String, CodingKey {
        case valid
        case malformed
        case wrongAllowlist = "wrong_allowlist"
        case streamCases = "stream_cases"
    }

    static func load() throws -> RelayFixture {
        let url = Bundle.module.url(forResource: "relay-frames", withExtension: "json")!
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(RelayFixture.self, from: data)
    }
}

private struct RelayVector: Decodable {
    var name: String
    var direction: String
    var frame: [String: JSONValue]
    var expectedAction: String

    enum CodingKeys: String, CodingKey {
        case name
        case direction
        case frame
        case expectedAction = "expected_action"
    }

    var directionEnum: FrameDirection {
        FrameDirection(rawValue: direction)!
    }

    func assertExpectedAction() throws {
        let payload = try fixturePayloadBytes()
        let parsedFrame = try? RelayFrame.fromFixtureObject(frame)
        switch expectedAction {
        case "accept":
            guard let parsedFrame else {
                return XCTFail("valid fixture did not parse for \(name)")
            }
            XCTAssertNoThrow(try FrameAllowlist.validate(parsedFrame, direction: directionEnum), name)
            switch directionEnum {
            case .publicInbound:
                var connection = RelayConnection(connectionID: "fixture-public")
                let outputs = connection.receivePublicBytes(Self.prefixed(payload))
                XCTAssertFalse(outputs.contains(.fatalRelayError), name)
            case .nodeToRelay:
                var receiver = PrivateFrameReceiver()
                if parsedFrame.type != "ready" {
                    _ = try receiver.receiveFromNode(try BoundedFrameStream.encode(RelayFrame(type: "ready")))
                }
                XCTAssertNoThrow(try receiver.receiveFromNode(Self.prefixed(payload)), name)
            case .relayToNode, .clientOutbound:
                XCTAssertNoThrow(try FrameAllowlist.validate(parsedFrame, direction: directionEnum), name)
            }
        case "poison_connection":
            XCTAssertEqual(directionEnum, .publicInbound, name)
            var connection = RelayConnection(connectionID: "fixture-public")
            let outputs = connection.receivePublicBytes(Self.prefixed(payload))
            XCTAssertTrue(outputs.contains(.closePublicConnection), name)
            XCTAssertEqual(connection.state, .state_CLOSED, name)
        case "fatal_relay_error":
            XCTAssertNotEqual(directionEnum, .publicInbound, name)
            if directionEnum == .relayToNode {
                return XCTFail("relay-to-node fixture vectors use fatal_bridge, not fatal_relay_error, for \(name)")
            }
            if directionEnum == .nodeToRelay {
                var receiver = PrivateFrameReceiver()
                if parsedFrame?.type != "ready" {
                    _ = try receiver.receiveFromNode(try BoundedFrameStream.encode(RelayFrame(type: "ready")))
                }
                XCTAssertThrowsError(try receiver.receiveFromNode(Self.prefixed(payload)), name)
            } else if let parsedFrame {
                XCTAssertThrowsError(try FrameAllowlist.validate(parsedFrame, direction: directionEnum), name)
            } else {
                XCTAssertThrowsError(try JSONDecoder().decode(RelayFrame.self, from: payload), name)
            }
        case "fatal_bridge":
            XCTAssertEqual(directionEnum, .relayToNode, name)
            if let parsedFrame {
                XCTAssertThrowsError(try FrameAllowlist.validate(parsedFrame, direction: directionEnum), name)
            } else {
                XCTAssertThrowsError(try JSONDecoder().decode(RelayFrame.self, from: payload), name)
            }
        case "discard_late_probe_reply":
            XCTFail("object fixtures do not model Node probe wait state for \(name)")
        default:
            XCTFail("unexpected fixture action \(expectedAction) for \(name)")
        }
    }

    private func fixturePayloadBytes() throws -> Data {
        try JSONEncoder().encode(JSONValue.object(frame))
    }

    private static func prefixed(_ payload: Data) -> Data {
        BoundedFrameStream.encodeLengthOnly(UInt32(payload.count)) + payload
    }
}

private struct StreamVector: Decodable {
    var name: String
    var channel: String
    var precondition: StreamPrecondition?
    var bytesHex: String
    var thenBytesHex: String?
    var expectedAction: String

    enum CodingKeys: String, CodingKey {
        case name
        case channel
        case precondition
        case bytesHex = "bytes_hex"
        case thenBytesHex = "then_bytes_hex"
        case expectedAction = "expected_action"
    }

    func expandBytes() throws -> Data {
        try Data(hexString: bytesHex)
    }

    func assertExpectedAction() throws {
        switch channel {
        case "public":
            try assertPublicAction()
        case "node_to_relay":
            try assertNodeToRelayAction()
        case "relay_to_node":
            try assertRelayToNodeAction()
        default:
            throw FixtureError.unsupportedStreamVector(channel)
        }
    }

    private func assertPublicAction() throws {
        let bytes = try expandBytes()
        switch expectedAction {
        case "reject_before_payload_allocation":
            XCTAssertGreaterThan(Self.prefixedLength(bytes), RelayProtocolConstants.maxPublicFrameBytes, name)
            var stream = BoundedFrameStream()
            XCTAssertThrowsError(try stream.append(bytes), name)
            var connection = RelayConnection(connectionID: "fixture-public")
            XCTAssertTrue(connection.receivePublicBytes(bytes).contains(.closePublicConnection), name)
        case "retain_until_probe_then_closed":
            var connection = RelayConnection(connectionID: "fixture-public")
            XCTAssertTrue(connection.receivePublicBytes(bytes).isEmpty, name)
            let outputs = connection.handleProbe(
                RelayFrame(type: "probe", fields: ["connection_id": .string("fixture-public"), "nonce": .string(testProbeNonce)]),
                publicFD: StubProbeSource(events: [])
            )
            XCTAssertTrue(outputs.contains(.closePublicConnection), name)
        case "decode_all_complete_frames":
            var stream = BoundedFrameStream()
            let frames = try stream.append(bytes)
            XCTAssertEqual(frames.count, 2, name)
            XCTAssertFalse(stream.hasPartialFrame, name)
            XCTAssertFalse(stream.isPoisoned, name)
        case "decode_prefix_keep_partial_tail":
            var stream = BoundedFrameStream()
            let frames = try stream.append(bytes)
            XCTAssertEqual(frames.count, 1, name)
            XCTAssertTrue(stream.hasPartialFrame, name)
            var connection = RelayConnection(connectionID: "fixture-public")
            XCTAssertEqual(Self.forwardedFrameCount(in: connection.receivePublicBytes(bytes)), 1, name)
            let outputs = connection.handleProbe(
                RelayFrame(type: "probe", fields: ["connection_id": .string("fixture-public"), "nonce": .string(testProbeNonce)]),
                publicFD: StubProbeSource(events: [])
            )
            XCTAssertTrue(outputs.contains(.closePublicConnection), name)
        case "poison_connection":
            var connection = RelayConnection(connectionID: "fixture-public")
            let outputs = connection.receivePublicBytes(bytes)
            XCTAssertTrue(outputs.contains(.closePublicConnection), name)
            XCTAssertEqual(connection.state, .state_CLOSED, name)
        case "decode_one_frame":
            var stream = BoundedFrameStream()
            let frames = try stream.append(bytes)
            XCTAssertEqual(frames.count, 1, name)
            XCTAssertFalse(stream.hasPartialFrame, name)
            XCTAssertFalse(stream.isPoisoned, name)
            var connection = RelayConnection(connectionID: "fixture-public")
            let outputs = connection.receivePublicBytes(bytes)
            XCTAssertEqual(Self.forwardedFrameCount(in: outputs), 1, name)
            XCTAssertEqual(Self.clientFrameCount(in: outputs), 0, name)
            XCTAssertFalse(outputs.contains(.closePublicConnection), name)
        default:
            XCTFail("unexpected public stream action \(expectedAction) for \(name)")
        }
    }

    private func assertNodeToRelayAction() throws {
        var receiver = PrivateFrameReceiver()
        _ = try receiver.receiveFromNode(try BoundedFrameStream.encode(RelayFrame(type: "ready")))
        let bytes = try expandBytes()
        if expectedAction == "fatal_relay_error" {
            XCTAssertThrowsError(try receiver.receiveFromNode(bytes), name)
            return
        }
        let frames = try receiver.receiveFromNode(bytes)
        var connection = RelayConnection(connectionID: precondition?.connectionID ?? "c1")
        if let requestID = precondition?.inFlightRequestID {
            _ = connection.receivePublicBytes(Self.toolsCallPayload(requestID: requestID))
        }
        switch expectedAction {
        case "close_then_late_response_discarded":
            guard precondition?.inFlightRequestID != nil,
                  let thenBytesHex
            else {
                return XCTFail("close-then-late vector requires precondition and then_bytes_hex for \(name)")
            }
            let closeOutputs = connection.handleNodeFrame(frames[0])
            XCTAssertTrue(closeOutputs.contains(.closePublicConnection), name)
            XCTAssertEqual(connection.state, .state_CLOSED, name)
            let lateFrames = try receiver.receiveFromNode(try Data(hexString: thenBytesHex))
            XCTAssertEqual(connection.handleNodeFrame(lateFrames[0]), [], name)
        case "accept":
            XCTAssertEqual(connection.handleNodeFrame(frames[0]).contains(.fatalRelayError), false, name)
        case "decode_response_and_forward":
            let outputs = connection.handleNodeFrame(frames[0])
            guard case .toClientPayload(_, completion: .result)? = outputs.first else {
                return XCTFail("expected forwarded result payload for \(name)")
            }
        case "decode_response_and_deny":
            XCTAssertEqual(connection.handleNodeFrame(frames[0]).first, .toClient(RelayFrame(type: "error", fields: [
                "request_id": .string(precondition?.inFlightRequestID ?? "mcp-1"),
                "message": .string("Memory request denied.")
            ]), completion: .result), name)
        case "fatal_relay_error":
            XCTAssertEqual(connection.handleNodeFrame(frames[0]), [.fatalRelayError], name)
        default:
            XCTFail("unexpected node stream action \(expectedAction) for \(name)")
        }
    }

    private func assertRelayToNodeAction() throws {
        var stream = BoundedFrameStream(maxFrameBytes: RelayProtocolConstants.maxPrivateFrameBytes, maxFrameOverheadBytes: 0)
        let bytes = try expandBytes()
        switch expectedAction {
        case "accept":
            if name == "relay probe reply never accepted connection" {
                return XCTFail("unknown probe replies are fatal_bridge, not accept")
            }
            let frames = try stream.append(bytes)
            XCTAssertEqual(frames.count, 1, name)
            XCTAssertNoThrow(try FrameAllowlist.validate(frames[0], direction: .relayToNode), name)
        case "discard_late_probe_reply":
            let frames = try stream.append(bytes)
            XCTAssertFalse(frames.isEmpty, name)
            let probeReplies = frames.filter { $0.type == "probe_reply" }
            XCTAssertEqual(probeReplies.count, 1, name)
            for frame in frames {
                XCTAssertNoThrow(try FrameAllowlist.validate(frame, direction: .relayToNode), name)
            }
        case "fatal_bridge":
            do {
                let frames = try stream.append(bytes)
                guard let frame = frames.first else {
                    return XCTFail("fatal bridge vector decoded no frame for \(name)")
                }
                if name == "relay probe reply never accepted connection" {
                    XCTAssertNoThrow(try FrameAllowlist.validate(frame, direction: .relayToNode), name)
                    XCTAssertEqual(frame.type, "probe_reply", name)
                } else {
                    XCTAssertThrowsError(try FrameAllowlist.validate(frame, direction: .relayToNode), name)
                }
            } catch {
                XCTAssertTrue(stream.isPoisoned, name)
            }
        default:
            XCTFail("unexpected relay-to-node stream action \(expectedAction) for \(name)")
        }
    }

    static func expectedBytesHexByName() throws -> [String: String] {
        let expected: [String: Data] = [
            "overlarge length": BoundedFrameStream.encodeLengthOnly(UInt32(RelayProtocolConstants.maxPublicFrameBytes + 1)),
            "partial frame": BoundedFrameStream.encodeLengthOnly(UInt32(32)),
            "two 48 KiB frames": (try! prefixedPublicHello(requestID: "large-a", exactPayloadBytes: 48 * RelayProtocolConstants.bytesPerKiB))
                + (try! prefixedPublicHello(requestID: "large-b", exactPayloadBytes: 48 * RelayProtocolConstants.bytesPerKiB)),
            "max public frame plus partial tail": (try! prefixedPublicHello(requestID: "large-max", exactPayloadBytes: RelayProtocolConstants.maxPublicFrameBytes))
                + BoundedFrameStream.encodeLengthOnly(UInt32(RelayProtocolConstants.maxPublicFrameBytes))
                + Data(repeating: UInt8(ascii: "{"), count: RelayProtocolConstants.frameLengthPrefixBytes),
            "duplicate public key": prefixed(Data(#"{"type":"cancel","mcp_request_id":"a","mcp_request_id":"b"}"#.utf8)),
            "nested duplicate public key": prefixed(Data(#"{"type":"tools_call","request_id":"mcp-1","name":"memory_search","arguments":{"query":"a","query":"b"}}"#.utf8)),
            "escaped duplicate public key": prefixed(Data(#"{"type":"ping","\u0074ype":"shutdown"}"#.utf8)),
            "node result valid": prefixed(nodeResponsePayload(resultPayload: Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8))),
            "node result over cap": prefixed(nodeResponsePayload(resultPayload: overCapResultPayload())),
            "node result mismatched id": prefixed(nodeResponsePayload(resultPayload: Data(#"{"type":"result","request_id":"mcp-other","payload":{}}"#.utf8))),
            "node result lone surrogate": prefixed(nodeResponsePayload(resultPayload: Data(#"{"type":"result","request_id":"mcp-1","payload":{"text":"\ud83d"}}"#.utf8))),
            "node result over depth": prefixed(nodeResponsePayload(resultPayload: Data((#"{"type":"result","request_id":"mcp-1","payload":"#
                + String(repeating: "[", count: RelayProtocolConstants.maxJSONNestingDepth + 1)
                + String(repeating: "]", count: RelayProtocolConstants.maxJSONNestingDepth + 1)
                + "}").utf8))),
            "refused cancel": prefixed(Data(#"{"type":"cancel","mcp_request_id":"mcp-1"}"#.utf8)),
            "node close then late response": prefixed(Data(#"{"type":"close","connection_id":"c2"}"#.utf8)),
            "node result padded base64": prefixed(nodeResponsePayload(resultPayload: Data(#"{"type":"result","request_id":"mcp-1","payload":{"x":"a"}}"#.utf8))),
            "node result unpadded base64": prefixed(nodeResponsePayload(
                resultPayload: Data(#"{"type":"result","request_id":"mcp-1","payload":{"x":"a"}}"#.utf8),
                stripPadding: true
            )),
            "request id over cap": prefixed(Data(#"{"type":"tools_list","request_id":"\#(String(repeating: "x", count: RelayProtocolConstants.maxRequestIDBytes + 1))"}"#.utf8)),
            "request id disallowed character": prefixed(Data(#"{"type":"tools_list","request_id":"bad\u0022id"}"#.utf8)),
            "request id escaped legal character": prefixed(Data(#"{"type":"tools_list","request_id":"\u0061"}"#.utf8)),
            "node response private cap exact": try privateCapExactNodeResponse(),
            "node response private cap over": BoundedFrameStream.encodeLengthOnly(UInt32(RelayProtocolConstants.maxPrivateFrameBytes + 1)),
            "relay accepted bytes": prefixed(Data(#"{"type":"accepted","connection_id":"c1"}"#.utf8)),
            "relay frame bytes": prefixed(Data(#"{"type":"frame","connection_id":"c1","frame_b64":"\#(Data(#"{"type":"ping"}"#.utf8).base64EncodedString())"}"#.utf8)),
            "relay closed bytes": prefixed(Data(#"{"type":"closed","connection_id":"c1"}"#.utf8)),
            "relay probe reply bytes": prefixed(Data(#"{"type":"probe_reply","connection_id":"c1","nonce":"\#(testProbeNonce)"}"#.utf8)),
            "relay closed then late probe reply": prefixed(Data(#"{"type":"closed","connection_id":"c1"}"#.utf8))
                + prefixed(Data(#"{"type":"probe_reply","connection_id":"c1","nonce":"\#(testProbeNonce)"}"#.utf8)),
            "relay probe reply after timeout": prefixed(Data(#"{"type":"probe_reply","connection_id":"c2","nonce":"fedcba9876543210fedcba9876543210"}"#.utf8)),
            "relay shutdown bytes": prefixed(Data(#"{"type":"relay_shutdown"}"#.utf8)),
            "relay bad json": prefixed(Data(#"{"type":"accepted""#.utf8)),
            "relay unknown type": prefixed(Data(#"{"type":"ready"}"#.utf8)),
            "relay missing field": prefixed(Data(#"{"type":"accepted"}"#.utf8)),
            "relay duplicate key": prefixed(Data(#"{"type":"accepted","connection_id":"c1","connection_id":"c2"}"#.utf8)),
            "relay over cap length": BoundedFrameStream.encodeLengthOnly(UInt32(RelayProtocolConstants.maxPrivateFrameBytes + 1)),
            "relay probe reply never accepted connection": prefixed(Data(#"{"type":"probe_reply","connection_id":"c999","nonce":"\#(testProbeNonce)"}"#.utf8))
        ]
        return expected.mapValues(\.hexString)
    }

    static let expectedThenBytesHexByName: [String: String] = [
        "node close then late response": prefixed(nodeResponsePayload(
            connectionID: "c2",
            requestID: "mcp-1",
            resultPayload: Data(#"{"type":"result","request_id":"mcp-1","payload":{}}"#.utf8)
        )).hexString
    ]

    private static func prefixedPublicHello(requestID: String, exactPayloadBytes: Int) throws -> Data {
        let prefix = #"{"type":"hello","request_id":"\#(requestID)","protocol_version":"2026-10-12","client_name":""#
        let suffix = #""}"#
        let padCount = exactPayloadBytes - Data(prefix.utf8).count - Data(suffix.utf8).count
        guard padCount >= 0 else {
            throw FixtureError.unsupportedStreamVector("payload too small")
        }
        let payload = Data((prefix + String(repeating: "a", count: padCount) + suffix).utf8)
        var output = BoundedFrameStream.encodeLengthOnly(UInt32(payload.count))
        output.append(payload)
        return output
    }

    private static func prefixed(_ payload: Data) -> Data {
        BoundedFrameStream.encodeLengthOnly(UInt32(payload.count)) + payload
    }

    private static func prefixedLength(_ bytes: Data) -> Int {
        let prefix = Array(bytes.prefix(RelayProtocolConstants.frameLengthPrefixBytes))
        return (Int(prefix[0]) << RelayProtocolConstants.byteShift24)
            | (Int(prefix[1]) << RelayProtocolConstants.byteShift16)
            | (Int(prefix[2]) << RelayProtocolConstants.byteShift8)
            | Int(prefix[3])
    }

    private static func toolsCallPayload(requestID: String) -> Data {
        prefixed(Data(#"{"type":"tools_call","request_id":"\#(requestID)","name":"memory_search","arguments":{"query":"x"}}"#.utf8))
    }

    private static func overCapResultPayload() -> Data {
        let head = #"{"type":"result","request_id":"mcp-1","payload":{"text":""#
        let tail = #""}}"#
        let pad = RelayProtocolConstants.maxResultFrameBytes + 1 - Data(head.utf8).count - Data(tail.utf8).count
        return Data((head + String(repeating: "a", count: pad) + tail).utf8)
    }

    private static func privateCapExactNodeResponse() throws -> Data {
        let prefix = #"{"type":"response","connection_id":"c1","request_id":"mcp-100","result_b64":""#
        let suffix = #""}"#
        let encodedLength = RelayProtocolConstants.maxPrivateFrameBytes
            - Data(prefix.utf8).count
            - Data(suffix.utf8).count
        guard encodedLength > 0 && encodedLength.isMultiple(of: 4) else {
            throw FixtureError.invalidFixture("private cap exact base64 payload length is not positive and divisible by 4")
        }
        let decodedBytes = Data(repeating: UInt8(ascii: "a"), count: encodedLength / 4 * 3)
        let payload = Data((prefix + decodedBytes.base64EncodedString() + suffix).utf8)
        guard payload.count == RelayProtocolConstants.maxPrivateFrameBytes else {
            throw FixtureError.invalidFixture("private cap exact payload length \(payload.count) != \(RelayProtocolConstants.maxPrivateFrameBytes)")
        }
        return prefixed(payload)
    }

    private static func nodeResponsePayload(
        connectionID: String = "c1",
        requestID: String = "mcp-1",
        resultPayload: Data,
        stripPadding: Bool = false
    ) -> Data {
        var encoded = resultPayload.base64EncodedString()
        if stripPadding {
            encoded.removeAll { $0 == "=" }
        }
        let payload = #"{"type":"response","connection_id":"\#(connectionID)","request_id":"\#(requestID)","result_b64":"\#(encoded)"}"#
        return Data(payload.utf8)
    }

    private static func clientFrameCount(in outputs: [RelayOutput]) -> Int {
        outputs.filter { output in
            if case .toClient = output { return true }
            if case .toClientPayload = output { return true }
            return false
        }.count
    }

    private static func forwardedFrameCount(in outputs: [RelayOutput]) -> Int {
        outputs.filter { output in
            guard case .toNode(let frame, _) = output else { return false }
            return frame.type == "frame"
        }.count
    }
}

private struct StreamPrecondition: Decodable {
    var connectionID: String?
    var inFlightRequestID: String?

    enum CodingKeys: String, CodingKey {
        case connectionID = "connection_id"
        case inFlightRequestID = "in_flight_request_id"
    }
}

private enum FixtureError: Error {
    case invalidHex(String)
    case invalidFixture(String)
    case unsupportedStreamVector(String)
}

private extension RelayFrame {
    static func fromFixtureObject(_ object: [String: JSONValue]) throws -> RelayFrame {
        let data = try JSONEncoder().encode(JSONValue.object(object))
        return try JSONDecoder().decode(RelayFrame.self, from: data)
    }

    func publicFrameTypeFromEnvelope() -> String? {
        guard type == "frame",
              case .string(let encoded)? = fields["frame_b64"],
              let payload = Data(base64Encoded: encoded),
              let decoded = try? JSONDecoder().decode(RelayFrame.self, from: payload)
        else {
            return nil
        }
        return decoded.type
    }
}

private extension Data {
    init(hexString: String) throws {
        guard hexString.count.isMultiple(of: 2) else {
            throw FixtureError.invalidHex(hexString)
        }
        var output = Data()
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else {
                throw FixtureError.invalidHex(hexString)
            }
            output.append(byte)
            index = next
        }
        self = output
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

private struct StubCredentials: PeerCredentialProvider {
    var peerUid: uid_t
    func peerUid(forFileDescriptor fd: Int32) throws -> uid_t {
        peerUid
    }
}

private struct StubAdminMembership: AdminGroupMembership {
    var adminUIDs: Set<uid_t>
    var lookupError: Error?

    init(adminUIDs: Set<uid_t>, lookupError: Error? = nil) {
        self.adminUIDs = adminUIDs
        self.lookupError = lookupError
    }

    func isAdmin(uid: uid_t) throws -> Bool {
        if let lookupError {
            throw lookupError
        }
        return adminUIDs.contains(uid)
    }
}

private struct StubAccountLookup: AccountUIDLookup {
    var accounts: [String: uid_t]

    func uid(forAccountName accountName: String) throws -> uid_t {
        guard let uid = accounts[accountName] else {
            throw PeerCheckError.installUidUnavailable
        }
        return uid
    }
}

private final class StubProbeSource: PublicFDProbeSource {
    var events: [PublicFDProbeEvent]
    init(events: [PublicFDProbeEvent]) { self.events = events }
    var isReadable: Bool { !events.isEmpty }
    func next(maximumBytes: Int) -> PublicFDProbeEvent? {
        events.isEmpty ? nil : events.removeFirst()
    }
}

private final class StubFileSystem: RelayFileSystem {
    var metadata: [String: PathMetadata]
    private(set) var unlinkedPaths: [String] = []

    init(metadata: [String: PathMetadata]) {
        self.metadata = metadata
    }

    func lstat(_ path: String) throws -> PathMetadata {
        guard let value = metadata[path] else {
            throw RelayFileSystemError.noEntry(path)
        }
        return value
    }

    func unlink(_ path: String) throws {
        unlinkedPaths.append(path)
    }

    func chmod(_ path: String, _ mode: mode_t) throws {}

    static func standardSocketTree() -> StubFileSystem {
        StubFileSystem(metadata: [
            "/Library": PathMetadata(owner: RelayProtocolConstants.rootUid, group: testRootGroup, mode: testRootAncestorMode, isDirectory: true, isSymlink: false),
            "/Library/Application Support": PathMetadata(owner: RelayProtocolConstants.rootUid, group: testRootGroup, mode: testRootAncestorMode, isDirectory: true, isSymlink: false),
            "/Library/Application Support/Sanctuary": PathMetadata(owner: RelayProtocolConstants.rootUid, group: testRootGroup, mode: testRootAncestorMode, isDirectory: true, isSymlink: false),
            "/Library/Application Support/Sanctuary/HermesMemoryBridge": PathMetadata(owner: RelayProtocolConstants.rootUid, group: testRootGroup, mode: testRootAncestorMode, isDirectory: true, isSymlink: false),
            testSocketDirectory: PathMetadata(owner: testOwnerUid, group: testGroup, mode: RelayProtocolConstants.socketDirectoryMode, isDirectory: true, isSymlink: false)
        ])
    }
}

private final class StubLock: RelayInstanceLock {
    var available: Bool

    init(available: Bool) {
        self.available = available
    }

    func tryLock(_ path: String) -> Bool {
        available
    }
}

private final class StubStartupOperations: RelayStartupOperations {
    var events: [String] = []
    var readyError: Error?

    init(readyError: Error? = nil) {
        self.readyError = readyError
    }

    func acquireInstanceLock() throws {
        events.append("lock")
    }

    func validateSocketPathUnderLock() throws {
        events.append("validate")
    }

    func spawnChild() throws {
        events.append("spawn")
    }

    func waitForChildReady(timeoutMilliseconds: Int) throws {
        events.append("ready:\(timeoutMilliseconds)")
        if let readyError {
            throw readyError
        }
    }

    func bindPublicSocket() throws {
        events.append("bind")
    }

    func unlinkLeftoverSocketWhileLocked() throws {
        events.append("unlink")
    }

    func chmodPublicSocket() throws {
        events.append("chmod")
    }

    func verifyPublicSocket() throws {
        events.append("verify")
    }

    func killChild() {
        events.append("kill")
    }

    func reapChild() {
        events.append("reap")
    }
}
