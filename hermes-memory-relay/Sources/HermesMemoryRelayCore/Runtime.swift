import Darwin
import Foundation

// The signal handler only stores a signal number; the single event loop owns all cleanup.
nonisolated(unsafe) private var relayStopSignal: sig_atomic_t = 0

private enum RuntimeLimits {
    // One accepted, one call, eight controls, one closed, and one probe reply per live slot.
    static let privateQueueFrames = RelayProtocolConstants.maxPublicConnections
        * (1 + 1 + RelayProtocolConstants.controlQueueDepthPerConnection + 1 + 1) + 1
    static let privateQueueBytes = privateQueueFrames
        * (RelayProtocolConstants.maxPrivateFrameBytes + RelayProtocolConstants.frameLengthPrefixBytes)
    // Checking signals one hundred times per probe interval bounds stop observation to 20 ms.
    static let pollMilliseconds = RelayProtocolConstants.probeReplyBoundMilliseconds / 100
    static let nanosecondsPerMillisecond: UInt64 = 1_000_000
}

private struct QueuedWrite {
    let bytes: Data
    var offset = 0
    let connectionID: String?
    let nodeCompletion: NodeWriteKind?
    let clientCompletion: ClientWriteKind?
}

private final class LiveConnection {
    let fd: Int32
    var core: RelayConnection
    var output: [QueuedWrite] = []
    init(fd: Int32, id: String) { self.fd = fd; core = RelayConnection(connectionID: id) }
    deinit { close(fd) }
}

struct NativeRelayFileSystem: RelayFileSystem {
    func lstat(_ path: String) throws -> PathMetadata {
        var info = stat()
        guard Darwin.lstat(path, &info) == 0 else {
            if errno == ENOENT { throw RelayFileSystemError.noEntry(path) }
            throw RuntimeFailure.socket
        }
        return PathMetadata(owner: info.st_uid, group: info.st_gid, mode: info.st_mode,
                            isDirectory: info.st_mode & S_IFMT == S_IFDIR,
                            isSymlink: info.st_mode & S_IFMT == S_IFLNK,
                            isSocket: info.st_mode & S_IFMT == S_IFSOCK)
    }
    func unlink(_ path: String) throws {
        guard Darwin.unlink(path) == 0 else { throw RuntimeFailure.socket }
    }
    func chmod(_ path: String, _ mode: mode_t) throws {
        guard Darwin.chmod(path, mode) == 0 else { throw RuntimeFailure.socket }
    }
}

final class NativeProbeSource: PublicFDProbeSource {
    let fd: Int32
    init(fd: Int32) { self.fd = fd }
    var isReadable: Bool {
        var item = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let count = poll(&item, 1, 0)
        return count != 0 // Errors also cannot establish a drained boundary.
    }
    func next(maximumBytes: Int) -> PublicFDProbeEvent? {
        var item = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let count = poll(&item, 1, 0)
        guard count >= 0 else { return .hangup }
        guard count > 0 else { return nil }
        if item.revents & Int16(POLLERR | POLLNVAL) != 0 { return .hangup }
        var bytes = [UInt8](repeating: 0, count: maximumBytes)
        let received = read(fd, &bytes, bytes.count)
        if received > 0 { return .data(Data(bytes.prefix(received))) }
        if received == 0 { return .eof }
        if errno == EAGAIN || errno == EWOULDBLOCK {
            return item.revents & Int16(POLLHUP) != 0 ? .hangup : nil
        }
        // EINTR cannot prove the barrier empty; refusing this connection is conservative and bounded.
        return .hangup
    }
}

/// One serial descriptor owner. Production supplies protected configuration and required admission checks.
public final class RelayRuntime {
    private let config: RuntimeConfiguration
    private let environment: [String: String]
    private let verifyPeer: (Int32) throws -> Void
    private let verifySocketPath: () throws -> Void
    private let socketGroup: gid_t
    private let instanceLock: RelayInstanceLock
    private var listener: Int32 = -1
    private var privateFD: Int32 = -1
    private var logFD: Int32 = -1
    private var child: pid_t?
    private var childReaped = false
    private var boundIdentity: (dev_t, ino_t)?
    private var receiver = PrivateFrameReceiver()
    private var issued: UInt64 = 0
    private var clients: [String: LiveConnection] = [:]
    private var nodeOutput: [QueuedWrite] = []
    private var ready = false
    private var stopping = false
    private var state = "state_CONFIG_CHECKED"

    // Required dependencies permit native test composition without an executable option that weakens admission.
    init(configuration: RuntimeConfiguration, environment: [String: String], socketGroup: gid_t,
         instanceLock: RelayInstanceLock, verifySocketPath: @escaping () throws -> Void,
         verifyPeer: @escaping (Int32) throws -> Void) {
        config = configuration
        self.environment = environment
        self.socketGroup = socketGroup
        self.instanceLock = instanceLock
        self.verifySocketPath = verifySocketPath
        self.verifyPeer = verifyPeer
    }

    /// Run the installed CLI or the exact same validation-only parser used before installation.
    public static func main(_ arguments: [String]) -> Int32 {
        signal(SIGPIPE, SIG_IGN)
        guard arguments.count == 3, arguments[1] == "--config" || arguments[1] == "--check-config" else {
            FileHandle.standardError.write(Data("usage: HermesMemoryRelay --config|--check-config <path>\n".utf8))
            return EX_USAGE
        }
        do {
            let config = try RuntimeConfiguration.load(path: arguments[2])
            if arguments[1] == "--check-config" { return EX_OK }
            guard let account = getpwuid(config.ownerUID), let home = account.pointee.pw_dir,
                  let group = getgrnam(config.group) else { throw RuntimeFailure.configuration }
            let configuredHome = String(cString: home)
            let groupID = group.pointee.gr_gid
            let identity = try HermesInstallIdentity(pinnedUID: config.hermesUID, accountName: config.hermesAccount)
                .validate(lookup: DarwinAccountUIDLookup())
            let verifier = try PeerVerifier(installIdentity: identity, ownerUid: config.ownerUID,
                                           credentials: DarwinPeerCredentialProvider(), adminMembership: DarwinAdminGroupMembership())
            let pathCheck = SocketPathValidator(socketDirectory: RuntimeConfiguration.parent(config.publicSocket),
                                                expectedSocketDirectoryOwner: config.ownerUID,
                                                expectedSocketDirectoryGroup: groupID)
            let runtime = RelayRuntime(configuration: config,
                                       environment: ["HOME": configuredHome, "LANG": "en_US.UTF-8", "TMPDIR": config.privateDirectory],
                                       socketGroup: groupID, instanceLock: DarwinInstanceLock(),
                                       verifySocketPath: { try pathCheck.validate(fileSystem: NativeRelayFileSystem()) },
                                       verifyPeer: { try verifier.requirePeer(fileDescriptor: $0) })
            return runtime.run()
        } catch {
            FileHandle.standardError.write(Data("HermesMemoryRelay state_CONFIG_CHECKED: startup refused\n".utf8))
            return EX_CONFIG
        }
    }

    /// Serve until a stop request or a transport failure; all owned descriptors converge through teardown.
    func run() -> Int32 {
        relayStopSignal = 0
        let signals = [SIGTERM, SIGINT, SIGHUP]
        for value in signals { signal(value) { relayStopSignal = $0 } }
        defer { for value in signals { signal(value, SIG_DFL) } }
        var result: Int32 = EX_OK
        do {
            state = "state_AWAIT_LOCK"
            // No socket metadata, unlink, bind or accept occurs before the lifetime flock.
            guard instanceLock.tryLock(config.privateDirectory + "/relay.lock") else { throw RuntimeFailure.lock }
            try verifySocketPath()
            logFD = try openLog(config.relayLog)
            state = "state_ENV_REPLACED"
            log("state_POLICY_PINNED not_provided")
            try state_SPAWN_CHILD()
            state = "state_CHILD_READY"
            let deadline = now() + milliseconds(RelayProtocolConstants.childReadyTimeoutMilliseconds)
            while !ready {
                if relayStopSignal != 0 { throw RuntimeFailure.readiness }
                guard !tryReap(), now() < deadline else { throw RuntimeFailure.readiness }
                try eventTurn(admitting: false)
            }
            guard relayStopSignal == 0, !tryReap() else { throw RuntimeFailure.readiness }
            try state_BIND_SOCKET()
            state = "state_READY"
            log("state_READY scoped memory search and get; writes not yet available")
            while relayStopSignal == 0 {
                guard !tryReap() else { throw RuntimeFailure.transport }
                try eventTurn(admitting: true)
            }
        } catch {
            result = ready ? EX_SOFTWARE : EX_CONFIG
            log("\(state): refused; bridge_log=\(config.bridgeLog)")
        }
        if !state_STOPPING() { result = EX_SOFTWARE }
        return result
    }

    private func state_SPAWN_CHILD() throws {
        var sockets = [Int32](repeating: -1, count: 2) // A socketpair has exactly two endpoints.
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0 else { throw RuntimeFailure.spawn }
        privateFD = sockets[0]
        let childFD = sockets[1]
        defer { close(childFD) }
        try nonblocking(privateFD)
        let plan = try ChildSupervisor.spawnPlan(config: ChildSupervisorConfig(
            executablePath: config.nodeExecutable, bridgeEntryPath: config.nodeEntry, bridgeLogPath: config.bridgeLog,
            relayFD: childFD, baseEnvironment: environment, bridgeIdentity: config.identityFingerprint,
            agentID: config.agentID, fortressID: config.fortressID))
        let bridgeLogFD = try openLog(plan.stdoutLogPath)
        defer { close(bridgeLogFD) }
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw RuntimeFailure.spawn }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw RuntimeFailure.spawn }
        defer { posix_spawnattr_destroy(&attributes) }
        func checked(_ code: Int32) throws { if code != 0 { throw RuntimeFailure.spawn } }
        // Only explicitly selected descriptors survive exec, including the source-equals-target case.
        try checked(posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)))
        switch plan.relayFDAction {
        case .duplicate(let source, let target): try checked(posix_spawn_file_actions_adddup2(&actions, source, target))
        case .inherit(let fd): try checked(posix_spawn_file_actions_addinherit_np(&actions, fd))
        }
        try checked(posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, plan.stdinPath, O_RDONLY, 0))
        try checked(posix_spawn_file_actions_adddup2(&actions, bridgeLogFD, STDOUT_FILENO))
        try checked(posix_spawn_file_actions_adddup2(&actions, bridgeLogFD, STDERR_FILENO))
        let argv = plan.arguments.map { strdup($0) } + [nil]
        let env = plan.environment.sorted { $0.key < $1.key }.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { argv.forEach { free($0) }; env.forEach { free($0) } }
        var pid: pid_t = 0
        let outcome = argv.withUnsafeBufferPointer { args in
            env.withUnsafeBufferPointer { values in
                posix_spawn(&pid, plan.executablePath, &actions, &attributes, args.baseAddress!, values.baseAddress!)
            }
        }
        try checked(outcome)
        child = pid
    }

    private func state_BIND_SOCKET() throws {
        try verifySocketPath()
        let fileSystem = NativeRelayFileSystem()
        do {
            let old = try fileSystem.lstat(config.publicSocket)
            guard old.isSocket, old.owner == config.ownerUID else { throw RuntimeFailure.socket }
            try fileSystem.unlink(config.publicSocket)
        } catch RelayFileSystemError.noEntry { /* No previous socket to reclaim. */ }
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw RuntimeFailure.socket }
        try nonblocking(listener)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = Array(config.publicSocket.utf8) + [UInt8(0)]
        guard path.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw RuntimeFailure.configuration }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: path) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let status = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard status == 0 else { throw RuntimeFailure.socket }
        let info = try RuntimeConfiguration.metadata(config.publicSocket)
        guard info.st_mode & S_IFMT == S_IFSOCK, info.st_uid == config.ownerUID else { throw RuntimeFailure.socket }
        boundIdentity = (info.st_dev, info.st_ino)
        guard chown(config.publicSocket, config.ownerUID, socketGroup) == 0,
              chmod(config.publicSocket, RelayProtocolConstants.publicSocketMode) == 0 else { throw RuntimeFailure.socket }
        let verified = try RuntimeConfiguration.metadata(config.publicSocket)
        guard verified.st_dev == info.st_dev, verified.st_ino == info.st_ino,
              verified.st_uid == config.ownerUID, verified.st_gid == socketGroup,
              verified.st_mode & 0o7777 == RelayProtocolConstants.publicSocketMode,
              listen(listener, Int32(RelayProtocolConstants.maxPublicConnections)) == 0 else { throw RuntimeFailure.socket }
    }

    private func eventTurn(admitting: Bool) throws {
        var descriptors = [pollfd(fd: privateFD, events: Int16(POLLIN | (nodeOutput.isEmpty ? 0 : POLLOUT)), revents: 0)]
        if admitting && listener >= 0 { descriptors.append(pollfd(fd: listener, events: Int16(POLLIN), revents: 0)) }
        let snapshot = clients.map { ($0.key, $0.value.fd) }
        let clientStart = descriptors.count
        for (id, fd) in snapshot {
            descriptors.append(pollfd(fd: fd, events: Int16(POLLIN | (clients[id]!.output.isEmpty ? 0 : POLLOUT)), revents: 0))
        }
        let count = poll(&descriptors, nfds_t(descriptors.count), Int32(RuntimeLimits.pollMilliseconds))
        if count < 0 && errno == EINTR { return }
        guard count >= 0 else { throw RuntimeFailure.transport }
        let privateEvents = descriptors[0].revents
        if privateEvents & Int16(POLLIN | POLLHUP | POLLERR) != 0 { try readPrivate() }
        if privateEvents & Int16(POLLNVAL) != 0 { throw RuntimeFailure.transport }
        if privateEvents & Int16(POLLOUT) != 0 { try flushNode() }
        if admitting && listener >= 0 && descriptors.count > 1 && descriptors[1].fd == listener
            && descriptors[1].revents & Int16(POLLIN) != 0 { try acceptOne() }
        for (offset, pair) in snapshot.enumerated() {
            let (id, fd) = pair
            // A close during private processing cannot transfer readiness to a reused descriptor.
            guard let connection = clients[id], connection.fd == fd else { continue }
            let events = descriptors[clientStart + offset].revents
            if events & Int16(POLLIN | POLLHUP | POLLERR | POLLNVAL) != 0 {
                let source = NativeProbeSource(fd: fd)
                if let event = source.next(maximumBytes: RelayProtocolConstants.maxPublicReadChunkBytes) {
                    let output: [RelayOutput]
                    switch event {
                    case .data(let bytes): output = connection.core.receivePublicBytes(bytes)
                    case .eof, .hangup: output = connection.core.peerClosed()
                    }
                    try apply(output, id: id)
                }
            }
            if events & Int16(POLLOUT) != 0, let current = clients[id] { try flushClient(current, id: id) }
        }
    }

    private func acceptOne() throws {
        let fd = accept(listener, nil, nil)
        if fd < 0 {
            if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { return }
            throw RuntimeFailure.socket
        }
        do {
            // Authentication completes before constructing the per-connection decoder or reading bytes.
            try verifyPeer(fd)
            guard clients.count < RelayProtocolConstants.maxPublicConnections, issued < UInt64.max else {
                close(fd); return
            }
            try nonblocking(fd)
        } catch { close(fd); return }
        issued += 1
        let id = "c\(issued)"
        clients[id] = LiveConnection(fd: fd, id: id)
        try enqueueNode(RelayFrame(type: "accepted", fields: ["connection_id": .string(id)]), id: id, kind: nil)
    }

    private func readPrivate() throws {
        var buffer = [UInt8](repeating: 0, count: RelayProtocolConstants.maxPublicReadChunkBytes)
        let count = read(privateFD, &buffer, buffer.count)
        if count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { return }
        guard count > 0 else { throw RuntimeFailure.transport }
        for frame in try receiver.receiveFromNode(Data(buffer.prefix(count))) {
            if frame.type == "ready" { ready = true; continue }
            guard case .string(let id)? = frame.fields["connection_id"], id.first == "c",
                  let counter = UInt64(id.dropFirst()), counter > 0, counter <= issued, id == "c\(counter)" else {
                throw RuntimeFailure.transport
            }
            if let connection = clients[id] {
                let output = frame.type == "probe"
                    ? connection.core.handleProbe(frame, publicFD: NativeProbeSource(fd: connection.fd))
                    : connection.core.handleNodeFrame(frame)
                try apply(output, id: id)
            } else if frame.type == "probe" {
                try enqueueNode(RelayFrame(type: "probe_reply", fields: frame.fields), id: nil, kind: nil)
            }
            // Issued but no longer live IDs need no retained connection object or tombstone.
        }
    }

    private func apply(_ outputs: [RelayOutput], id: String) throws {
        for output in outputs {
            switch output {
            case .toNode(let frame, let kind): try enqueueNode(frame, id: id, kind: kind)
            case .toClient(let frame, let kind): try enqueueClient(try BoundedFrameStream.encode(frame), id: id, kind: kind)
            case .toClientPayload(let payload, let kind):
                try enqueueClient(BoundedFrameStream.encodeLengthOnly(UInt32(payload.count)) + payload, id: id, kind: kind)
            case .closePublicConnection: clients.removeValue(forKey: id)
            case .fatalRelayError: throw RuntimeFailure.transport
            }
        }
    }

    private func enqueueNode(_ frame: RelayFrame, id: String?, kind: NodeWriteKind?) throws {
        let bytes = try BoundedFrameStream.encode(frame)
        // Churn shares one transport ceiling; closing clients cannot reset private-queue headroom.
        guard bytes.count <= RelayProtocolConstants.maxPrivateFrameBytes + RelayProtocolConstants.frameLengthPrefixBytes,
              nodeOutput.count < RuntimeLimits.privateQueueFrames,
              nodeOutput.reduce(bytes.count, { $0 + $1.bytes.count }) <= RuntimeLimits.privateQueueBytes else {
            throw RuntimeFailure.transport
        }
        nodeOutput.append(QueuedWrite(bytes: bytes, connectionID: id, nodeCompletion: kind, clientCompletion: nil))
    }

    private func enqueueClient(_ bytes: Data, id: String, kind: ClientWriteKind) throws {
        guard let connection = clients[id] else { return }
        guard connection.output.count < RelayProtocolConstants.maxClientOutboundFramesPerConnection else {
            try apply(connection.core.peerClosed(), id: id); return
        }
        connection.output.append(QueuedWrite(bytes: bytes, connectionID: id, nodeCompletion: nil, clientCompletion: kind))
    }

    private func writeHead(_ queue: inout [QueuedWrite], fd: Int32) throws -> QueuedWrite? {
        guard !queue.isEmpty else { return nil }
        let count = queue[0].bytes.withUnsafeBytes { buffer in
            write(fd, buffer.baseAddress!.advanced(by: queue[0].offset), buffer.count - queue[0].offset)
        }
        if count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) { return nil }
        guard count > 0 else { throw RuntimeFailure.transport }
        queue[0].offset += count
        // Only the exact fully written frame retires its completion token.
        return queue[0].offset == queue[0].bytes.count ? queue.removeFirst() : nil
    }

    private func flushNode() throws {
        if let written = try writeHead(&nodeOutput, fd: privateFD), let id = written.connectionID {
            clients[id]?.core.markNodeFrameWritten(written.nodeCompletion)
        }
    }

    private func flushClient(_ connection: LiveConnection, id: String) throws {
        do {
            if let written = try writeHead(&connection.output, fd: connection.fd), let kind = written.clientCompletion {
                connection.core.markClientFrameWritten(kind)
            }
        } catch { try apply(connection.core.peerClosed(), id: id) }
    }

    private func state_STOPPING() -> Bool {
        stopping = true
        state = "state_STOPPING"
        if listener >= 0 { close(listener); listener = -1 }
        clients.removeAll()
        if child != nil && !childReaped {
            try? enqueueNode(RelayShutdownModel.gracefulShutdownFrame(), id: nil, kind: nil)
            waitForChild(milliseconds: RelayProtocolConstants.probeReplyBoundMilliseconds, flush: true)
            if !childReaped, let pid = child { _ = kill(pid, SIGTERM) }
            waitForChild(milliseconds: RelayProtocolConstants.childSigtermGraceMilliseconds, flush: false)
            if !childReaped, let pid = child { _ = kill(pid, SIGKILL) }
            waitForChild(milliseconds: RelayProtocolConstants.relayChildReapBoundMilliseconds, flush: false)
        }
        if privateFD >= 0 { close(privateFD); privateFD = -1 }
        let reaped = child == nil || childReaped
        if !reaped { log("state_STOPPING reap_timeout") }
        // Reap must precede unlink, and dev/inode identity prevents deleting a replacement socket.
        if reaped, let identity = boundIdentity,
           let current = try? RuntimeConfiguration.metadata(config.publicSocket),
           current.st_dev == identity.0, current.st_ino == identity.1,
           current.st_mode & S_IFMT == S_IFSOCK, current.st_uid == config.ownerUID {
            _ = unlink(config.publicSocket)
        }
        if logFD >= 0 { close(logFD); logFD = -1 }
        return reaped
    }

    private func waitForChild(milliseconds duration: Int, flush: Bool) {
        let deadline = now() + milliseconds(duration)
        while !tryReap(), now() < deadline {
            if flush { try? flushNode() }
            var item = pollfd(fd: -1, events: 0, revents: 0)
            _ = poll(&item, 0, Int32(RuntimeLimits.pollMilliseconds))
        }
    }

    private func tryReap() -> Bool {
        if childReaped { return true }
        guard let pid = child else { return false }
        var status: Int32 = 0
        let result = waitpid(pid, &status, WNOHANG)
        if result == pid { childReaped = true }
        // An unproven wait result never permits signalling or deleting another process's objects.
        return childReaped
    }

    private func openLog(_ path: String) throws -> Int32 {
        let fd = open(path, O_CREAT | O_APPEND | O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                      RuntimeConfiguration.protectedFileMode)
        guard fd >= 0 else { throw RuntimeFailure.configuration }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == config.ownerUID, info.st_mode & 0o7777 == RuntimeConfiguration.protectedFileMode else {
            close(fd); throw RuntimeFailure.configuration
        }
        return fd
    }

    private func log(_ message: String) {
        let data = Data((message + "\n").utf8)
        if logFD >= 0 { _ = data.withUnsafeBytes { write(logFD, $0.baseAddress, $0.count) } }
        else { FileHandle.standardError.write(data) }
    }
    private func nonblocking(_ fd: Int32) throws {
        guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0,
              fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw RuntimeFailure.transport }
        var noPipe: Int32 = 1 // SO_NOSIGPIPE is a Boolean socket option.
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noPipe, socklen_t(MemoryLayout.size(ofValue: noPipe))) == 0 else {
            throw RuntimeFailure.transport
        }
    }
    private func now() -> UInt64 { DispatchTime.now().uptimeNanoseconds }
    private func milliseconds(_ value: Int) -> UInt64 { UInt64(value) * RuntimeLimits.nanosecondsPerMillisecond }
}
