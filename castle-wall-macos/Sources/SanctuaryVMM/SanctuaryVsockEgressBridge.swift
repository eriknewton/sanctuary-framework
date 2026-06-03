import Foundation

#if canImport(Containerization)
import Containerization
import ContainerizationOS
#endif

/// Wires a single host-side vsock listener for the egress proxy.
///
/// Architecture:
///   - The host registers ONE VsockListener on a dedicated port (0x0FFF_0001).
///   - In the guest, a proxyVsock bridges a UDS (/run/sanctuary-egress.sock)
///     to that vsock port.
///   - Guest processes that need network access connect to the UDS.
///   - Traffic flows: guest UDS -> vsock -> host VsockListener -> egress-proxy.ts
///   - The egress proxy applies the allowlist and forwards to the internet.
///
/// Security invariant:
///   - The guest has exactly ONE path to the outside world: this vsock port.
///   - VZ refuses connections to host vsock ports with no registered listener.
///   - vminitd:1024 is guest-reachable but cannot be used for egress (B2 escape matrix).
///   - 0 VZNetworkDeviceConfiguration entries (no eth0, no network interface).
///
/// Port selection rationale (coordinator note — LinuxPod.swift:238-239):
///   - Apple's hostVsockPorts and guestVsockPorts both start at 0x1000_0000
///     and increment upward for stdio, copy, and relay operations.
///   - We use 0x0FFF_0001 (below the range) to avoid port collision.
///   - This is safe because LinuxPod never decrements the atomics.
public struct SanctuaryVsockEgressConfig: Sendable {
    /// Host-side vsock port for the egress proxy listener.
    public let hostPort: UInt32
    /// Guest-side UDS path that bridges to the vsock port.
    public let guestSocketPath: String
    /// Host address and port of the HTTP CONNECT proxy (egress-proxy.ts).
    public let proxyListenAddress: String
    public let proxyListenPort: UInt16

    public init(
        hostPort: UInt32 = 0x0FFF_0001,
        guestSocketPath: String = "/run/sanctuary-egress.sock",
        proxyListenAddress: String = "127.0.0.1",
        proxyListenPort: UInt16 = 0
    ) {
        self.hostPort = hostPort
        self.guestSocketPath = guestSocketPath
        self.proxyListenAddress = proxyListenAddress
        self.proxyListenPort = proxyListenPort
    }
}

/// Bridges the guest egress path to the host-side allowlist proxy
/// via a single vsock port.
///
/// Lifecycle:
///   1. Before VM boot: register the VsockListener on the host
///   2. After VM boot: tell vminitd to proxyVsock the guest UDS to the port
///   3. Guest processes connect to the UDS for network access
///   4. Host-side: accept vsock connections and pipe to egress-proxy.ts
///   5. On VM stop: finish the listener
public final class SanctuaryVsockEgressBridge: @unchecked Sendable {
    public let config: SanctuaryVsockEgressConfig
    private var isRunning = false

    public init(config: SanctuaryVsockEgressConfig = SanctuaryVsockEgressConfig()) {
        self.config = config
    }

    #if canImport(Containerization)

    /// Accept connections from the guest on the vsock port and pipe each
    /// to the host-side egress proxy. Each connection is an independent
    /// TCP-over-vsock stream that the egress proxy handles as an HTTP
    /// CONNECT request.
    ///
    /// This method runs until the listener is finished (VM shutdown).
    public func serve(listener: VsockListener) async {
        isRunning = true
        for await connection in listener {
            guard isRunning else { break }
            Task {
                await self.handleConnection(connection)
            }
        }
    }

    /// Stop accepting new connections.
    public func stop() {
        isRunning = false
    }

    private func handleConnection(_ guestFd: FileHandle) async {
        // Pipe the guest vsock fd to the host-side egress proxy.
        // The egress proxy listens on a local TCP port; we connect to it
        // and relay bytes bidirectionally.
        //
        // The actual relay is a simple fd-to-fd copy. The egress proxy
        // handles HTTP CONNECT parsing, allowlist evaluation, DNS resolution,
        // and upstream connection.
        let proxyFd: FileHandle
        do {
            proxyFd = try connectToProxy()
        } catch {
            guestFd.closeFile()
            return
        }

        // Bidirectional relay: guest <-> proxy
        let relayTask1 = Task { self.relay(from: guestFd, to: proxyFd) }
        let relayTask2 = Task { self.relay(from: proxyFd, to: guestFd) }
        _ = await relayTask1.value
        _ = await relayTask2.value
        guestFd.closeFile()
        proxyFd.closeFile()
    }

    private func connectToProxy() throws -> FileHandle {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw SanctuaryVsockEgressBridgeError.proxyConnectFailed(
                reason: "socket() failed: \(String(cString: strerror(errno)))")
        }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(config.proxyListenPort).bigEndian
        inet_pton(AF_INET, config.proxyListenAddress, &addr.sin_addr)

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else {
            close(fd)
            throw SanctuaryVsockEgressBridgeError.proxyConnectFailed(
                reason: "connect() failed: \(String(cString: strerror(errno)))")
        }

        return FileHandle(fileDescriptor: fd, closeOnDealloc: false)
    }

    private func relay(from source: FileHandle, to destination: FileHandle) {
        let bufferSize = 16 * 1024
        while true {
            let data = source.availableData
            if data.isEmpty { break }
            destination.write(data)
        }
    }

    #else

    public func serve(listener: Any) async {
        // Containerization not available on this platform
    }

    public func stop() {}

    #endif
}

public enum SanctuaryVsockEgressBridgeError: Error {
    case proxyConnectFailed(reason: String)
    case listenerRegistrationFailed
}
