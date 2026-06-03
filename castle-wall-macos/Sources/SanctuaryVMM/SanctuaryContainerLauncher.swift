import Foundation

#if canImport(Containerization)
import Containerization
import ContainerizationOS
#endif

/// Configuration for launching an agent inside a no-network Linux VM
/// using Apple's Containerization library.
public struct SanctuaryContainerConfig: Sendable {
    public let kernelPath: String
    public let initfsReference: String
    public let ociImageReference: String
    public let rootfsSizeBytes: UInt64
    public let cpuCount: Int
    public let memoryBytes: UInt64
    public let rootfsPins: [SanctuaryArtifactPin]
    /// Vsock port for the egress proxy (host-side VsockListener).
    /// Must be in the 0x1000_0000+ range to avoid collision with
    /// Apple Containerization's internal port allocation
    /// (LinuxPod.swift:238-239: both hostVsockPorts and guestVsockPorts
    /// start at 0x1000_0000).
    ///
    /// We use a port BELOW the 0x1000_0000 range (e.g. 0x0FFF_0001)
    /// so there is no collision with Apple's ascending allocation.
    public let egressVsockPort: UInt32

    public init(
        kernelPath: String,
        initfsReference: String = "ghcr.io/apple/containerization/vminit:0.33.3",
        ociImageReference: String,
        rootfsSizeBytes: UInt64 = 2 * 1024 * 1024 * 1024,
        cpuCount: Int = 2,
        memoryBytes: UInt64 = 512 * 1024 * 1024,
        rootfsPins: [SanctuaryArtifactPin] = [],
        egressVsockPort: UInt32 = 0x0FFF_0001
    ) {
        self.kernelPath = kernelPath
        self.initfsReference = initfsReference
        self.ociImageReference = ociImageReference
        self.rootfsSizeBytes = rootfsSizeBytes
        self.cpuCount = cpuCount
        self.memoryBytes = memoryBytes
        self.rootfsPins = rootfsPins
        self.egressVsockPort = egressVsockPort
    }
}

/// Request to execute a process inside the container.
public struct SanctuaryGuestExecRequest: Codable, Sendable {
    public let command: String
    public let args: [String]
    public let cwd: String
    public let env: [String: String]

    public init(command: String, args: [String], cwd: String, env: [String: String]) {
        self.command = command
        self.args = args
        self.cwd = cwd
        self.env = env
    }
}

/// Result of a guest process execution.
public struct SanctuaryGuestExecResult: Sendable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public init(exitCode: Int32, stdout: String, stderr: String) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

public enum SanctuaryContainerLauncherError: Error {
    case networkAttachmentDetected(count: Int)
    case integrityCheckFailed(underlying: Error)
    case containerizationUnavailable
    case bootFailed(underlying: Error)
}

/// Launches agent processes inside a no-network Linux VM using
/// Apple's Containerization library (0.33.3+).
///
/// Architecture (B1 re-platform):
///   - Boots via ContainerManager (replaces hand-rolled VZ config)
///   - Zero network attachments (network: nil, networking: false)
///   - Single vsock device for: vminitd control (port 1024),
///     stdio relay (0x1000_0000+), and our egress proxy (0x0FFF_0001)
///   - Guest rootfs is an OCI image assembled by ContainerizationEXT4
///   - Integrity check targets the finished EXT4 file, not raw layers
///
/// Port model (from LinuxPod.swift:238-239):
///   - hostVsockPorts: Atomic<UInt32>(0x1000_0000) -- ascending for stdio/copy/relay
///   - guestVsockPorts: Atomic<UInt32>(0x1000_0000) -- ascending for guest-initiated
///   - Our egress proxy: 0x0FFF_0001 (below the range, no collision)
///   - vminitd control: port 1024 (guest-side listener, host connects to it)
///     NOTE: guest-reachable; adversarial case deferred to B2 escape matrix
public final class SanctuaryContainerLauncher: @unchecked Sendable {
    private let config: SanctuaryContainerConfig

    public init(config: SanctuaryContainerConfig) {
        self.config = config
    }

    #if canImport(Containerization)

    /// Boot the container and execute the given process.
    /// Asserts zero network attachments before returning.
    public func launchAndExec(
        containerId: String,
        request: SanctuaryGuestExecRequest
    ) async throws -> SanctuaryGuestExecResult {
        var manager = try await ContainerManager(
            kernel: Kernel(
                path: URL(fileURLWithPath: config.kernelPath),
                platform: .linuxArm
            ),
            initfsReference: config.initfsReference,
            network: nil
        )

        defer {
            try? manager.delete(containerId)
        }

        let stdoutCapture = CaptureWriter()
        let stderrCapture = CaptureWriter()

        let container = try await manager.create(
            containerId,
            reference: config.ociImageReference,
            rootfsSizeInBytes: Int(config.rootfsSizeBytes),
            networking: false
        ) { [config] @Sendable cfg in
            cfg.cpus = config.cpuCount
            cfg.memoryInBytes = UInt64(config.memoryBytes)
            cfg.process.arguments = [request.command] + request.args
            cfg.process.workingDirectory = request.cwd
            for (key, value) in request.env {
                cfg.process.environment[key] = value
            }
            cfg.process.stdout = stdoutCapture
            cfg.process.stderr = stderrCapture
        }

        // HOST-SIDE ASSERTION: 0 network devices configured.
        let nicCount = container.interfaces.count
        guard nicCount == 0 else {
            throw SanctuaryContainerLauncherError.networkAttachmentDetected(count: nicCount)
        }

        try await container.create()
        try await container.start()
        let exitStatus = try await container.wait()
        try await container.stop()

        return SanctuaryGuestExecResult(
            exitCode: exitStatus.exitCode,
            stdout: stdoutCapture.text,
            stderr: stderrCapture.text
        )
    }

    #else

    public func launchAndExec(
        containerId: String,
        request: SanctuaryGuestExecRequest
    ) async throws -> SanctuaryGuestExecResult {
        throw SanctuaryContainerLauncherError.containerizationUnavailable
    }

    #endif
}

/// Captures bytes written by a guest stdio stream.
final class CaptureWriter: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = Data()

    var text: String {
        lock.lock()
        defer { lock.unlock() }
        return String(data: buffer, encoding: .utf8) ?? "<non-utf8 \(buffer.count) bytes>"
    }

    var byteCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return buffer.count
    }
}

#if canImport(Containerization)
extension CaptureWriter: Writer {
    func write(_ data: Data) throws {
        guard !data.isEmpty else { return }
        lock.lock()
        buffer.append(data)
        lock.unlock()
    }

    func close() throws {}
}
#endif
