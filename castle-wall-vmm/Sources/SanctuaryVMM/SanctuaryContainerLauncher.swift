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
    /// RESERVED. Under the `.into` Unix-socket relay (see
    /// `SanctuaryVsockEgressConfig`), Apple's `LinuxContainer` allocates the
    /// egress vsock port itself from its internal `hostVsockPorts` allocator
    /// (LinuxContainer.swift relayUnixSocket), so this value is no longer used
    /// to register a listener. It is retained as a reserved, below-range
    /// (< 0x1000_0000) constant for forward compatibility and is harmless.
    public let egressVsockPort: UInt32
    /// B2 INNER-CONFINEMENT. When true (the production default), the launcher
    /// installs a trusted seccomp-deny-`AF_VSOCK` filter before EVERY plugin
    /// process runs (`SanctuaryGuestJail`), closing the proven vminitd box
    /// escape regardless of whether the plugin cooperates. Disable only to
    /// reproduce the unconfined baseline in a drill.
    public let applyGuestJail: Bool
    /// How the jail is delivered into the guest. `.pythonPreamble` (default,
    /// drill-proven; needs python3 in the image) or `.staticBinary` (the
    /// static `sanctuary-jail` shim is bind-mounted in; works on python-less
    /// images). FAIL-CLOSED either way: if the selected delivery cannot run,
    /// the plugin does NOT launch unjailed (static: host-side validation
    /// throws before boot; python: the in-guest exec of python3 fails and
    /// the box exits).
    public let guestJailDelivery: SanctuaryGuestJailDelivery

    public init(
        kernelPath: String,
        initfsReference: String = "ghcr.io/apple/containerization/vminit:0.33.3",
        ociImageReference: String,
        rootfsSizeBytes: UInt64 = 2 * 1024 * 1024 * 1024,
        cpuCount: Int = 2,
        memoryBytes: UInt64 = 512 * 1024 * 1024,
        rootfsPins: [SanctuaryArtifactPin] = [],
        egressVsockPort: UInt32 = 0x0FFF_0001,
        applyGuestJail: Bool = true,
        guestJailDelivery: SanctuaryGuestJailDelivery = .pythonPreamble
    ) {
        self.kernelPath = kernelPath
        self.initfsReference = initfsReference
        self.ociImageReference = ociImageReference
        self.rootfsSizeBytes = rootfsSizeBytes
        self.cpuCount = cpuCount
        self.memoryBytes = memoryBytes
        self.rootfsPins = rootfsPins
        self.egressVsockPort = egressVsockPort
        self.applyGuestJail = applyGuestJail
        self.guestJailDelivery = guestJailDelivery
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
    case egressBridgeSetupFailed(reason: String)
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
        // B2 inner-confinement: plan the jail BEFORE boot. A throw here (static
        // shim missing/invalid) means the plugin is never launched — fail closed.
        let jailPlan = try makeJailPlan(for: request)
        defer { cleanupJailPlan(jailPlan) }

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

        let launchConfig = self.config
        let jailedArguments = jailPlan?.argv ?? [request.command] + request.args
        let jailShare = Self.shareMount(for: jailPlan)
        let container = try await manager.create(
            containerId,
            reference: launchConfig.ociImageReference,
            rootfsSizeInBytes: launchConfig.rootfsSizeBytes,
            networking: false
        ) { @Sendable cfg in
            cfg.cpus = launchConfig.cpuCount
            cfg.memoryInBytes = launchConfig.memoryBytes
            // B2 inner-confinement: born-confined plugin argv. When applyGuestJail
            // is on (production default), the trusted launcher prepends the jail
            // delivery (python preamble or static shim) so the plugin cannot reach
            // vminitd, whether or not it cooperates. seccomp survives the exec.
            cfg.process.arguments = jailedArguments
            cfg.process.workingDirectory = request.cwd
            for (key, value) in request.env {
                cfg.process.environmentVariables.append("\(key)=\(value)")
            }
            cfg.process.stdout = stdoutCapture
            cfg.process.stderr = stderrCapture
            // Static delivery: read-only virtiofs share exposing ONLY the
            // staged sanctuary-jail shim at the fixed guest mount point.
            if let jailShare {
                cfg.mounts.append(jailShare)
            }
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

    /// Boot the container with a single egress path wired to the host-side
    /// allowlist proxy, then execute the given process.
    ///
    /// Mechanism (Apple Containerization `.into` Unix-socket relay):
    ///   The container is created with one `UnixSocketConfiguration(.into)` whose
    ///   `source` is the host proxy's Unix socket and whose `destination` is the
    ///   in-guest socket path. Apple's `LinuxContainer` then, on boot:
    ///     1. allocates a vsock port and a host-side `VsockListener`,
    ///     2. creates a guest UDS at a staging path and BIND-MOUNTS it into the
    ///        container rootfs at `guestSocketPath` (the step that makes the
    ///        socket visible to the guest process), and
    ///     3. relays guest `connect(guestSocketPath)` -> vsock ->
    ///        host `connect(hostProxyUdsPath)`.
    ///
    /// Lifecycle:
    ///   1. Create container with the `.into` egress socket (network: nil,
    ///      networking: false)
    ///   2. Assert 0 NICs (host-side)
    ///   3. Boot the VM (Apple sets up the relay + bind-mount)
    ///   4. Start the guest process
    ///   5. Wait for guest exit; tear down container
    public func launchWithEgress(
        containerId: String,
        request: SanctuaryGuestExecRequest,
        egressConfig: SanctuaryVsockEgressConfig
    ) async throws -> SanctuaryGuestExecResult {
        // B2 inner-confinement: plan the jail BEFORE boot. A throw here (static
        // shim missing/invalid) means the plugin is never launched — fail closed.
        let jailPlan = try makeJailPlan(for: request)
        defer { cleanupJailPlan(jailPlan) }

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

        let launchConfig = self.config
        let egress = egressConfig
        let jailedArguments = jailPlan?.argv ?? [request.command] + request.args
        let jailShare = Self.shareMount(for: jailPlan)
        let container = try await manager.create(
            containerId,
            reference: launchConfig.ociImageReference,
            rootfsSizeInBytes: launchConfig.rootfsSizeBytes,
            networking: false
        ) { @Sendable cfg in
            cfg.cpus = launchConfig.cpuCount
            cfg.memoryInBytes = launchConfig.memoryBytes
            // B2 inner-confinement: born-confined plugin argv. When applyGuestJail
            // is on (production default), the trusted launcher prepends the jail
            // delivery (python preamble or static shim) so the plugin cannot reach
            // vminitd, whether or not it cooperates. seccomp survives the exec.
            cfg.process.arguments = jailedArguments
            cfg.process.workingDirectory = request.cwd
            for (key, value) in request.env {
                cfg.process.environmentVariables.append("\(key)=\(value)")
            }
            cfg.process.stdout = stdoutCapture
            cfg.process.stderr = stderrCapture

            // EGRESS: share the host-side allowlist proxy's Unix socket INTO the
            // guest. Apple relays guest UDS -> vsock -> host UDS and bind-mounts
            // the guest socket into the container rootfs at guestSocketPath. This
            // is the guest's ONLY path to the outside world.
            cfg.sockets.append(
                UnixSocketConfiguration(
                    source: URL(fileURLWithPath: egress.hostProxyUdsPath),
                    destination: URL(fileURLWithPath: egress.guestSocketPath),
                    direction: .into
                )
            )

            // Static delivery: read-only virtiofs share exposing ONLY the
            // staged sanctuary-jail shim at the fixed guest mount point.
            if let jailShare {
                cfg.mounts.append(jailShare)
            }
        }

        // HOST-SIDE ASSERTION: 0 network devices configured. A `.into` socket
        // relay is a vsock UDS relay, not a VZNetworkDeviceConfiguration, so the
        // interface count must still be exactly 0.
        let nicCount = container.interfaces.count
        guard nicCount == 0 else {
            throw SanctuaryContainerLauncherError.networkAttachmentDetected(count: nicCount)
        }

        // Boot the VM. Apple's LinuxContainer sets up the .into socket relay and
        // bind-mounts the guest egress socket into the rootfs during create().
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

    /// Convert a jail plan's staged-share fields into the virtiofs mount the
    /// guest sees. Read-only is load-bearing: the hostile plugin must not be
    /// able to modify the trusted shim. No `noexec` (the shim must exec);
    /// `nosuid`/`nodev` follow the package's default-mount hardening.
    private static func shareMount(for plan: SanctuaryGuestJailPlan?) -> Containerization.Mount? {
        guard let plan,
              let hostShareDirectory = plan.hostShareDirectory,
              let guestMountPoint = plan.guestMountPoint else {
            return nil
        }
        return .share(
            source: hostShareDirectory,
            destination: guestMountPoint,
            options: ["ro", "nosuid", "nodev"]
        )
    }

    #else

    public func launchAndExec(
        containerId: String,
        request: SanctuaryGuestExecRequest
    ) async throws -> SanctuaryGuestExecResult {
        throw SanctuaryContainerLauncherError.containerizationUnavailable
    }

    public func launchWithEgress(
        containerId: String,
        request: SanctuaryGuestExecRequest,
        egressConfig: SanctuaryVsockEgressConfig
    ) async throws -> SanctuaryGuestExecResult {
        throw SanctuaryContainerLauncherError.containerizationUnavailable
    }

    #endif

    /// Build the jail plan for a request, or `nil` when the jail is disabled
    /// (drill baseline only). FAIL-CLOSED: any error from planning (missing
    /// or invalid static shim, staging failure) propagates and the plugin is
    /// never launched. There is no fallback from one delivery mode to
    /// another and no fallback to an unjailed launch.
    private func makeJailPlan(
        for request: SanctuaryGuestExecRequest
    ) throws -> SanctuaryGuestJailPlan? {
        guard config.applyGuestJail else { return nil }
        return try SanctuaryGuestJail.makePlan(
            delivery: config.guestJailDelivery,
            command: request.command,
            args: request.args
        )
    }

    /// Remove the private staging directory created for static delivery.
    private func cleanupJailPlan(_ plan: SanctuaryGuestJailPlan?) {
        if let dir = plan?.hostShareDirectory {
            try? FileManager.default.removeItem(atPath: dir)
        }
    }
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
