import Foundation

/// Configuration for wiring guest egress to the host-side allowlist proxy.
///
/// Mechanism (Apple Containerization `.into` Unix-socket relay):
///   - The host-side egress proxy (egress-proxy.ts) listens on a Unix domain
///     socket at `hostProxyUdsPath`.
///   - The container is created with a `UnixSocketConfiguration(direction: .into)`
///     whose `source` is that host UDS and whose `destination` is the in-guest
///     path `guestSocketPath` (default `/run/sanctuary-egress.sock`).
///   - Apple's `LinuxContainer` machinery then, on boot:
///       1. allocates a single vsock port (host-side `VsockListener`),
///       2. tells vminitd to create a guest UDS at a staging path OUTSIDE the
///          rootfs and BIND-MOUNTS it into the container rootfs at
///          `guestSocketPath` (this bind-mount is what makes the socket visible
///          to the guest process — the step a manual `relaySocket` call omits),
///       3. relays bytes: guest `connect(guestSocketPath)` -> vsock ->
///          host `connect(hostProxyUdsPath)`.
///   - A guest process gets network access by connecting to `guestSocketPath`
///     and speaking HTTP CONNECT; the host proxy applies the egress allowlist.
///
/// Security invariant:
///   - The guest's ONLY path to the outside world is this single UDS -> vsock ->
///     proxy chain. There are 0 `VZNetworkDeviceConfiguration` entries (no eth0);
///     `SanctuaryContainerLauncher` host-asserts `container.interfaces.count == 0`
///     before boot and throws otherwise.
///   - vminitd's control port (1024) is guest-reachable but cannot open egress to
///     an unregistered host port (B2 escape matrix).
public struct SanctuaryVsockEgressConfig: Sendable {
    /// Host-side Unix socket path the egress proxy (egress-proxy.ts) listens on.
    public let hostProxyUdsPath: String
    /// Guest-side UDS path (bind-mounted into the container rootfs) that guest
    /// processes connect to for egress.
    public let guestSocketPath: String

    public init(
        hostProxyUdsPath: String,
        guestSocketPath: String = "/run/sanctuary-egress.sock"
    ) {
        self.hostProxyUdsPath = hostProxyUdsPath
        self.guestSocketPath = guestSocketPath
    }
}
