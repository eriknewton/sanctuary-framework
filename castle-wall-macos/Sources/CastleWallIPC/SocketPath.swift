//
// SocketPath.swift
//
// Mirror of `server/src/castle-wall/runtime/socket-path.ts`. Given the same
// platform + fortressPath + homeDir + explicitOverride, this resolver MUST
// return byte-equivalent path strings to the TypeScript helper.
//
// Test parity: every fixture in `socket-path.test.ts` is reproduced in
// `SocketPathTests.swift`. Cross-language string equivalence keeps the
// macOS extension and the Sanctuary main client connecting to the same
// socket regardless of which side picked the path first.
//

import Foundation
import Darwin

public enum SocketPathSource: String, Equatable {
    case macosActiveConfig = "macos_active_config"
    case explicitOverride = "explicit_override"
    case linuxPerFortress = "linux_per_fortress"
    case macosRootDaemon = "macos_root_daemon"
    case macosPerFortress = "macos_per_fortress"
    case macosHomeDefault = "macos_home_default"
}

public struct ResolvedSocketPath: Equatable {
    public let path: String
    public let source: SocketPathSource

    public init(path: String, source: SocketPathSource) {
        self.path = path
        self.source = source
    }
}

public enum SocketPath {
    // Active-config discovery file. Relocated out of world-writable /tmp into the
    // root-protected Castle Wall directory (A2/B2). MUST match the TS mirror
    // (server/src/castle-wall/runtime/socket-path.ts).
    public static let activeConfigPath =
        "/Library/Application Support/Sanctuary/castle-active.json"

    // Legacy /tmp location, read-fallback only (half-migrated box). Nothing
    // writes here anymore.
    public static let legacyActiveConfigPath = "/tmp/sanctuary-castle-active.json"

    /// Resolve the UDS socket path the macOS extension or the Linux client
    /// should connect to.
    ///
    /// `platform` should be one of "darwin", "linux", or any other lowercase
    /// platform identifier. Unknown platforms degrade to the macOS fallback
    /// chain so the extension still produces a usable address.
    public static func resolve(
        platform: String,
        fortressId: String? = nil,
        fortressPath: String? = nil,
        homeDir: String? = nil,
        explicitOverride: String? = nil,
        activeConfigPath: String = SocketPath.activeConfigPath
    ) -> ResolvedSocketPath {
        if platform == "darwin" {
            if let active = resolveActiveConfigSocketPath(configPath: activeConfigPath) {
                return active
            }
            // Legacy /tmp read-fallback ONLY for the production default path, so a
            // test passing an explicit (hermetic) configPath is not perturbed by
            // a stray /tmp file from a real daemon.
            if activeConfigPath == SocketPath.activeConfigPath,
               let legacyActive = resolveActiveConfigSocketPath(
                   configPath: SocketPath.legacyActiveConfigPath) {
                return legacyActive
            }
        }

        if let override = explicitOverride, !override.isEmpty {
            return ResolvedSocketPath(path: override, source: .explicitOverride)
        }

        if platform == "darwin" {
            return resolveDarwinFallback(fortressPath: fortressPath, homeDir: homeDir)
        }

        if platform == "linux" {
            let fid = fortressId ?? "default"
            return ResolvedSocketPath(
                path: "/run/sanctuary/\(fid)/filter.sock",
                source: .linuxPerFortress
            )
        }

        return resolveDarwinFallback(fortressPath: fortressPath, homeDir: homeDir)
    }

    /// DISCOVERY-grade liveness: true iff an active-config discovery file
    /// names a LIVE daemon pid. The daemon writes its active-config only AFTER
    /// the IPC listener is up and the signed policy manifest is loaded
    /// (`server/src/castle-wall/runtime/macos-daemon.ts`).
    ///
    /// Discovery ONLY — never a trust gate, and NEVER an arm gate (codex P1).
    /// The file can live at the legacy world-writable /tmp path, so any local
    /// user can forge "daemon present"; the IPC handshake binds the pinned key,
    /// so discovery spoofing cannot make the wall trust an impostor daemon —
    /// but it COULD have lit the Arm button onto a deny-all brick (the exact B2
    /// fail-open class). Arming paths MUST use
    /// `activeDaemonPresentForArming` instead.
    ///
    /// The legacy /tmp fallback is consulted only for the production default
    /// path (same hermetic-test semantics as `resolve`); under A2 the
    /// root-owned custody dir forces the operator-UID daemon to write its
    /// discovery file to the legacy path, so skipping it would read a healthy
    /// A2 box as daemon-down.
    public static func activeDaemonPresent(
        activeConfigPath: String = SocketPath.activeConfigPath
    ) -> Bool {
        if resolveActiveConfigSocketPath(configPath: activeConfigPath) != nil {
            return true
        }
        if activeConfigPath == SocketPath.activeConfigPath,
           resolveActiveConfigSocketPath(
               configPath: SocketPath.legacyActiveConfigPath) != nil {
            return true
        }
        return false
    }

    /// ARM-GRADE readiness (codex P1): the fail-closed probe the host app's
    /// Arm gate and auto-arm paths MUST use. Strictly stronger than
    /// `activeDaemonPresent` (which stays discovery-grade for non-arming
    /// uses):
    ///
    ///   (a) The legacy world-writable /tmp fallback is NEVER consulted. Any
    ///       local user can plant that file; arming on it is the B2 fail-open
    ///       class this gate exists to kill. There is structurally no legacy
    ///       code path in this function.
    ///   (b) The active-config must sit at the protected custody path,
    ///       root-owned (the same `FileCustody.fileIsRootOwned` gate the
    ///       sysext's fingerprint trust-gate applies, F-A2-4) and must not be
    ///       a symlink — a planted link must not launder a custody check onto
    ///       attacker-controlled content.
    ///   (c) Liveness is proven by actually CONNECTING to the unix socket the
    ///       config names (connect + immediate close, bounded timeout) — not
    ///       by `kill(pid, 0)`, which any live unrelated pid satisfies. The
    ///       config parse (live pid named, non-empty socket_path) is still
    ///       required first; the connect is the additional, unforgeable leg.
    ///
    /// `custody`, `isSymlink`, and `canConnect` are injectable for tests only
    /// (CI runs unprivileged and cannot create root-owned files); production
    /// call sites use the defaults.
    public static func activeDaemonPresentForArming(
        activeConfigPath: String = SocketPath.activeConfigPath,
        custody: FileCustody = FileCustody(),
        isSymlink: (String) -> Bool = SocketPath.pathIsSymlink,
        canConnect: (String) -> Bool = { canConnectUnixSocket(at: $0) }
    ) -> Bool {
        // (b) Custody: root-owned regular file at the protected path.
        guard custody.fileIsRootOwned(activeConfigPath) else {
            return false
        }
        guard !isSymlink(activeConfigPath) else {
            return false
        }
        // Parse gate (same invariants as discovery: non-empty socket_path,
        // pid > 0, pid alive).
        guard let resolved = resolveActiveConfigSocketPath(configPath: activeConfigPath) else {
            return false
        }
        // (c) Liveness: a daemon is "up" only if its socket accepts a connect.
        return canConnect(resolved.path)
    }

    /// lstat-semantics symlink probe (`FileManager.attributesOfItem` does not
    /// traverse the final path component). Separate from the ownership probe
    /// so tests that simulate root ownership still exercise the symlink
    /// rejection.
    public static func pathIsSymlink(_ path: String) -> Bool {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return false
        }
        return (attrs[.type] as? FileAttributeType) == .typeSymbolicLink
    }

    /// Bounded-timeout unix-socket connect probe: connect + immediate close,
    /// nothing written. Only a SUCCESSFUL connect counts — ECONNREFUSED (stale
    /// socket file, dead daemon) and EACCES (mode-restricted socket we cannot
    /// reach) both read as "not connectable", because neither proves a live
    /// daemon THIS process could actually talk to.
    public static func canConnectUnixSocket(at path: String, timeoutMs: Int32 = 500) -> Bool {
        let pathBytes = Array(path.utf8)
        // sockaddr_un.sun_path is 104 bytes on Darwin (incl. NUL).
        guard pathBytes.count + 1 <= 104 else {
            return false
        }
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            return false
        }
        defer { _ = Darwin.close(fd) }

        // Non-blocking so a wedged listener cannot hang the UI probe.
        let flags = Darwin.fcntl(fd, F_GETFL, 0)
        _ = Darwin.fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { rawBuffer in
            for (i, byte) in pathBytes.enumerated() {
                rawBuffer[i] = byte
            }
            rawBuffer[pathBytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let connectResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                Darwin.connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if connectResult == 0 {
            return true
        }
        guard errno == EINPROGRESS else {
            return false
        }
        var pollFD = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard Darwin.poll(&pollFD, 1, timeoutMs) == 1,
              (pollFD.revents & Int16(POLLOUT)) != 0 else {
            return false
        }
        var socketError: Int32 = -1
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard Darwin.getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &len) == 0 else {
            return false
        }
        return socketError == 0
    }

    private static func resolveDarwinFallback(
        fortressPath: String?,
        homeDir: String?
    ) -> ResolvedSocketPath {
        if let fp = fortressPath, !fp.isEmpty {
            return ResolvedSocketPath(
                path: "\(stripTrailingSlash(fp))/castle.sock",
                source: .macosPerFortress
            )
        }
        if let hd = homeDir, !hd.isEmpty {
            return ResolvedSocketPath(
                path: "\(stripTrailingSlash(hd))/.sanctuary/castle.sock",
                source: .macosHomeDefault
            )
        }
        return ResolvedSocketPath(
            path: "/var/run/sanctuary-castle.sock",
            source: .macosRootDaemon
        )
    }

    private static func resolveActiveConfigSocketPath(configPath: String) -> ResolvedSocketPath? {
        guard let data = FileManager.default.contents(atPath: configPath) else {
            return nil
        }
        guard
            let parsed = try? JSONSerialization.jsonObject(with: data),
            let object = parsed as? [String: Any],
            let socketPath = object["socket_path"] as? String,
            !socketPath.isEmpty,
            let pid = object["pid"] as? Int,
            pid > 0,
            isPidAlive(pid)
        else {
            return nil
        }
        return ResolvedSocketPath(path: socketPath, source: .macosActiveConfig)
    }

    private static func isPidAlive(_ pid: Int) -> Bool {
        kill(pid_t(pid), 0) == 0 || errno == EPERM
    }

    private static func stripTrailingSlash(_ value: String) -> String {
        if value.count > 1 && value.hasSuffix("/") {
            return String(value.dropLast())
        }
        return value
    }
}
