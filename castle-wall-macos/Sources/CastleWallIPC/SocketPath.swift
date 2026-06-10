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

    /// F-UX-2 (manual arm gate): true iff an active-config discovery file names
    /// a LIVE daemon pid. The daemon writes its active-config only AFTER the
    /// IPC listener is up and the signed policy manifest is loaded
    /// (`server/src/castle-wall/runtime/macos-daemon.ts`), so this is the host
    /// app's "daemon up with policy" readiness probe for arming. Arming without
    /// it would fail-close the machine to deny-all (the B2 lesson).
    ///
    /// Discovery/readiness ONLY — never a trust gate. The IPC handshake binds
    /// the pinned key; the sysext's fingerprint gate ignores non-root-owned
    /// active-config (F-A2-4). A forged file can light up an Arm button, but it
    /// cannot make the wall trust an impostor daemon.
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
