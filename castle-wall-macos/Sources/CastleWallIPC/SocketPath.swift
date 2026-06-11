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
    public let diagnostics: SocketPathDiagnostics

    public init(
        path: String,
        source: SocketPathSource,
        diagnostics: SocketPathDiagnostics = SocketPathDiagnostics()
    ) {
        self.path = path
        self.source = source
        self.diagnostics = diagnostics
    }
}

public struct SocketPathDiagnostics: Equatable {
    public var activeConfigPath: String?
    public var activeConfigStatus: String?
    public var legacyActiveConfigPath: String?
    public var legacyActiveConfigStatus: String?
    public var selectedConfigPath: String?
    public var selectedFortressPath: String?

    public init(
        activeConfigPath: String? = nil,
        activeConfigStatus: String? = nil,
        legacyActiveConfigPath: String? = nil,
        legacyActiveConfigStatus: String? = nil,
        selectedConfigPath: String? = nil,
        selectedFortressPath: String? = nil
    ) {
        self.activeConfigPath = activeConfigPath
        self.activeConfigStatus = activeConfigStatus
        self.legacyActiveConfigPath = legacyActiveConfigPath
        self.legacyActiveConfigStatus = legacyActiveConfigStatus
        self.selectedConfigPath = selectedConfigPath
        self.selectedFortressPath = selectedFortressPath
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
        var diagnostics = SocketPathDiagnostics(activeConfigPath: activeConfigPath)
        if platform == "darwin" {
            let active = resolveActiveConfigSocketPath(configPath: activeConfigPath)
            diagnostics.activeConfigStatus = active.status
            if let active = active.config {
                if fortressPath == nil || active.fortressPath == fortressPath {
                    diagnostics.selectedConfigPath = activeConfigPath
                    diagnostics.selectedFortressPath = active.fortressPath
                    return ResolvedSocketPath(
                        path: active.path,
                        source: .macosActiveConfig,
                        diagnostics: diagnostics
                    )
                }
                diagnostics.activeConfigStatus = "fortress_mismatch"
            }
            // Legacy /tmp read-fallback ONLY for the production default path, so a
            // test passing an explicit (hermetic) configPath is not perturbed by
            // a stray /tmp file from a real daemon.
            if activeConfigPath == SocketPath.activeConfigPath {
                diagnostics.legacyActiveConfigPath = SocketPath.legacyActiveConfigPath
                let legacyActive = resolveActiveConfigSocketPath(
                    configPath: SocketPath.legacyActiveConfigPath)
                diagnostics.legacyActiveConfigStatus = legacyActive.status
                if let legacyActive = legacyActive.config {
                    if fortressPath == nil || legacyActive.fortressPath == fortressPath {
                        diagnostics.selectedConfigPath = SocketPath.legacyActiveConfigPath
                        diagnostics.selectedFortressPath = legacyActive.fortressPath
                        return ResolvedSocketPath(
                            path: legacyActive.path,
                            source: .macosActiveConfig,
                            diagnostics: diagnostics
                        )
                    }
                    diagnostics.legacyActiveConfigStatus = "fortress_mismatch"
                }
            }
        }

        if let override = explicitOverride, !override.isEmpty {
            return ResolvedSocketPath(
                path: override,
                source: .explicitOverride,
                diagnostics: diagnostics
            )
        }

        if platform == "darwin" {
            return resolveDarwinFallback(
                fortressPath: fortressPath,
                homeDir: homeDir,
                diagnostics: diagnostics
            )
        }

        if platform == "linux" {
            let fid = fortressId ?? "default"
            return ResolvedSocketPath(
                path: "/run/sanctuary/\(fid)/filter.sock",
                source: .linuxPerFortress,
                diagnostics: diagnostics
            )
        }

        return resolveDarwinFallback(
            fortressPath: fortressPath,
            homeDir: homeDir,
            diagnostics: diagnostics
        )
    }

    private static func resolveDarwinFallback(
        fortressPath: String?,
        homeDir: String?,
        diagnostics: SocketPathDiagnostics
    ) -> ResolvedSocketPath {
        if let fp = fortressPath, !fp.isEmpty {
            return ResolvedSocketPath(
                path: "\(stripTrailingSlash(fp))/castle.sock",
                source: .macosPerFortress,
                diagnostics: diagnostics
            )
        }
        if let hd = homeDir, !hd.isEmpty {
            return ResolvedSocketPath(
                path: "\(stripTrailingSlash(hd))/.sanctuary/castle.sock",
                source: .macosHomeDefault,
                diagnostics: diagnostics
            )
        }
        return ResolvedSocketPath(
            path: "/var/run/sanctuary-castle.sock",
            source: .macosRootDaemon,
            diagnostics: diagnostics
        )
    }

    private static func resolveActiveConfigSocketPath(
        configPath: String
    ) -> (config: (path: String, fortressPath: String?)?, status: String) {
        guard let data = FileManager.default.contents(atPath: configPath) else {
            return (nil, "absent")
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
            return (nil, "invalid_or_stale")
        }
        return ((
            path: socketPath,
            fortressPath: object["fortress_path"] as? String
        ), "accepted")
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
