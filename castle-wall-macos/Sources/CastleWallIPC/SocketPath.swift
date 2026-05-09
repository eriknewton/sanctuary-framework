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

public enum SocketPathSource: String, Equatable {
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
    /// Resolve the UDS socket path the macOS extension or the Linux client
    /// should connect to. Pure: no I/O, no syscalls.
    ///
    /// `platform` should be one of "darwin", "linux", or any other lowercase
    /// platform identifier. Unknown platforms degrade to the macOS fallback
    /// chain so the extension still produces a usable address.
    public static func resolve(
        platform: String,
        fortressId: String? = nil,
        fortressPath: String? = nil,
        homeDir: String? = nil,
        explicitOverride: String? = nil
    ) -> ResolvedSocketPath {
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

    private static func stripTrailingSlash(_ value: String) -> String {
        if value.count > 1 && value.hasSuffix("/") {
            return String(value.dropLast())
        }
        return value
    }
}
