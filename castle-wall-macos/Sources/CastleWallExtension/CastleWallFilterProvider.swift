//
// CastleWallFilterProvider.swift
//
// NEFilterProvider subclass: Castle Layer 1 macOS surface.
//
// Foundation scope: subclass exists, lifecycle hooks compile against the
// NetworkExtension framework, and `startFilter` opens the IPC client toward
// Sanctuary main and idles. NO actual packet decisions are returned in
// this build; `handleNewFlow` is intentionally absent. Alpha-2 adds:
//   - NEFilterDataProvider.handleNewFlow(_:) returning verdicts
//   - NEFilterFlow surface inspection (URL, hostname, IP)
//   - manifest-store sync for allowlist
//   - per-process scoping
//

import Foundation
import NetworkExtension
import CastleWallIPC

/// Castle Wall NEFilterProvider. Subclasses NEFilterDataProvider to gain
/// the data-layer flow callbacks (Alpha-2) while keeping a minimal lifecycle
/// in the foundation scope.
@objc(CastleWallFilterProvider)
public final class CastleWallFilterProvider: NEFilterDataProvider {
    private var ipcClient: IPCClient?

    public override func startFilter(
        completionHandler: @escaping (Error?) -> Void
    ) {
        CastleWallLog.lifecycle.info("CastleWallFilterProvider.startFilter invoked")

        let resolved = SocketPath.resolve(
            platform: "darwin",
            fortressPath: ProcessInfo.processInfo.environment["SANCTUARY_FORTRESS_PATH"],
            homeDir: NSHomeDirectory(),
            explicitOverride: ProcessInfo.processInfo.environment["SANCTUARY_CASTLE_SOCKET"]
        )
        CastleWallLog.lifecycle.info("ipc socket path resolved: \(resolved.path) (\(resolved.source.rawValue))")

        // Foundation scope: pinned-key load failure should NOT block the
        // extension from starting; we log and continue. Alpha-2 wires the
        // pinned-key install flow and tightens this to a hard fail.
        let pinnedPath = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent(".sanctuary")
            .appendingPathComponent("castle-pinned-pubkey.bin")
        let pinnedKey: Data
        do {
            pinnedKey = try Auth.loadPinnedPublicKey(at: pinnedPath)
        } catch {
            CastleWallLog.auth.notice(
                "pinned public key not yet provisioned (foundation-scope tolerated): \(String(describing: error))"
            )
            completionHandler(nil)
            return
        }

        let client = IPCClient(
            options: IPCClientOptions(path: resolved.path),
            pinnedPublicKey: pinnedKey
        )
        self.ipcClient = client

        Task.detached { [weak self] in
            do {
                _ = try await client.start()
                CastleWallLog.lifecycle.info("ipc handshake completed (foundation tolerance)")
            } catch {
                CastleWallLog.lifecycle.notice(
                    "ipc handshake failed (foundation-scope tolerated): \(String(describing: error))"
                )
                _ = self
            }
        }

        completionHandler(nil)
    }

    public override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        CastleWallLog.lifecycle.info("CastleWallFilterProvider.stopFilter reason=\(reason.rawValue)")
        ipcClient?.close()
        ipcClient = nil
        completionHandler()
    }
}
