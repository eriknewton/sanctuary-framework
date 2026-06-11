//
// ManifestStore.swift
//
// In-memory mirror of the active allowlist manifest. The filter provider
// loads the manifest from the runtime via IPC at extension start (in
// response to its own `manifest_subscribe` request) and updates it on
// each `manifest_updated` notification.
//
// The store is the canonical-snapshot surface the evaluator consults. It
// also fires a paired `FlowCache.clear()` on each update so cached
// outcomes do not survive a ruleset shift.
//
// Phase 1 stores the full ruleset. Delta patches are reserved for v1.x.
//
// Thread safety: shared between the IPC bridge (which writes on each
// `manifest_updated`) and the filter callback queue (which reads on each
// new flow). Access is guarded by `os_unfair_lock`.
//
// Source: Castle Wall macOS Phase 1 packet filter + manifest sync spawn
// prompt (2026-05-11), section "Pre-baked architectural decisions" +
// "Manifest sync path".
//

import Foundation
import os.lock
import CastleWallIPC

/// Snapshot of the manifest the filter provider currently trusts.
public struct ManifestSnapshot: Equatable {
    public let signatureB64url: String?
    public let rules: [ManifestRule]
    public let updatedAt: Date
    /// The agent-origin descriptor carried in this signed manifest body, if
    /// any. `nil` when the (verified) body did not include one. Surfaced so
    /// the IPC bridge can install it on the engine after signature
    /// verification (2026-05-29 origin-classifier foundation).
    public let agentOrigin: AgentOriginWire?
    public let operatorBaseline: OperatorBaselineWire?

    public init(
        signatureB64url: String?,
        rules: [ManifestRule],
        updatedAt: Date,
        agentOrigin: AgentOriginWire? = nil,
        operatorBaseline: OperatorBaselineWire? = nil
    ) {
        self.signatureB64url = signatureB64url
        self.rules = rules
        self.updatedAt = updatedAt
        self.agentOrigin = agentOrigin
        self.operatorBaseline = operatorBaseline
    }
}

/// Notified when the manifest changes. The filter provider hooks the
/// flow cache through this callback so cached entries never outlive the
/// rules that produced them.
public typealias ManifestChangeObserver = (ManifestSnapshot) -> Void

public final class ManifestStore {
    private var snapshot: ManifestSnapshot?
    private var observers: [(UUID, ManifestChangeObserver)] = []
    private var lock = os_unfair_lock_s()
    public let lastValidManifestURL: URL?

    public init(lastValidManifestURL: URL? = nil) {
        self.lastValidManifestURL = lastValidManifestURL
    }

    public static func defaultLastValidManifestURL() -> URL? {
        guard let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            return nil
        }
        return base
            .appendingPathComponent("Sanctuary", isDirectory: true)
            .appendingPathComponent("CastleWall", isDirectory: true)
            .appendingPathComponent("last-valid-manifest.json")
    }

    /// Replace the active snapshot. Notifies every registered observer
    /// after releasing the internal lock so observer callbacks may safely
    /// re-enter the store (a typical pattern is for the observer to also
    /// read `currentSnapshot()` for its own bookkeeping).
    public func update(_ snapshot: ManifestSnapshot) {
        os_unfair_lock_lock(&lock)
        self.snapshot = snapshot
        let observersCopy = self.observers.map { $0.1 }
        os_unfair_lock_unlock(&lock)
        for observer in observersCopy {
            observer(snapshot)
        }
    }

    public func persistLastValidManifest(_ body: ManifestUpdatedBody) throws {
        guard let url = lastValidManifestURL else {
            return
        }
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(body)
        try data.write(to: url, options: [.atomic])
    }

    public func loadPersistedManifest() throws -> ManifestUpdatedBody? {
        guard let url = lastValidManifestURL else {
            return nil
        }
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(ManifestUpdatedBody.self, from: data)
    }

    /// Read the current snapshot. Returns `nil` until the first update.
    public func currentSnapshot() -> ManifestSnapshot? {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        return snapshot
    }

    /// Read just the rules. Returns the empty array until the first update.
    public func currentRules() -> [ManifestRule] {
        return currentSnapshot()?.rules ?? []
    }

    /// Subscribe to manifest changes. The token is opaque; pass it to
    /// `removeObserver(_:)` to unsubscribe. Observers are NOT invoked
    /// for the current snapshot at subscription time; the filter provider
    /// reads the current snapshot itself if it needs the initial state.
    @discardableResult
    public func addObserver(_ observer: @escaping ManifestChangeObserver) -> UUID {
        let token = UUID()
        os_unfair_lock_lock(&lock)
        observers.append((token, observer))
        os_unfair_lock_unlock(&lock)
        return token
    }

    public func removeObserver(_ token: UUID) {
        os_unfair_lock_lock(&lock)
        observers.removeAll { $0.0 == token }
        os_unfair_lock_unlock(&lock)
    }

    /// True when at least one snapshot has been received from the runtime.
    public var hasSnapshot: Bool {
        return currentSnapshot() != nil
    }
}
