//
// FlowCache.swift
//
// In-memory LRU cache keyed by `FlowCacheKey`. The filter provider
// consults the cache before evaluating against the manifest so a hot
// flow does not pay the rule-traversal cost on every packet. Cache
// contents are evicted wholesale on manifest change because the
// authoritative ruleset has shifted.
//
// Phase 1 capacity: 1024 entries (per spawn prompt's pre-baked
// architectural decision). Eviction policy: least-recently-used.
//
// Thread safety: the filter provider's NEFilterDataProvider callbacks
// run on a private dispatch queue managed by the framework. The cache
// uses an internal `os_unfair_lock` so concurrent reads + writes from
// independent flow callbacks are safe.
//
// Source: Castle Wall macOS Phase 1 packet filter + manifest sync spawn
// prompt (2026-05-11), section "Pre-baked architectural decisions".
//

import Foundation
import os.lock

/// LRU-bounded cache of evaluation outcomes keyed by destination tuple.
public final class FlowCache {
    public let capacity: Int
    private var entries: [FlowCacheKey: EvaluationOutcome]
    private var ordering: [FlowCacheKey]
    private var lock = os_unfair_lock_s()

    public init(capacity: Int = 1024) {
        precondition(capacity > 0, "FlowCache capacity must be positive")
        self.capacity = capacity
        self.entries = [:]
        self.entries.reserveCapacity(capacity)
        self.ordering = []
        self.ordering.reserveCapacity(capacity)
    }

    /// Look up an entry. Hits move the key to the most-recently-used
    /// position. Misses return `nil`.
    public func get(_ key: FlowCacheKey) -> EvaluationOutcome? {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        guard let value = entries[key] else { return nil }
        moveToFront(key)
        return value
    }

    /// Insert or update an entry. Capacity-bounded; eviction is LRU.
    public func put(_ key: FlowCacheKey, _ outcome: EvaluationOutcome) {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        if entries[key] != nil {
            entries[key] = outcome
            moveToFront(key)
            return
        }
        entries[key] = outcome
        ordering.insert(key, at: 0)
        if ordering.count > capacity {
            evictOldest()
        }
    }

    /// Drop every entry. Called when the manifest snapshot changes.
    public func clear() {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        entries.removeAll(keepingCapacity: true)
        ordering.removeAll(keepingCapacity: true)
    }

    /// Number of entries currently held.
    public var count: Int {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        return entries.count
    }

    /// True when the cache holds the given key. Does not affect LRU
    /// ordering.
    public func contains(_ key: FlowCacheKey) -> Bool {
        os_unfair_lock_lock(&lock)
        defer { os_unfair_lock_unlock(&lock) }
        return entries[key] != nil
    }

    private func moveToFront(_ key: FlowCacheKey) {
        if let idx = ordering.firstIndex(of: key) {
            ordering.remove(at: idx)
        }
        ordering.insert(key, at: 0)
    }

    private func evictOldest() {
        guard let oldest = ordering.popLast() else { return }
        entries.removeValue(forKey: oldest)
    }
}
