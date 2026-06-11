//
// FlowEvaluatorEngine.swift
//
// Pure (no NetworkExtension) verdict engine. Holds the
// `ManifestStore` + `FlowCache` + `AgentResolver` substrate and exposes
// `evaluate(_:)` for descriptor-driven verdict decisions.
//
// Why this is a separate class from `CastleWallFilterProvider`:
// `NEFilterDataProvider` expects to be instantiated by sysextd inside a
// loaded system-extension bundle. Calling its initializer from a plain
// XCTest process crashes the framework before the test body runs (the
// framework's internal state setup asserts a context that does not exist
// outside sysextd). The engine is the testable surface; the provider is
// a thin adapter that holds an engine and forwards from
// `handleNewFlow(_:)`.
//

import Foundation

public final class FlowEvaluatorEngine {
    public let manifestStore: ManifestStore
    public let flowCache: FlowCache
    public let agentResolver: AgentResolver

    /// The last signed `agentOrigin` descriptor delivered over IPC, retained
    /// across daemon restarts (pre-seed retention). `nil` means none has been
    /// delivered yet => the classifier treats EVERYTHING as `.agent` (machine
    /// -wide default-deny). A daemon crash therefore leaves the sysext
    /// fail-closed: it keeps the last descriptor (or, if it never had one,
    /// classify-all-agent). It is NEVER cleared to a more-permissive state on
    /// IPC loss.
    private let agentOriginLock = NSLock()
    private var _agentOrigin: AgentOriginDescriptor?

    public init(
        manifestStore: ManifestStore = ManifestStore(),
        flowCache: FlowCache = FlowCache(),
        agentResolver: @escaping AgentResolver = FlowEvaluatorEngine.defaultAgentResolver,
        agentOrigin: AgentOriginDescriptor? = nil
    ) {
        self.manifestStore = manifestStore
        self.flowCache = flowCache
        self.agentResolver = agentResolver
        self._agentOrigin = agentOrigin
        // When the manifest store changes, evict cached outcomes wholesale
        // so a deny rule that arrives after a flow was allowed cannot keep
        // serving stale verdicts.
        self.manifestStore.addObserver { [weak self] _ in
            self?.flowCache.clear()
        }
    }

    /// The currently-retained agent-origin descriptor (thread-safe read).
    public var agentOrigin: AgentOriginDescriptor? {
        agentOriginLock.lock()
        defer { agentOriginLock.unlock() }
        return _agentOrigin
    }

    /// Install a freshly-verified `agentOrigin` descriptor delivered over the
    /// signed IPC envelope. Evicts the flow cache so prior verdicts computed
    /// under the old descriptor cannot serve a now-stale operator/agent
    /// decision.
    ///
    /// FAIL-CLOSED: callers MUST only pass descriptors that have already
    /// passed signed-envelope verification. A `nil` here would relax to
    /// classify-all-agent; the IPC layer never forwards `nil` on a transient
    /// drop -- it simply stops delivering, and the last descriptor is
    /// retained.
    public func updateAgentOrigin(_ descriptor: AgentOriginDescriptor) {
        agentOriginLock.lock()
        _agentOrigin = descriptor
        agentOriginLock.unlock()
        flowCache.clear()
    }

    public static let defaultAgentResolver: AgentResolver = { sourceAppId in
        return (agentId: sourceAppId, templateId: "unknown")
    }

    /// Evaluate a flow against the current manifest snapshot, consulting
    /// the cache first. Side effects: a fresh `(allow|drop)` outcome lands
    /// in the cache so subsequent flows from the same (source app, dest)
    /// tuple short-circuit. Uncertain outcomes are NOT cached because the
    /// resolution arrives via the operator-decision IPC path.
    public func evaluate(_ descriptor: FilterFlowDescriptor) -> EvaluationOutcome {
        let key = FlowCacheKey.from(descriptor)
        if let cached = flowCache.get(key) {
            return cached
        }
        let outcome = AllowlistEvaluator.evaluate(
            flow: descriptor,
            rules: manifestStore.currentRules(),
            agentOrigin: agentOrigin,
            operatorBaseline: manifestStore.currentSnapshot()?.operatorBaseline
        )
        switch outcome {
        case .allow, .drop:
            flowCache.put(key, outcome)
        case .uncertain:
            break
        }
        return outcome
    }
}
