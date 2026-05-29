//
// FilterFlowDescriptor.swift
//
// A testable, framework-free descriptor of the inputs the filter provider
// extracts from `NEFilterFlow`. NEFilterFlow itself is an Apple framework
// class that is hard to construct in unit tests; the provider extracts the
// fields the evaluator cares about into this struct, evaluates against the
// manifest, and returns an `EvaluationOutcome`. Tests drive the evaluator
// against synthesized FilterFlowDescriptor values directly.
//
// Source: Castle Wall macOS Phase 1 packet filter + manifest sync spawn
// prompt (2026-05-11), section "Pre-baked architectural decisions".
//

import Foundation

/// The transport protocol of an outbound flow. Mirrors
/// `RuleProtocol` on the server side.
public enum FlowProtocol: String, Codable, Equatable {
    case tcp
    case udp
}

/// A framework-free representation of one new flow the system extension is
/// being asked to evaluate.
///
/// `sourceAppIdentifier` is the per-process attribution Apple's
/// `NEFilterFlow.sourceAppIdentifier` exposes (typically a code-signing
/// identity / bundle id). The Sanctuary side maps this to an `agentId`
/// + `templateId` via the wrapped-agent registry; the evaluator consumes
/// the mapped identifiers, not the raw OS-level identifier.
public struct FilterFlowDescriptor: Equatable {
    public let sourceAppIdentifier: String
    public let agentId: String
    public let templateId: String
    public let destinationHost: String?
    public let destinationIp: String
    public let destinationPort: Int
    public let networkProtocol: FlowProtocol
    public let hostnameSource: String?
    public let opaqueDestination: Bool

    // MARK: - Typed origin fields (2026-05-29 origin-classifier foundation)
    //
    // Decoded from `NEFilterFlow.sourceAppAuditToken` by the provider.
    // The raw hex token (`sourceAppIdentifier`, above) is retained for audit
    // provenance only; classification reads these typed fields instead.
    //
    // FAIL-CLOSED CONTRACT: `sourceUnattributed == true` means the provider
    // could NOT positively decode the origin (nil token, decode failure,
    // errSecCSUnsigned, EPERM/FB12057582, ESRCH, etc.). The classifier MUST
    // map any such descriptor to `.unattributed`, which routes to the
    // default-deny + allowlist path. There is no path from `sourceUnattributed`
    // to operator-allow.

    /// Real user id of the flow's source process, from `audit_token_to_ruid`.
    /// Meaningful only when `sourceUnattributed == false`.
    public let sourceRuid: uid_t
    /// Process id of the flow's source process, from `audit_token_to_pid`.
    public let sourcePid: pid_t
    /// PID-generation counter, from `audit_token_to_pidversion`; defeats
    /// PID-reuse confusion. Meaningful only when `sourceUnattributed == false`.
    public let sourcePidVersion: Int32
    /// Code-signing identity (`SigningID`) resolved via
    /// `SecCodeCopyGuestWithAttributes` + `SecCodeCopySigningInformation`,
    /// when available. `nil` when unresolved (NOT a positive signal).
    public let sourceSigningId: String?
    /// Code-signing Team identifier, when available. `nil` when unresolved.
    public let sourceTeamId: String?
    /// True when the provider could not POSITIVELY attribute the origin.
    /// Fail-closed: forces `.unattributed` -> deny side.
    public let sourceUnattributed: Bool

    public init(
        sourceAppIdentifier: String,
        agentId: String,
        templateId: String,
        destinationHost: String?,
        destinationIp: String,
        destinationPort: Int,
        networkProtocol: FlowProtocol,
        hostnameSource: String?,
        opaqueDestination: Bool,
        sourceRuid: uid_t = 0,
        sourcePid: pid_t = 0,
        sourcePidVersion: Int32 = 0,
        sourceSigningId: String? = nil,
        sourceTeamId: String? = nil,
        sourceUnattributed: Bool = true
    ) {
        self.sourceAppIdentifier = sourceAppIdentifier
        self.agentId = agentId
        self.templateId = templateId
        self.destinationHost = destinationHost
        self.destinationIp = destinationIp
        self.destinationPort = destinationPort
        self.networkProtocol = networkProtocol
        self.hostnameSource = hostnameSource
        self.opaqueDestination = opaqueDestination
        self.sourceRuid = sourceRuid
        self.sourcePid = sourcePid
        self.sourcePidVersion = sourcePidVersion
        self.sourceSigningId = sourceSigningId
        self.sourceTeamId = sourceTeamId
        self.sourceUnattributed = sourceUnattributed
    }
}

/// The output of evaluating a flow against the manifest. Maps to a
/// `NEFilterNewFlowVerdict` at the framework boundary; the evaluator
/// itself returns this enum so it stays testable without
/// NetworkExtension.
public enum EvaluationOutcome: Equatable {
    /// A rule with disposition `allow` matched. Pass without further
    /// inspection. The matched rule id rides with the outcome so the
    /// audit log can record provenance.
    case allow(matchedRuleId: String)

    /// A rule with disposition `deny` matched, OR the default-deny branch
    /// fired with no matching rule. The `matchedRuleId` is `nil` for the
    /// default-deny case.
    case drop(matchedRuleId: String?)

    /// No rule matched; the prompt-disposition path is required. The
    /// extension surfaces a `flow_pending_approval` to the runtime; until
    /// the operator's decision returns, the flow is held in a `needsRules`
    /// holding pattern at the framework layer. The `requestId` is generated
    /// at the call site and threaded through the IPC bridge.
    case uncertain
}

/// The cache key used by `FlowCache`. Computed from the destination tuple
/// plus the source-app identifier so each wrapped agent has its own cache
/// scope. Cache entries store the `EvaluationOutcome` shape only; rebuild
/// from the manifest after a manifest update.
public struct FlowCacheKey: Hashable, Equatable {
    public let sourceAppIdentifier: String
    public let destinationHost: String?
    public let destinationIp: String
    public let destinationPort: Int
    public let networkProtocol: FlowProtocol

    public init(
        sourceAppIdentifier: String,
        destinationHost: String?,
        destinationIp: String,
        destinationPort: Int,
        networkProtocol: FlowProtocol
    ) {
        self.sourceAppIdentifier = sourceAppIdentifier
        self.destinationHost = destinationHost
        self.destinationIp = destinationIp
        self.destinationPort = destinationPort
        self.networkProtocol = networkProtocol
    }

    /// Build a cache key from a flow descriptor.
    public static func from(_ descriptor: FilterFlowDescriptor) -> FlowCacheKey {
        return FlowCacheKey(
            sourceAppIdentifier: descriptor.sourceAppIdentifier,
            destinationHost: descriptor.destinationHost,
            destinationIp: descriptor.destinationIp,
            destinationPort: descriptor.destinationPort,
            networkProtocol: descriptor.networkProtocol
        )
    }
}
