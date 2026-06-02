//
// OriginClassifier.swift
//
// Fail-closed origin classification for Castle Wall flows.
//
// The 2026-05-29 attribution research proved that on a daily-driver Mac no
// same-session signal reliably separates agent traffic from operator traffic;
// only an OS-identity change (a dedicated NAT runtime, recommended; or a
// dedicated UID account, fallback) survives adversarial escape. BOTH survivors
// rest on this one shared rule: convert attribution from an *inference*
// ("not provably the agent => treat as operator", which fails OPEN) into a
// *positive kernel fact*, and route everything that is not POSITIVELY the
// operator to the default-deny + allowlist path.
//
// HARD SECURITY INVARIANT (do not violate):
//   `OriginClass` is `.agent`, `.operator`, or `.unattributed`.
//   ONLY a positive operator determination yields the allow fast-path.
//   `.agent` AND `.unattributed` BOTH route to default-deny + allowlist.
//   A nil / undecodable / errSecCSUnsigned / EPERM / ESRCH token is
//   `sourceUnattributed == true` => `.unattributed` => deny side.
//   When no `agentOrigin` descriptor has been delivered yet (older daemon /
//   pre-seed missing), EVERYTHING classifies `.agent` (machine-wide
//   default-deny preserved). There is NO path where "could not determine
//   origin" reaches operator-allow.
//

import Foundation
import CastleWallIPC

public extension AgentOriginDescriptor {
    /// Build a classifier descriptor from the verified wire type. Returns
    /// `nil` only when the wire descriptor is structurally unusable for its
    /// declared mode, so an empty/half-built descriptor never reaches the
    /// classifier as a usable input (the classifier would then fall back to
    /// classify-all-`.agent`, the fail-closed default).
    ///
    /// FAIL-CLOSED: a malformed UID-mode descriptor (no `agent_uid`) yields
    /// `nil` here rather than a descriptor that could mis-resolve a flow as
    /// operator. A NAT-mode descriptor with neither signing id nor team id is
    /// likewise unusable (it can never positively match the egress helper).
    init?(wire: AgentOriginWire) {
        switch wire.mode {
        case .uid:
            // UID mode requires the dedicated agent account uid; without it
            // every non-system flow would resolve `.operator`, which is
            // exactly the fail-open we must prevent.
            guard wire.agentUid != nil else { return nil }
            self.init(
                mode: .uid,
                egressHelperSigningId: nil,
                egressHelperTeamId: nil,
                agentRuntimePortRange: nil,
                agentUid: wire.agentUid.map { uid_t($0) },
                systemUidAllowCeiling: uid_t(wire.systemUidAllowCeiling)
            )
        case .nat:
            // NAT mode requires at least one egress-helper identity axis.
            guard wire.egressHelperSigningId != nil || wire.egressHelperTeamId != nil else {
                return nil
            }
            var portRange: ClosedRange<Int>?
            if let pair = wire.agentRuntimePortRange, pair.count == 2 {
                let lo = pair[0]
                let hi = pair[1]
                if lo <= hi { portRange = lo...hi }
            }
            self.init(
                mode: .nat,
                egressHelperSigningId: wire.egressHelperSigningId,
                egressHelperTeamId: wire.egressHelperTeamId,
                agentRuntimePortRange: portRange,
                agentUid: nil,
                systemUidAllowCeiling: uid_t(wire.systemUidAllowCeiling)
            )
        }
    }
}

/// The three-way origin classification of a flow.
public enum OriginClass: String, Equatable {
    /// Positively the wrapped agent (or no `agentOrigin` yet => everything is
    /// treated as agent). Routes to default-deny + allowlist.
    case agent
    /// POSITIVELY the human operator (or an explicitly-allowed system daemon
    /// on the conceded low-UID path). The ONLY class that earns the allow
    /// fast-path.
    case `operator`
    /// Origin could not be positively determined. Fail-closed: routes to the
    /// default-deny + allowlist path, exactly like `.agent`.
    case unattributed
}

/// The install mode the daemon has provisioned.
public enum AgentOriginMode: String, Equatable, Codable {
    /// Agent runs inside a Sanctuary-owned NAT runtime; the egress helper has
    /// a distinct signing identity. Recommended (default).
    case nat
    /// Agent runs under its own dedicated macOS user account. Fallback.
    case uid
}

/// The signed descriptor the daemon delivers over IPC telling the sysext how
/// to recognise agent-originated flows. Additive + optional in the signed
/// envelope: an older sysext ignores it; a newer sysext with no descriptor
/// classifies everything `.agent`.
public struct AgentOriginDescriptor: Equatable {
    public let mode: AgentOriginMode

    // NAT mode inputs.
    /// SigningID of the runtime's egress helper process (NAT mode).
    public let egressHelperSigningId: String?
    /// Team identifier of the runtime's egress helper process (NAT mode).
    public let egressHelperTeamId: String?
    /// Optional source-port range the agent runtime egresses from (NAT mode).
    public let agentRuntimePortRange: ClosedRange<Int>?

    // UID mode inputs.
    /// The dedicated agent account's real uid (UID mode).
    public let agentUid: uid_t?
    /// Real uids strictly below this ceiling are treated as system daemons
    /// and earn the (conceded, explicit) operator low-UID path. Applies in
    /// UID mode.
    public let systemUidAllowCeiling: uid_t

    public init(
        mode: AgentOriginMode,
        egressHelperSigningId: String? = nil,
        egressHelperTeamId: String? = nil,
        agentRuntimePortRange: ClosedRange<Int>? = nil,
        agentUid: uid_t? = nil,
        systemUidAllowCeiling: uid_t
    ) {
        self.mode = mode
        self.egressHelperSigningId = egressHelperSigningId
        self.egressHelperTeamId = egressHelperTeamId
        self.agentRuntimePortRange = agentRuntimePortRange
        self.agentUid = agentUid
        self.systemUidAllowCeiling = systemUidAllowCeiling
    }
}

public enum OriginClassifier {

    /// Classify a flow's origin. `agentOrigin == nil` means no descriptor has
    /// been delivered yet; in that case EVERYTHING is `.agent` so the
    /// machine-wide default-deny posture is preserved (fail-closed, never
    /// operator-allow).
    public static func originClass(
        descriptor: FilterFlowDescriptor,
        agentOrigin: AgentOriginDescriptor?
    ) -> OriginClass {
        // 1. Undecodable / unattributed origin always fails closed FIRST,
        //    regardless of mode. This dominates every other branch.
        if descriptor.sourceUnattributed {
            return .unattributed
        }

        // 2. No descriptor delivered yet: classify everything `.agent`.
        //    Preserves today's machine-wide default-deny. NEVER operator.
        guard let agentOrigin else {
            return .agent
        }

        switch agentOrigin.mode {
        case .uid:
            return classifyUid(descriptor: descriptor, agentOrigin: agentOrigin)
        case .nat:
            return classifyNat(descriptor: descriptor, agentOrigin: agentOrigin)
        }
    }

    // MARK: - UID mode

    private static func classifyUid(
        descriptor: FilterFlowDescriptor,
        agentOrigin: AgentOriginDescriptor
    ) -> OriginClass {
        // The agent's dedicated account: positively the agent.
        if let agentUid = agentOrigin.agentUid, descriptor.sourceRuid == agentUid {
            return .agent
        }

        // Conceded, EXPLICIT low-UID path: system daemons (ruid strictly
        // below the ceiling) are the only inferred operator-allow. This is
        // the documented residual risk (DNS via mDNSResponder, etc.).
        if descriptor.sourceRuid < agentOrigin.systemUidAllowCeiling {
            return .operator
        }

        // Any other RESOLVED high uid that is not the agent account is the
        // operator's own session. The ruid came from a successful audit-token
        // decode (sourceUnattributed == false was checked above), so this is
        // a positive determination, not an inference-from-absence.
        return .operator
    }

    // MARK: - NAT mode

    private static func classifyNat(
        descriptor: FilterFlowDescriptor,
        agentOrigin: AgentOriginDescriptor
    ) -> OriginClass {
        // NAT mode keys on the egress helper's signing identity. If we have
        // no signing identity for this flow, we CANNOT positively place it on
        // either side -> fail closed to `.unattributed` (deny side).
        guard descriptor.sourceSigningId != nil || descriptor.sourceTeamId != nil else {
            return .unattributed
        }

        if matchesEgressHelper(descriptor: descriptor, agentOrigin: agentOrigin) {
            // Optionally tighten on the runtime port range when configured.
            if let range = agentOrigin.agentRuntimePortRange,
               !range.contains(descriptor.destinationPort) {
                // Signing matches the egress helper but the flow is outside
                // the configured runtime port range: treat as agent anyway
                // (deny side). Never relax to operator on a partial match.
                return .agent
            }
            return .agent
        }

        // A resolved signing identity that is NOT the egress helper is the
        // operator's own software.
        return .operator
    }

    private static func matchesEgressHelper(
        descriptor: FilterFlowDescriptor,
        agentOrigin: AgentOriginDescriptor
    ) -> Bool {
        // Require the configured axis to match. SigningID match alone is
        // sufficient; when a Team id is also configured, it must match too.
        if let wantSigningId = agentOrigin.egressHelperSigningId {
            guard descriptor.sourceSigningId == wantSigningId else {
                return false
            }
        }
        if let wantTeamId = agentOrigin.egressHelperTeamId {
            guard descriptor.sourceTeamId == wantTeamId else {
                return false
            }
        }
        // If neither axis is configured, an egress-helper match is not
        // expressible; do not claim a match.
        return agentOrigin.egressHelperSigningId != nil
            || agentOrigin.egressHelperTeamId != nil
    }
}
