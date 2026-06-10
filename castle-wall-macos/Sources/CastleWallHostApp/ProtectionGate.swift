//
// ProtectionGate.swift
//
// F-UX-2: pure decision logic for the host app's manual Arm / Disarm control
// and the auto-arm re-evaluation path.
//
// Fail-closed semantics (the B2 lesson):
//   - ARM must never succeed unless the helper can sign (enabled + pin) AND
//     the daemon is up with a loaded policy. The sysext fail-closes to
//     deny-all without a policy-bearing daemon, so arming early does not
//     protect anything — it bricks the network while the status pill reads
//     green.
//   - DISARM is unconditional. The operator can ALWAYS stand the wall down,
//     and a manual disarm must stick (auto-arm must not immediately re-arm,
//     or disarm would be a no-op and the operator's only exit would be
//     System Settings — the exact F-UX-2 drill pain).
//
// Pure functions only — the UI wires them to live state; tests cover the
// matrices without touching SMAppService / NEFilterManager.
//

import Foundation

enum ProtectionGate {
    /// Arming is allowed only when the helper is ready (enabled + pin present)
    /// AND the daemon is up with a loaded policy. `daemonUpWithPolicy` MUST
    /// come from the ARM-GRADE probe
    /// (`SocketPath.activeDaemonPresentForArming`: root-owned non-symlink
    /// active-config at the protected path + a successful unix-socket
    /// connect), never from discovery-grade `activeDaemonPresent`, whose
    /// legacy /tmp fallback any local user can forge (codex P1).
    /// Fail-closed: any missing leg blocks arm.
    static func canArm(helperReady: Bool, daemonUpWithPolicy: Bool) -> Bool {
        helperReady && daemonUpWithPolicy
    }

    /// Disarm is unconditional — never gate the operator's ability to stand
    /// the wall down. Encoded as a function (not a constant at the call site)
    /// so the invariant is named and test-asserted.
    static func canDisarm() -> Bool {
        true
    }

    /// Codex P2: the Disarm control stays on screen while armed OR while the
    /// last disarm attempt has not been VERIFIED complete (a re-read proving
    /// `NEFilterManager.isEnabled == false`). Without the second leg, a failed
    /// `saveToPreferences` drops `filterState` out of the armed states, the
    /// header flips to the Arm control, and the operator loses the in-app exit
    /// path while the REAL filter may still be enabled.
    static func disarmControlVisible(isArmed: Bool, disarmPending: Bool) -> Bool {
        isArmed || disarmPending
    }

    /// Auto-arm fires only when arming is allowed, the wall is not already
    /// armed (or mid-transition), and the operator has not manually disarmed.
    /// The operator-disarm latch is what makes the Disarm button real: without
    /// it the auto-arm re-evaluation loop would re-arm within seconds of every
    /// manual disarm.
    static func shouldAutoArm(
        canArm: Bool,
        alreadyArmed: Bool,
        operatorDisarmed: Bool
    ) -> Bool {
        canArm && !alreadyArmed && !operatorDisarmed
    }

    /// Plain-English reason the Arm control is disabled, or nil when arming
    /// is allowed. Surfaced as the control's tooltip + caption so a blocked
    /// arm is never silent (the F-UX-2 drill pain: `autoArmProtection` bailed
    /// with no trace).
    static func armBlockedReason(
        helperReady: Bool,
        daemonUpWithPolicy: Bool
    ) -> String? {
        switch (helperReady, daemonUpWithPolicy) {
        case (true, true):
            return nil
        case (false, false):
            return "Background helper not ready and Sanctuary daemon not running."
        case (false, true):
            return "Background helper not ready (approve it in System Settings, or trust anchor missing)."
        case (true, false):
            return "Sanctuary daemon not running with a policy. Start an agent with `sanctuary wrap`."
        }
    }
}
