//
// CodeRequirement.swift
//
// Builds the code-signing requirement the helper's NSXPCListener delegate pins
// connections to (§4.4). Only a binary that satisfies this requirement — our
// shim, signed under our Team ID with the right designated identifier — is
// allowed to request a signature.
//
// RESIDUAL R1 (state this plainly, in code and the PR body): this validates the
// *binary*, not its *intent*. Same-UID malware cannot extract the key (P1) and
// cannot itself satisfy this requirement, but it CAN invoke our on-disk shim and
// ask the helper to sign a *malicious* payload. XPC caller validation is
// necessary hygiene; it does not by itself stop a bad-content signature. Closing
// R1 needs helper-side CONTENT policy and is explicitly out of scope for B2.
//

import Foundation

public enum CodeRequirement {
    /// The designated-requirement string the helper pins peer connections to.
    /// Form: hardened Apple anchor + our Team OU + the shim's designated
    /// identifier. Passed to `NSXPCConnection.setCodeSigningRequirement(_:)`
    /// (macOS 13+ — this is why the package floor is 13).
    public static func signerClientRequirement(
        teamID: String = SignerConstants.teamID,
        identifier: String = SignerConstants.signerClientIdentifier
    ) -> String {
        // `anchor apple generic` + leaf OU == Team ID is the standard
        // Developer-ID + team pin; `identifier` pins the designated identifier
        // so a different binary signed under the same team is still rejected.
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"\(identifier)\""
    }

    /// Build a `SecRequirement` from the requirement string, or nil if the
    /// string fails to compile. The helper uses this on macOS < 13 fallback
    /// paths and for an explicit pre-flight check; on macOS 13+ the listener
    /// uses `setCodeSigningRequirement` directly.
    public static func makeRequirement(_ text: String) -> SecRequirement? {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(
            text as CFString,
            [],
            &requirement
        )
        guard status == errSecSuccess else { return nil }
        return requirement
    }
}
