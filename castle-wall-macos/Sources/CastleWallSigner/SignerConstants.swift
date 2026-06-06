//
// SignerConstants.swift
//
// Stable identifiers shared by the root signer helper (CastleWallSignerHelper),
// the code-signed shim the Node daemon spawns (CastleWallSignerClient), and the
// host app that registers the helper via SMAppService.
//
// These strings are wire/identity constants. Changing a mach-service name or a
// bundle identifier is an install-time incompatibility (the daemon would look
// up a service the helper never published; the XPC caller check would reject a
// shim with the wrong designated identifier). Treat them like the Castle Wall
// wire constants: do not change without a coordinated re-pin.
//

import Foundation

public enum SignerConstants {
    /// Apple Developer Team ID (the OU on our Developer-ID leaf cert). This is
    /// the same team the sysext + host app are signed under; the XPC caller
    /// check pins to it so only our binaries can request a signature.
    public static let teamID = "YFQSWQ9BJN"

    /// Designated code-signing identifier of the shim the TS daemon spawns.
    /// The helper's NSXPCListener delegate rejects any connection whose peer
    /// does not satisfy a requirement built around this identifier (§4.4).
    public static let signerClientIdentifier =
        "ai.sanctuaryprotocol.macos.castle-wall.signer-client"

    /// Launchd label / bundle identifier of the root helper itself. Used as the
    /// SMAppService plist name and the helper's own designated identifier.
    public static let signerHelperIdentifier =
        "ai.sanctuaryprotocol.macos.castle-wall.signer-helper"

    /// Mach service name the helper publishes and the shim connects to. Must
    /// match the `MachServices` key in the helper LaunchDaemon plist.
    public static let machServiceName =
        "ai.sanctuaryprotocol.macos.castle-wall.signer"

    /// Root-owned protected directory that holds the trust anchor (pin) and the
    /// helper's private signing key. Created + owned by the helper (root:wheel).
    public static let protectedDirectory =
        "/Library/Application Support/Sanctuary"

    /// Public trust-anchor file (raw 32-byte Ed25519 verifying key). Written
    /// root:wheel 0644 by the helper; read by the sysext + the daemon. This is
    /// the SAME path the sysext already reads — A2 only changes the owner.
    public static let pinnedPublicKeyFilename = "castle-pinned-pubkey.bin"

    /// The helper's private signing key, raw 32 bytes, stored root:wheel 0600.
    /// Never leaves the helper process; never read by the Node daemon.
    public static let signerPrivateKeyFilename = "castle-signer-privkey.bin"

    /// Absolute path to the public pin file.
    public static var pinnedPublicKeyPath: String {
        "\(protectedDirectory)/\(pinnedPublicKeyFilename)"
    }

    /// Absolute path to the helper's private key file.
    public static var signerPrivateKeyPath: String {
        "\(protectedDirectory)/\(signerPrivateKeyFilename)"
    }

    /// Purpose labels carried over XPC for the audit trail ONLY. The helper
    /// signs opaque bytes regardless of purpose; it never parses the payload
    /// (§4.3 — no manifest awareness in the helper).
    public enum SignPurpose {
        public static let manifest = "manifest"
        public static let nonce = "nonce"
    }
}
