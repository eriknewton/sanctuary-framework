//
// SignerService.swift
//
// The request-handling core of the root helper, implementing the XPC protocol
// against the key + pin stores. Lives in the library (not the executable) so the
// sign / publicKey / installPin logic is unit-testable by direct call, without
// root and without an NSXPCListener. The helper executable (main.swift) only
// wires this object to a mach-service listener and pins the caller requirement.
//
// Custody invariants enforced here:
//   • the private key is loaded transiently to sign and never returned (P1/#6);
//   • signing needs no passphrase — the helper holds the key directly (P3);
//   • installPin is the only writer of the root-owned pin (P2).
//

import Foundation

/// Optional sink so the helper can record per-request audit lines. Kept as a
/// closure so the library has no dependency on a concrete audit backend.
public typealias SignerAuditSink = (_ event: String, _ detail: [String: String]) -> Void

public final class SignerService: NSObject, CastleWallSignerXPCProtocol {
    private let keyStore: SignerKeyStore
    private let pinStore: PinStore
    private let audit: SignerAuditSink?

    public init(
        keyStore: SignerKeyStore = SignerKeyStore(),
        pinStore: PinStore = PinStore(),
        audit: SignerAuditSink? = nil
    ) {
        self.keyStore = keyStore
        self.pinStore = pinStore
        self.audit = audit
    }

    /// Ensure the root-owned custody directory exists + is custodial BEFORE any
    /// key/pin I/O (F-A2-1). Creates it root-owned-restrictive on first run; if
    /// it already exists but is NOT root-owned (uid 0) or is group/other-writable,
    /// throws so the helper can fail closed — never silently adopt an
    /// operator-owned custody directory a non-root process may have planted.
    public func ensureCustodyDirectory() throws {
        try keyStore.custody.ensureDirectory(keyStore.directory, mode: 0o755)
    }

    public func sign(
        payload: Data,
        purpose: String,
        reply: @escaping (Data?, String?) -> Void
    ) {
        // Reject empty payloads outright — there is nothing legitimate to sign.
        guard !payload.isEmpty else {
            audit?("signer_sign_rejected", ["reason": "empty_payload", "purpose": purpose])
            reply(nil, "empty payload")
            return
        }
        do {
            let key = try keyStore.loadOrCreate()
            let signature = try key.sign(payload)
            audit?("signer_sign", [
                "purpose": purpose,
                "payload_bytes": String(payload.count),
            ])
            reply(signature, nil)
        } catch {
            // Generic error to the caller; details stay helper-side. Never leak
            // key material in the message (#6).
            audit?("signer_sign_failed", ["purpose": purpose])
            reply(nil, "sign failed")
        }
    }

    public func publicKey(reply: @escaping (Data?, String?) -> Void) {
        do {
            let key = try keyStore.loadOrCreate()
            reply(key.publicKeyBytes, nil)
        } catch {
            audit?("signer_pubkey_failed", [:])
            reply(nil, "public key unavailable")
        }
    }

    public func installPin(reply: @escaping (Data?, String?) -> Void) {
        do {
            let key = try keyStore.loadOrCreate()
            let pub = key.publicKeyBytes
            try pinStore.write(publicKey: pub)
            audit?("signer_install_pin", [
                "pin_sha256_prefix": Self.sha256Prefix(pub),
            ])
            reply(pub, nil)
        } catch {
            audit?("signer_install_pin_failed", [:])
            reply(nil, "install pin failed")
        }
    }

    /// Short fingerprint of the pin for the audit line (not the key itself).
    private static func sha256Prefix(_ data: Data) -> String {
        // Cheap, dependency-free hex of the first 8 bytes of the raw key — a
        // stable fingerprint for correlating the pinned key across logs without
        // any crypto-hash import. (The key bytes are public.)
        return data.prefix(8).map { String(format: "%02x", $0) }.joined()
    }
}
