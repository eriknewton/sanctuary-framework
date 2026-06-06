//
// SignerXPCProtocol.swift
//
// The XPC contract between the root helper (server) and the code-signed shim
// (client). Kept deliberately tiny: the helper exposes key-gen-backed signing of
// OPAQUE bytes, public-key retrieval, and the one-time pin install. It has NO
// manifest/nonce awareness — `purpose` is an audit label only (§4.3).
//
// Replies follow the (result, error) convention: on success `error` is nil; on
// failure the result is nil and `error` carries a generic message. The helper
// never returns key material — only signatures and the public key (P1/#6).
//

import Foundation

@objc public protocol CastleWallSignerXPCProtocol {
    /// Sign opaque bytes with the helper's private key. `purpose` is recorded in
    /// the helper's audit trail but does NOT change behavior — the helper does
    /// not parse `payload`. Reply: 64-byte raw Ed25519 signature, or error.
    func sign(
        payload: Data,
        purpose: String,
        reply: @escaping (_ signature: Data?, _ error: String?) -> Void
    )

    /// Return the 32-byte raw Ed25519 public key, generating + persisting the
    /// keypair on first call. Reply: public key bytes, or error.
    func publicKey(
        reply: @escaping (_ publicKey: Data?, _ error: String?) -> Void
    )

    /// One-time re-pin: ensure the helper key exists and (re)write the public
    /// pin file root:wheel 0644, replacing the old passphrase-derived pin. The
    /// rotation proof binding K_old → K_helper is built daemon-side (it still
    /// holds K_old); the helper only owns K_helper + the pin file. Idempotent:
    /// re-running re-asserts the same pin. Reply: the now-pinned public key, or
    /// error.
    func installPin(
        reply: @escaping (_ publicKey: Data?, _ error: String?) -> Void
    )
}
