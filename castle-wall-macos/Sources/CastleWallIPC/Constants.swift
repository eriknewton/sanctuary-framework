//
// Constants.swift
//
// Wire constants synchronized with `server/src/castle-wall/constants.ts` and
// `castle-wall-daemon/src/lib.rs::constants`. Bumping any value here means a
// wire incompatibility; the cross-language fixture suite will trip.
//

import Foundation

public enum CastleWallConstants {
    /// Schema version for v1 allowlist rules, manifest, and signed envelopes.
    public static let schemaVersionV1: UInt32 = 1

    /// Audit-log layer for every Castle Wall event. Layer 1 per the Castle
    /// Architecture ADR.
    public static let auditLayer = "l1"

    /// Ed25519 signature scheme tag used in manifest envelopes (matches
    /// federation v0.1).
    public static let signatureSchemeV1 = "ed25519-v1"

    /// IPC framing header per scope-lock section 5 (LSP-style).
    public static let ipcContentLengthHeader = "Content-Length"

    /// Fixed length of an IPC request_id nonce in bytes (16 bytes hex-encoded
    /// produces a 32-char string).
    public static let requestIdNonceBytes = 16

    /// JSON-RPC method namespace for IPC messages.
    public static let ipcNamespace = "castle-wall"

    /// Challenge-response nonce length in bytes (Ed25519 signing input).
    public static let challengeNonceBytes = 32
}
