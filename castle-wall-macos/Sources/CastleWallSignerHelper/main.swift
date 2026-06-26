//
// CastleWallSignerHelper — main.swift
//
// The root-owned SMAppService LaunchDaemon that owns Castle Wall's signing key.
// It publishes a mach service, validates every connecting peer against our
// shim's code-signing requirement (§4.4), and serves opaque-byte signing +
// public-key retrieval + the one-time pin install (SignerService).
//
// What this binary is NOT: it has no manifest awareness, holds no passphrase,
// and never returns key material. The private key is generated + stored
// root-only by SignerKeyStore on first request.
//
// RESIDUAL R1: the caller check authenticates the BINARY (our shim), not the
// INTENT of the bytes it asks us to sign. Same-UID malware that invokes the
// legitimate shim can still request a malicious-content signature; closing that
// needs helper-side content policy (out of scope for B2). See CodeRequirement.swift.
//

import Foundation
import CastleWallSigner

// MARK: - Audit (stderr → launchd log)

private let auditQueue = DispatchQueue(label: "ai.sanctuaryprotocol.castle-wall.signer.audit")

private func auditLine(_ event: String, _ detail: [String: String]) {
    auditQueue.sync {
        var fields = detail
        fields["event"] = event
        fields["ts"] = ISO8601DateFormatter().string(from: Date())
        // Deterministic key order so log lines diff cleanly.
        let body = fields.keys.sorted()
            .map { "\($0)=\(fields[$0] ?? "")" }
            .joined(separator: " ")
        FileHandle.standardError.write(Data("[castle-wall-signer] \(body)\n".utf8))
    }
}

// MARK: - Listener delegate (caller code-requirement validation)

final class SignerListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let service: SignerService
    private let requirement: String

    init(service: SignerService, requirement: String) {
        self.service = service
        self.requirement = requirement
    }

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        // Pin the peer to our shim's designated requirement. macOS 13+ enforces
        // this at the XPC layer: a connection whose code signature does not
        // satisfy `requirement` is torn down before any message is delivered.
        // This is the load-bearing caller check — necessary hygiene, NOT a
        // content guarantee (R1).
        if #available(macOS 13.0, *) {
            newConnection.setCodeSigningRequirement(requirement)
        } else {
            // The package floor is macOS 13, so this branch is unreachable in
            // production. Refuse rather than accept unvalidated on an older OS.
            auditLine("signer_reject", ["reason": "os_below_floor"])
            return false
        }

        auditLine("signer_accept", [
            "pid": String(newConnection.processIdentifier),
            "euid": String(newConnection.effectiveUserIdentifier),
        ])

        newConnection.exportedInterface =
            NSXPCInterface(with: CastleWallSignerXPCProtocol.self)
        newConnection.exportedObject = service
        newConnection.resume()
        return true
    }
}

// MARK: - Bring-up

let service = SignerService(audit: auditLine)
let auditProducerService = SignerService(
    keyStore: SignerKeyStore(
        directory: SignerConstants.protectedDirectory,
        filename: SignerConstants.auditProducerPrivateKeyFilename
    ),
    pinStore: PinStore(
        directory: SignerConstants.protectedDirectory,
        filename: SignerConstants.auditProducerPublicKeyFilename
    ),
    audit: auditLine
)

// A2/B2 custody bring-up: ensure the protected directory exists ROOT-OWNED and
// not group/other-writable BEFORE any key/pin I/O (F-A2-1). If an operator-owned
// directory was planted first, fail closed (exit non-zero) rather than adopt it —
// a 0600 key inside an operator-writable dir can still be unlinked + swapped by
// same-UID malware. launchd (KeepAlive) respawns us and re-surfaces the fault
// until the operator repairs ownership.
do {
    try service.ensureCustodyDirectory()
    auditLine("signer_custody_ok", ["dir": SignerConstants.protectedDirectory])
} catch {
    auditLine("signer_custody_fault", [
        "dir": SignerConstants.protectedDirectory,
        "detail": "directory is not root-owned or is group/other-writable",
    ])
    FileHandle.standardError.write(Data((
        "[castle-wall-signer] FATAL: custody directory "
        + "\(SignerConstants.protectedDirectory) must be root-owned and not "
        + "group/other-writable. Refusing to serve. Repair with: "
        + "sudo chown -R root:wheel '\(SignerConstants.protectedDirectory)' && "
        + "sudo chmod 755 '\(SignerConstants.protectedDirectory)'\n"
    ).utf8))
    exit(1)
}

// Touch the key store at startup so the keypair exists before the first signing
// request and any storage/permission fault surfaces in the launchd log early.
service.publicKey { pub, err in
    if let pub {
        auditLine("signer_ready", ["pubkey_present": "true", "pubkey_bytes": String(pub.count)])
    } else {
        auditLine("signer_startup_warning", ["error": err ?? "unknown"])
    }
}
auditProducerService.installPin { pub, err in
    if let pub {
        auditLine("audit_producer_ready", ["pubkey_present": "true", "pubkey_bytes": String(pub.count)])
    } else {
        auditLine("audit_producer_startup_warning", ["error": err ?? "unknown"])
    }
}

let delegate = SignerListenerDelegate(
    service: service,
    requirement: CodeRequirement.signerClientRequirement()
)
let auditProducerDelegate = SignerListenerDelegate(
    service: auditProducerService,
    requirement: CodeRequirement.castleWallExtensionRequirement()
)

let listener = NSXPCListener(machServiceName: SignerConstants.machServiceName)
listener.delegate = delegate
listener.resume()

auditLine("signer_listening", ["mach_service": SignerConstants.machServiceName])

let auditProducerListener = NSXPCListener(
    machServiceName: SignerConstants.auditProducerMachServiceName
)
auditProducerListener.delegate = auditProducerDelegate
auditProducerListener.resume()

auditLine("audit_producer_listening", [
    "mach_service": SignerConstants.auditProducerMachServiceName,
])

// LaunchDaemon: park the main thread on the run loop. launchd owns our lifecycle
// and will respawn us if we exit (KeepAlive); we never return.
RunLoop.main.run()
