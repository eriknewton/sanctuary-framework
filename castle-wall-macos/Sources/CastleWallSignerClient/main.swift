//
// CastleWallSignerClient — main.swift
//
// The tiny code-signed shim the TypeScript daemon `execFile`s to talk to the
// root helper over XPC (the daemon cannot speak XPC natively — §4.3). It is the
// binary the helper's caller check pins to (signer-client identifier + Team ID).
//
// Usage:
//   castle-wall-signer-client sign-manifest [--in <path>]   # bytes on stdin if no --in
//   castle-wall-signer-client sign-nonce    [--in <path>]
//   castle-wall-signer-client get-pubkey
//   castle-wall-signer-client re-pin
//
// Output: base64url (no padding) of the signature / public key on stdout, then
// exit 0. Any failure (bad args, unreachable helper, helper error) prints a
// generic message to stderr and exits non-zero — the TS side treats non-zero as
// fail-closed (no unsigned/local-signed fallback in production).
//
// Signing is low-frequency (policy load/reload + each sysext handshake, never
// per-flow), so a short-lived process per signature is acceptable and far
// simpler than embedding an XPC client in Node.
//

import Foundation
import CastleWallSigner

// MARK: - base64url (no padding)

func base64url(_ data: Data) -> String {
    var s = data.base64EncodedString()
    s = s.replacingOccurrences(of: "+", with: "-")
    s = s.replacingOccurrences(of: "/", with: "_")
    while s.hasSuffix("=") { s.removeLast() }
    return s
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("castle-wall-signer-client: \(message)\n".utf8))
    exit(1)
}

func readPayload(args: [String]) -> Data {
    if let inIdx = args.firstIndex(of: "--in"), inIdx + 1 < args.count {
        let path = args[inIdx + 1]
        guard let data = FileManager.default.contents(atPath: path) else {
            fail("cannot read input file: \(path)")
        }
        return data
    }
    // Read raw bytes from stdin.
    return FileHandle.standardInput.readDataToEndOfFile()
}

// MARK: - XPC round-trip

enum Operation {
    case sign(payload: Data, purpose: String)
    case publicKey
    case installPin
}

func run(_ operation: Operation) -> Never {
    let connection = NSXPCConnection(
        machServiceName: SignerConstants.machServiceName,
        options: .privileged
    )
    connection.remoteObjectInterface =
        NSXPCInterface(with: CastleWallSignerXPCProtocol.self)
    connection.resume()

    let semaphore = DispatchSemaphore(value: 0)
    var output: Data?
    var errorMessage: String?

    let proxy = connection.remoteObjectProxyWithErrorHandler { error in
        errorMessage = "helper unreachable: \(error.localizedDescription)"
        semaphore.signal()
    }

    guard let signer = proxy as? CastleWallSignerXPCProtocol else {
        fail("could not obtain signer proxy")
    }

    switch operation {
    case let .sign(payload, purpose):
        signer.sign(payload: payload, purpose: purpose) { signature, err in
            output = signature
            errorMessage = err
            semaphore.signal()
        }
    case .publicKey:
        signer.publicKey { pub, err in
            output = pub
            errorMessage = err
            semaphore.signal()
        }
    case .installPin:
        signer.installPin { pub, err in
            output = pub
            errorMessage = err
            semaphore.signal()
        }
    }

    // Bounded wait: a wedged helper must not hang the daemon's signing path.
    let waitResult = semaphore.wait(timeout: .now() + 10)
    connection.invalidate()

    if waitResult == .timedOut {
        fail("helper timed out")
    }
    if let errorMessage {
        fail(errorMessage)
    }
    guard let output, !output.isEmpty else {
        fail("helper returned empty result")
    }

    FileHandle.standardOutput.write(Data(base64url(output).utf8))
    exit(0)
}

// MARK: - Arg parse

let args = Array(CommandLine.arguments.dropFirst())
guard let mode = args.first else {
    fail("missing mode (sign-manifest|sign-nonce|get-pubkey|re-pin)")
}

switch mode {
case "sign-manifest":
    run(.sign(payload: readPayload(args: args), purpose: SignerConstants.SignPurpose.manifest))
case "sign-nonce":
    run(.sign(payload: readPayload(args: args), purpose: SignerConstants.SignPurpose.nonce))
case "get-pubkey":
    run(.publicKey)
case "re-pin":
    run(.installPin)
default:
    fail("unknown mode: \(mode)")
}
