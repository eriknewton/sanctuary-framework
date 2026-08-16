/**
 * Node ↔ root-helper signing bridge (B2).
 *
 * The Castle Wall daemon is Node/TypeScript and cannot speak XPC natively, so it
 * spawns a small code-signed Swift shim (`castle-wall-signer-client`) to relay
 * sign requests to the root helper, which owns the Ed25519 signing key. The
 * helper signs OPAQUE bytes — the daemon canonicalizes the manifest in TS and
 * hands the already-canonical bytes to the shim (§4.3). No key material ever
 * flows back: the shim returns base64url signatures / the public key.
 *
 * FAIL-CLOSED (hard constraint #5): any failure to obtain a signature — shim
 * missing, helper unreachable, non-zero exit, timeout, malformed output — throws
 * `HelperSignerError`. There is NO fallback to local signing here; the caller
 * (daemon) must refuse to arm rather than emit an unsigned or locally-signed
 * manifest. The local-sign path exists only behind an explicit dev/test flag in
 * the daemon, never as an error fallback.
 */

import { spawn } from "node:child_process";

import { fromBase64url } from "../../core/encoding.js";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from "../../core/crypto-suite-registry.js";

/** Thrown on any failure to obtain a signature / public key from the helper. */
export class HelperSignerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HelperSignerError";
  }
}

/** Shim invocation result. */
export interface ShimResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

/** Injectable shim runner so unit tests can drive the bridge without a binary. */
export type ShimInvoker = (
  args: string[],
  stdin: Uint8Array | null,
) => Promise<ShimResult>;

export interface HelperSignerClientOptions {
  /** Absolute path to the code-signed `castle-wall-signer-client` shim. */
  clientBinaryPath: string;
  /** Per-invocation timeout. Default 10s (signing is low-frequency). */
  timeoutMs?: number;
  /** Override the process runner (tests). */
  invoke?: ShimInvoker;
}

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Default shim runner: spawn the shim, write `stdin` (if any), collect stdout,
 * enforce a timeout. Returns the raw result; success/failure interpretation is
 * the client's job.
 */
function spawnInvoker(clientBinaryPath: string, timeoutMs: number): ShimInvoker {
  return (args, stdin) =>
    new Promise<ShimResult>((resolve, reject) => {
      const child = spawn(clientBinaryPath, args, {
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      let settled = false;

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill("SIGKILL");
        reject(new HelperSignerError(`shim timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      child.stdout.on("data", (d: Buffer) => {
        stdout += d.toString("utf8");
      });
      child.stderr.on("data", (d: Buffer) => {
        stderr += d.toString("utf8");
      });
      child.on("error", (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        // ENOENT (shim missing) lands here → fail closed.
        reject(new HelperSignerError(`shim spawn failed: ${err.message}`));
      });
      child.on("close", (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, code });
      });

      if (stdin && stdin.length > 0) {
        child.stdin.write(Buffer.from(stdin));
      }
      child.stdin.end();
    });
}

/**
 * Talks to the root signer helper through the shim. Stateless; one short-lived
 * shim process per call (signing is low-frequency — policy load/reload + each
 * sysext handshake, never per-flow).
 */
export class HelperSignerClient {
  private readonly invoke: ShimInvoker;

  constructor(options: HelperSignerClientOptions) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.invoke =
      options.invoke ?? spawnInvoker(options.clientBinaryPath, timeoutMs);
  }

  /** Fetch the helper's 32-byte public key (generates the keypair on first call). */
  async getPublicKey(): Promise<Uint8Array> {
    const bytes = await this.run(["get-pubkey"], null);
    if (bytes.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new HelperSignerError(
        `helper public key is ${bytes.length} bytes (expected 32)`,
      );
    }
    return bytes;
  }

  /** Sign opaque canonical manifest bytes. Returns the 64-byte signature. */
  async signManifest(canonicalBytes: Uint8Array): Promise<Uint8Array> {
    return this.signBytes("sign-manifest", canonicalBytes);
  }

  /** Sign a handshake nonce. Returns the 64-byte signature. */
  async signNonce(nonce: Uint8Array): Promise<Uint8Array> {
    return this.signBytes("sign-nonce", nonce);
  }

  /**
   * One-time re-pin: tell the helper to (re)write the root-owned pin file and
   * return the now-pinned public key. Operator-gated upstream (never agent-driven).
   */
  async installPin(): Promise<Uint8Array> {
    const bytes = await this.run(["re-pin"], null);
    if (bytes.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new HelperSignerError(
        `helper pin is ${bytes.length} bytes (expected 32)`,
      );
    }
    return bytes;
  }

  private async signBytes(
    mode: "sign-manifest" | "sign-nonce",
    payload: Uint8Array,
  ): Promise<Uint8Array> {
    if (payload.length === 0) {
      throw new HelperSignerError("refusing to sign empty payload");
    }
    const sig = await this.run([mode], payload);
    if (sig.length !== ED25519_SIGNATURE_BYTES) {
      throw new HelperSignerError(
        `helper signature is ${sig.length} bytes (expected 64)`,
      );
    }
    return sig;
  }

  /** Run the shim, fail closed on any error, decode base64url stdout. */
  private async run(args: string[], stdin: Uint8Array | null): Promise<Uint8Array> {
    let result: ShimResult;
    try {
      result = await this.invoke(args, stdin);
    } catch (err) {
      if (err instanceof HelperSignerError) throw err;
      throw new HelperSignerError(
        `shim invocation failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (result.code !== 0) {
      throw new HelperSignerError(
        `shim exited ${result.code ?? "null"}: ${result.stderr.trim() || "(no stderr)"}`,
      );
    }
    const out = result.stdout.trim();
    if (out.length === 0) {
      throw new HelperSignerError("shim returned empty stdout");
    }
    try {
      return fromBase64url(out);
    } catch (err) {
      throw new HelperSignerError(
        `shim output is not valid base64url: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
}
