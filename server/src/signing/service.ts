import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { canonicalBytes, decodeCanonical, refuse, safeInteger, SIGNER_HEADER_MAX_BYTES, SIGNER_FRAME_MAX_BYTES, SIGNER_PROTOCOL, SIGNER_REQUEST_DEADLINE_MS, UNLOCK_CHALLENGE_DOMAIN } from "./contract.js";
import { encodeSignerFrame } from "../linux-business/producer-custody.js";
import { parseStrict } from "../smb/parse-strict.js";
import { createRecordSigner, type RecordRequest, type SigningGrant } from "./record-signer.js";
import { EncryptedIdentityProvider } from "./identity-provider.js";
import { strictVerify, verifyRecord } from "./strict-verifier.js";
import type { StoredIdentity } from "../core/identity.js";

// Must match business_profile/signer_service.rs and custody.rs, and the service unit ExecStart.
export const SIGNER_BINARY = "/usr/libexec/sanctuary-business-signer";
export const LENGTH_BYTES = 4;
export const RESPONSE_MAX_BYTES = SIGNER_HEADER_MAX_BYTES;
export const NS_PER_MS = 1_000_000n;
const TOKEN_ID_BYTES = 16; // A 128-bit identifier has 32 lowercase hexadecimal characters.
const SELF_TEST_NONCE_BYTES = 32;
const ED25519_PUBLIC_BYTES = 32;
// This inert counter adapter establishes transport composition; later writers supply their own closed payload adapters.
export const INERT_COUNTER_SCHEMA = z.object({ count: safeInteger }).strict();
export const INERT_RECORD_KIND = "counter";
export function publicFrame(value: unknown): Buffer {
  const body = Buffer.from(canonicalBytes(value));
  if (body.length > RESPONSE_MAX_BYTES) return refuse();
  const size = Buffer.alloc(LENGTH_BYTES); size.writeUInt32BE(body.length);
  return Buffer.concat([size, body]);
}
export function parsePublicFrame(frame: Uint8Array): Record<string, unknown> {
  if (frame.length < LENGTH_BYTES || frame.length > RESPONSE_MAX_BYTES + LENGTH_BYTES) return refuse();
  const bytes = Buffer.from(frame); const length = bytes.readUInt32BE();
  if (length + LENGTH_BYTES !== bytes.length) return refuse();
  const value = parseStrict(bytes.subarray(LENGTH_BYTES), RESPONSE_MAX_BYTES);
  if (!value || typeof value !== "object" || Array.isArray(value) || !Buffer.from(canonicalBytes(value)).equals(bytes.subarray(LENGTH_BYTES))) return refuse();
  return value as Record<string, unknown>;
}
/** Owns an encrypted provider solely inside the per-lease worker; only record signatures leave it. */
export function workerSigner(identity: StoredIdentity, key: Uint8Array, grant: SigningGrant, started: string) {
  const provider = new EncryptedIdentityProvider(identity, key, grant);
  try {
    // The internally generated self-test binds the same role and machine required by the private K1a provider.
    const body = canonicalBytes({ v: 1, role: grant.role, machine_id: grant.machine_id, epoch: grant.epoch, kid: grant.kid,
      descriptor_digest: "sha256:" + (awaitlessDigest(canonicalBytes(grant))), boot_id: readBootId(), lease_id: grant.lease_id,
      challenge_nonce: randomBytes(SELF_TEST_NONCE_BYTES).toString("hex"), started_boottime_ns: started });
    const message = Buffer.concat([Buffer.from(UNLOCK_CHALLENGE_DOMAIN), body]);
    const signature = provider.sign(message);
    try { if (!strictVerify(message, signature, decodeCanonical(grant.public_key, ED25519_PUBLIC_BYTES))) return refuse(); }
    finally { signature.fill(0); }
    const signer = createRecordSigner(grant, provider, INERT_COUNTER_SCHEMA, INERT_RECORD_KIND);
    return { signRecord: (request: RecordRequest) => signer.signRecord(request), close: () => provider.close() };
  } catch { provider.close(); return refuse(); }
}
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
function awaitlessDigest(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("hex"); }
function readBootId(): string { return readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().replaceAll("-", ""); }

/** The native bridge supplies authenticated AF_UNIX packets; it has no unlock or factor API. */
export class SigningServiceClient {
  #child: ChildProcessWithoutNullStreams;
  #ready: Promise<boolean>;
  #busy = false;
  #closed = false;
  constructor(child: ChildProcessWithoutNullStreams) {
    this.#child = child; child.stderr.resume();
    // Stream failure closes the caller without an unhandled diagnostic or unsigned fallback.
    child.stdin.on("error", () => { this.#closed = true; child.kill(); });
    this.#ready = new Promise(resolve => {
      const frame = publicFrame({op: "BRIDGE_READY"}); const size = Buffer.alloc(LENGTH_BYTES); size.writeUInt32BE(frame.length);
      const expected = Buffer.concat([size, frame]); let bytes = Buffer.alloc(0); let done = false;
      const finish = (ok: boolean) => {
        if (done) return; done = true; clearTimeout(timer);
        child.stdout.off("data", data); child.off("error", failed); child.off("exit", failed);
        if (!ok) { this.#closed = true; child.kill(); } resolve(ok);
      };
      const failed = () => finish(false);
      const data = (chunk: Buffer) => {
        // No caller byte is sent until the native peer-credential receiver reports readiness.
        if (bytes.length + chunk.length > expected.length) return finish(false);
        bytes = Buffer.concat([bytes, chunk]);
        if (bytes.length === expected.length) finish(bytes.equals(expected));
      };
      const timer = setTimeout(failed, SIGNER_REQUEST_DEADLINE_MS);
      child.stdout.on("data", data); child.once("error", failed); child.once("exit", failed);
    });
  }
  static connect(): SigningServiceClient {
    // A fixed executable and empty environment prevent caller loader options from entering the native bridge.
    return new SigningServiceClient(spawn(SIGNER_BINARY, ["--bridge"], { env: {}, stdio: "pipe" }));
  }
  async #request(packet: Uint8Array): Promise<Record<string, unknown>> {
    // One outstanding operation and no queue retain ownership until response or child exit.
    if (this.#closed || this.#busy || packet.length > SIGNER_FRAME_MAX_BYTES) return refuse();
    this.#busy = true;
    try {
      if (!await this.#ready) return refuse();
      const frame = await new Promise<Buffer>((resolve, reject) => {
        let buffer = Buffer.alloc(0); let settled = false;
        const cleanup = () => { clearTimeout(timer); this.#child.stdout.off("data", data); this.#child.off("error", failed); this.#child.off("exit", failed); };
        const failed = () => { if (settled) return; settled = true; cleanup(); this.#closed = true; this.#child.kill(); reject(new Error("K1_REFUSED")); };
        const data = (chunk: Buffer) => {
          // Bound before concatenation because a corrupted bridge must not allocate unbounded response memory.
          if (buffer.length + chunk.length > RESPONSE_MAX_BYTES + LENGTH_BYTES * 2) return failed();
          buffer = Buffer.concat([buffer, chunk]);
          if (buffer.length < LENGTH_BYTES) return;
          const length = buffer.readUInt32BE();
          if (length > RESPONSE_MAX_BYTES + LENGTH_BYTES || buffer.length > length + LENGTH_BYTES) return failed();
          if (buffer.length === length + LENGTH_BYTES) { settled = true; cleanup(); resolve(buffer.subarray(LENGTH_BYTES)); }
        };
        const timer = setTimeout(failed, SIGNER_REQUEST_DEADLINE_MS);
        this.#child.stdout.on("data", data); this.#child.once("exit", failed); this.#child.once("error", failed);
        const size = Buffer.alloc(LENGTH_BYTES); size.writeUInt32BE(packet.length);
        this.#child.stdin.write(Buffer.concat([size, packet]), error => { if (error) failed(); });
      });
      const value = parsePublicFrame(frame);
      if (value.op === "REFUSED") return refuse();
      return value;
    } catch { this.#closed = true; this.#child.kill(); return refuse(); }
    finally { this.#busy = false; }
  }
  async status(): Promise<{ state: string; grant: SigningGrant; expires_boottime_ns: string }> {
    const value = await this.#request(canonicalBytes({ op: "STATUS" }));
    if (value.op !== "STATUS" || typeof value.state !== "string" || typeof value.expires_boottime_ns !== "string" || !value.grant) return refuse();
    return { state: value.state, grant: value.grant as SigningGrant, expires_boottime_ns: value.expires_boottime_ns };
  }
  async signRecord(request: RecordRequest, grant: SigningGrant, deadlineBoottimeNs: bigint): Promise<{ signature: string; kid: string }> {
    const requestId = randomBytes(TOKEN_ID_BYTES).toString("hex");
    const frame = encodeSignerFrame({v: 1, protocol: SIGNER_PROTOCOL, request_id: requestId, activation_id: grant.activation_id,
      lease_id: grant.lease_id, generation: grant.generation, epoch: request.epoch, role: request.role,
      deadline_boottime_ns: deadlineBoottimeNs.toString(), preimage_length: request.preimage_bytes.length}, request.preimage_bytes);
    const value = await this.#request(frame);
    // The consumer accepts only a correlated strictly verified signature and never manufactures unsigned success.
    if (Object.keys(value).sort().join(",") !== "kid,op,request_id,signature" || value.op !== "SIGNED" || value.request_id !== requestId || value.kid !== grant.kid || typeof value.signature !== "string" ||
      !verifyRecord(request.preimage_bytes, value.signature, grant, INERT_COUNTER_SCHEMA, INERT_RECORD_KIND)) return refuse();
    return { signature: value.signature, kid: grant.kid };
  }
  async close(): Promise<void> {
    this.#closed = true;
    if (this.#child.exitCode !== null || this.#child.signalCode !== null) return;
    await new Promise<void>(resolve => { this.#child.once("exit", () => resolve()); this.#child.kill(); });
  }
}
