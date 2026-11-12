import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import { canonicalBytes, refuse, SIGNER_FRAME_MAX_BYTES, SIGNER_PROTOCOL, SIGNER_REQUEST_DEADLINE_MS } from "../../src/signing/contract.js";
import { encodeSignerFrame } from "../../src/linux-business/producer-custody.js";
import { parsePublicFrame, RESPONSE_MAX_BYTES, LENGTH_BYTES, INERT_COUNTER_SCHEMA, INERT_RECORD_KIND } from "../../src/signing/service.js";
import { verifyRecord } from "../../src/signing/strict-verifier.js";
import type { RecordRequest, SigningGrant } from "../../src/signing/record-signer.js";
const TOKEN_ID_BYTES = 16; // A 128-bit identifier has 32 lowercase hexadecimal characters.
import {loadCheckedCorpus} from "./business-corpus.js";
import {isStrictEd25519PointEncoding} from "../../src/core/identity.js";
import {decodeCanonical, ROLE_REGISTRY} from "../../src/signing/contract.js";
import recordSchema from "../../src/signing/linux-business-records.schema.json";
export interface StatusReply {
  op: "STATUS"; state: string; grant: SigningGrant;
  started_boottime_ns: string; expires_boottime_ns: string; boot_id: string;
  anchor_revision: number | null; anchor_digest: string | null;
}
type StatusCorpus = {schema: {fields: Record<string,string>; grant_fields: Record<string,string>; states: string[]; anchor_pair: string[]}; cases: {id: string; packet_hex: string; accept: boolean}[]};
// Must match signer_status_vectors.json: schema data drives both runtime parsers, including nested grant fields.
export const statusCorpus = loadCheckedCorpus("signer_status_vectors.json") as StatusCorpus;
if (new Set(statusCorpus.cases.map(row => row.id)).size !== statusCorpus.cases.length || statusCorpus.cases.some(row => !row.id)) refuse();
const shape = (value: unknown): value is Record<string,unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
function typed(value: unknown, type: string): boolean {
  switch (type) {
    case "StatusOp": return value === "STATUS";
    case "State": return typeof value === "string" && statusCorpus.schema.states.includes(value);
    case "Grant": return objectFields(value, statusCorpus.schema.grant_fields);
    case "Role": return ROLE_REGISTRY.some(row => row.role === value);
    case "Point": try { return typeof value === "string" && isStrictEd25519PointEncoding(decodeCanonical(value, 32)); } catch {return false;}
    case "N": case "Pos": return typeof value === "number" && Number.isSafeInteger(value) && value >= (type === "N" ? recordSchema.definitions.N.min : recordSchema.definitions.Pos.min) && value <= recordSchema.bounds.safe_integer;
    case "U64": return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) <= BigInt(recordSchema.bounds.u64_max);
    case "ID": return typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
    case "Kid": return typeof value === "string" && /^k1:sha256:[a-f0-9]{64}$/.test(value);
    case "Digest": return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
    case "NullablePos": return value === null || typed(value, "Pos");
    case "NullableDigest": return value === null || typed(value, "Digest");
    default: return false;
  }
}
function objectFields(value: unknown, fields: Record<string,string>): boolean {
  // Exact key equality prevents an unrecognized authority field from reaching readiness.
  return shape(value) && Object.keys(value).sort().join(",") === Object.keys(fields).sort().join(",") && Object.entries(fields).every(([key,type]) => typed(value[key],type));
}
function parseStatus(value: Record<string,unknown>): StatusReply {
  const [revision, digest] = statusCorpus.schema.anchor_pair;
  if (!objectFields(value, statusCorpus.schema.fields) || (value[revision] === null) !== (value[digest] === null)) return refuse();
  return value as unknown as StatusReply;
}
export function parseStatusPacket(packet: Uint8Array): StatusReply {
  try { return parseStatus(parsePublicFrame(packet)); } catch { return refuse(); }
}
// Must match require_unix_socket in signer_peer.rs and the spawn in k1-service.ts: relay stdin must be an AF_UNIX socket.
/** Test-only relay transport; the real signer remains the authority for every request. */
export class RelayClient {
  #child: ChildProcessWithoutNullStreams;
  #ready: Promise<boolean>;
  #busy = false;
  #closed = false;
  constructor(child: ChildProcessWithoutNullStreams) {
    this.#child = child; child.stderr.resume();
    // Stream failure closes the caller without an unhandled diagnostic or unsigned fallback.
    child.stdin.on("error", () => { this.#closed = true; child.kill(); });
    // The listener is installed before STATUS is sent; the signer never sends unsolicited readiness.
    this.#ready = this.#exchange(canonicalBytes({op: "STATUS"})).then(value => {
      parseStatus(value); return true;
    }).catch(() => { this.#closed = true; child.kill(); return false; });
  }
  async #request(packet: Uint8Array): Promise<Record<string, unknown>> {
    if (!await this.#ready) return refuse();
    return this.#exchange(packet);
  }
  async #exchange(packet: Uint8Array): Promise<Record<string, unknown>> {
    // One outstanding operation and no queue retain ownership until response or child exit.
    if (this.#closed || this.#busy || packet.length > SIGNER_FRAME_MAX_BYTES) return refuse();
    this.#busy = true;
    try {
      const frame = await new Promise<Buffer>((resolve, reject) => {
        let buffer = Buffer.alloc(0); let settled = false;
        const cleanup = () => { clearTimeout(timer); this.#child.stdout.off("data", data); this.#child.off("error", failed); this.#child.off("exit", failed); };
        const failed = () => { if (settled) return; settled = true; cleanup(); this.#closed = true; this.#child.kill(); reject(new Error("K1_REFUSED")); };
        const data = (chunk: Buffer) => {
          // Bound before concatenation because a corrupted relay must not allocate unbounded response memory.
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
  async status(): Promise<StatusReply> {
    try { return parseStatus(await this.#request(canonicalBytes({ op: "STATUS" }))); }
    catch { this.#closed = true; this.#child.kill(); return refuse(); }
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
