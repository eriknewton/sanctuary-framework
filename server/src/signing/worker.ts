import { constants, openSync, closeSync, fstatSync, readSync, writeSync } from "node:fs";
import { advance, type JoinState, type JoinRecord, type JoinResult } from "./record-joins.js";
import { ReadStream, isatty } from "node:tty";
import { derivePurposeKey } from "../core/key-derivation.js";
import { unlockExistingMasterReadOnlyWithEnvelope } from "../core/master-custody.js";
import { decrypt, type EncryptedPayload } from "../core/encryption.js";
import type { StoredIdentity } from "../core/identity.js";
import type { StorageBackend } from "../storage/interface.js";
import { validateCustodyProfile } from "./provision.js";
import { decryptBinding, validateEncryptedPayload } from "./binding-store.js";
import { canonicalBytes, refuse, SIGNER_FRAME_MAX_BYTES, SIGNER_HEADER_MAX_BYTES, SIGNER_PREIMAGE_MAX_BYTES } from "./contract.js";
import { decodeSignerFrame } from "../linux-business/producer-custody.js";
import { parseStrict } from "../smb/parse-strict.js";
import { publicFrame, workerSigner, LENGTH_BYTES } from "./service.js";
import type { SigningGrant } from "./record-signer.js";

/** Validation-only entrypoint; successful joins convey no signing or installed authority. */
export function validateBusinessJoin(state: JoinState, record: JoinRecord): JoinResult {
  // Must match records.rs::advance and the shared corpus consumers without widening service.ts inert dispatch.
  return advance(state, record);
}

// Must match custody.rs: only private stdin/stdout and the validated terminal at fd3 survive exec.
const TTY_FD = 3;
const STDIN_FD = 0;
const STDOUT_FD = 1;
const FACTOR_MAX_BYTES = 1024;
const TTY_RETRY_MS = 10;
const CARRIAGE_RETURN = 13;
const LINE_FEED = 10;
const INTERRUPT = 3;
const END_OF_INPUT = 4;
const BACKSPACE = 8;
const DELETE = 127;
const PASSPHRASE_MODE = "p".charCodeAt(0);
const RECOVERY_MODE = "r".charCodeAt(0);
const ttyWait = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
const PRIVATE_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
const IDENTITY_PURPOSE = "identity-encryption";
function exact(fd: number, length: number): Buffer {
  if (length > SIGNER_FRAME_MAX_BYTES) return refuse();
  const bytes = Buffer.alloc(length); let used = 0;
  while (used < length) { const n = readSync(fd, bytes, used, length - used, null); if (n === 0) return refuse(); used += n; }
  return bytes;
}
function frame(): { bytes: Buffer; header: Record<string, unknown>; body: Buffer } {
  const size = exact(STDIN_FD, LENGTH_BYTES); const length = size.readUInt32BE();
  // Both private stdio and public sockets share the bounded canonical frame contract.
  if (length > SIGNER_HEADER_MAX_BYTES) return refuse();
  const raw = exact(STDIN_FD, length); const header = parseStrict(raw, SIGNER_HEADER_MAX_BYTES) as Record<string, unknown>;
  if (!header || !Buffer.from(canonicalBytes(header)).equals(raw)) return refuse();
  const bodyLength = header.preimage_length;
  if (typeof bodyLength !== "number" || !Number.isSafeInteger(bodyLength) || bodyLength < 0 || bodyLength > SIGNER_PREIMAGE_MAX_BYTES) return refuse();
  const body = exact(STDIN_FD, bodyLength); return { bytes: Buffer.concat([size, raw, body]), header, body };
}
function readFactor(inode: string, device: string): {passphrase: string} | {recoveryKey: string} {
  const owned = Buffer.alloc(FACTOR_MAX_BYTES); const one = Buffer.alloc(1); let stream: ReadStream | undefined;
  try {
    // Worker revalidation refuses a pipe even if a compromised parent supplies it as fd3.
    const terminal = fstatSync(TTY_FD, {bigint: true});
    if (!isatty(TTY_FD) || !terminal.isCharacterDevice() || terminal.ino.toString() !== inode || terminal.rdev.toString() !== device) return refuse();
    stream = new ReadStream(TTY_FD); stream.setRawMode(true);
    writeSync(TTY_FD, "K1 factor mode [p=passphrase,r=recovery]: ");
    let recovery: boolean | undefined; let length = 0;
    for (;;) {
      try { if (readSync(TTY_FD, one, 0, 1, null) !== 1) return refuse(); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EAGAIN") return refuse();
        Atomics.wait(ttyWait, 0, 0, TTY_RETRY_MS); continue;
      }
      if (one[0] === CARRIAGE_RETURN || one[0] === LINE_FEED) {
        if (recovery !== undefined) break;
        if (length !== 1 || (owned[0] !== PASSPHRASE_MODE && owned[0] !== RECOVERY_MODE)) return refuse();
        recovery = owned[0] === RECOVERY_MODE; owned.fill(0); length = 0;
        writeSync(TTY_FD, recovery ? "K1 recovery key: " : "K1 passphrase: "); continue;
      }
      // Raw terminal editing removes the preceding UTF-8 code point without retaining corrected factor bytes.
      if (one[0] === BACKSPACE || one[0] === DELETE) {
        if (length > 0) { let start = length - 1; while (start > 0 && (owned[start]! & 0xc0) === 0x80) start--; owned.fill(0, start, length); length = start; }
        continue;
      }
      if (one[0] === INTERRUPT || one[0] === END_OF_INPUT || length === FACTOR_MAX_BYTES) return refuse();
      owned[length++] = one[0];
    }
    const factor = new TextDecoder("utf-8", { fatal: true }).decode(owned.subarray(0, length));
    return recovery ? {recoveryKey: factor} : {passphrase: factor};
  } finally {
    // Mutable intake buffers are wiped locally while immutable factor and library copies remain bounded by worker reaping.
    owned.fill(0); one.fill(0); stream?.setRawMode(false); writeSync(TTY_FD, "\n"); closeSync(TTY_FD);
  }
}
class ReadOnlyStore implements StorageBackend {
  #root: number; #owner: number;
  constructor(root: string, owner: number) {
    this.#root = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW); this.#owner = owner;
    const stat = fstatSync(this.#root);
    if (stat.uid !== owner || (stat.mode & 0o777) !== DIRECTORY_MODE) { closeSync(this.#root); return refuse(); }
  }
  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    // Held directory descriptors and exact components prevent symlinks or namespace traversal from selecting a different store.
    if (!/^_[a-z_]+$/.test(namespace) || !/^[a-zA-Z0-9_-]+$/.test(key)) return refuse();
    let directory: number | undefined; let file: number | undefined;
    try {
      directory = openSync(`/proc/self/fd/${this.#root}/${namespace}`, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      const parent = fstatSync(directory);
      if (parent.uid !== this.#owner || (parent.mode & 0o777) !== DIRECTORY_MODE) return refuse();
      file = openSync(`/proc/self/fd/${directory}/${key}.enc`, constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = fstatSync(file);
      if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== this.#owner || (stat.mode & 0o777) !== PRIVATE_MODE || stat.size > SIGNER_PREIMAGE_MAX_BYTES) return refuse();
      const bytes = exact(file, stat.size); const extra = Buffer.alloc(1);
      if (readSync(file, extra, 0, 1, null) !== 0) return refuse(); return bytes;
    } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return null; return refuse(); }
    finally { if (file !== undefined) closeSync(file); if (directory !== undefined) closeSync(directory); }
  }
  // must match refuse() in contract.ts.
  async write(): Promise<void> { throw new Error("K1_REFUSED"); }
  async delete(): Promise<boolean> { return refuse(); }
  async list(): Promise<never> { return refuse(); }
  async exists(): Promise<boolean> { return refuse(); }
  async totalSize(): Promise<number> { return refuse(); }
  close(): void { closeSync(this.#root); }
}
async function main(): Promise<void> {
  const initial = frame();
  if (Object.keys(initial.header).sort().join(",") !== "op,preimage_length" || initial.header.op !== "UNLOCK") return refuse();
  const config = parseStrict(initial.body, SIGNER_PREIMAGE_MAX_BYTES) as {grant: SigningGrant; root: string; owner: number; fortress_id: string; roster_digest: string; binding_high_water: number; started_boottime_ns: string; tty_inode: string; tty_device: string};
  const store = new ReadOnlyStore(config.root, config.owner);
  let master: Uint8Array | undefined; let key: Uint8Array | undefined; let plain: Uint8Array | undefined;
  let signer: ReturnType<typeof workerSigner> | undefined;
  try {
    const credential = readFactor(config.tty_inode, config.tty_device);
    // Only the authenticated envelope returned by the read-only custody API establishes the two-wrap profile.
    const unlocked = await unlockExistingMasterReadOnlyWithEnvelope(store, credential); master = unlocked.masterKey;
    validateCustodyProfile(unlocked.envelope);
    const bindingBytes = await store.read("_producer_custody", "binding"); if (!bindingBytes) return refuse();
    const binding = decryptBinding(parseStrict(bindingBytes, SIGNER_PREIMAGE_MAX_BYTES) as EncryptedPayload, master,
      {fortress_id: config.fortress_id, machine_id: config.grant.machine_id, role: config.grant.role});
    if (binding.transaction_state !== "LOCKED" || binding.epoch !== config.grant.epoch || binding.kid !== config.grant.kid || binding.identity_id !== config.grant.identity_id || binding.roster_digest !== config.roster_digest || binding.high_water !== config.binding_high_water) return refuse();
    key = derivePurposeKey(master, IDENTITY_PURPOSE); master.fill(0); master = undefined;
    const identityBytes = await store.read("_identities", binding.identity_id); if (!identityBytes) return refuse();
    const outer = parseStrict(identityBytes, SIGNER_PREIMAGE_MAX_BYTES) as EncryptedPayload; validateEncryptedPayload(outer);
    plain = decrypt(outer, key);
    const identity = parseStrict(plain, SIGNER_PREIMAGE_MAX_BYTES) as StoredIdentity;
    if (!Buffer.from(canonicalBytes(identity)).equals(Buffer.from(plain))) return refuse();
    signer = workerSigner(identity, key, config.grant, config.started_boottime_ns);
    key.fill(0); key = undefined; plain.fill(0); plain = undefined;
    writeSync(STDOUT_FD, publicFrame({op: "READY"}));
    for (;;) {
      const request = frame();
      if (Object.keys(request.header).sort().join(",") === "op,preimage_length" && request.header.op === "LOCK" && request.body.length === 0) {
        return;
      }
      const {header, preimage} = decodeSignerFrame(request.bytes);
      if (header.activation_id !== config.grant.activation_id || header.lease_id !== config.grant.lease_id || header.generation !== config.grant.generation) return refuse();
      const signed = signer.signRecord({ role: header.role, epoch: header.epoch, preimage_bytes: preimage });
      writeSync(STDOUT_FD, publicFrame({op: "SIGNED", request_id: header.request_id, ...signed}));
    }
  } finally { signer?.close(); key?.fill(0); master?.fill(0); plain?.fill(0); store.close(); }
}
// The release entrypoint accepts no argv, environment credential, injected callback or caller challenge.
const acknowledgeWipe = () => {
  // main has wiped owned buffers before this acknowledgement; native reaping closes immutable library copies.
  writeSync(STDOUT_FD, publicFrame({op: "WIPED"})); process.exit(0);
};
// Only the directly executed CommonJS release worker may enter the attended protocol.
if (typeof require !== "undefined" && typeof module !== "undefined" && require.main === module) void main().then(acknowledgeWipe, acknowledgeWipe);
