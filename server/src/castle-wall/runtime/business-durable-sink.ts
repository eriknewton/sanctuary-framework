import {constants} from "node:fs";
import {open, lstat, rename, unlink, type FileHandle} from "node:fs/promises";
import {join, isAbsolute} from "node:path";
import {canonicalBytes} from "../../signing/contract.js";
import {parseStrict} from "../../smb/parse-strict.js";
import checkpointBounds from "../../signing/checkpoint-bounds.json";
import {PRODUCER_ENVELOPE_MAX_BYTES} from "../../signing/business-append-wire.js";
import type {BusinessDurableSink, DurableBusinessAcceptance} from "./business-record-consumer.js";

// The generated checkpoint ceiling includes the join state. Four envelope-sized
// fields cover E, projection, pin and identity at JSON's six-byte escape ceiling.
export const BUSINESS_SNAPSHOT_MAX_BYTES = checkpointBounds.honest_max_bytes + 4 * 6 * PRODUCER_ENVELOPE_MAX_BYTES;
const SNAPSHOT = "business.accepted.json";
const STAGE = "business.pending.json";
const LOCK = "business.lock";
const same = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(Buffer.from(b));
const encode = (value: DurableBusinessAcceptance): Uint8Array => {
  const bytes = canonicalBytes({...value, envelope: Buffer.from(value.envelope).toString("base64url")});
  if (bytes.byteLength > BUSINESS_SNAPSHOT_MAX_BYTES) throw Error("BUSINESS_SNAPSHOT_BOUND");
  return bytes;
};
const decode = (bytes: Uint8Array): DurableBusinessAcceptance => {
  const value = parseStrict(bytes, BUSINESS_SNAPSHOT_MAX_BYTES) as Record<string, unknown>;
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).sort().join(",") !== "checkpoint,envelope,identity,pin,projection"
      || typeof value.envelope !== "string") throw Error("BUSINESS_SNAPSHOT");
  const envelope = Buffer.from(value.envelope, "base64url");
  if (envelope.length > PRODUCER_ENVELOPE_MAX_BYTES || envelope.toString("base64url") !== value.envelope) throw Error("BUSINESS_SNAPSHOT");
  const accepted = {...value, envelope} as unknown as DurableBusinessAcceptance;
  if (!same(encode(accepted), bytes)) throw Error("BUSINESS_SNAPSHOT");
  return accepted;
};

/** Open an exclusively owned Linux snapshot in a caller-provisioned private directory.
 * Consumers must validate load() using createBusinessRecordConsumer before ACK.
 * close() releases ownership only after the current operation completes. */
export async function createBusinessDurableSink(directory: string): Promise<BusinessDurableSink & {close(): Promise<void>}> {
  if (process.platform !== "linux" || !isAbsolute(directory)) throw Error("BUSINESS_DIRECTORY");
  const parent = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  let lock: FileHandle | undefined;
  const held = `/proc/self/fd/${parent.fd}`;
  try {
    const metadata = await parent.stat();
    const current = await lstat(directory);
    if (!metadata.isDirectory() || metadata.dev !== current.dev || metadata.ino !== current.ino
        || (metadata.mode & 0o777) !== 0o700 || metadata.uid !== process.getuid?.()) throw Error("BUSINESS_DIRECTORY");
    // Exclusive ownership precedes all reads; an uncertain prior owner is never silently adopted.
    lock = await open(join(held, LOCK), constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    await lock.sync();
    await parent.sync();
  } catch (error) { await lock?.close(); await parent.close(); throw error; }
  let closed = false;
  let operation: Promise<unknown> | null = null;
  let pending: Uint8Array | null = null;
  const read = async (name: string): Promise<Uint8Array | null> => {
    let file: FileHandle;
    try { file = await open(join(held, name), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return null; throw error; }
    try {
      const metadata = await file.stat();
      if (!metadata.isFile() || metadata.nlink !== 1 || metadata.uid !== process.getuid?.()
          || (metadata.mode & 0o777) !== 0o600 || metadata.size > BUSINESS_SNAPSHOT_MAX_BYTES) throw Error("BUSINESS_SNAPSHOT");
      const bytes = await file.readFile();
      // The lock does not make stat and read atomic; refuse changed or oversized snapshots.
      if (bytes.byteLength !== metadata.size || bytes.byteLength > BUSINESS_SNAPSHOT_MAX_BYTES) throw Error("BUSINESS_SNAPSHOT");
      decode(bytes);
      return bytes;
    } finally { await file.close(); }
  };
  const owned = <T>(work: () => Promise<T>): Promise<T> => {
    if (closed || operation) return Promise.reject(Error("BUSINESS_BUSY"));
    const running = work();
    operation = running;
    return running.finally(() => { operation = null; });
  };
  return {
    load: () => owned(async () => {
      const bytes = await read(SNAPSHOT);
      return bytes ? decode(bytes) : null;
    }),
    persist: value => owned(async () => {
      const bytes = encode(value);
      // A failed publication owns exact bytes until they can be republished and read back.
      if (pending && !same(pending, bytes)) throw Error("BUSINESS_HELD");
      pending = bytes;
      const prior = await read(SNAPSHOT);
      if (prior) {
        const accepted = decode(prior);
        if (value.identity.sequence < accepted.identity.sequence
            || (value.identity.sequence === accepted.identity.sequence && !same(prior, bytes))) {
          // A refused replay never owns publication bytes and must not obstruct the next valid call.
          pending = null;
          throw Error("BUSINESS_REPLAY");
        }
      }
      let stage: FileHandle;
      try { stage = await open(join(held, STAGE), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST" || !same((await read(STAGE)) ?? new Uint8Array(), bytes)) throw error;
        stage = await open(join(held, STAGE), constants.O_WRONLY | constants.O_NOFOLLOW);
      }
      try { await stage.writeFile(bytes); await stage.sync(); }
      finally { await stage.close(); }
      await rename(join(held, STAGE), join(held, SNAPSHOT));
      await parent.sync();
      const durable = await read(SNAPSHOT);
      // Must match PolledSinkAdapter in business_wal.rs: only exact durable readback may produce an ACK.
      if (!durable || !same(durable, bytes)) throw Error("BUSINESS_READBACK");
      pending = null;
      return decode(durable);
    }),
    close: async () => {
      closed = true;
      if (operation) await operation.catch(() => {});
      await lock?.close();
      await unlink(join(held, LOCK));
      await parent.close();
    },
  };
}
