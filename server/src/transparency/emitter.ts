/**
 * Sanctuary Verifiable Transparency — checkpoint emitter.
 *
 * Builds, signs, and persists enforcement checkpoints over the local
 * fortress. FAIL-CLOSED EVERYWHERE (hard constraint #5):
 *
 *   - audit chain fails integrity        → refuse (AuditIntegrityError)
 *   - no Castle Wall policy on disk      → refuse
 *   - emitting binary unreadable         → refuse
 *   - signer unreachable / bad signature → refuse; NOTHING is persisted
 *   - checkpoint store rolled back       → refuse (MAC'd counter floor)
 *   - previous checkpoint malformed      → refuse
 *
 * There is NO unsigned or partial checkpoint, ever.
 */

import { createHash } from "node:crypto";
import { open, readdir, readFile, rm } from "node:fs/promises";
import { uptime as osUptime } from "node:os";
import { join } from "node:path";

import { canonicalJson, sha256Hex } from "../audit/chain.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../core/encoding.js";
import { hmacSha256 } from "../core/hashing.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { computeAuditRoot } from "../audit/chain.js";
import type { AuditLog } from "../operational/audit-log.js";
import type {
  FilesystemStorageCapabilities,
  StorageBackend,
} from "../storage/interface.js";
import {
  TRANSPARENCY_CHECKPOINT_GENESIS,
  TRANSPARENCY_CHECKPOINT_SCHEMA_VERSION,
  checkpointPayloadOf,
  checkpointSigningBytes,
  computeCheckpointHash,
  isEnforcementCheckpointRecord,
  transparencyRuleLabel,
  verifyEnforcementCheckpointSignature,
  type CheckpointEnforcement,
  type CheckpointPolicy,
  type CheckpointRuleCounter,
  type EnforcementCheckpointPayload,
  type EnforcementCheckpointRecord,
} from "./checkpoint.js";
import { ED25519_SIGNATURE_BYTES } from "../core/crypto-suite-registry.js";

export const TRANSPARENCY_CHECKPOINT_NAMESPACE = "_transparency_checkpoints";
export const TRANSPARENCY_CHECKPOINT_KEY_PREFIX = "enforcement-checkpoint-";
export const TRANSPARENCY_FLOOR_META_KEY = "transparency-counter-floor-v1";

const TRANSPARENCY_FLOOR_MARKER = "__sanctuary_transparency_counter_floor_v1";
const TRANSPARENCY_FLOOR_MAC_DOMAIN =
  "sanctuary.transparency-counter-floor.v1\n";
const TRANSPARENCY_POLICY_RULES_DOMAIN =
  "sanctuary.transparency.policy-rules.v1";
const TRANSPARENCY_EMIT_LOCK_FILE = ".transparency-emit.lock";
const TRANSPARENCY_EMIT_LOCK_TIMEOUT_MS = 5_000;
const TRANSPARENCY_EMIT_LOCK_RETRY_MS = 100;

/**
 * Signing handle for checkpoint emission. Carries NO private key material —
 * production custody is the Castle Wall root signer helper (#387): the
 * helper signs opaque domain-separated bytes and only the signature and
 * public key ever reach this process. The dev/test local path decrypts the
 * castle-pinned key transiently inside `sign` (core/identity.ts zeroes it).
 */
export interface TransparencySigner {
  signer_kid: string;
  /** Raw 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  /** Sign opaque domain-separated bytes → raw 64-byte Ed25519 signature. */
  sign(bytes: Uint8Array): Promise<Uint8Array>;
}

export class TransparencyEmitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransparencyEmitError";
  }
}

export interface EmitEnforcementCheckpointInput {
  storage: StorageBackend;
  auditLog: AuditLog;
  fortressId: string;
  /** Fortress root (policy lives at `<fortressPath>/policy/egress/...`). */
  fortressPath: string;
  /** Master key; used ONLY to derive the counter-floor MAC key. */
  masterKey: Uint8Array;
  signer: TransparencySigner;
  /** Absolute path of the emitting binary (hashed into the checkpoint). */
  binaryPath: string;
  /** Emitting package version string. */
  version: string;
  /** Clock override for tests. */
  now?: () => Date;
}

/** Persisted-checkpoint key for a counter value (zero-padded, sort-stable). */
export function checkpointStorageKey(counter: number): string {
  return `${TRANSPARENCY_CHECKPOINT_KEY_PREFIX}${String(counter).padStart(20, "0")}`;
}

/**
 * Read every persisted checkpoint record, sorted by counter ascending.
 * A malformed record is a hard error (the store is authoritative emission
 * state; continuing past corruption could mint a forked counter).
 */
export async function readPersistedCheckpoints(
  storage: StorageBackend
): Promise<EnforcementCheckpointRecord[]> {
  let metas;
  try {
    metas = await storage.list(
      TRANSPARENCY_CHECKPOINT_NAMESPACE,
      TRANSPARENCY_CHECKPOINT_KEY_PREFIX
    );
  } catch (err) {
    throw new TransparencyEmitError(
      `transparency checkpoint store could not be listed: ${errorMessage(err)}`
    );
  }
  const records: EnforcementCheckpointRecord[] = [];
  for (const meta of metas) {
    const raw = await storage.read(TRANSPARENCY_CHECKPOINT_NAMESPACE, meta.key);
    if (!raw) {
      throw new TransparencyEmitError(
        `transparency checkpoint ${meta.key} disappeared during read`
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      throw new TransparencyEmitError(
        `transparency checkpoint ${meta.key} is not valid JSON (store corrupted or tampered)`
      );
    }
    if (!isEnforcementCheckpointRecord(parsed)) {
      throw new TransparencyEmitError(
        `transparency checkpoint ${meta.key} is malformed (store corrupted or tampered)`
      );
    }
    records.push(parsed);
  }
  records.sort((a, b) => a.counter - b.counter);
  return records;
}

/**
 * Emit one signed enforcement checkpoint. Returns the persisted record.
 * Throws `TransparencyEmitError` (or `AuditIntegrityError` from the audit
 * layer) on ANY failure; on failure nothing has been persisted.
 */
export async function emitEnforcementCheckpoint(
  input: EmitEnforcementCheckpointInput
): Promise<EnforcementCheckpointRecord> {
  const floorMacKey = derivePurposeKey(
    input.masterKey,
    "transparency-counter-floor"
  );
  try {
    return await withEmitLock(input.storage, async () => {
      // 1. Verified audit-chain view, STREAMED. Strict mode: AuditIntegrityError
      //    on a chain that does not verify — never checkpoint a tampered log.
      //    We fold the Merkle leaf hashes, the covered sequence range, the head
      //    hash, and the per-rule enforcement counters incrementally so the full
      //    decrypted chain is never simultaneously resident (the daemon-OOM-on-a-
      //    large-log fix); only the cheap entry-hash leaves accumulate, which the
      //    Merkle root structurally requires. `reset` discards a torn-read pass
      //    that the audit log's read-consistency loop abandons, so these folds
      //    reflect exactly the single accepted verified pass.
      let entryHashes: string[] = [];
      let lowestSequence: number | null = null;
      let highestSequence = 0;
      let headHash = "GENESIS";
      let entryCount = 0;
      let enforcementAcc = newEnforcementAccumulator();
      await input.auditLog.streamVerifiedChain({
        onEntry: (item) => {
          entryHashes.push(item.entry_hash);
          if (lowestSequence === null) lowestSequence = item.sequence;
          highestSequence = item.sequence;
          headHash = item.entry_hash;
          entryCount++;
          accumulateEnforcement(enforcementAcc, input.fortressId, item.entry);
        },
        reset: () => {
          entryHashes = [];
          lowestSequence = null;
          highestSequence = 0;
          headHash = "GENESIS";
          entryCount = 0;
          enforcementAcc = newEnforcementAccumulator();
        },
      });

      // 2. Policy posture (hashes + counts only).
      const policy = await readPolicyPosture(input.fortressPath);

      // 3. Emitting-binary identity (self-reported; documented as such).
      const daemon = await readBinaryIdentity(input.binaryPath, input.version);

      // 4. Counter continuity against the persisted store + MAC'd floor.
      const previous = await readPersistedCheckpoints(input.storage);
      const last = previous.at(-1);
      const floor = await readCounterFloor(input.storage, floorMacKey);
      if (floor.status === "invalid") {
        throw new TransparencyEmitError(
          "transparency counter floor failed authentication (tampered, forged, or wrong key); refusing to emit"
        );
      }
      if (floor.status === "valid") {
        if (!last || last.counter < floor.highest_counter) {
          throw new TransparencyEmitError(
            `transparency checkpoint store rollback detected: counter floor is ${floor.highest_counter} but the highest persisted checkpoint is ${last ? last.counter : "absent"}; refusing to emit`
          );
        }
      } else if (last) {
        // Floor absent but checkpoints exist. The floor is written on every
        // emission, so an established store without a floor means the floor
        // record was deleted — fail closed rather than re-anchoring.
        throw new TransparencyEmitError(
          "transparency counter floor is missing for an established checkpoint store (floor deletion or rollback); refusing to emit"
        );
      }
      const counter = (last?.counter ?? 0) + 1;
      const previousCheckpointHash = last
        ? computeCheckpointHash(checkpointPayloadOf(last))
        : TRANSPARENCY_CHECKPOINT_GENESIS;

      // 5. Build the payload over the SAME entry set the Merkle root covers.
      const payload: EnforcementCheckpointPayload = {
        checkpoint_kind: "enforcement-checkpoint",
        schema_version: TRANSPARENCY_CHECKPOINT_SCHEMA_VERSION,
        counter,
        previous_checkpoint_hash: previousCheckpointHash,
        issued_at: (input.now?.() ?? new Date()).toISOString(),
        fortress_id: input.fortressId,
        audit: {
          merkle_root: computeAuditRoot(entryHashes),
          lowest_sequence: lowestSequence ?? 0,
          highest_sequence: highestSequence,
          head_hash: headHash,
          entry_count: entryCount,
        },
        policy,
        daemon,
        enforcement: finalizeEnforcement(enforcementAcc),
      };

      // 6. Sign, then independently verify the returned signature before
      //    persisting anything (a signer that returns garbage must not
      //    produce a persisted-but-unverifiable checkpoint).
      let signature: Uint8Array;
      try {
        signature = await input.signer.sign(checkpointSigningBytes(payload));
      } catch (err) {
        throw new TransparencyEmitError(
          `transparency checkpoint signing failed (nothing was emitted): ${errorMessage(err)}`
        );
      }
      if (signature.length !== ED25519_SIGNATURE_BYTES) {
        throw new TransparencyEmitError(
          `transparency signer returned a ${signature.length}-byte signature (expected 64); nothing was emitted`
        );
      }
      const record: EnforcementCheckpointRecord = {
        ...payload,
        signer_kid: input.signer.signer_kid,
        signature: toBase64url(signature),
        signature_algorithm: "Ed25519",
        payload_encoding: "domain-separated-canonical-json-v1",
        public_key: toBase64url(input.signer.publicKey),
      };
      if (!verifyEnforcementCheckpointSignature(record, input.signer.publicKey)) {
        throw new TransparencyEmitError(
          "transparency signer returned a signature that does not verify against its own public key; nothing was emitted"
        );
      }

      // 7. Persist the checkpoint durably, THEN raise the floor. A crash
      //    between the two leaves floor == counter-1, which still satisfies
      //    the floor invariant (floor is a lower bound).
      await writeRecordDurable(
        input.storage,
        TRANSPARENCY_CHECKPOINT_NAMESPACE,
        checkpointStorageKey(counter),
        stringToBytes(JSON.stringify(record))
      );
      await writeCounterFloor(input.storage, floorMacKey, counter);
      return record;
    });
  } finally {
    floorMacKey.fill(0);
  }
}

/**
 * Incremental enforcement accumulator. Lets the emitter fold the per-rule
 * allow/block counters one streamed audit entry at a time, so the full
 * decrypted chain never has to be materialized to count (the bounded-memory
 * Merkle/emit path). The finalized result is byte-identical to the previous
 * batch `countEnforcement` over the same ordered entry set.
 */
interface EnforcementAccumulator {
  totalAllowed: number;
  totalBlocked: number;
  byLabel: Map<string, { allowed: number; blocked: number }>;
}

function newEnforcementAccumulator(): EnforcementAccumulator {
  return { totalAllowed: 0, totalBlocked: 0, byLabel: new Map() };
}

function accumulateEnforcement(
  acc: EnforcementAccumulator,
  fortressId: string,
  entry: { operation: string; details?: Record<string, unknown> }
): void {
  const kind =
    entry.operation === "egress_allowed"
      ? "allowed"
      : entry.operation === "egress_blocked"
        ? "blocked"
        : null;
  if (!kind) return;
  if (kind === "allowed") acc.totalAllowed++;
  else acc.totalBlocked++;
  const ruleId = entry.details?.rule_id;
  if (typeof ruleId !== "string" || ruleId.length === 0) return;
  const label = transparencyRuleLabel(fortressId, ruleId);
  const bucket = acc.byLabel.get(label) ?? { allowed: 0, blocked: 0 };
  bucket[kind]++;
  acc.byLabel.set(label, bucket);
}

function finalizeEnforcement(acc: EnforcementAccumulator): CheckpointEnforcement {
  const rules: CheckpointRuleCounter[] = [...acc.byLabel.entries()]
    .map(([rule_label, counts]) => ({ rule_label, ...counts }))
    .sort((a, b) => a.rule_label.localeCompare(b.rule_label));
  return { total_allowed: acc.totalAllowed, total_blocked: acc.totalBlocked, rules };
}

/**
 * Hash the Castle Wall policy inputs: every rule file under
 * `policy/egress/rules/`, plus the published manifest when present.
 * A fortress with NO rules directory has no Castle Wall policy to attest —
 * refuse rather than emitting a checkpoint that implies enforcement.
 */
async function readPolicyPosture(
  fortressPath: string
): Promise<CheckpointPolicy> {
  const rulesDir = join(fortressPath, "policy", "egress", "rules");
  let filenames: string[];
  try {
    filenames = (await readdir(rulesDir))
      .filter((name) => name.endsWith(".json"))
      .sort();
  } catch (err) {
    throw new TransparencyEmitError(
      `no Castle Wall policy found (cannot read ${rulesDir}: ${errorMessage(err)}); enforcement checkpoints attest a policy-bearing fortress; configure Castle Wall first`
    );
  }
  const fileHashes: Array<{ name: string; sha256: string }> = [];
  for (const name of filenames) {
    let bytes: Uint8Array;
    try {
      bytes = await readFile(join(rulesDir, name));
    } catch (err) {
      throw new TransparencyEmitError(
        `policy rule file ${name} could not be read: ${errorMessage(err)}`
      );
    }
    fileHashes.push({
      name,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  }
  const rulesSha256 = sha256Hex(
    `${TRANSPARENCY_POLICY_RULES_DOMAIN}\n${canonicalJson(fileHashes)}`
  );

  let manifestSha256: string | null = null;
  try {
    const manifestBytes = await readFile(
      join(fortressPath, "policy", "egress", "manifest.json")
    );
    manifestSha256 = createHash("sha256").update(manifestBytes).digest("hex");
  } catch (err) {
    if (!isNotFound(err)) {
      throw new TransparencyEmitError(
        `policy manifest exists but could not be read: ${errorMessage(err)}`
      );
    }
  }

  return {
    rules_sha256: rulesSha256,
    rules_count: fileHashes.length,
    manifest_sha256: manifestSha256,
  };
}

async function readBinaryIdentity(
  binaryPath: string,
  version: string
): Promise<{ version: string; binary_sha256: string }> {
  let bytes: Uint8Array;
  try {
    bytes = await readFile(binaryPath);
  } catch (err) {
    throw new TransparencyEmitError(
      `emitting binary could not be hashed (${binaryPath}): ${errorMessage(err)}`
    );
  }
  return {
    version,
    binary_sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

// ---- MAC'd counter floor ------------------------------------------------

function floorMacBytes(
  macKey: Uint8Array,
  data: { highest_counter: number }
): Uint8Array {
  return hmacSha256(
    macKey,
    stringToBytes(TRANSPARENCY_FLOOR_MAC_DOMAIN + canonicalJson(data))
  );
}

/** Authenticated read state of the MAC'd transparency counter floor. */
export type CounterFloorState =
  | { status: "valid"; highest_counter: number }
  | { status: "absent" }
  | { status: "invalid" };

/**
 * Read + AUTHENTICATE the on-disk transparency counter floor under the
 * fortress master. Exported for the anti-rollback Stage 2 Rekor
 * counter-floor cross-check (core/anti-rollback.ts), which compares this
 * on-disk floor against the highest externally-anchored counter. Derives
 * the same floor MAC key the emitter uses, and zeroes it after.
 *
 *  - "valid":   floor authenticates → trustworthy on-disk lower bound.
 *  - "absent":  no floor record → no checkpoint has been emitted yet
 *               (or the floor was deleted; the caller decides whether that
 *               is suspicious given whether anchored evidence exists).
 *  - "invalid": present but tampered/forged/wrong-key → never read as a
 *               number; the Stage 2 caller fails toward FREEZE.
 */
export async function readTransparencyCounterFloor(
  storage: StorageBackend,
  masterKey: Uint8Array
): Promise<CounterFloorState> {
  const floorMacKey = derivePurposeKey(masterKey, "transparency-counter-floor");
  try {
    return await readCounterFloor(storage, floorMacKey);
  } finally {
    floorMacKey.fill(0);
  }
}

/**
 * Re-baseline the on-disk transparency counter floor to `targetCounter`
 * (anti-rollback Stage 2, restore-attest). This is the Stage-2 analogue of
 * Stage 1's epoch-witness re-baseline: after an operator attests a legitimate
 * restore, the floor is raised so it is ≥ the highest locally-recorded anchored
 * counter, making the attested state internally consistent (otherwise the
 * Stage-2 recompute in enforceCustodyFloor would correctly re-detect the floor
 * regression and re-freeze). It NEVER lowers a higher current floor (monotonic;
 * a re-baseline below the present floor is a no-op). Returns the floor value in
 * effect after the call. Derives + zeroes the floor MAC key like the emitter.
 */
export async function rebaselineTransparencyCounterFloor(
  storage: StorageBackend,
  masterKey: Uint8Array,
  targetCounter: number
): Promise<number> {
  const floorMacKey = derivePurposeKey(masterKey, "transparency-counter-floor");
  try {
    const current = await readCounterFloor(storage, floorMacKey);
    const currentValue = current.status === "valid" ? current.highest_counter : 0;
    // Only raise (monotonic). A tampered floor (invalid) is treated as 0 here,
    // so the re-baseline writes a fresh authenticated floor at the target.
    const next = Math.max(currentValue, targetCounter);
    if (next <= 0) return currentValue; // nothing to anchor to; leave as-is
    if (current.status === "valid" && next === currentValue) return currentValue;
    await writeCounterFloor(storage, floorMacKey, next);
    return next;
  } finally {
    floorMacKey.fill(0);
  }
}

async function readCounterFloor(
  storage: StorageBackend,
  macKey: Uint8Array
): Promise<CounterFloorState> {
  let raw: Uint8Array | null;
  try {
    raw = await storage.read("_meta", TRANSPARENCY_FLOOR_META_KEY);
  } catch {
    return { status: "invalid" };
  }
  if (!raw) return { status: "absent" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytesToString(raw));
  } catch {
    return { status: "invalid" };
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as Record<string, unknown>)[TRANSPARENCY_FLOOR_MARKER] !== true
  ) {
    return { status: "invalid" };
  }
  const data = (parsed as Record<string, unknown>).data;
  const mac = (parsed as Record<string, unknown>).mac;
  if (
    !data ||
    typeof data !== "object" ||
    typeof (data as Record<string, unknown>).highest_counter !== "number" ||
    !Number.isSafeInteger((data as Record<string, unknown>).highest_counter) ||
    ((data as Record<string, unknown>).highest_counter as number) <= 0 ||
    typeof mac !== "string"
  ) {
    return { status: "invalid" };
  }
  const highestCounter = (data as { highest_counter: number }).highest_counter;
  let providedMac: Uint8Array;
  try {
    providedMac = fromBase64url(mac);
  } catch {
    return { status: "invalid" };
  }
  if (
    !constantTimeEqual(
      providedMac,
      floorMacBytes(macKey, { highest_counter: highestCounter })
    )
  ) {
    return { status: "invalid" };
  }
  return { status: "valid", highest_counter: highestCounter };
}

async function writeCounterFloor(
  storage: StorageBackend,
  macKey: Uint8Array,
  highestCounter: number
): Promise<void> {
  const data = { highest_counter: highestCounter };
  const envelope = {
    [TRANSPARENCY_FLOOR_MARKER]: true,
    data,
    mac: toBase64url(floorMacBytes(macKey, data)),
  };
  await writeRecordDurable(
    storage,
    "_meta",
    TRANSPARENCY_FLOOR_META_KEY,
    stringToBytes(JSON.stringify(envelope))
  );
}

// ---- Cross-process emit lock ---------------------------------------------

/**
 * Serialize concurrent emitters on filesystem backends so two processes
 * cannot mint the same counter. Mirrors the audit-write lock discipline:
 * O_EXCL create, provably-stale break (dead holder PID or pre-boot
 * acquired_at), bounded wait, fail closed on sustained contention.
 * Non-filesystem backends (single-process tests) run unlocked.
 */
async function withEmitLock<T>(
  storage: StorageBackend,
  operation: () => Promise<T>
): Promise<T> {
  const capabilities = asFilesystemCapabilities(storage);
  if (!capabilities) return operation();
  const { mkdir } = await import("node:fs/promises");
  const dir = capabilities.namespacePath(TRANSPARENCY_CHECKPOINT_NAMESPACE);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const lockPath = join(dir, TRANSPARENCY_EMIT_LOCK_FILE);
  const started = Date.now();
  for (;;) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      try {
        await handle.writeFile(
          JSON.stringify({
            pid: process.pid,
            acquired_at: new Date().toISOString(),
          })
        );
        await handle.sync();
      } finally {
        await handle.close();
      }
      break;
    } catch (err) {
      const code =
        err instanceof Error && "code" in err
          ? String((err as NodeJS.ErrnoException).code)
          : "";
      if (code !== "EEXIST") {
        throw new TransparencyEmitError(
          `transparency emit lock could not be acquired: ${errorMessage(err)}`
        );
      }
      if (await breakProvablyStaleLock(lockPath)) continue;
      if (Date.now() - started >= TRANSPARENCY_EMIT_LOCK_TIMEOUT_MS) {
        throw new TransparencyEmitError(
          `another transparency emission is in progress (lock ${lockPath} held >${TRANSPARENCY_EMIT_LOCK_TIMEOUT_MS}ms); refusing to emit concurrently`
        );
      }
      await sleep(TRANSPARENCY_EMIT_LOCK_RETRY_MS);
    }
  }
  try {
    return await operation();
  } finally {
    await rm(lockPath, { force: true });
  }
}

async function breakProvablyStaleLock(lockPath: string): Promise<boolean> {
  let holderPid: number | undefined;
  let acquiredAtMs: number | undefined;
  try {
    const parsed = JSON.parse(await readFile(lockPath, "utf8")) as {
      pid?: unknown;
      acquired_at?: unknown;
    };
    if (typeof parsed.pid === "number" && Number.isInteger(parsed.pid)) {
      holderPid = parsed.pid;
    }
    if (typeof parsed.acquired_at === "string") {
      const t = Date.parse(parsed.acquired_at);
      if (!Number.isNaN(t)) acquiredAtMs = t;
    }
  } catch (err) {
    const code =
      err instanceof Error && "code" in err
        ? String((err as NodeJS.ErrnoException).code)
        : "";
    // Vanished: the holder released it; retry the acquire immediately.
    if (code === "ENOENT") return true;
    // Unreadable/corrupt: cannot PROVE staleness — never break it.
    return false;
  }
  if (holderPid === process.pid) return false;
  const bootTimeMs = currentBootTimeMs();
  const predatesBoot =
    acquiredAtMs !== undefined &&
    bootTimeMs !== undefined &&
    acquiredAtMs < bootTimeMs;
  const holderDead = holderPid !== undefined && !isProcessAlive(holderPid);
  if (!predatesBoot && !holderDead) return false;
  await rm(lockPath, { force: true });
  return true;
}

// ---- Small helpers --------------------------------------------------------

async function writeRecordDurable(
  storage: StorageBackend,
  namespace: string,
  key: string,
  bytes: Uint8Array
): Promise<void> {
  const capabilities = asFilesystemCapabilities(storage);
  if (capabilities) {
    await capabilities.writeDurable(namespace, key, bytes);
    return;
  }
  await storage.write(namespace, key, bytes);
}

function asFilesystemCapabilities(
  storage: StorageBackend
): FilesystemStorageCapabilities | undefined {
  const candidate = storage as Partial<FilesystemStorageCapabilities>;
  if (
    typeof candidate.namespacePath === "function" &&
    typeof candidate.writeDurable === "function"
  ) {
    return candidate as FilesystemStorageCapabilities;
  }
  return undefined;
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    const code =
      err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    return code === "EPERM";
  }
}

function currentBootTimeMs(): number | undefined {
  try {
    return Date.now() - osUptime() * 1000;
  } catch {
    return undefined;
  }
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function isNotFound(err: unknown): boolean {
  return (
    err instanceof Error &&
    "code" in err &&
    String((err as NodeJS.ErrnoException).code) === "ENOENT"
  );
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
