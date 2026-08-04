/**
 * Memory Checkpoint -- encrypted local filesystem checkpoint store.
 *
 * Persists checkpoint metadata and encrypted StateStore export bundles under
 * `<fortress>/checkpoints/<id>/`. The bundle is encrypted with the
 * master-key-derived `memory-checkpoint-v1` purpose key; `record.json` is
 * plaintext non-secret metadata used for listing and pruning.
 */

import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";
import {
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";

import { bytesToString, fromBase64url, stringToBytes } from "../core/encoding.js";
import { decrypt, encrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import {
  MemoryCheckpointDeleteError,
  MemoryCheckpointEncryptionError,
  MemoryCheckpointPersistenceError,
  MemoryCheckpointReadError,
  MemoryCheckpointValidationError,
  type MemoryCheckpointRecord,
} from "./types.js";

export const MEMORY_CHECKPOINT_FORMAT_VERSION = 1;
export const MEMORY_CHECKPOINT_PURPOSE = "memory-checkpoint-v1";

const CHECKPOINT_ID_RE = /^cp_\d{8}T\d{9}Z_[0-9a-f]{16}$/;
const AAD_DOMAIN = "sanctuary.memory-checkpoint.v1\n";

export interface MemoryCheckpointDirent {
  name: string;
  isDirectory(): boolean;
}

export interface MemoryCheckpointFsOps {
  mkdir(
    path: string,
    options: { recursive?: boolean; mode?: number },
  ): Promise<void>;
  writeFile(
    path: string,
    data: string | Uint8Array,
    options: { mode?: number },
  ): Promise<void>;
  readFile(path: string): Promise<Uint8Array>;
  readdir(path: string): Promise<MemoryCheckpointDirent[]>;
  rename(oldPath: string, newPath: string): Promise<void>;
  rm(
    path: string,
    options: { recursive?: boolean; force?: boolean },
  ): Promise<void>;
}

export interface MemoryCheckpointClock {
  now(): Date;
}

export const systemMemoryCheckpointClock: MemoryCheckpointClock = {
  now: () => new Date(),
};

export const nodeMemoryCheckpointFsOps: MemoryCheckpointFsOps = {
  mkdir: async (path, options) => {
    await mkdir(path, options);
  },
  writeFile,
  readFile: async (path: string) => {
    const data = await readFile(path);
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  },
  readdir: (path: string) => readdir(path, { withFileTypes: true }),
  rename,
  rm,
};

export interface MemoryCheckpointStoreOptions {
  fortressPath: string;
  fsOps?: MemoryCheckpointFsOps;
  clock?: MemoryCheckpointClock;
}

export interface PersistMemoryCheckpointInput {
  record: MemoryCheckpointRecord;
  bundle: string;
  masterKey: Uint8Array;
}

function isErrno(err: unknown, code: string): boolean {
  return (
    err instanceof Error &&
    "code" in err &&
    (err as NodeJS.ErrnoException).code === code
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function compactCreatedAt(createdAt: string): string {
  const parsed = new Date(createdAt);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== createdAt) {
    throw new MemoryCheckpointValidationError(
      `invalid memory checkpoint created_at "${createdAt}": expected canonical ISO timestamp`,
      "invalid_created_at",
    );
  }
  return createdAt.replace(/[-:.]/g, "");
}

function first16HexOfBundleHash(bundleHash: string): string {
  const bytes = fromBase64url(bundleHash);
  const hex = Buffer.from(bytes).toString("hex");
  if (hex.length < 16) {
    throw new MemoryCheckpointValidationError(
      "invalid memory checkpoint bundle_hash: decoded hash is too short",
      "invalid_bundle_hash",
    );
  }
  return hex.slice(0, 16);
}

export function buildMemoryCheckpointId(
  createdAt: string,
  bundleHash: string,
): string {
  return `cp_${compactCreatedAt(createdAt)}_${first16HexOfBundleHash(bundleHash)}`;
}

export function assertValidMemoryCheckpointId(id: string): void {
  if (!CHECKPOINT_ID_RE.test(id)) {
    throw new MemoryCheckpointValidationError(
      `invalid memory checkpoint id "${id}"`,
      "invalid_checkpoint_id",
    );
  }
}

function checkpointAad(record: Pick<MemoryCheckpointRecord, "id" | "created_at">): Uint8Array {
  return stringToBytes(
    AAD_DOMAIN + JSON.stringify({ created_at: record.created_at, id: record.id }),
  );
}

function parseStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new MemoryCheckpointReadError(
      `malformed memory checkpoint record: ${field} must be a string array`,
      "record_malformed",
    );
  }
  return value;
}

function parsePerNamespace(value: unknown): Record<string, { content_sha256: string; item_count: number }> {
  if (!isRecord(value)) {
    throw new MemoryCheckpointReadError(
      "malformed memory checkpoint record: completeness_summary.per_namespace must be an object",
      "record_malformed",
    );
  }
  const out: Record<string, { content_sha256: string; item_count: number }> = {};
  for (const [namespace, item] of Object.entries(value)) {
    if (
      !isRecord(item) ||
      typeof item.content_sha256 !== "string" ||
      typeof item.item_count !== "number" ||
      !Number.isInteger(item.item_count) ||
      item.item_count < 0
    ) {
      throw new MemoryCheckpointReadError(
        `malformed memory checkpoint record: per_namespace entry "${namespace}" is invalid`,
        "record_malformed",
      );
    }
    out[namespace] = {
      content_sha256: item.content_sha256,
      item_count: item.item_count,
    };
  }
  return out;
}

export function parseMemoryCheckpointRecord(raw: string): MemoryCheckpointRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new MemoryCheckpointReadError(
      "malformed memory checkpoint record: record.json is not valid JSON",
      "record_corrupt",
      err,
    );
  }
  if (!isRecord(parsed)) {
    throw new MemoryCheckpointReadError(
      "malformed memory checkpoint record: record.json must be an object",
      "record_malformed",
    );
  }
  const summary = parsed.completeness_summary;
  if (
    typeof parsed.id !== "string" ||
    typeof parsed.created_at !== "string" ||
    !(
      parsed.source === "on_demand" ||
      parsed.source === "scheduled" ||
      parsed.source === "forensic_quarantine"
    ) ||
    typeof parsed.total_keys !== "number" ||
    !Number.isInteger(parsed.total_keys) ||
    parsed.total_keys < 0 ||
    typeof parsed.bundle_hash !== "string" ||
    !(parsed.retention_expires_at === null || typeof parsed.retention_expires_at === "string") ||
    parsed.format_version !== MEMORY_CHECKPOINT_FORMAT_VERSION ||
    !isRecord(summary) ||
    typeof summary.namespace_count !== "number" ||
    !Number.isInteger(summary.namespace_count) ||
    summary.namespace_count < 0 ||
    typeof summary.total_keys !== "number" ||
    !Number.isInteger(summary.total_keys) ||
    summary.total_keys < 0
  ) {
    throw new MemoryCheckpointReadError(
      "malformed memory checkpoint record: required fields are missing or invalid",
      "record_malformed",
    );
  }

  const record: MemoryCheckpointRecord = {
    id: parsed.id,
    created_at: parsed.created_at,
    source: parsed.source,
    namespaces: parseStringArray(parsed.namespaces, "namespaces"),
    total_keys: parsed.total_keys,
    bundle_hash: parsed.bundle_hash,
    completeness_summary: {
      namespace_count: summary.namespace_count,
      total_keys: summary.total_keys,
      per_namespace: parsePerNamespace(summary.per_namespace),
    },
    retention_expires_at: parsed.retention_expires_at,
    format_version: parsed.format_version,
  };
  assertValidMemoryCheckpointId(record.id);
  const expectedId = buildMemoryCheckpointId(record.created_at, record.bundle_hash);
  if (record.id !== expectedId) {
    throw new MemoryCheckpointReadError(
      `malformed memory checkpoint record: id does not match created_at and bundle_hash (expected ${expectedId})`,
      "record_id_mismatch",
    );
  }
  return record;
}

export class MemoryCheckpointStore {
  private readonly fortressPath: string;
  private readonly fsOps: MemoryCheckpointFsOps;
  private readonly clock: MemoryCheckpointClock;

  constructor(options: MemoryCheckpointStoreOptions) {
    this.fortressPath = options.fortressPath;
    this.fsOps = options.fsOps ?? nodeMemoryCheckpointFsOps;
    this.clock = options.clock ?? systemMemoryCheckpointClock;
  }

  now(): Date {
    return new Date(this.clock.now().getTime());
  }

  private checkpointsDir(): string {
    return join(this.fortressPath, "checkpoints");
  }

  private checkpointDir(id: string): string {
    assertValidMemoryCheckpointId(id);
    return join(this.checkpointsDir(), id);
  }

  async create(input: PersistMemoryCheckpointInput): Promise<MemoryCheckpointRecord> {
    const expectedId = buildMemoryCheckpointId(
      input.record.created_at,
      input.record.bundle_hash,
    );
    if (input.record.id !== expectedId) {
      throw new MemoryCheckpointValidationError(
        `memory checkpoint record id mismatch: expected ${expectedId}, got ${input.record.id}`,
        "record_id_mismatch",
      );
    }
    assertValidMemoryCheckpointId(input.record.id);

    let encrypted: EncryptedPayload;
    try {
      encrypted = encrypt(
        stringToBytes(input.bundle),
        derivePurposeKey(input.masterKey, MEMORY_CHECKPOINT_PURPOSE),
        checkpointAad(input.record),
      );
    } catch (err) {
      throw new MemoryCheckpointEncryptionError(
        `memory checkpoint encryption failed: ${err instanceof Error ? err.message : String(err)}`,
        "encrypt_failed",
        err,
      );
    }

    const baseDir = this.checkpointsDir();
    const finalDir = this.checkpointDir(input.record.id);
    const tempDir = join(
      baseDir,
      `.tmp-${input.record.id}-${process.pid}-${randomBytes(6).toString("hex")}`,
    );

    try {
      await this.fsOps.mkdir(baseDir, { recursive: true, mode: 0o700 });
      await this.fsOps.mkdir(tempDir, { recursive: false, mode: 0o700 });
      await this.fsOps.writeFile(
        join(tempDir, "bundle.enc"),
        `${JSON.stringify(encrypted)}\n`,
        { mode: 0o600 },
      );
      await this.fsOps.writeFile(
        join(tempDir, "record.json"),
        `${JSON.stringify(input.record, null, 2)}\n`,
        { mode: 0o600 },
      );
      await this.fsOps.rename(tempDir, finalDir);
      return input.record;
    } catch (err) {
      let cleanupDetail = "";
      try {
        await this.fsOps.rm(tempDir, { recursive: true, force: true });
      } catch (cleanupErr) {
        cleanupDetail = `; temp cleanup also failed: ${
          cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr)
        }`;
      }
      throw new MemoryCheckpointPersistenceError(
        `memory checkpoint create failed while writing ${input.record.id}: ${
          err instanceof Error ? err.message : String(err)
        }${cleanupDetail}`,
        "write_failed",
        err,
      );
    }
  }

  async list(): Promise<MemoryCheckpointRecord[]> {
    let entries: MemoryCheckpointDirent[];
    try {
      entries = await this.fsOps.readdir(this.checkpointsDir());
    } catch (err) {
      if (isErrno(err, "ENOENT")) return [];
      throw new MemoryCheckpointReadError(
        `memory checkpoint list failed: ${err instanceof Error ? err.message : String(err)}`,
        "list_failed",
        err,
      );
    }

    const records: MemoryCheckpointRecord[] = [];
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith(".tmp-")) continue;
      const record = await this.get(entry.name);
      if (record) records.push(record);
    }
    return records.sort((a, b) =>
      b.created_at.localeCompare(a.created_at) || b.id.localeCompare(a.id)
    );
  }

  async get(id: string): Promise<MemoryCheckpointRecord | null> {
    const dir = this.checkpointDir(id);
    let raw: Uint8Array;
    try {
      raw = await this.fsOps.readFile(join(dir, "record.json"));
    } catch (err) {
      if (isErrno(err, "ENOENT")) return null;
      throw new MemoryCheckpointReadError(
        `memory checkpoint read failed for ${id}: ${err instanceof Error ? err.message : String(err)}`,
        "record_read_failed",
        err,
      );
    }
    return parseMemoryCheckpointRecord(bytesToString(raw));
  }

  async delete(id: string): Promise<boolean> {
    const dir = this.checkpointDir(id);
    try {
      await this.fsOps.rm(dir, { recursive: true, force: false });
      return true;
    } catch (err) {
      if (isErrno(err, "ENOENT")) return false;
      throw new MemoryCheckpointDeleteError(
        `memory checkpoint delete failed for ${id}: ${err instanceof Error ? err.message : String(err)}`,
        "delete_failed",
        err,
      );
    }
  }

  async readBundle(id: string, masterKey: Uint8Array): Promise<string> {
    const record = await this.get(id);
    if (!record) {
      throw new MemoryCheckpointReadError(
        `memory checkpoint bundle read failed for ${id}: checkpoint not found`,
        "checkpoint_not_found",
      );
    }

    let payload: EncryptedPayload;
    try {
      const raw = await this.fsOps.readFile(join(this.checkpointDir(id), "bundle.enc"));
      payload = JSON.parse(bytesToString(raw)) as EncryptedPayload;
    } catch (err) {
      throw new MemoryCheckpointReadError(
        `memory checkpoint bundle read failed for ${id}: ${
          err instanceof Error ? err.message : String(err)
        }`,
        "bundle_read_failed",
        err,
      );
    }

    try {
      return bytesToString(
        decrypt(
          payload,
          derivePurposeKey(masterKey, MEMORY_CHECKPOINT_PURPOSE),
          checkpointAad(record),
        ),
      );
    } catch (err) {
      throw new MemoryCheckpointReadError(
        `memory checkpoint bundle decrypt failed for ${id}: ${
          err instanceof Error ? err.message : String(err)
        }`,
        "decrypt_failed",
        err,
      );
    }
  }
}
