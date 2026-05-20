/**
 * sanctuary audit-chain export
 *
 * Dumps the audit chain to a JSONL file or stdout.
 *
 * Does not require the master passphrase - reads raw envelope bytes from
 * storage, which are stored as plaintext JSON wrappers around the encrypted
 * payload. The encrypted_payload_bytes field remains encrypted; the
 * structural chain metadata (sequence, prev_hash, entry_hash) is readable
 * without a key, which is what the external verifier needs.
 *
 * Usage:
 *   sanctuary audit-chain export [--output <path>] [--storage-path <path>]
 *   sanctuary audit-chain export --output chain.jsonl
 */

import { createWriteStream } from "node:fs";
import { Writable } from "node:stream";
import { basename, join } from "node:path";
import type { StorageBackend } from "../storage/interface.js";
import { bytesToString } from "../core/encoding.js";
import type { PersistedAuditEnvelopeV2 } from "../l2-operational/audit-log.js";
import type { AuditCheckpointRecord } from "../audit/chain.js";

export const AUDIT_EXPORT_NAMESPACE = "_audit";
export const AUDIT_EXPORT_CHECKPOINT_NAMESPACE = "_audit_checkpoints";

/** Record types in a JSONL export file. */
export type ExportRecord = EntryExportRecord | CheckpointExportRecord | LegacyAnchorExportRecord;

export interface EntryExportRecord {
  type: "entry";
  seq: number;
  schema_version: number;
  prev_hash: string;
  entry_hash: string;
  timestamp: string;
  /** Base64url-encoded encrypted payload bytes. Sufficient to recompute entry_hash. */
  encrypted_payload_bytes: string;
}

export interface CheckpointExportRecord {
  type: "checkpoint";
  checkpoint_kind: "audit-checkpoint";
  checkpoint_sequence: number;
  from_sequence: number;
  root_hash: string;
  previous_checkpoint_sequence: number;
  signed_at: string;
  signer_kid: string | null;
  signature: string | null;
  public_key?: string;
  unsigned: boolean;
}

export interface LegacyAnchorExportRecord {
  type: "legacy_anchor";
  checkpoint_sequence: number;
  from_sequence: number;
  root_hash: string;
  previous_checkpoint_sequence: number;
  signed_at: string;
  signer_kid: string | null;
  signature: string | null;
  public_key?: string;
  unsigned: boolean;
}

/**
 * Export an audit chain from a StorageBackend to a Writable stream.
 *
 * Entries are written in sequence order, followed by checkpoints.
 * Each line is a JSON object terminated with a newline (JSONL format).
 *
 * This function is intentionally separated from CLI arg parsing so the
 * drill test can call it directly with a MemoryStorage backend.
 */
export async function exportAuditChain(
  storage: StorageBackend,
  out: Writable
): Promise<void> {
  // Export entries, sorted by key (keys are sequence-padded for natural sort)
  const entryMetas = await storage.list(AUDIT_EXPORT_NAMESPACE);
  entryMetas.sort((a, b) => a.key.localeCompare(b.key));

  for (const meta of entryMetas) {
    const raw = await storage.read(AUDIT_EXPORT_NAMESPACE, meta.key);
    if (!raw) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      continue;
    }
    if (!isPersistedAuditEnvelopeV2(parsed)) continue;

    const record: EntryExportRecord = {
      type: "entry",
      seq: parsed.sequence,
      schema_version: parsed.schema_version,
      prev_hash: parsed.prev_hash,
      entry_hash: parsed.entry_hash,
      timestamp: parsed.timestamp,
      encrypted_payload_bytes: parsed.encrypted_payload_bytes,
    };
    out.write(JSON.stringify(record) + "\n");
  }

  // Export checkpoints and legacy anchors
  const cpMetas = await storage.list(AUDIT_EXPORT_CHECKPOINT_NAMESPACE);
  cpMetas.sort((a, b) => a.key.localeCompare(b.key));

  for (const meta of cpMetas) {
    const raw = await storage.read(AUDIT_EXPORT_CHECKPOINT_NAMESPACE, meta.key);
    if (!raw) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      continue;
    }
    if (!isAuditCheckpointRecord(parsed)) continue;

    if (parsed.checkpoint_kind === "audit-checkpoint") {
      const record: CheckpointExportRecord = {
        type: "checkpoint",
        checkpoint_kind: "audit-checkpoint",
        checkpoint_sequence: parsed.checkpoint_sequence,
        from_sequence: parsed.from_sequence,
        root_hash: parsed.root_hash,
        previous_checkpoint_sequence: parsed.previous_checkpoint_sequence,
        signed_at: parsed.signed_at,
        signer_kid: parsed.signer_kid,
        signature: parsed.signature,
        ...(parsed.public_key != null ? { public_key: parsed.public_key } : {}),
        unsigned: parsed.unsigned,
      };
      out.write(JSON.stringify(record) + "\n");
    } else if (parsed.checkpoint_kind === "legacy-anchor") {
      const record: LegacyAnchorExportRecord = {
        type: "legacy_anchor",
        checkpoint_sequence: parsed.checkpoint_sequence,
        from_sequence: parsed.from_sequence,
        root_hash: parsed.root_hash,
        previous_checkpoint_sequence: parsed.previous_checkpoint_sequence,
        signed_at: parsed.signed_at,
        signer_kid: parsed.signer_kid,
        signature: parsed.signature,
        ...(parsed.public_key != null ? { public_key: parsed.public_key } : {}),
        unsigned: parsed.unsigned,
      };
      out.write(JSON.stringify(record) + "\n");
    }
  }
}

/** CLI args for the export subcommand. */
export interface ExportArgs {
  output?: string;
  storagePath?: string;
  fortressPath?: string;
  argv: string[];
  env?: NodeJS.ProcessEnv;
}

export function parseExportArgs(argv: string[], env?: NodeJS.ProcessEnv): ExportArgs {
  const output = flagValue(argv, "--output") ?? flagValue(argv, "-o");
  const fortressPath =
    flagValue(argv, "--fortress") ??
    flagValue(argv, "--fortress-path") ??
    env?.SANCTUARY_STORAGE_PATH ??
    env?.SANCTUARY_FORTRESS_PATH;
  const storagePath = flagValue(argv, "--storage-path");
  return { output, storagePath, fortressPath, argv, env };
}

export async function runExport(args: ExportArgs): Promise<void> {
  const { default: os } = await import("node:os");

  const fortressPath =
    args.fortressPath ??
    process.env.SANCTUARY_FORTRESS_PATH ??
    process.env.SANCTUARY_STORAGE_PATH ??
    join(os.homedir(), ".sanctuary");
  const storagePath = args.storagePath ?? resolveAuditStoragePath(fortressPath);

  const { FilesystemStorage } = await import("../storage/filesystem.js");
  const storage = new FilesystemStorage(storagePath);

  if (args.output) {
    const stream = createWriteStream(args.output, { encoding: "utf8" });
    await exportAuditChain(storage, stream);
    await new Promise<void>((resolve, reject) => {
      stream.end(() => resolve());
      stream.on("error", reject);
    });
    process.stderr.write(`Exported audit chain to ${args.output}\n`);
  } else {
    await exportAuditChain(storage, process.stdout);
  }
}

export function resolveAuditStoragePath(path: string): string {
  return basename(path) === "state" ? path : join(path, "state");
}

// --- Type guards (duplicated from audit-log.ts to avoid server-runtime imports) ---

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isPersistedAuditEnvelopeV2(value: unknown): value is PersistedAuditEnvelopeV2 {
  return (
    isRecord(value) &&
    value.schema_version === 2 &&
    typeof value.sequence === "number" &&
    Number.isSafeInteger(value.sequence) &&
    value.sequence > 0 &&
    typeof value.prev_hash === "string" &&
    typeof value.entry_hash === "string" &&
    typeof value.timestamp === "string" &&
    typeof value.encrypted_payload_bytes === "string"
  );
}

function isAuditCheckpointRecord(value: unknown): value is AuditCheckpointRecord {
  return (
    isRecord(value) &&
    (value.checkpoint_kind === "audit-checkpoint" ||
      value.checkpoint_kind === "legacy-anchor") &&
    typeof value.checkpoint_sequence === "number" &&
    Number.isSafeInteger(value.checkpoint_sequence) &&
    typeof value.from_sequence === "number" &&
    Number.isSafeInteger(value.from_sequence) &&
    typeof value.root_hash === "string" &&
    typeof value.previous_checkpoint_sequence === "number" &&
    Number.isSafeInteger(value.previous_checkpoint_sequence) &&
    typeof value.signed_at === "string" &&
    (typeof value.signer_kid === "string" || value.signer_kid === null) &&
    (typeof value.signature === "string" || value.signature === null) &&
    typeof value.unsigned === "boolean"
  );
}

function flagValue(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}
