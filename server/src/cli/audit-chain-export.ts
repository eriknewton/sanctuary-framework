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
import type { PersistedAuditEnvelopeV2 } from "../operational/audit-log.js";
// G1 (post-#969 sweep re-gate): the checkpoint shape predicate and the
// control-key allowlist are imported from the PURE, dependency-free
// `audit/checkpoint-shape.ts` shared with the runtime audit log. This
// module's no-server-runtime-imports posture survives (the shared module
// imports nothing), and the hand-duplicated validator that had drifted
// WEAKER than the runtime's (letting a record missing schema_version /
// signature_algorithm / payload_encoding export uncounted) is gone.
import {
  AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS,
  isAuditCheckpointRecord,
  isAuditRotationAnchorEnvelope,
} from "../audit/checkpoint-shape.js";
import { lockdownBanner, readLockdownStatus } from "../lockdown/status.js";
import { homeFortressPath } from "../paths.js";
import { flagValue } from "./argv.js";

export const AUDIT_EXPORT_NAMESPACE = "_audit";
export const AUDIT_EXPORT_CHECKPOINT_NAMESPACE = "_audit_checkpoints";
// F2 HIGH-1 (adversarial gate 2026-07-14): the root Castle Wall daemon's own
// audit chain. Its presence means an `_audit`-only export is INCOMPLETE. These
// literals byte-match `operational/audit-store-split.ts`; duplicated here
// because this raw exporter deliberately avoids server-runtime imports.
export const AUDIT_EXPORT_DAEMON_NAMESPACE = "_audit-daemon";
// F2 HIGH-R3 (adversarial re-gate 2026-07-14): the durable `_meta`
// migration-established marker (byte-matches audit-log.ts). Its presence proves
// the writer-split migration ran, so an `_audit`-only export is INCOMPLETE even
// if the `_audit-daemon` directory itself was deleted/renamed. Unauthenticated
// presence is sufficient here (this raw exporter has no master key): erring
// toward "present" only over-requires --operator-only, which is fail-closed.
export const AUDIT_EXPORT_SPLIT_ESTABLISHED_META_KEY =
  "audit-store-split-established-v1";
// F-2 (dry-bar sweep 2026-07-27): the CLOSED allowlist of legitimate
// NON-EXPORT control records that live in `_audit_checkpoints` under fixed
// keys. Only a record under one of THESE keys may be skipped without
// counting: the P1-A fix's shape-based "not a recognized checkpoint, so a
// control record" arm could not discriminate a control record from a
// checkpoint-keyed record failing strict validation, so a
// parse-valid-but-malformed checkpoint vanished from the export with
// `checkpointsSkipped` still 0 and the evidence pack signed the export as
// complete or empty. G1/G5: the list is now DEFINED in the shared pure
// `audit/checkpoint-shape.ts` (one sync mechanism with the audit log's own
// key constants, no duplicated literals); this alias keeps the exporter's
// public name stable.
export const AUDIT_EXPORT_CONTROL_KEYS: readonly string[] =
  AUDIT_CHECKPOINT_NAMESPACE_CONTROL_KEYS;

/** Record types in a JSONL export file. */
export type ExportRecord =
  | EntryExportRecord
  | CheckpointExportRecord
  | LegacyAnchorExportRecord
  | RotationAnchorExportRecord;

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

export interface RotationAnchorExportRecord {
  type: "rotation_anchor";
  base_sequence: number;
  base_prev_hash: string;
  /**
   * Re-gate round 3: the anchor's master-key MAC (canonical 43-char unpadded
   * base64url of the 32-byte HMAC-SHA256), carried
   * so a verifier that DOES hold the custody key (the fortress runtime, or a
   * future audited-verify mode) can check anchor authenticity. Including it
   * leaks nothing: an HMAC-SHA256 output over data already present in this
   * export is a PRF output, computationally independent of the key, and is
   * useless to anyone without that key. The standalone offline verifier does
   * NOT verify it (it has no key) and says so in its report.
   */
  mac: string;
}

/**
 * P1-A (dry-bar round 6): the outcome of an audit-chain export, so a caller can
 * tell a GENUINELY-EMPTY chain ("listed 0 records") apart from a CORRUPT one
 * ("listed N, exported < N; the remainder were unreadable / invalid JSON / not a
 * V2 envelope and were SKIPPED"). Without this, an all-skipped chain produced
 * zero bytes and rendered as a DEFINITIVE "the audit-chain export was empty" — a
 * corrupt chain presented as a clean one, the opposite of the tamper-evidence
 * the export exists to provide — and a partly-corrupt chain was signed as
 * silently-complete. A nonzero `*Skipped` count means the export is INCOMPLETE
 * and must NOT be presented as complete or definitively empty.
 */
export interface AuditChainExportSummary {
  /** Entry records listed in the `_audit` namespace. */
  entriesListed: number;
  /** Entry records successfully written to the export. */
  entriesExported: number;
  /**
   * Entry records LISTED but not exported: unreadable at read time, invalid
   * JSON, or not a V2 audit envelope (corruption / tamper / wrong schema).
   */
  entriesSkipped: number;
  /** Checkpoint/anchor records listed in `_audit_checkpoints`. */
  checkpointsListed: number;
  /** Checkpoint/anchor records successfully written to the export. */
  checkpointsExported: number;
  /**
   * Checkpoint/anchor records LISTED but skipped as GENUINE CORRUPTION:
   * unreadable at read time, invalid JSON, or (F-2) parse-valid under a
   * checkpoint/anchor or unrecognized key while failing strict validation.
   * Records under the CLOSED control-key allowlist
   * ({@link AUDIT_EXPORT_CONTROL_KEYS}, e.g. the `__head_anchor` head pointer)
   * are legitimate non-export control records and are NOT counted here.
   */
  checkpointsSkipped: number;
}

/** Total records listed but skipped (a nonzero total means an INCOMPLETE export). */
export function totalRecordsSkipped(s: AuditChainExportSummary): number {
  return s.entriesSkipped + s.checkpointsSkipped;
}

/**
 * Export an audit chain from a StorageBackend to a Writable stream.
 *
 * Entries are written in sequence order, followed by checkpoints.
 * Each line is a JSON object terminated with a newline (JSONL format).
 *
 * This function is intentionally separated from CLI arg parsing so the
 * drill test can call it directly with a MemoryStorage backend.
 *
 * Returns a {@link AuditChainExportSummary} counting listed/exported/skipped
 * records so a caller never presents a corrupt (all-skipped) chain as empty, or
 * a partly-corrupt chain as complete (P1-A).
 */
export async function exportAuditChain(
  storage: StorageBackend,
  out: Writable
): Promise<AuditChainExportSummary> {
  // Export entries, sorted by key (keys are sequence-padded for natural sort)
  const entryMetas = await storage.list(AUDIT_EXPORT_NAMESPACE);
  entryMetas.sort((a, b) => a.key.localeCompare(b.key));

  let entriesExported = 0;
  let entriesSkipped = 0;
  for (const meta of entryMetas) {
    const raw = await storage.read(AUDIT_EXPORT_NAMESPACE, meta.key);
    if (!raw) {
      entriesSkipped++;
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      entriesSkipped++;
      continue;
    }
    if (!isPersistedAuditEnvelopeV2(parsed)) {
      entriesSkipped++;
      continue;
    }

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
    entriesExported++;
  }

  // Export checkpoints and legacy anchors
  const cpMetas = await storage.list(AUDIT_EXPORT_CHECKPOINT_NAMESPACE);
  cpMetas.sort((a, b) => a.key.localeCompare(b.key));

  let checkpointsExported = 0;
  let checkpointsSkipped = 0;
  for (const meta of cpMetas) {
    const raw = await storage.read(AUDIT_EXPORT_CHECKPOINT_NAMESPACE, meta.key);
    if (!raw) {
      checkpointsSkipped++;
      continue;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytesToString(raw));
    } catch {
      checkpointsSkipped++;
      continue;
    }
    // Re-gate round 3: the SHARED rotation-anchor shape predicate (marker +
    // data + a canonical 43-char base64url mac, the only strings the legitimate
    // writer can emit). The old local guard accepted marker + data with
    // NO mac requirement, which was NOT inclusion-safe: the standalone
    // verifier checks anchor linkage only, so a forged mac-less anchor
    // consistent with a truncated suffix exported unskipped and could PASS
    // external verification while the runtime rejected it. A `__rotation_anchor`
    // record failing this shape now falls through to the counted-skip arm
    // below (it is not a control key), forcing the pack's read_failed.
    if (isAuditRotationAnchorEnvelope(parsed)) {
      const record: RotationAnchorExportRecord = {
        type: "rotation_anchor",
        base_sequence: parsed.data.base_sequence,
        base_prev_hash: parsed.data.base_prev_hash,
        mac: parsed.mac,
      };
      out.write(JSON.stringify(record) + "\n");
      checkpointsExported++;
      continue;
    }
    if (!isAuditCheckpointRecord(parsed)) {
      // F-2 (dry-bar sweep 2026-07-27): the skip is KEY-AWARE. A record under a
      // key on the CLOSED control allowlist (`__head_anchor`,
      // `__custody_epoch_keys`) is a legitimate NON-EXPORT control record, NOT
      // corruption; it is skipped uncounted so a healthy fortress never
      // false-positives a `read_failed` (the P1-A fix, which this preserves).
      // Any OTHER key whose record parses but fails strict validation is a
      // malformed checkpoint/anchor (writer schema drift, corruption, or a
      // foreign blob) and MUST be counted: the P1-A shape-only arm could not
      // tell the two apart, so a parse-valid-but-malformed checkpoint vanished
      // from the export while `checkpointsSkipped` stayed 0 and the evidence
      // pack signed the export as complete or definitively empty.
      if (AUDIT_EXPORT_CONTROL_KEYS.includes(meta.key)) {
        continue;
      }
      checkpointsSkipped++;
      continue;
    }

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
      checkpointsExported++;
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
      checkpointsExported++;
    }
  }

  return {
    entriesListed: entryMetas.length,
    entriesExported,
    entriesSkipped,
    checkpointsListed: cpMetas.length,
    checkpointsExported,
    checkpointsSkipped,
  };
}

/** CLI args for the export subcommand. */
export interface ExportArgs {
  output?: string;
  storagePath?: string;
  fortressPath?: string;
  /** F2 HIGH-1: explicitly acknowledge an operator-chain-only export on a
   * fortress that has a daemon chain. Without it, the export fails closed
   * rather than silently omitting the daemon chain. */
  operatorOnly?: boolean;
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
  const operatorOnly = argv.includes("--operator-only");
  return { output, storagePath, fortressPath, operatorOnly, argv, env };
}

/**
 * F2 HIGH-1 + HIGH-R3: return true iff the fortress ran the writer-split
 * migration, so an `_audit`-only export is INCOMPLETE. True when the
 * `_audit-daemon` namespace holds an entry, OR its directory exists but is
 * unreadable, OR (HIGH-R3) the durable `_meta` migration-established marker is
 * present even though the daemon directory was deleted/renamed. Fail closed: any
 * listing error is treated as "present" so an operator-only export never
 * silently hides a daemon chain.
 */
/** HIGH-R3: public boundary/migration-aware presence probe, reused by `doctor`
 * so its single-chain audit check refuses to report OK on a migrated fortress.
 * Unauthenticated (no master key): fail-closed toward "present". */
export async function fortressRanAuditStoreSplitMigration(
  storage: StorageBackend
): Promise<boolean> {
  return daemonAuditChainPresent(storage);
}

async function daemonAuditChainPresent(
  storage: StorageBackend
): Promise<boolean> {
  try {
    if ((await storage.list(AUDIT_EXPORT_DAEMON_NAMESPACE)).length > 0) return true;
  } catch {
    return true;
  }
  // HIGH-R3: the daemon namespace can be deleted; the `_meta` established marker
  // is not co-deletable with it and still proves the export would be incomplete.
  try {
    if (await storage.exists("_meta", AUDIT_EXPORT_SPLIT_ESTABLISHED_META_KEY)) {
      return true;
    }
  } catch {
    return true;
  }
  return false;
}

export async function runExport(args: ExportArgs): Promise<void> {
  const fortressPath =
    args.fortressPath ??
    process.env.SANCTUARY_FORTRESS_PATH ??
    process.env.SANCTUARY_STORAGE_PATH ??
    homeFortressPath();
  const storagePath = args.storagePath ?? resolveAuditStoragePath(fortressPath);

  const { FilesystemStorage } = await import("../storage/filesystem.js");
  const storage = new FilesystemStorage(storagePath);
  const banner = lockdownBanner(await readLockdownStatus(storagePath));
  if (banner) process.stderr.write(banner);

  // F2 HIGH-1 (adversarial gate 2026-07-14): this raw exporter dumps the
  // operator `_audit` chain only. After the writer-split, the root daemon's
  // enforcement evidence lives in `_audit-daemon`, so an unqualified export on
  // a migrated fortress would be silently INCOMPLETE. Fail closed: refuse
  // unless the operator explicitly acknowledges an operator-only export with
  // `--operator-only`. (Exporting both chains + the boundary record is a
  // deferred follow-up; the verifier assumes one sequence from genesis.)
  if (!args.operatorOnly && (await daemonAuditChainPresent(storage))) {
    throw new Error(
      "This fortress has a root daemon audit chain (_audit-daemon), so an " +
        "'_audit'-only export would be INCOMPLETE (it omits the daemon's " +
        "enforcement evidence). Re-run with --operator-only to export just the " +
        "operator chain (and note the omission), or export the daemon chain " +
        "separately. Exporting both chains in one file is not yet supported.",
    );
  }
  if (args.operatorOnly && (await daemonAuditChainPresent(storage))) {
    process.stderr.write(
      "NOTE: --operator-only export. The root daemon audit chain (_audit-daemon) " +
        "exists and is NOT included in this file; this export is operator-chain-only.\n",
    );
  }

  if (args.output) {
    const stream = createWriteStream(args.output, { encoding: "utf8" });
    const summary = await exportAuditChain(storage, stream);
    await new Promise<void>((resolve, reject) => {
      stream.end(() => resolve());
      stream.on("error", reject);
    });
    process.stderr.write(`Exported audit chain to ${args.output}\n`);
    writeSkipNoteIfIncomplete(summary);
  } else {
    const summary = await exportAuditChain(storage, process.stdout);
    writeSkipNoteIfIncomplete(summary);
  }
}

/**
 * P1-A: make a silently-incomplete export LOUD on the CLI. When any listed
 * record was unreadable / corrupt / non-V2 it was skipped, so the export is NOT
 * a complete chain; disclose that on stderr rather than presenting a truncated
 * file as the whole audit history.
 */
function writeSkipNoteIfIncomplete(summary: AuditChainExportSummary): void {
  const skipped = totalRecordsSkipped(summary);
  if (skipped === 0) return;
  process.stderr.write(
    `WARNING: this export is INCOMPLETE. ${skipped} listed record(s) were ` +
      `unreadable, invalid JSON, or not a recognized audit record and were ` +
      `SKIPPED (entries: listed ${summary.entriesListed}, exported ` +
      `${summary.entriesExported}, skipped ${summary.entriesSkipped}; ` +
      `checkpoints: listed ${summary.checkpointsListed}, exported ` +
      `${summary.checkpointsExported}, skipped ${summary.checkpointsSkipped}). ` +
      `The exported chain does NOT contain the skipped records; do NOT treat ` +
      `this file as a complete audit chain.\n`
  );
}

export function resolveAuditStoragePath(path: string): string {
  return basename(path) === "state" ? path : join(path, "state");
}

// --- Type guards ---
//
// G1 + re-gate round 3: `isAuditCheckpointRecord` AND
// `isAuditRotationAnchorEnvelope` are IMPORTED from the shared pure
// `audit/checkpoint-shape.ts` (see the import block); both local duplicates
// had drifted weaker than the runtime's and are deleted. The round-2 claim
// that looser-guard drift here "errs toward inclusion and is therefore safe"
// was adjudicated TRUE for the envelope guard ONLY: the standalone verifier
// recomputes every entry hash, so an entry accepted loosely still fails
// downstream verification. It was FALSE for the rotation anchor: the
// verifier checks anchor LINKAGE only (it cannot check the custody-keyed
// MAC), so a loosely-accepted forged anchor could pass external verification
// end to end. The one guard below stays a local duplicate (this exporter
// must not import the server runtime), and it is in the hash-recomputed,
// inclusion-safe class.

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

// isRotationAnchorRecord deleted (re-gate round 3): replaced by the shared
// `isAuditRotationAnchorEnvelope` from `audit/checkpoint-shape.ts`, which
// additionally requires `mac` to be a canonical 43-char base64url encoding
// of the 32-byte MAC, the only strings the legitimate writer can emit.
