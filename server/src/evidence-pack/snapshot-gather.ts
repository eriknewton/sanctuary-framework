/** Typed read outcomes shared with the legacy gather without interpreting its prose. */
import { Writable } from "node:stream";
import { basename, join } from "node:path";
import type { FilesystemStorage } from "../storage/filesystem.js";
import type { StorageBackend } from "../storage/interface.js";
import { readFileCustodyWithStats } from "../storage/custody-fs.js";
import { fortressRanAuditStoreSplitMigration, exportAuditChain, totalRecordsSkipped, type AuditChainExportSummary } from "../cli/audit-chain-export.js";
import { daemonMigrationEstablished } from "../operational/audit-store-split.js";
import { readPersistedCheckpoints } from "../transparency/emitter.js";
import { TRANSPARENCY_BUNDLE_FORMAT, type TransparencyBundle } from "../transparency/checkpoint.js";
import { CASTLE_GLOBAL_PINNED_PUBKEY_PATH } from "../transparency/signer.js";
import { verifyTransparencyCheckpoints, checkpointPayloadHash } from "../transparency/verify.js";
import { auditExtent } from "./snapshot-nested.js";
import * as C from "./snapshot-contract.js";
export type GatherFailure = Exclude<typeof C.ABSENT_REASONS[number], "no_records">;
export type GatherRead<T> = { state: "included"; value: T } | { state: "empty_verified"; reason: "no_records" } | { state: "read_failed"; reason: GatherFailure; cause?: unknown; summary?: AuditChainExportSummary };
const empty = { state: C.COMPONENT.empty_verified, reason: "no_records" } as const;
export async function gatherAuditExport(storage: FilesystemStorage, masterKey: Uint8Array, maximumBytes = Number.POSITIVE_INFINITY): Promise<GatherRead<string>> {
  try {
    // Both split probes prevent an operator-only chain from being presented as the complete gathered chain.
    if (await fortressRanAuditStoreSplitMigration(storage) || await daemonMigrationEstablished(storage, masterKey)) return { state: C.COMPONENT.read_failed, reason: "split_store" };
    const chunks: Buffer[] = []; let size = 0; let oversized = false;
    // The legacy writer ignores backpressure, so record overflow without emitting an unhandled stream error.
    const sink = new Writable({ write(chunk, _encoding, done) { if (!oversized) { size += chunk.length; oversized = size > maximumBytes; if (!oversized) chunks.push(Buffer.from(chunk)); } done(); } });
    const summary = await exportAuditChain(storage, sink);
    // The v0 reason vocabulary maps size overflow to read_error rather than signing an incomplete audit chain.
    C.requireSnapshot(!oversized, C.HARD.limit_exceeded);
    // Skipped records make the read incomplete even when the exporter produced zero bytes.
    if (totalRecordsSkipped(summary) > 0) return { state: C.COMPONENT.read_failed, reason: "invalid_records", summary };
    const value = Buffer.concat(chunks).toString("utf8");
    return value.length ? { state: C.COMPONENT.included, value } : empty;
  } catch (cause) { return { state: C.COMPONENT.read_failed, reason: "read_error", cause }; }
}
export async function gatherTransparencyExport(storage: StorageBackend, generatedAt: string): Promise<GatherRead<TransparencyBundle>> {
  try {
    const checkpoints = await readPersistedCheckpoints(storage);
    if (!checkpoints.length) return empty;
    const keys = new Set(checkpoints.map(c => c.public_key));
    if (keys.size !== 1) return { state: C.COMPONENT.read_failed, reason: "mixed_keys" };
    return { state: C.COMPONENT.included, value: { format: TRANSPARENCY_BUNDLE_FORMAT, exported_at: generatedAt, public_key: [...keys][0], checkpoints } };
  } catch (cause) { return { state: C.COMPONENT.read_failed, reason: "read_error", cause }; }
}
export interface CastlePin { key: string; pathClass: "global" | "fortress-local" }
export async function resolveSnapshotTransparencyPin(fortress: string, localSign: boolean, globalPath = CASTLE_GLOBAL_PINNED_PUBKEY_PATH): Promise<CastlePin> {
  // An existing global pin is authoritative, so invalid custody never falls back to a local key.
  try {
    const pin = await readFileCustodyWithStats(globalPath, { uid: 0, mode: { rejectGroupOrOtherWrite: true }, parent: { uid: 0, mode: { rejectGroupOrOtherWrite: true } }, maxBytes: C.KEY_BYTES, verifyPathIdentity: true });
    const key = pin.data.toString("base64url"); C.publicKey(key);
    return { key, pathClass: "global" };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  C.requireSnapshot(localSign, C.HARD.pin_invalid);
  // Both pin locations use the signer module's canonical public pin basename.
  const pin = await readFileCustodyWithStats(join(fortress, basename(CASTLE_GLOBAL_PINNED_PUBKEY_PATH)), { uid: process.getuid?.(), mode: { rejectGroupOrOtherWrite: true }, parent: { uid: process.getuid?.(), mode: { rejectGroupOrOtherWrite: true } }, maxBytes: C.KEY_BYTES, verifyPathIdentity: true });
  const key = pin.data.toString("base64url"); C.publicKey(key);
  return { key, pathClass: "fortress-local" };
}
export interface SnapshotGather {
  audit: C.Component<C.AuditExtent>;
  transparency: C.Component<C.TransparencyExtent>;
  auditBytes?: Uint8Array;
  transparencyBytes?: Uint8Array;
  transparencyPin?: CastlePin;
}
export async function gatherSnapshot(input: { storage: FilesystemStorage; masterKey: Uint8Array; fortress: string; generatedAt: string; localSign: boolean; globalPinPath?: string }): Promise<SnapshotGather> {
  const a = await gatherAuditExport(input.storage, input.masterKey, C.MAX_FILE_BYTES);
  const t = await gatherTransparencyExport(input.storage, input.generatedAt);
  const auditBytes = a.state === C.COMPONENT.included ? C.utf8(a.value) : undefined;
  const audit: C.Component<C.AuditExtent> = auditBytes ? { state: C.COMPONENT.included, filename: C.AUDIT_FILENAME, extent: auditExtent(C.parseAuditRecords(auditBytes)) } : { state: a.state, reason: "reason" in a ? a.reason : "read_error" } as C.Component<C.AuditExtent>;
  const result: SnapshotGather = { audit, auditBytes, transparency: empty };
  if (t.state !== C.COMPONENT.included) { result.transparency = { state: t.state, reason: t.reason } as C.Component<C.TransparencyExtent>; return result; }
  let pin: CastlePin;
  try { pin = await resolveSnapshotTransparencyPin(input.fortress, input.localSign, input.globalPinPath); }
  catch { result.transparency = { state: C.COMPONENT.read_failed, reason: "pin_unavailable" }; return result; }
  // A self-consistent bundle cannot choose its own authority instead of the authenticated Castle pin.
  if (t.value.public_key !== pin.key || t.value.checkpoints.some(c => c.public_key !== pin.key)) { result.transparency = { state: C.COMPONENT.read_failed, reason: "key_mismatch" }; return result; }
  const bytes = C.utf8(JSON.stringify(t.value, null, 2) + C.LF);
  const parsed = C.parseTransparency(bytes);
  const checked = verifyTransparencyCheckpoints(parsed, { publicKey: pin.key, trustEmbedded: false, allowPartial: true });
  C.requireSnapshot(checked.verdict === C.STATUS.PASS || checked.verdict === C.STATUS.PARTIAL, C.HARD.nested_invalid);
  const records = parsed.checkpoints;
  result.transparency = { state: C.COMPONENT.included, filename: C.TRANSPARENCY_FILENAME, extent: { checkpoint_count: records.length, first_counter: records[0].counter, last_counter: records.at(-1)!.counter, last_checkpoint_payload_sha256: checkpointPayloadHash(records.at(-1)!), fortress_id: records[0].fortress_id } };
  result.transparencyBytes = bytes; result.transparencyPin = pin;
  return result;
}
