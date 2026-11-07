/** Bounded nested checks preserve incomplete verification as PARTIAL. */
import { verifyAuditChainRecords, type ExportRecord, type EntryExportRecord, type CheckpointExportRecord, type RotationAnchorExportRecord } from "../cli/audit-chain-verify.js";
import { verifyTransparencyCheckpoints, checkpointPayloadHash } from "../transparency/verify.js";
import * as C from "./snapshot-contract.js";
export interface NestedOutcome { report: C.NestedReport; partial: C.PartialReason[]; recordKinds?: readonly string[] }
export function auditExtent(records: readonly C.AuditRecord[]): C.AuditExtent {
  const e = records.filter((r): r is EntryExportRecord => r.type === C.RECORD.entry).sort((a, b) => a.seq - b.seq);
  const c = records.filter((r): r is CheckpointExportRecord => r.type === C.RECORD.checkpoint).sort((a, b) => a.checkpoint_sequence - b.checkpoint_sequence);
  return { entry_count: e.length, first_sequence: e[0]?.seq ?? null, last_sequence: e.at(-1)?.seq ?? null, head_hash: e.at(-1)?.entry_hash ?? null, checkpoint_count: c.length, first_checkpoint_sequence: c[0]?.checkpoint_sequence ?? null, last_checkpoint_sequence: c.at(-1)?.checkpoint_sequence ?? null };
}
export function compareExtent(actual: C.AuditExtent | C.TransparencyExtent, expected: C.AuditExtent | C.TransparencyExtent): void {
  // Extents describe the captured records undergoing nested checks, never just a signed assertion.
  C.requireSnapshot(C.canonicalSnapshotJSON(actual) === C.canonicalSnapshotJSON(expected), C.HARD.extent_mismatch);
}
export function auditTraversal(spans: readonly number[], partitions: number, entries: number): number {
  C.cap(partitions, C.MAX_KEYS); C.cap(entries, C.MAX_RECORDS); let work = entries * partitions;
  C.cap(work, C.MAX_AUDIT_TRAVERSAL);
  for (const span of spans) { C.cap(span, C.MAX_RECORDS); work += span; C.cap(work, C.MAX_AUDIT_TRAVERSAL); }
  return work;
}
export function verifySnapshotAudit(bytes: Uint8Array, extent: C.AuditExtent, keys: readonly C.TrustKey[]): NestedOutcome {
  C.cap(keys.length, C.MAX_KEYS);
  const pins = keys.filter(k => k.role === C.PIN_ROLE.audit); C.requireSnapshot(pins.length > 0, C.HARD.pin_invalid);
  const records = C.parseAuditRecords(bytes); compareExtent(auditExtent(records), extent);
  const partial = new Set<C.PartialReason>();
  const entries = records.filter((r): r is EntryExportRecord => r.type === C.RECORD.entry).sort((a, b) => a.seq - b.seq);
  const cps = records.filter((r): r is CheckpointExportRecord => r.type === C.RECORD.checkpoint).sort((a, b) => a.checkpoint_sequence - b.checkpoint_sequence);
  const legacy = records.filter((r): r is Extract<ExportRecord, { type: "legacy_anchor" }> => r.type === C.RECORD.legacy);
  C.requireSnapshot(legacy.length <= 1, C.HARD.nested_invalid);
  const rotations = records.filter((r): r is RotationAnchorExportRecord => r.type === C.RECORD.rotation);
  C.requireSnapshot(rotations.length <= 1, C.HARD.nested_invalid); const base = rotations[0]?.base_sequence ?? 1;
  for (const r of records) {
    if (r.type === C.RECORD.legacy) partial.add(C.PARTIAL.audit_legacy_anchor_unverified);
    else if (r.type === C.RECORD.rotation) { partial.add(C.PARTIAL.audit_rotation_anchor_unverified); if (r.mac !== undefined) partial.add(C.PARTIAL.audit_custody_mac_unverified); }
    else if (!C.PUBLIC_AUDIT_KINDS.includes(r.type as never)) partial.add(C.PARTIAL.extension_unverified);
  }
  const assignments = new Map<string, CheckpointExportRecord[]>(); const spans: number[] = []; let traversal = 0; const seqs = new Set(entries.map(e => e.seq));
  C.requireSnapshot(seqs.size === entries.length, C.HARD.nested_invalid); let previous = legacy[0]?.checkpoint_sequence ?? 0;
  if (rotations.length && cps[0] && cps[0].previous_checkpoint_sequence < base) previous = cps[0].previous_checkpoint_sequence;
  let covered = Math.max(base - 1, legacy[0]?.checkpoint_sequence ?? 0);
  for (const cp of cps) {
    // One global walk prevents partitions from concealing checkpoint forks, duplicates or uncovered spans.
    C.requireSnapshot(cp.checkpoint_sequence > previous && cp.previous_checkpoint_sequence === previous, C.HARD.nested_invalid); previous = cp.checkpoint_sequence;
    if (cp.from_sequence < base) partial.add(C.PARTIAL.audit_pruned_root_unverified);
    else { const span = cp.checkpoint_sequence - cp.from_sequence + 1; C.cap(span, C.MAX_RECORDS); traversal += span; C.cap(traversal, C.MAX_AUDIT_TRAVERSAL); spans.push(span); for (let seq = cp.from_sequence; seq <= cp.checkpoint_sequence; seq++) C.requireSnapshot(seqs.has(seq), C.HARD.nested_invalid); }
    if (cp.from_sequence > covered + 1) partial.add(C.PARTIAL.audit_span_gap); covered = Math.max(covered, cp.checkpoint_sequence);
    const key = cp.unsigned ? pins[0].public_key_base64url : cp.public_key;
    C.requireSnapshot(key && pins.some(p => p.public_key_base64url === key), C.HARD.pin_invalid);
    const assigned = assignments.get(key) ?? []; assigned.push(cp); assignments.set(key, assigned);
  }
  if ((entries.at(-1)?.seq ?? 0) > covered) partial.add(C.PARTIAL.audit_tail_unanchored);
  if (cps.length === 0) assignments.set(pins[0].public_key_base64url, []);
  auditTraversal(spans, assignments.size, entries.length);
  const common = records.filter((r): r is ExportRecord => r.type !== C.RECORD.checkpoint && r.type !== C.RECORD.extension);
  const findings: string[] = []; const scope = new Set<string>(); let signatures = 0; let checked = 0;
  // DEBT(PACK-AUDIT-REHASH): Each partition rehashes captured payloads up to MAX_KEYS * MAX_FILE_BYTES; signature work also scales with checkpoints and rotation hops outside the traversal budget.
  for (const [key, checkpoints] of assignments) {
    // Each checkpoint is verified exactly once under its role pin and unused pins create no calls.
    const report = verifyAuditChainRecords([...common, ...checkpoints], { publicKey: key, trustEmbedded: false }); const kinds = report.findings.map(f => f.kind);
    scope.add(report.rotation_anchor_scope); scope.add(report.signature_coverage_scope);
    C.requireSnapshot((report.verdict === C.STATUS.PASS && kinds.length === 0) || (report.verdict === C.STATUS.FAIL && kinds.length > 0 && kinds.every(k => C.AUDIT_PARTIAL_FINDINGS.includes(k))), C.HARD.nested_invalid);
    for (const kind of kinds) partial.add(kind as C.PartialReason);
    findings.push(...kinds); signatures += report.signatures_verified; checked += report.checkpoints_verified;
  }
  C.requireSnapshot(checked === cps.length, C.HARD.nested_invalid);
  return { recordKinds: [...new Set(records.map(r => r.type))], report: { verdict: findings.length ? C.STATUS.FAIL : C.STATUS.PASS, entries_verified: entries.length, checkpoints_verified: checked, signatures_verified: signatures, signature_basis: C.SIGNATURE_BASIS, not_checked: [...scope], findings: [...new Set(findings)].sort() }, partial: [...partial].sort() };
}
export function verifySnapshotTransparency(bytes: Uint8Array, extent: C.TransparencyExtent, keys: readonly C.TrustKey[]): NestedOutcome {
  C.cap(keys.length, C.MAX_KEYS);
  const pins = keys.filter(k => k.role === C.PIN_ROLE.transparency); C.requireSnapshot(pins.length === 1, C.HARD.pin_invalid);
  const bundle = C.parseTransparency(bytes); const key = pins[0].public_key_base64url;
  // Embedded transparency keys must equal the independent role pin before any nested call.
  C.requireSnapshot(bundle.public_key === key && bundle.checkpoints.every(c => c.public_key === key), C.HARD.pin_invalid);
  const report = verifyTransparencyCheckpoints(bundle, { publicKey: key, trustEmbedded: false, allowPartial: true });
  C.requireSnapshot(report.verdict === C.STATUS.PASS || report.verdict === C.STATUS.PARTIAL, C.HARD.nested_invalid);
  const ordered = [...bundle.checkpoints].sort((a, b) => a.counter - b.counter); const last = ordered.at(-1)!;
  compareExtent({ checkpoint_count: ordered.length, first_counter: ordered[0].counter, last_counter: last.counter, last_checkpoint_payload_sha256: checkpointPayloadHash(last), fortress_id: last.fortress_id }, extent);
  return { report: { verdict: report.verdict, checkpoints_verified: report.checkpoints_verified, signature_basis: report.signature_basis, findings: report.findings.map(f => f.kind), not_checked: report.not_checked }, partial: report.verdict === C.STATUS.PARTIAL ? [C.PARTIAL.transparency_prefix_unverified] : [] };
}
export function absentOutcome(component: Exclude<C.Component<unknown>, { state: "included" }>, role: "audit" | "transparency"): NestedOutcome {
  return { report: { state: C.COMPONENT.absent, reason: component.reason }, partial: [C.PARTIAL[`${role}_absent`], C.PARTIAL[`${role}_${component.state}`]] };
}
export function joinSnapshotVerdict(partial: readonly C.PartialReason[], manifest: C.SnapshotManifest, audit: NestedOutcome, transparency: NestedOutcome): { status: C.SnapshotStatus; exit_code: number; accepted: boolean; snapshot_integrity: typeof C.INTEGRITY.verified | typeof C.INTEGRITY.bytes_match; partial_reasons: C.PartialReason[] } {
  const reasons = [...new Set(partial)].sort();
  // PASS requires complete component inclusion, public audit kinds, passing nested verdicts and no incomplete evidence.
  const clean = manifest.components.audit.state === C.COMPONENT.included
    && manifest.components.transparency.state === C.COMPONENT.included
    && audit.report.verdict === C.STATUS.PASS && transparency.report.verdict === C.STATUS.PASS
    && audit.recordKinds !== undefined && audit.recordKinds.every(kind => C.PUBLIC_AUDIT_KINDS.includes(kind as never))
    && manifest.extensions.length === 0 && reasons.length === 0;
  // Missing partial reasons for incomplete evidence are an internal verification failure.
  C.requireSnapshot(clean === (reasons.length === 0), C.HARD.nested_invalid);
  // PARTIAL is never exit 0 because matching bytes alone cannot establish complete public verification.
  return { status: clean ? C.STATUS.PASS : C.STATUS.PARTIAL, exit_code: clean ? C.EXIT_PASS : C.EXIT_PARTIAL, accepted: clean, snapshot_integrity: clean ? C.INTEGRITY.verified : C.INTEGRITY.bytes_match, partial_reasons: reasons };
}
