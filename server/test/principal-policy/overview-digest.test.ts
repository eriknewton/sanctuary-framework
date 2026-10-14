/** Served destination rows share the digest's existing verdict evidence gate. */
import { describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { buildAuditDigest } from "../../src/principal-policy/posture.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import * as C from "../../src/castle-wall/constants.js";

const NOW = Date.parse("2026-10-14T12:00:00Z");
const DAY = 24 * 60 * 60 * 1000;
const SUBJECT = "fortress:test/uid-503";
const key = ed25519.utils.randomPrivateKey();
const publicKey = Buffer.from(ed25519.getPublicKey(key)).toString("base64url");
const log = () => new AuditLog(new MemoryStorage(), generateRandomKey());
async function append(audit: AuditLog, seq: number, options: {
  host?: string | null; ip?: string; port?: number; operation?: string;
  signedOperation?: string; captured?: number; forged?: boolean; provenance?: boolean;
  storedHost?: string; timestamp?: string;
} = {}) {
  const operation = options.operation ?? "egress_blocked";
  const captured = options.captured ?? NOW - 1000;
  const canonical = JSON.stringify({ timestamp: new Date(captured).toISOString(), layer: "l1",
    operation: options.signedOperation ?? operation, identity_id: SUBJECT, result: "blocked",
    details: { dest_host: options.host === undefined ? "blocked.example" : options.host, dest_ip: options.ip, dest_port: options.port } });
  const signature = ed25519.sign(producerSigningBytes(canonical, captured, seq), options.forged ? ed25519.utils.randomPrivateKey() : key);
  await audit.appendCritical({ layer: "l1", operation, identity_id: SUBJECT, result: "success",
    timestamp: options.timestamp ?? new Date(NOW - 1000).toISOString(), details: {
      seq, dest_host: options.storedHost ?? "stored.example",
      ...(options.provenance === false ? {} : { [C.CASTLE_WALL_AUDIT_PROVENANCE_KEY]: C.CASTLE_WALL_AUDIT_PROVENANCE_VALUE }),
      [C.CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: Buffer.from(signature).toString("base64url"),
      [C.CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]: C.CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [C.CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
      [C.CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: captured,
      [C.CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]: C.CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
      [C.CASTLE_WALL_PRODUCER_SUBJECT_BINDING_DETAIL_KEY]: C.CASTLE_WALL_PRODUCER_SUBJECT_BINDING_SIGNED_IDENTITY_ID,
    } });
}
const digest = (auditLog: AuditLog) => buildAuditDigest({ auditLog, originMachine: "fortress:test", protectionClaimSubject: SUBJECT, now: NOW, pinnedProducerKeyB64url: publicKey });

describe("Overview served digest", () => {
  it("conserves counted blocks in destination rows below the cap", async () => {
    const audit = log();
    await append(audit, 1); await append(audit, 2); await append(audit, 3, { host: null });
    const d = await digest(audit);
    expect(d.blocked_destinations).toEqual([
      { destination: "blocked.example", blocks: 2, last_blocked_at: new Date(NOW - 1000).toISOString() },
      { destination: null, blocks: 1, last_blocked_at: new Date(NOW - 1000).toISOString() },
    ]);
    expect(d.blocked_destinations.reduce((n, row) => n + row.blocks, 0)).toBe(d.kernel_blocks);
    expect(d.blocked_destination_count).toBe(2);
  });
  it("serves the ten largest rows and accounts for the dropped blocks", async () => {
    const audit = log(); let seq = 0;
    // Twelve destinations with frequencies 1..12 exercise the ten-row cap.
    for (let i = 1; i <= 12; i++) for (let j = 0; j < i; j++) await append(audit, ++seq, { host: `host-${i}` });
    const d = await digest(audit);
    expect(d.blocked_destinations).toHaveLength(10);
    expect(d.blocked_destination_count).toBe(12);
    expect(d.blocked_destinations.map(row => row.blocks)).toEqual([12, 11, 10, 9, 8, 7, 6, 5, 4, 3]);
    expect(d.blocked_destinations.reduce((n, row) => n + row.blocks, 0) + 1 + 2).toBe(d.kernel_blocks);
  });
  for (const [name, options, seq] of [
    ["allow", { operation: "egress_allowed", signedOperation: "egress_approved" }, 2],
    ["operator decision", { operation: "operator_decision", signedOperation: "egress_pending" }, 2],
    ["forged signature", { forged: true }, 2],
    ["duplicate", {}, 1],
    ["old capture", { captured: NOW - DAY - 1 }, 2],
    ["signed allow on block", { signedOperation: "egress_approved" }, 2],
    ["no provenance", { provenance: false }, 2],
  ] as const) it(`excludes ${name} from blocked destinations`, async () => {
    const audit = log(); await append(audit, 1);
    const before = await digest(audit);
    await append(audit, seq, options);
    const after = await digest(audit);
    expect(after.blocked_destinations).toEqual([{ destination: "blocked.example", blocks: 1, last_blocked_at: new Date(NOW - 1000).toISOString() }]);
    expect(after.blocked_destinations).toEqual(before.blocked_destinations);
    expect(after.kernel_blocks).toBe(before.kernel_blocks);
    expect(after.blocked_destination_count).toBe(before.blocked_destination_count);
  });
  it("takes the verified signed destination and capture time", async () => {
    const audit = log(); await append(audit, 1, { host: "signed.example", storedHost: "unsigned.example", captured: NOW - 2000 });
    expect((await digest(audit)).blocked_destinations).toEqual([{ destination: "signed.example", blocks: 1, last_blocked_at: new Date(NOW - 2000).toISOString() }]);
  });
  it("bounds labels, sanitizes controls, brackets IPs and validates ports", async () => {
    const audit = log();
    await append(audit, 1, { host: "a".repeat(300), port: 65535 });
    await append(audit, 2, { host: "a\nb", port: -1 });
    await append(audit, 3, { host: null, ip: "::1", port: 0 });
    const labels = (await digest(audit)).blocked_destinations.map(row => row.destination);
    expect(labels).toContain("a".repeat(253) + ":65535");
    expect(labels).toContain("a b"); expect(labels).toContain("[::1]:0");
  });
  it("uses channel details and sorts by frequency, last time and destination", async () => {
    const audit = log();
    for (const [host, timestamp] of [["z", NOW - 1000], ["b", NOW - 2000], ["a", NOW - 2000], [null, NOW - 2000]] as const) {
      await audit.appendCritical({ layer: "l1", operation: "egress_blocked", identity_id: SUBJECT, result: "failure", timestamp: new Date(timestamp).toISOString(), details: {
        [C.CASTLE_WALL_AUDIT_PROVENANCE_KEY]: C.CASTLE_WALL_AUDIT_PROVENANCE_VALUE, destination: { host, port: 443 },
      } });
    }
    const d = await buildAuditDigest({ auditLog: audit, originMachine: "test", protectionClaimSubject: null, now: NOW });
    expect(d.blocked_destinations.map(row => row.destination)).toEqual(["z:443", "a:443", "b:443", null]);
  });
  for (const cause of ["unavailable key", "read failure"] as const) it(`serves fail-honest fields for ${cause}`, async () => {
    const audit = log();
    if (cause === "read failure") vi.spyOn(audit, "query").mockRejectedValue(new Error("unreadable"));
    const d = await buildAuditDigest({ auditLog: audit, originMachine: "test", protectionClaimSubject: null, now: NOW, producerKeyExpectedButUnavailable: cause === "unavailable key" });
    expect(d).toMatchObject({ window_complete: false, kernel_allow_overrides: 0, blocked_destinations: [], blocked_destination_count: 0 });
  });
  it("marks a truncated query incomplete", async () => {
    const audit = log(); const result = await audit.query({});
    vi.spyOn(audit, "query").mockResolvedValue({ ...result, total: result.entries.length + 1 });
    expect((await digest(audit)).window_complete).toBe(false);
  });
  for (const inWindow of [true, false]) it(`counts superseding verdicts in-window=${inWindow}`, async () => {
    const audit = log();
    await append(audit, 1, { operation: "egress_verdict_superseded", forged: true, timestamp: new Date(inWindow ? NOW - 1000 : NOW - DAY - 1).toISOString() });
    expect((await digest(audit)).kernel_allow_overrides).toBe(inWindow ? 1 : 0);
  });
});


it("bounds adversarial destination work to the query cap and serves only ten rows", async () => {
  const audit = log(); await append(audit, 1);
  const result = await audit.query({});
  const count = 50_000; // Production digest query ceiling.
  const entries = Array.from({ length: count }, (_, i) => ({ ...result.entries[0]!, details: {
    [C.CASTLE_WALL_AUDIT_PROVENANCE_KEY]: C.CASTLE_WALL_AUDIT_PROVENANCE_VALUE, dest_host: `host-${i}`,
  } }));
  const query = vi.spyOn(audit, "query").mockResolvedValue({ ...result, entries, total: count });
  const d = await buildAuditDigest({ auditLog: audit, originMachine: "test", protectionClaimSubject: null, now: NOW });
  expect(d.blocked_destinations).toHaveLength(10);
  expect(d.blocked_destination_count).toBe(count);
  expect(d.kernel_blocks).toBe(count);
  expect(query).toHaveBeenCalledWith({ since: new Date(NOW - DAY).toISOString(), limit: count });
});
