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

// Coverage consumes the public audit reads, including every sealed verdict arm.
describe("round 2 window coverage", () => {
  for (const sealed_region of [
    { status: "verified", entries_verified: 1, sealed_tip_sequence: 1 },
    { status: "unreadable", note: "privilege" },
    { status: "incomplete", expected_tip: 2, highest_present: 1 },
    { status: "hash_mismatch", sequence: 1, expected: "a", actual: "b" },
  ] as const) it(`withholds coverage for sealed ${sealed_region.status}`, async () => {
    const audit = log(); await append(audit, 1);
    const verdict = await audit.getAuditChainVerdict();
    vi.spyOn(audit, "getAuditChainVerdict").mockResolvedValue({ ...verdict, sealed_region });
    expect(await digest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "sealed_region" });
    const result = await audit.query({});
    vi.spyOn(audit, "query").mockResolvedValue({ ...result, total: result.total + 1 });
    // The lane's sealed-region bound holds even when the query is also truncated.
    expect(await digest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "sealed_region" });
  });
  for (const status of ["not_present", "empty"] as const) it(`covers an unpruned log with sealed ${status}`, async () => {
    const audit = log(); await append(audit, 1);
    const verdict = await audit.getAuditChainVerdict();
    vi.spyOn(audit, "getAuditChainVerdict").mockResolvedValue({ ...verdict, sealed_region: { status } });
    expect(await digest(audit)).toMatchObject({ window_complete: true, window_incomplete_reason: null });
  });
  // Entry timestamps are caller-supplied and need not rise with sequence, so a floor entry's time never settles a pruned log.
  for (const [name, age] of [["before", DAY + 1], ["at", DAY], ["after", DAY - 1]] as const) it(`reads a pruned log as retention with its floor entry ${name} window start`, async () => {
    const audit = new AuditLog(new MemoryStorage(), generateRandomKey(), { maxEntries: 2 });
    for (let i = 0; i < 3; i++) await append(audit, i + 1, { timestamp: new Date(NOW - age).toISOString() });
    expect((await audit.authenticatedRotationFloor()).status).toBe("valid");
    expect(await digest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "retention" });
  });
  it("covers a log whose authenticated floor is its first entry", async () => {
    const audit = log(); await append(audit, 1);
    vi.spyOn(audit, "authenticatedRotationFloor").mockResolvedValue({ status: "valid", base_sequence: 1, base_prev_hash: "unknown" });
    expect(await digest(audit)).toMatchObject({ window_complete: true, window_incomplete_reason: null });
  });
  it("withholds coverage for an invalid rotation anchor", async () => {
    const audit = log(); await append(audit, 1);
    vi.spyOn(audit, "authenticatedRotationFloor").mockResolvedValue({ status: "invalid" });
    expect(await digest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "coverage_unknown" });
  });
  it("withholds coverage when the authenticated floor disagrees with the retained sequence", async () => {
    const audit = log(); await append(audit, 1);
    vi.spyOn(audit, "authenticatedRotationFloor").mockResolvedValue({ status: "valid", base_sequence: 2, base_prev_hash: "unknown" });
    expect(await digest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "coverage_unknown" });
  });
  it("does not infer an unpruned chain from an absent anchor alone", async () => {
    const audit = new AuditLog(new MemoryStorage(), generateRandomKey(), { maxEntries: 2 });
    for (let i = 0; i < 3; i++) await append(audit, i + 1);
    vi.spyOn(audit, "authenticatedRotationFloor").mockResolvedValue({ status: "absent" });
    expect(await digest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "coverage_unknown" });
  });
  it("keeps an empty log's retention coverage unknown without a first sequence", async () => {
    expect(await digest(log())).toMatchObject({ window_complete: false, window_incomplete_reason: "coverage_unknown" });
  });
  it("names a query cut by its read limit", async () => {
    const audit = log(); const result = await audit.query({});
    vi.spyOn(audit, "query").mockResolvedValue({ ...result, total: 1 });
    expect(await digest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "read_limit" });
  });
});

describe("round 2 destination labels", () => {
  for (const [name, chars] of [
    ["C1", "\u0080\u0085\u009f"],
    ["bidirectional", "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"],
    ["zero width", "\u200b\u200c\u200d\u2060\ufeff"],
  ] as const) it(`replaces ${name} characters`, async () => {
    const audit = log(); await append(audit, 1, { host: `a${chars}b` });
    expect((await digest(audit)).blocked_destinations[0]?.destination).toBe(`a${" ".repeat(chars.length)}b`);
  });
  for (const ip of ["::1", undefined]) it(`falls back from an empty host to ${ip ?? "the null bucket"}`, async () => {
    const audit = log(); await append(audit, 1, { host: " \n\u200b ", ip, port: 443 });
    expect((await digest(audit)).blocked_destinations[0]?.destination).toBe(ip ? "[::1]:443" : null);
  });
});

describe("round 2 coverage read bounds", () => {
  // The posture surface builds the digest inside runEagerReads (buildDigest in posture-routes.ts); this mirrors it.
  const eagerDigest = (audit: AuditLog) => audit.runEagerReads(() => digest(audit));
  // Fails before the head re-check in routineWindowCoverage (round 2 fail-before evidence).
  it("withholds coverage for an append between the chain head and eager view reads", async () => {
    let clock: { mockRestore(): void } | undefined;
    let head: { mockRestore(): void } | undefined;
    try {
      // Freeze the backstop clock so a timed reload cannot discard the prefix during this schedule.
      clock = vi.spyOn(Date, "now").mockReturnValue(NOW);
      const firstSequence = 1; // Audit chains start at sequence one.
      const retainedCount = 2; // Keep a suffix with a floor entry distinct from the tip.
      const appendedCount = retainedCount + firstSequence; // One extra append rotates the first entry off disk.
      const audit = new AuditLog(new MemoryStorage(), generateRandomKey(), { maxEntries: retainedCount });
      const readHead = audit.getChainHead.bind(audit);
      for (let seq = firstSequence; seq <= appendedCount; seq++) await append(audit, seq);
      expect(await audit.authenticatedRotationFloor()).toMatchObject({ status: "valid", base_sequence: firstSequence + 1 });
      const spy = vi.spyOn(audit, "getChainHead").mockImplementationOnce(async () => {
        const snapshot = await readHead();
        await append(audit, appendedCount + 1);
        return snapshot;
      });
      head = spy;
      const result = await eagerDigest(audit);
      // The coverage check reads the head once before and once after the view.
      expect(spy).toHaveBeenCalledTimes(2);
      expect((await readHead()).sequence).toBe(appendedCount + 1);
      // Must match routineWindowCoverage in posture.ts: a head that moved during the view read cannot vouch for coverage.
      expect(result).toMatchObject({ window_complete: false, window_incomplete_reason: "coverage_unknown" });
    } finally {
      head?.mockRestore();
      clock?.mockRestore();
    }
  });
  // Fails before the head re-check in routineWindowCoverage (round 2 fail-before evidence).
  it("withholds coverage when a reloaded view races an append", async () => {
    const reverifyMs = 60 * 1000; // This log's backstop interval; the clock steps past it once to force a disk reload.
    let clock: { mockRestore(): void } | undefined;
    let head: { mockRestore(): void } | undefined;
    try {
      let now = NOW;
      clock = vi.spyOn(Date, "now").mockImplementation(() => now);
      const firstSequence = 1; // Audit chains start at sequence one.
      const retainedCount = 2; // Disk keeps two entries, so a view reloaded from disk starts above the first sequence.
      const appendedCount = retainedCount + firstSequence; // One extra append rotates the first entry off disk.
      const audit = new AuditLog(new MemoryStorage(), generateRandomKey(), { maxEntries: retainedCount, eagerReverifyIntervalMs: reverifyMs });
      const readHead = audit.getChainHead.bind(audit);
      for (let seq = firstSequence; seq <= appendedCount; seq++) await append(audit, seq);
      now += reverifyMs; // The next eager read reloads the view from disk.
      expect((await audit.runEagerReads(() => audit.query({}))).entries).toHaveLength(retainedCount);
      head = vi.spyOn(audit, "getChainHead").mockImplementationOnce(async () => {
        const snapshot = await readHead();
        await append(audit, appendedCount + 1);
        return snapshot;
      });
      const result = await eagerDigest(audit);
      // Must match routineWindowCoverage in posture.ts: a head that moved during the view read cannot vouch for coverage.
      expect(result).toMatchObject({ window_complete: false, window_incomplete_reason: "coverage_unknown" });
    } finally {
      head?.mockRestore();
      clock?.mockRestore();
    }
  });
  // fail-before-exempt: existing behavior; plant retention whenever the authenticated base sequence exceeds one.
  it("covers a pruned prefix still held in the eager view but reports retention outside it", async () => {
    let clock: { mockRestore(): void } | undefined;
    try {
      // Freeze the backstop clock so a timed reload cannot discard the prefix before the eager read.
      clock = vi.spyOn(Date, "now").mockReturnValue(NOW);
      const firstSequence = 1; // Audit chains start at sequence one.
      const retainedCount = 2; // Keep a suffix with a floor entry distinct from the tip.
      const appendedCount = retainedCount + firstSequence; // One extra append rotates the first entry off disk.
      const audit = new AuditLog(new MemoryStorage(), generateRandomKey(), { maxEntries: retainedCount });
      for (let seq = firstSequence; seq <= appendedCount; seq++) await append(audit, seq);
      expect(await audit.authenticatedRotationFloor()).toMatchObject({ status: "valid", base_sequence: firstSequence + 1 });
      await audit.runEagerReads(async () => {
        const retained = await audit.query({});
        const head = await audit.getChainHead();
        expect(retained.entries).toHaveLength(appendedCount);
        expect(head.sequence - retained.total + firstSequence).toBe(firstSequence);
        // Must match routineWindowCoverage in posture.ts: the same full view supplies both counts and coverage.
        expect(await digest(audit)).toMatchObject({ window_complete: true, window_incomplete_reason: null, kernel_blocks: appendedCount });
      });
      // A disk read loses the rotated prefix, so its smaller count cannot claim complete coverage.
      expect(await digest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "retention", kernel_blocks: retainedCount });
    } finally {
      clock?.mockRestore();
    }
  });
  it("settles coverage from the eager view without re-reading the chain from disk", async () => {
    const audit = log(); await append(audit, 1);
    const stream = vi.spyOn(audit, "streamVerifiedChain"); const view = vi.spyOn(audit, "verifiedChainView");
    const query = vi.spyOn(audit, "query");
    expect(await eagerDigest(audit)).toMatchObject({ window_complete: true, window_incomplete_reason: null });
    expect(stream).not.toHaveBeenCalled(); expect(view).not.toHaveBeenCalled();
    // Must match the retained-view read budget in routineWindowCoverage (posture.ts): the digest cap or the retention cap.
    expect(query).toHaveBeenCalledWith({ limit: Math.max(50_000, audit.getRetentionConfig().maxEntries) });
  });
  it("withholds coverage when the chain head and the retained view disagree", async () => {
    const audit = log(); await append(audit, 1);
    // One retained entry under a head at sequence 2 means the oldest retained entry is not the chain's first.
    vi.spyOn(audit, "getChainHead").mockResolvedValue({ sequence: 2, entry_hash: "unknown" });
    expect(await eagerDigest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "coverage_unknown" });
  });
  it("withholds coverage when the retained view is larger than one read", async () => {
    // Retention keeps entries 2 and 3, so the uncut view locates the floor entry and reads retention.
    const audit = new AuditLog(new MemoryStorage(), generateRandomKey(), { maxEntries: 2 });
    for (const [seq, at] of [[1, NOW - DAY - 3], [2, NOW - DAY - 2], [3, NOW - 1000]] as const) await append(audit, seq, { timestamp: new Date(at).toISOString() });
    expect(await digest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "retention" });
    const real = audit.query.bind(audit);
    // A cut drops the oldest entries, so the floor entry's position is lost; only the retained-view read (no since) is cut.
    vi.spyOn(audit, "query").mockImplementation(async (options) => {
      const result = await real(options);
      return options.since ? result : { ...result, entries: result.entries.slice(1) };
    });
    expect(await digest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "coverage_unknown" });
  });
  it("withholds coverage if the chain head cannot be read", async () => {
    const audit = log(); await append(audit, 1);
    vi.spyOn(audit, "getChainHead").mockRejectedValue(new Error("unreadable"));
    expect(await eagerDigest(audit)).toMatchObject({ window_complete: false, window_incomplete_reason: "coverage_unknown" });
  });
});
