/**
 * Audit-chain PASS requires signature verification for every type: "checkpoint" record.
 * Claims are exercised through the production source handler and parser.
 * Unsigned, keyed zero-checkpoint, and discriminator cases fail before this change.
 * Fully signed, missing-key, invalid-signature, and no-key empty-coverage cases are regression guards.
 * AUDIT-VERIFY-UNSIGNED-1024
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { exportAuditChain } from "../../src/cli/audit-chain-export.js";
import {
  AUDIT_CHAIN_GENESIS,
  AUDIT_CHAIN_SCHEMA_VERSION,
  checkpointSigningBytes,
  computeAuditEntryHash,
  computeAuditRoot,
} from "../../src/audit/chain.js";
import {
  AUDIT_CHAIN_VERIFY_EXIT_OK,
  AUDIT_CHAIN_VERIFY_EXIT_RELAXED_FINDINGS,
  AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS,
  verifyAuditChainContent,
  parseJsonl,
  parseVerifyArgs,
  runVerify,
  auditChainVerifyExitCode,
  type CheckpointExportRecord,
  type EntryExportRecord,
  type VerifyReport,
} from "../../src/cli/audit-chain-verify.js";
const SIGNING_SEED_BYTES = 32; // Ed25519 private seeds contain 32 bytes.
const SIGNING_SEED = new Uint8Array(SIGNING_SEED_BYTES).fill(1);
const PUBLIC_KEY = Buffer.from(ed25519.getPublicKey(SIGNING_SEED)).toString("base64url");
const FIXTURE_TIME = "2026-01-01T00:00:00.000Z";
const CHECKPOINT_COUNT = 2; // Two checkpoints allow both all-unsigned and mixed coverage.

// Fixture construction follows audit-chain-verify-exit.test.ts, using the
// production hash helpers and the same JSONL encoding.
function cleanEntries(count: number): EntryExportRecord[] {
  const entries: EntryExportRecord[] = [];
  let prevHash = AUDIT_CHAIN_GENESIS;
  for (let seq = 1; seq <= count; seq++) {
    const encryptedPayloadBytes = Buffer.from(`payload-${seq}`).toString("base64url");
    const entryHash = computeAuditEntryHash({
      sequence: seq,
      prev_hash: prevHash,
      timestamp: FIXTURE_TIME,
      encrypted_payload_bytes: encryptedPayloadBytes,
      schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
    });
    entries.push({
      type: "entry",
      seq,
      schema_version: AUDIT_CHAIN_SCHEMA_VERSION,
      prev_hash: prevHash,
      entry_hash: entryHash,
      timestamp: FIXTURE_TIME,
      encrypted_payload_bytes: encryptedPayloadBytes,
    });
    prevHash = entryHash;
  }
  return entries;
}

function asJsonl(records: readonly unknown[]): string {
  return records.map((record) => JSON.stringify(record)).join("\n") + "\n";
}

function checkpoint(entry: EntryExportRecord, unsigned: boolean): CheckpointExportRecord {
  const payload = {
    checkpoint_kind: "audit-checkpoint" as const,
    checkpoint_sequence: entry.seq,
    from_sequence: entry.seq,
    root_hash: computeAuditRoot([entry.entry_hash]),
    previous_checkpoint_sequence: entry.seq - 1,
    signed_at: FIXTURE_TIME,
  };
  return {
    type: "checkpoint",
    ...payload,
    signer_kid: unsigned ? null : "fixture-signer",
    signature: unsigned ? null : Buffer.from(
      ed25519.sign(checkpointSigningBytes(payload), SIGNING_SEED),
    ).toString("base64url"),
    public_key: PUBLIC_KEY,
    unsigned,
  };
}

describe("audit-chain checkpoint signature coverage", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function writeFixture(name: string, content: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-audit-chain-cli-"));
    tempDirs.push(dir);
    const file = join(dir, name);
    await writeFile(file, content);
    return file;
  }

  async function verifySourceAndCommand(records: readonly unknown[], flags: string[] = []): Promise<{
    code: number;
    reports: VerifyReport[];
  }> {
    const content = asJsonl(records);
    const file = await writeFixture("chain.jsonl", content);
    const args = parseVerifyArgs(["--input", file, "--storage-path", tempDirs.at(-1)!, ...flags]);
    const sourceReport = verifyAuditChainContent(content, args);
    const chunks: string[] = [];
    // Invoke the production CLI handler without a stale dist bundle or child process;
    // the source path also remains visible to the fail-before gate.
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
      chunks.push(String(chunk));
      return true;
    });
    let code: number;
    try {
      code = await runVerify(args);
    } finally {
      stdout.mockRestore();
    }
    expect(code).toBe(auditChainVerifyExitCode(sourceReport, args.strict));
    return { code, reports: [sourceReport, JSON.parse(chunks.join("")) as VerifyReport] };
  }

  it.each([
    { label: "default strict", flags: [], exit: AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS },
    { label: "pinned key", flags: ["--public-key", PUBLIC_KEY], exit: AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS },
    { label: "embedded opt-in", flags: ["--trust-embedded"], exit: AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS },
    { label: "relaxed", flags: ["--no-strict"], exit: AUDIT_CHAIN_VERIFY_EXIT_RELAXED_FINDINGS },
  ])("all unsigned checkpoints FAIL with one finding each ($label)", async ({ flags, exit }) => {
    const entries = cleanEntries(CHECKPOINT_COUNT);
    const checkpoints = entries.map((entry) => checkpoint(entry, true));
    const { code, reports } = await verifySourceAndCommand([...entries, ...checkpoints], flags);
    expect(code).toBe(exit);
    for (const report of reports) {
      expect(report.verdict).toBe("FAIL");
      expect(report.signatures_verified).toBe(0);
      expect(report.findings).toEqual(checkpoints.map((cp) => ({
        kind: "checkpoint_unsigned",
        seq: cp.checkpoint_sequence,
        message: expect.stringMatching(/marked unsigned \(unsigned: true\).*no signature was verified for it/),
      })));
      expect(report.signatures_skipped).toBe(report.findings.length);
    }
  });

  it.each([
    { flags: ["--public-key", PUBLIC_KEY], exit: AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS },
    { flags: ["--public-key", PUBLIC_KEY, "--no-strict"], exit: AUDIT_CHAIN_VERIFY_EXIT_RELAXED_FINDINGS },
  ])("a verified and an unsigned checkpoint FAIL with one unsigned finding ($flags)", async ({ flags, exit }) => {
    const entries = cleanEntries(CHECKPOINT_COUNT);
    const signed = checkpoint(entries[0]!, false);
    const unsigned = checkpoint(entries[1]!, true);
    const { code, reports } = await verifySourceAndCommand([...entries, signed, unsigned], flags);
    expect(code).toBe(exit);
    for (const report of reports) {
      expect(report).toMatchObject({
        verdict: "FAIL", signature_basis: "pinned", signatures_verified: 1, signatures_skipped: 1,
      });
      expect(report.findings).toEqual([
        expect.objectContaining({ kind: "checkpoint_unsigned", seq: unsigned.checkpoint_sequence }),
      ]);
    }
  });

  it("does not verify a non-null signature on a checkpoint marked unsigned", async () => {
    const entries = cleanEntries(1);
    const cp = { ...checkpoint(entries[0]!, false), unsigned: true };
    expect(cp.signature).not.toBeNull();
    const { code, reports } = await verifySourceAndCommand([...entries, cp], ["--public-key", PUBLIC_KEY]);
    expect(code).toBe(AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS);
    for (const report of reports) {
      expect(report).toMatchObject({ verdict: "FAIL", signatures_skipped: 1, signatures_verified: 0 });
      expect(report.findings).toEqual([expect.objectContaining({
        kind: "checkpoint_unsigned",
        seq: cp.checkpoint_sequence,
        message: expect.stringContaining("no signature was verified for it"),
      })]);
    }
  });

  it.each([
    { opts: { publicKey: PUBLIC_KEY }, basis: "pinned" },
    { opts: { trustEmbedded: true }, basis: "embedded" },
  ])("corrupt JSON retains the requested $basis policy", ({ opts, basis }) => {
    const report = verifyAuditChainContent("{", opts);
    expect(report).toMatchObject({ verdict: "FAIL", signature_basis: basis });
    expect(report.findings).toEqual([expect.objectContaining({ kind: "malformed_input" })]);
  });

  describe("regression guards: fully signed PASS", () => {
    it.each([
      { basis: "pinned", flags: ["--public-key", PUBLIC_KEY] },
      { basis: "embedded", flags: ["--trust-embedded"] },
    ])("fully verified checkpoints still PASS with $basis keys", async ({ basis, flags }) => {
      const entries = cleanEntries(CHECKPOINT_COUNT);
      const { code, reports } = await verifySourceAndCommand(
        [...entries, ...entries.map((entry) => checkpoint(entry, false))], flags,
      );
      expect(code).toBe(AUDIT_CHAIN_VERIFY_EXIT_OK);
      for (const report of reports) {
        expect(report).toMatchObject({
          verdict: "PASS", signature_basis: basis,
          signatures_verified: CHECKPOINT_COUNT, signatures_skipped: 0, findings: [],
        });
      }
    });
  });

  it.each([{ flags: [] }, { flags: ["--no-strict"] }])("zero checkpoints may PASS only with no key policy ($flags)", async ({ flags }) => {
    const { code, reports } = await verifySourceAndCommand(cleanEntries(1), flags);
    expect(code).toBe(AUDIT_CHAIN_VERIFY_EXIT_OK);
    for (const report of reports) {
      expect(report).toMatchObject({
        verdict: "PASS", signature_basis: "none", checkpoints_verified: 0,
        signatures_verified: 0, signatures_skipped: 0, findings: [],
      });
      expect(report.signature_coverage_scope).toContain("no-key verification with zero checkpoints may PASS without signature evidence");
      expect(report.signature_coverage_scope).toContain("legacy-anchor signatures are outside this verifier's checks");
      expect(report.signature_coverage_scope).toContain('type: "checkpoint"');
      expect(report.rotation_anchor_scope).not.toContain("signature_basis");
    }
  });

  it.each([
    { basis: "pinned", flags: ["--public-key", PUBLIC_KEY], exit: AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS },
    { basis: "embedded", flags: ["--trust-embedded"], exit: AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS },
    { basis: "pinned", flags: ["--public-key", PUBLIC_KEY, "--no-strict"], exit: AUDIT_CHAIN_VERIFY_EXIT_RELAXED_FINDINGS },
    { basis: "embedded", flags: ["--trust-embedded", "--no-strict"], exit: AUDIT_CHAIN_VERIFY_EXIT_RELAXED_FINDINGS },
  ])("zero checkpoints FAIL under the requested $basis policy ($flags)", async ({ basis, flags, exit }) => {
    const { code, reports } = await verifySourceAndCommand(cleanEntries(1), flags);
    expect(code).toBe(exit);
    for (const report of reports) {
      expect(report).toMatchObject({
        verdict: "FAIL", signature_basis: basis, checkpoints_verified: 0,
        signatures_verified: 0, signatures_skipped: 0,
        findings: [{ kind: "checkpoint_coverage_absent", message: "no checkpoint record was present to verify against the supplied key" }],
      });
      expect(report.signature_coverage_scope).toContain("checkpoint_coverage_absent");
    }
  });

  describe("regression guards: missing-key retained", () => {
    it.each([
      { flags: [], exit: AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS },
      { flags: ["--no-strict"], exit: AUDIT_CHAIN_VERIFY_EXIT_RELAXED_FINDINGS },
    ])("signed checkpoints without a trusted key retain missing-key findings ($flags)", async ({ flags, exit }) => {
      const entries = cleanEntries(1);
      const { code, reports } = await verifySourceAndCommand([...entries, checkpoint(entries[0]!, false)], flags);
      expect(code).toBe(exit);
      for (const report of reports) {
        expect(report).toMatchObject({ verdict: "FAIL", signatures_verified: 0, signatures_skipped: 0 });
        expect(report.findings).toEqual([
          expect.objectContaining({ kind: "checkpoint_signature_missing_key", seq: entries[0]!.seq }),
        ]);
      }
    });
  });

  it.each([
    { label: "string", unsigned: "false" },
    { label: "null", unsigned: null },
    { label: "number", unsigned: 0 },
    { label: "object", unsigned: {} },
    { label: "missing", unsigned: undefined },
  ])("rejects a $label unsigned discriminator before checking signatures", async ({ unsigned }) => {
    const entries = cleanEntries(1);
    // Keep the valid signature: only the invalid discriminator should fail.
    const cp = { ...checkpoint(entries[0]!, false), unsigned };
    const { code, reports } = await verifySourceAndCommand([...entries, cp], ["--public-key", PUBLIC_KEY]);
    expect(code).toBe(AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS);
    for (const report of reports) {
      expect(report).toMatchObject({ verdict: "FAIL", signatures_verified: 0, signatures_skipped: 0 });
      expect(report.findings).toEqual([expect.objectContaining({ kind: "schema_error", seq: cp.checkpoint_sequence })]);
    }
  });

  it.each([
    { label: "null", signature: null },
    { label: "missing", signature: undefined },
    { label: "invalid", signature: Buffer.from(new Uint8Array(SIGNING_SEED_BYTES * 2)).toString("base64url") }, // Ed25519 signatures contain two 32-byte components.
  ])("regression guard: a $label signature marked signed fails without incrementing skipped", async ({ signature }) => {
    const entries = cleanEntries(1);
    const cp = { ...checkpoint(entries[0]!, false), signature };
    const { code, reports } = await verifySourceAndCommand([...entries, cp], ["--public-key", PUBLIC_KEY]);
    expect(code).toBe(AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS);
    for (const report of reports) {
      expect(report).toMatchObject({ verdict: "FAIL", signatures_verified: 0, signatures_skipped: 0 });
      expect(report.findings).toEqual([expect.objectContaining({ kind: "checkpoint_signature_invalid" })]);
    }
  });

  it("rejects an unsigned checkpoint whose span lies below a rotation anchor", async () => {
    const entries = cleanEntries(CHECKPOINT_COUNT);
    const retained = entries[1]!;
    const cp = checkpoint(entries[0]!, true);
    const { code, reports } = await verifySourceAndCommand([
      retained, cp,
      { type: "rotation_anchor", base_sequence: retained.seq, base_prev_hash: retained.prev_hash },
    ], ["--public-key", PUBLIC_KEY]);
    expect(code).toBe(AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS);
    for (const report of reports) {
      expect(report.findings).toEqual([expect.objectContaining({ kind: "checkpoint_unsigned", seq: cp.checkpoint_sequence })]);
      expect(report.signatures_skipped).toBe(1);
    }
  });

  it("counts only the unsigned finding when the same checkpoint has a root mismatch", async () => {
    const entries = cleanEntries(1);
    const cp = { ...checkpoint(entries[0]!, true), root_hash: computeAuditRoot([]) };
    const { code, reports } = await verifySourceAndCommand([...entries, cp]);
    expect(code).toBe(AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS);
    for (const report of reports) {
      expect(report.findings.map((finding) => finding.kind)).toEqual(["checkpoint_root_mismatch", "checkpoint_unsigned"]);
      expect(report.findings.every((finding) => finding.seq === cp.checkpoint_sequence)).toBe(true);
      expect(report.signatures_skipped).toBe(report.findings.filter((finding) => finding.kind === "checkpoint_unsigned").length);
      expect(report.signatures_skipped).toBe(1);
    }
  });

  it("verifies the production writer's honestly unsigned export as FAIL", async () => {
    const storage = new MemoryStorage();
    const masterKey = new Uint8Array(SIGNING_SEED_BYTES).fill(1); // AES-256 uses the same 32-byte key width.
    const log = new AuditLog(storage, masterKey, { checkpointInterval: 1 }); // Each append must produce a checkpoint.
    try {
      await log.appendCritical({ layer: "l2", operation: "state_read", identity_id: "fixture", result: "success" });
      await log.flush();
      const chunks: string[] = [];
      const out = new Writable({
        write(chunk, _encoding, callback) { chunks.push(String(chunk)); callback(); },
      });
      await exportAuditChain(storage, out);
      const records = parseJsonl(chunks.join(""));
      const checkpoints = records.filter((record) => record.type === "checkpoint");
      expect(checkpoints).toHaveLength(1);
      expect(checkpoints[0]).toMatchObject({ unsigned: true, signature: null });
      expect(checkpoints[0]).not.toHaveProperty("public_key");
      const { code, reports } = await verifySourceAndCommand(records);
      expect(code).toBe(AUDIT_CHAIN_VERIFY_EXIT_STRICT_FINDINGS);
      for (const report of reports) {
        expect(report).toMatchObject({ verdict: "FAIL", signatures_verified: 0, signatures_skipped: checkpoints.length });
        expect(report.findings).toEqual([expect.objectContaining({ kind: "checkpoint_unsigned", seq: checkpoints[0]!.checkpoint_sequence })]);
      }
    } finally {
      masterKey.fill(0);
    }
  });

  it.each([
    { opts: { publicKey: PUBLIC_KEY }, basis: "pinned" },
    { opts: { trustEmbedded: true }, basis: "embedded" },
  ])("empty keyed input preserves $basis policy and reports absent coverage", ({ opts, basis }) => {
    for (const content of ["", "\n"]) {
      const report = verifyAuditChainContent(content, opts);
      expect(report).toMatchObject({ verdict: "FAIL", signature_basis: basis, checkpoints_verified: 0 });
      expect(report.findings.map((finding) => finding.kind)).toEqual(["checkpoint_coverage_absent", "empty_input"]);
      expect(report.signature_coverage_scope).toContain("checkpoint_coverage_absent");
    }
  });

});
