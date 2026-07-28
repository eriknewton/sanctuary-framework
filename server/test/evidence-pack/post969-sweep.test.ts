/**
 * Sanctuary MCP Server - Evidence Pack: post-#969 sweep regressions (F-1/F-2/F-3)
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dry-bar sweep 2026-07-27 (fresh Codex lens over main 7ded8d8f), three
 * confirmed findings, one shared shape: an UNDETERMINED state (corrupt file,
 * malformed record, unverified planted file) collapsing into a DEFINITIVE
 * signed claim (verified-empty census, complete/empty export, "carries no
 * evidentiary content").
 *
 *  - F-1: the hub agent registry reader is best-effort BY PINNED DESIGN
 *    (corruption -> [] for the dashboard consumer), so the pack minted the
 *    definitive `empty_verified` "No wrapped AI harnesses are recorded"
 *    witness over a corrupt plaintext file. The pack now consumes a STRICT
 *    reader that reports absent / ok / unreadable distinctly.
 *  - F-2: a parse-valid but shape-invalid `_audit_checkpoints` record hit the
 *    P1-A "legitimate control record" skip arm uncounted, so the pack signed
 *    the audit-chain export as complete or definitively empty over a
 *    malformed checkpoint. The skip is now KEY-AWARE.
 *  - F-3: ANY `._*` name was exempt from the foreign-file refusal, so a
 *    planted `._counsel-notes.md` survived unmanifested while the SIGNED
 *    recipe said it carried no evidentiary content. The exemption now
 *    requires name pairing with a pack filename AND the AppleDouble magic.
 *
 * TEST RULE (from the sweep spec): the far side is the REAL pack outcome path
 * fed by REAL corrupt state on disk -- the shipped strict reader over a real
 * file, the shipped exporter over a real FilesystemStorage fortress -- never a
 * mock of the reader.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { isAuditRotationAnchorEnvelope } from "../../src/audit/checkpoint-shape.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { AuditLog, AUDIT_EPOCH_KEYS_KEY } from "../../src/operational/audit-log.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import {
  exportAuditChain,
  AUDIT_EXPORT_CHECKPOINT_NAMESPACE,
  AUDIT_EXPORT_CONTROL_KEYS,
} from "../../src/cli/audit-chain-export.js";
import {
  gatherDiscreteExports,
  readHubAgentsSource,
  writePackDirectory,
} from "../../src/evidence-pack/cli.js";
import { buildInventorySnapshot } from "../../src/evidence-pack/inventory.js";
import {
  APPLEDOUBLE_MAGIC,
  APPLEDOUBLE_VERSION_2,
  MAX_APPLEDOUBLE_FORK_BYTES,
} from "../../src/evidence-pack/pack-files.js";
import {
  buildEvidencePack,
  MANIFEST_FILENAME,
  REPORT_FILENAME,
  type AuditReadData,
  type BuildEvidencePackDeps,
} from "../../src/evidence-pack/generate.js";
import {
  emptyVerified,
  populated,
  type ReadOutcome,
} from "../../src/evidence-pack/read-outcome.js";
import { verifyAuditChainContent } from "../../src/cli/audit-chain-verify.js";
import { bytesToString, toBase64url } from "../../src/core/encoding.js";
import type {
  EvidencePack,
  EvidencePackInput,
  InventorySnapshot,
  RetentionFacts,
} from "../../src/evidence-pack/types.js";
import {
  localAgentsFilePath,
  writePersistedLocalAgents,
} from "../../src/hub/agent-registry-persistence.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import { Writable } from "node:stream";

// ── shared fixtures ──────────────────────────────────────────────────

let masterKey: Uint8Array;
let signer: StoredIdentity;

beforeEach(async () => {
  masterKey = generateRandomKey(32);
  const storage = new MemoryStorage();
  const identityManager = new IdentityManager(storage, masterKey);
  const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("post969-law", identityEncKey, "pw");
  await identityManager.save(storedIdentity);
  const primary = identityManager.getDefault();
  if (!primary) throw new Error("fixture: no primary identity");
  signer = primary;
});

const dirs: string[] = [];
afterEach(async () => {
  for (const d of dirs.splice(0)) {
    await rm(d, { recursive: true, force: true }).catch(() => undefined);
  }
});

async function tmpDir(prefix: string): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

function entry(timestamp: string, operation: string): AuditEntry {
  return {
    timestamp,
    layer: "l2",
    operation,
    identity_id: "agent-a",
    result: "success",
  };
}

const RETENTION: RetentionFacts = {
  max_entries: 100_000,
  retained_total: 1,
  max_total_size_bytes: 100 * 1024 * 1024,
  retained_total_size_bytes: 100,
  ever_pruned: false,
  earliest_retained_at: "2026-04-02T10:00:00.000Z",
  daemon_store: { status: "absent", included_entry_count: 0 },
};

function deps(): BuildEvidencePackDeps {
  const audit: ReadOutcome<AuditReadData> = populated({
    entries: [entry("2026-04-02T10:00:00.000Z", "gate_allow:x")],
    retention: RETENTION,
  });
  return { audit, signer, masterKey };
}

function input(over: Partial<EvidencePackInput> = {}): EvidencePackInput {
  return {
    firm_name: "Post969 Test Law LLP",
    quarter: { year: 2026, quarter: 2 },
    generated_at_override: "2026-07-27T00:00:00.000Z",
    custody: populated({
      custody_mode: "passphrase",
      outbound_denied_by_default: populated(true),
    }),
    ...over,
  };
}

function reportText(pack: EvidencePack): string {
  const report = pack.files.find((f) => f.filename === REPORT_FILENAME);
  if (!report) throw new Error("expected a report file");
  return report.content;
}

/** Render a pack whose agents inventory came from the REAL on-disk registry read. */
function packWithAgentsFrom(fortressRoot: string): EvidencePack {
  const snapshot: InventorySnapshot = buildInventorySnapshot({
    agents: readHubAgentsSource(fortressRoot),
    proxyServers: { ok: true, records: [] },
    observedDestinations: { ok: true, records: [] },
  });
  return buildEvidencePack({ ...input(), inventory: snapshot }, deps());
}

function agentRecord(over: Partial<LocalAgentRecord> = {}): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: "agent-x",
    identity_id: "id-1",
    harness: "claude_code",
    model_provider: {
      vendor: "anthropic",
      model_id: "claude-opus-4",
      runs_locally: false,
    },
    policy_id: "pol-1",
    status: "active",
    budget_summary: { last_refreshed_at: "2026-07-01T00:00:00.000Z" },
    last_activity_at: "2026-07-10T00:00:00.000Z",
    wrapped_at: "2026-06-15T00:00:00.000Z",
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: true,
      can_change_template: true,
    },
    ...over,
  };
}

// ── F-1: corrupt hub registry must never sign a verified-empty census ────────

describe("F-1: a corrupt local-agents.json is a disclosed read failure, never 'No wrapped AI harnesses are recorded'", () => {
  const DEFINITIVE = "No wrapped AI harnesses are recorded";

  async function fortressWithRegistryBytes(content: string): Promise<string> {
    const root = await tmpDir("sanctuary-post969-f1-");
    const filePath = localAgentsFilePath(root);
    await mkdir(join(root, "state", "_hub"), { recursive: true });
    await writeFile(filePath, content, "utf-8");
    return root;
  }

  // FAIL-WITHOUT-FIX: on pre-fix main the best-effort reader mapped each of
  // these real on-disk corruptions to ok+[] and the signed report rendered the
  // definitive census line.
  const CORRUPTIONS: Array<[string, string]> = [
    ["invalid JSON", "{ not json at all"],
    ["agents not an array", '{"version":"1.1","agents":"not-an-array"}'],
    ["truncated file", '{"version":"1.1","agents":[{"agent_'],
    [
      "parse-valid but wrong record shape",
      '{"version":"1.1","agents":[{"agent_id":42}]}',
    ],
    ["wrong top-level version", '{"version":"9.9","agents":[]}'],
  ];

  for (const [label, bytes] of CORRUPTIONS) {
    it(`${label}: read_failed at the source AND the incomplete note in the signed report`, async () => {
      const root = await fortressWithRegistryBytes(bytes);
      const source = readHubAgentsSource(root);
      expect(source.ok).toBe(false);
      expect(source.records).toEqual([]);
      // Host-independent reason: no tmp path, no home dir.
      expect(source.reason).toBeDefined();
      expect(source.reason).not.toContain(root);
      expect(source.reason).not.toContain(tmpdir());

      const report = reportText(packWithAgentsFrom(root));
      expect(report).not.toContain(DEFINITIVE);
      expect(report).toContain(
        "could not be read for this period, so this section is INCOMPLETE"
      );
      expect(report).toContain("NOT a statement that none exist");
    });
  }

  it("an ABSENT registry file is still an honest verified-empty (the definitive line survives)", async () => {
    const root = await tmpDir("sanctuary-post969-f1-absent-");
    const source = readHubAgentsSource(root);
    expect(source).toEqual({ ok: true, records: [] });
    const report = reportText(packWithAgentsFrom(root));
    expect(report).toContain(DEFINITIVE);
  });

  it("a VALID registry written by the shipped writer renders its rows (populated path intact)", async () => {
    const root = await tmpDir("sanctuary-post969-f1-valid-");
    writePersistedLocalAgents(root, [agentRecord()]);
    const source = readHubAgentsSource(root);
    expect(source.ok).toBe(true);
    expect(source.records).toHaveLength(1);
    const report = reportText(packWithAgentsFrom(root));
    expect(report).toContain("agent-x");
    expect(report).not.toContain(DEFINITIVE);
  });

  it("probe-10: Markdown-hostile persisted fields are neutralized before the signed table", async () => {
    const root = await tmpDir("sanctuary-post969-f1-md-");
    writePersistedLocalAgents(root, [
      agentRecord({ agent_id: "evil|agent\ninjected-row" }),
    ]);
    const report = reportText(packWithAgentsFrom(root));
    // Pipe escaped, newline collapsed: the field cannot terminate its cell or
    // fabricate a new table row in the signed report.
    expect(report).toContain("evil\\|agent injected-row");
    expect(report).not.toContain("evil|agent\ninjected-row");
  });

  // FAIL-WITHOUT-FIX (G4, re-gate round 2): with pipes escaped but not
  // backslashes, a crafted backslash-pipe pair rendered as an ESCAPED
  // backslash followed by a LIVE `|` delimiter, shifting cells within the row.
  it("G4: a crafted backslash-pipe field cannot re-arm the cell delimiter", async () => {
    const root = await tmpDir("sanctuary-post969-g4-");
    writePersistedLocalAgents(root, [
      // agent_id carries a literal backslash followed by a pipe.
      agentRecord({ agent_id: "evil\\|shift" }),
    ]);
    const report = reportText(packWithAgentsFrom(root));
    // Backslash escaped FIRST, then the pipe: three backslashes + pipe in the
    // artifact, so both characters are inert.
    expect(report).toContain("evil\\\\\\|shift");
  });

  // FAIL-WITHOUT-FIX (G2, re-gate round 2; both lenses): the strict reader's
  // `existsSync` gate returned false for EVERY failure, so a permission-denied
  // `state/_hub` directory read as "absent" -> ok+[] -> the definitive signed
  // census line over a registry whose existence was never determined.
  it.skipIf(typeof process.getuid === "function" && process.getuid() === 0)(
    "G2: an unreadable state/_hub directory is a disclosed read failure, never a verified-empty census",
    async () => {
      const root = await tmpDir("sanctuary-post969-g2-");
      const hubDir = join(root, "state", "_hub");
      await mkdir(hubDir, { recursive: true });
      await writeFile(
        join(hubDir, "local-agents.json"),
        '{"version":"1.1","agents":[]}',
        "utf-8"
      );
      await chmod(hubDir, 0o000);
      try {
        const source = readHubAgentsSource(root);
        expect(source.ok).toBe(false);
        expect(source.records).toEqual([]);
        const report = reportText(packWithAgentsFrom(root));
        expect(report).not.toContain(DEFINITIVE);
        expect(report).toContain(
          "could not be read for this period, so this section is INCOMPLETE"
        );
      } finally {
        await chmod(hubDir, 0o700);
      }
    }
  );
});

// ── F-2: malformed checkpoint records are COUNTED, never silently dropped ────

describe("F-2: a parse-valid but shape-invalid audit checkpoint is counted and forces read_failed", () => {
  const enc = new TextEncoder();
  const GEN_AT = "2026-07-27T00:00:00.000Z";

  async function freshFortress() {
    const root = await tmpDir("sanctuary-post969-f2-");
    const statePath = join(root, "state");
    const storage = new FilesystemStorage(statePath);
    const key = generateRandomKey();
    return { root, statePath, storage, key };
  }

  // FAIL-WITHOUT-FIX: on pre-fix main this record hit the uncounted control-
  // record skip arm; checkpointsSkipped stayed 0 and the pack rendered the
  // export as definitively empty.
  it("the sweep repro: _audit empty + one malformed checkpoint record is NOT 'the audit-chain export was empty'", async () => {
    const f = await freshFortress();
    await f.storage.write(
      AUDIT_EXPORT_CHECKPOINT_NAMESPACE,
      "audit-checkpoint-00000000000000000001",
      enc.encode(
        '{"checkpoint_kind":"audit-checkpoint","checkpoint_sequence":"not-a-number"}'
      )
    );
    const chunks: string[] = [];
    const sink = new Writable({
      write(chunk, _enc2, cb) {
        chunks.push(String(chunk));
        cb();
      },
    });
    const summary = await exportAuditChain(f.storage, sink);
    expect(summary.checkpointsListed).toBe(1);
    expect(summary.checkpointsExported).toBe(0);
    expect(summary.checkpointsSkipped).toBe(1);

    const out = await gatherDiscreteExports(f.storage, f.key, "fortress-1", GEN_AT);
    expect(out.audit_chain.status).toBe("read_failed");
    if (out.audit_chain.status === "read_failed") {
      expect(out.audit_chain.reason).toMatch(/skipped/i);
    }
  });

  // FAIL-WITHOUT-FIX (G1, re-gate round 2, Codex): the exporter's
  // hand-duplicated validator had drifted WEAKER than the runtime's, so a
  // record missing schema_version, signature_algorithm, and payload_encoding
  // (numeric sequences and string hashes present) EXPORTED uncounted and the
  // pack could sign a populated export over it. The shared pure predicate in
  // audit/checkpoint-shape.ts closes the drift structurally.
  it("G1: a checkpoint missing schema_version/signature_algorithm/payload_encoding is counted, never exported", async () => {
    const f = await freshFortress();
    const driftedShape = {
      checkpoint_kind: "audit-checkpoint",
      checkpoint_sequence: 1,
      from_sequence: 1,
      // Even a well-formed 64-hex hash: the missing fields alone must fail it.
      root_hash: "a".repeat(64),
      previous_checkpoint_sequence: 0,
      signed_at: "2026-07-01T00:00:00.000Z",
      signer_kid: null,
      signature: null,
      unsigned: true,
    };
    await f.storage.write(
      AUDIT_EXPORT_CHECKPOINT_NAMESPACE,
      "audit-checkpoint-00000000000000000001",
      enc.encode(JSON.stringify(driftedShape))
    );
    const chunks: string[] = [];
    const sink = new Writable({
      write(chunk, _enc2, cb) {
        chunks.push(String(chunk));
        cb();
      },
    });
    const summary = await exportAuditChain(f.storage, sink);
    expect(summary.checkpointsListed).toBe(1);
    expect(summary.checkpointsExported).toBe(0);
    expect(summary.checkpointsSkipped).toBe(1);
    // The malformed record did NOT ship in the export bytes.
    expect(chunks.join("")).toBe("");

    const out = await gatherDiscreteExports(f.storage, f.key, "fortress-1", GEN_AT);
    expect(out.audit_chain.status).toBe("read_failed");
  });

  it("G5: the control-key allowlist carries the audit log's own epoch-keys key (one shared definition)", () => {
    expect(AUDIT_EXPORT_CONTROL_KEYS).toContain(AUDIT_EPOCH_KEYS_KEY);
    expect(AUDIT_EXPORT_CONTROL_KEYS).toContain("__custody_epoch_keys");
  });

  it("an unrecognized non-control key with a parse-valid record is counted too (closed allowlist)", async () => {
    const f = await freshFortress();
    await f.storage.write(
      AUDIT_EXPORT_CHECKPOINT_NAMESPACE,
      "sneaky-note",
      enc.encode('{"note":"planted"}')
    );
    const summary = await exportAuditChain(f.storage, new Writable({
      write(_c, _e, cb) {
        cb();
      },
    }));
    expect(summary.checkpointsSkipped).toBe(1);
  });

  it("P1-A regression: a healthy fortress with a REAL __head_anchor control record still exports with zero skipped", async () => {
    const f = await freshFortress();
    const auditLog = new AuditLog(f.storage, f.key);
    await auditLog.appendCritical({
      layer: "l1",
      operation: "healthy-op",
      identity_id: "agent-a",
      result: "success",
    });
    await auditLog.flush();
    // Control for the control: prove the head-anchor control record actually
    // exists in the namespace this test claims to exercise, so a future
    // storage-layout change cannot turn this into a vacuous pass.
    const keys = (await f.storage.list(AUDIT_EXPORT_CHECKPOINT_NAMESPACE)).map(
      (m) => m.key
    );
    expect(keys).toContain("__head_anchor");
    expect(AUDIT_EXPORT_CONTROL_KEYS).toContain("__head_anchor");

    const summary = await exportAuditChain(f.storage, new Writable({
      write(_c, _e, cb) {
        cb();
      },
    }));
    expect(summary.checkpointsSkipped).toBe(0);
    expect(summary.entriesSkipped).toBe(0);

    const out = await gatherDiscreteExports(f.storage, f.key, "fortress-1", GEN_AT);
    expect(out.audit_chain.status).toBe("populated");
  });
});

// ── R3: rotation anchors need the runtime's SHAPE (incl. mac), and the ───────
// ── offline verifier is honest about what it does not prove ──────────────────

describe("R3: a mac-less rotation anchor is counted corrupt, and the exported anchor carries its mac", () => {
  const enc = new TextEncoder();
  const GEN_AT = "2026-07-27T00:00:00.000Z";
  const MARKER = "__sanctuary_audit_rotation_anchor_v1";

  async function freshFortress() {
    const root = await tmpDir("sanctuary-post969-r3-");
    const statePath = join(root, "state");
    const storage = new FilesystemStorage(statePath);
    const key = generateRandomKey();
    return { root, statePath, storage, key };
  }

  function collectExport() {
    const chunks: string[] = [];
    const sink = new Writable({
      write(chunk, _enc2, cb) {
        chunks.push(String(chunk));
        cb();
      },
    });
    return { chunks, sink };
  }

  // FAIL-WITHOUT-FIX (R3, Codex): the exporter's local anchor guard required
  // marker + data only, NO mac, while the runtime requires and MAC-verifies
  // mac. A forged mac-less anchor consistent with a truncated suffix was
  // rejected by the runtime yet exported UNSKIPPED, and the standalone
  // verifier (linkage-only) could PASS it end to end.
  it("Codex repro: a forged marker+data anchor with no mac is counted skipped and forces read_failed", async () => {
    const f = await freshFortress();
    await f.storage.write(
      AUDIT_EXPORT_CHECKPOINT_NAMESPACE,
      "__rotation_anchor",
      enc.encode(
        JSON.stringify({
          [MARKER]: true,
          data: { base_sequence: 5, base_prev_hash: "f".repeat(64) },
        })
      )
    );
    const { chunks, sink } = collectExport();
    const summary = await exportAuditChain(f.storage, sink);
    expect(summary.checkpointsListed).toBe(1);
    expect(summary.checkpointsExported).toBe(0);
    expect(summary.checkpointsSkipped).toBe(1);
    // The forged anchor shipped zero export bytes.
    expect(chunks.join("")).toBe("");

    const out = await gatherDiscreteExports(f.storage, f.key, "fortress-1", GEN_AT);
    expect(out.audit_chain.status).toBe("read_failed");
  });

  it("a shape-complete anchor exports WITH its mac, so a key-holding verifier can check authenticity", async () => {
    const f = await freshFortress();
    // Fixture mirrors the runtime writer's envelope byte layout (marker +
    // data + unpadded-base64url mac); authenticity is deliberately NOT the
    // exporter's claim, so any well-formed mac exercises the path.
    const mac = toBase64url(new Uint8Array(32).fill(7));
    await f.storage.write(
      AUDIT_EXPORT_CHECKPOINT_NAMESPACE,
      "__rotation_anchor",
      enc.encode(
        JSON.stringify({
          [MARKER]: true,
          data: { base_sequence: 5, base_prev_hash: "f".repeat(64) },
          mac,
        })
      )
    );
    const { chunks, sink } = collectExport();
    const summary = await exportAuditChain(f.storage, sink);
    expect(summary.checkpointsExported).toBe(1);
    expect(summary.checkpointsSkipped).toBe(0);
    const record = JSON.parse(chunks.join("").trim());
    expect(record.type).toBe("rotation_anchor");
    expect(record.mac).toBe(mac);

    // The standalone verifier parses the mac-bearing anchor without complaint
    // and stamps the honesty bound into its report.
    const report = verifyAuditChainContent(chunks.join(""));
    expect(
      report.findings.filter(
        (fi) => fi.kind === "malformed_input" || fi.kind === "schema_error"
      )
    ).toEqual([]);
    expect(report.rotation_anchor_scope).toContain(
      "does not prove the anchor is authentic"
    );
    expect(report.rotation_anchor_scope).toContain("fortress runtime");
  });

  // FAIL-WITHOUT-FIX (R4, final verify): the round-3 mac check was
  // alphabet-only, so `mac: "A"` (or any impossible-length or
  // non-round-tripping string) passed the shape and exported unskipped while
  // the runtime rejected it at MAC compare. The predicate now accepts EXACTLY
  // the strings the legitimate writer can emit: canonical unpadded base64url
  // of a 32-byte HMAC-SHA256 (length 43, final char's unused low bits zero).
  it("R4: non-canonical mac strings (impossible length, padded, non-round-tripping) are counted skipped and force read_failed", async () => {
    const goodMac = toBase64url(new Uint8Array(32).fill(7));
    expect(goodMac).toHaveLength(43);
    const badMacs: Array<[string, string]> = [
      ["alphabet-valid but impossible length", "A"],
      ["padded base64 of 32 bytes", `${goodMac}=`],
      ["length 44", `${goodMac}A`],
      // 43 chars, alphabet-valid, but the final char's 2 unused low bits are
      // set ("B" = index 1), so it does not round-trip through decode/encode.
      ["43 chars but non-round-tripping final char", `${goodMac.slice(0, 42)}B`],
    ];
    for (const [label, mac] of badMacs) {
      const f = await freshFortress();
      await f.storage.write(
        AUDIT_EXPORT_CHECKPOINT_NAMESPACE,
        "__rotation_anchor",
        enc.encode(
          JSON.stringify({
            [MARKER]: true,
            data: { base_sequence: 5, base_prev_hash: "f".repeat(64) },
            mac,
          })
        )
      );
      const { chunks, sink } = collectExport();
      const summary = await exportAuditChain(f.storage, sink);
      expect(summary.checkpointsSkipped, label).toBe(1);
      expect(summary.checkpointsExported, label).toBe(0);
      expect(chunks.join(""), label).toBe("");
      const out = await gatherDiscreteExports(f.storage, f.key, "fortress-1", GEN_AT);
      expect(out.audit_chain.status, label).toBe("read_failed");
    }
  });

  it("R4: a REAL runtime-written rotation anchor passes the shared predicate and exports unskipped with its mac", async () => {
    // Drive the runtime's own rotation path: append past maxEntries so
    // maybeRotate prunes a prefix and writeRotationAnchor persists the anchor.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const writer = new AuditLog(storage, masterKey, { maxEntries: 5 });
    for (let i = 0; i < 12; i++) {
      await writer.appendCritical({
        layer: "l1",
        operation: `op-${i}`,
        identity_id: "id-1",
        result: "success",
      });
    }
    await writer.flush();
    const raw = await storage.read(AUDIT_EXPORT_CHECKPOINT_NAMESPACE, "__rotation_anchor");
    expect(raw).not.toBeNull();
    const anchor = JSON.parse(bytesToString(raw!)) as { mac: string };
    // The no-legitimate-anchor-miscounted guarantee, empirically: the shared
    // predicate accepts what the real writer wrote.
    expect(isAuditRotationAnchorEnvelope(anchor)).toBe(true);

    const { chunks, sink } = collectExport();
    const summary = await exportAuditChain(storage, sink);
    expect(summary.checkpointsSkipped).toBe(0);
    expect(summary.entriesSkipped).toBe(0);
    const anchorLines = chunks
      .join("")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { type: string; mac?: string })
      .filter((r) => r.type === "rotation_anchor");
    expect(anchorLines).toHaveLength(1);
    expect(anchorLines[0]!.mac).toBe(anchor.mac);
  });

  it("the signed section-10 prose states the offline anchor check's bound (linkage and shape, not authenticity)", () => {
    const pack = buildEvidencePack(
      {
        ...input(),
        discrete_exports: {
          transparency: emptyVerified(),
          audit_chain: populated('{"type":"entry"}\n'),
          anchor: emptyVerified(),
        },
      },
      deps()
    );
    const report = reportText(pack);
    expect(report).toContain(
      "checks rotation anchors for shape and linkage ONLY"
    );
    expect(report).toContain(
      "cannot and does not prove anchor authenticity"
    );
    expect(report).toContain("the fortress runtime, which holds that key");
  });
});

// ── F-3: the AppleDouble exemption is verified, not name-pattern-trusted ─────

describe("F-3: planted `._*` files are refused; only verified forks of the pack's own files are exempt", () => {
  function simplePack(): EvidencePack {
    return buildEvidencePack(input(), deps());
  }

  // FAIL-WITHOUT-FIX: on pre-fix main writePackDirectory resolved and the
  // planted Markdown survived beside the pack, unmanifested, while the signed
  // recipe said ignored `._*` files carry no evidentiary content.
  it("refuses to write beside a planted `._counsel-notes.md` (unpaired name)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-post969-f3-"));
    dirs.push(dir);
    await writeFile(join(dir, "._counsel-notes.md"), "# privileged notes\n", "utf-8");
    await expect(writePackDirectory(dir, simplePack())).rejects.toThrow(
      /did not write/
    );
    // Fail-closed: nothing written, the operator's file untouched.
    expect(await readdir(dir)).toEqual(["._counsel-notes.md"]);
  });

  it("refuses a fake fork that pairs with a pack filename but lacks the AppleDouble magic", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-post969-f3-fake-"));
    dirs.push(dir);
    // Name-paired with the conditional transparency export, content is JSON:
    // exactly the smuggling shape the name-pattern exemption allowed.
    await writeFile(
      join(dir, "._transparency-bundle.json"),
      '{"planted":"evidence-like content"}',
      "utf-8"
    );
    await expect(writePackDirectory(dir, simplePack())).rejects.toThrow(
      /did not write/
    );
    expect(await readdir(dir)).toEqual(["._transparency-bundle.json"]);
  });

  it("still tolerates a GENUINE AppleDouble fork of a pack file (magic verified), so the tool stays usable", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-post969-f3-real-"));
    dirs.push(dir);
    const fork = Buffer.from([...APPLEDOUBLE_MAGIC, 0x00, 0x02, 0x00, 0x00]);
    await writeFile(join(dir, "._00_pack_manifest.json"), fork);
    await expect(writePackDirectory(dir, simplePack())).resolves.toBeUndefined();
    const after = await readdir(dir);
    expect(after).toContain("._00_pack_manifest.json");
    expect(after).toContain(MANIFEST_FILENAME);
    // Sanity: the fork bytes were not swept or rewritten.
    expect(await readFile(join(dir, "._00_pack_manifest.json"))).toEqual(fork);
  });

  // FAIL-WITHOUT-FIX (G3a, re-gate round 2): a 4-byte magic forgery passed the
  // round-1 check; the header check now also requires the AppleDouble
  // version-2 field.
  it("G3: refuses a fake fork forging only the 4 magic bytes (no version field)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-post969-g3a-"));
    dirs.push(dir);
    await writeFile(
      join(dir, "._transparency-bundle.json"),
      Buffer.concat([
        Buffer.from(APPLEDOUBLE_MAGIC),
        Buffer.from("planted content, not a version field"),
      ])
    );
    await expect(writePackDirectory(dir, simplePack())).rejects.toThrow(
      /did not write/
    );
    expect(await readdir(dir)).toEqual(["._transparency-bundle.json"]);
  });

  it("G3: refuses a header-forged fork exceeding the size bound", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-post969-g3b-"));
    dirs.push(dir);
    await writeFile(
      join(dir, "._transparency-bundle.json"),
      Buffer.concat([
        Buffer.from([...APPLEDOUBLE_MAGIC, ...APPLEDOUBLE_VERSION_2]),
        Buffer.alloc(MAX_APPLEDOUBLE_FORK_BYTES),
      ])
    );
    await expect(writePackDirectory(dir, simplePack())).rejects.toThrow(
      /did not write/
    );
    expect(await readdir(dir)).toEqual(["._transparency-bundle.json"]);
  });

  it("the SIGNED recipe claims exactly what the checks prove, and nothing more (G3b honesty)", () => {
    const report = reportText(simplePack());
    // The blanket unverified claim is gone...
    expect(report).not.toContain("carries no evidentiary content");
    // ...replaced by the checked, narrowed rule the enforcement actually
    // applies, plus the explicit bound on what the checks do NOT prove.
    expect(report).toContain(
      "pass the generator's AppleDouble header and size checks"
    );
    expect(report).toContain("AppleDouble signature and version bytes");
    expect(report).toContain("do NOT prove its content is inert");
    expect(report).toContain("OUTSIDE the pack's signed claims");
  });
});
