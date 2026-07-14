/**
 * F2 BLOCKER-1 (adversarial re-gate round 3, 2026-07-14) REQUIRED REPRO.
 *
 * The round-1/2 fix routed the sealed-region verdict into cleanliness claims
 * per-surface (whack-a-mole). Round 3 collapsed it into ONE shared chokepoint
 * (`AuditLog.getAuditChainVerdict()`) that folds BOTH routine suffix findings
 * AND the sealed-region crypto verdict. This test is the end-to-end proof that
 * NO clean-claiming surface reports a false green over a tampered sealed entry:
 *
 *   - a migrated fortress with an intact suffix and a boundary-sealed prefix,
 *   - one sealed prefix entry tampered IN PLACE (hash_mismatch, not deletion),
 *   - the two agent/operator-facing surfaces the gate named:
 *       (a) `buildAuditDigest`      -> `chain_verified` MUST be false,
 *       (b) `sanctuary_audit_search`-> MUST deny (never a `verified_against_
 *           audit_chain` stamp).
 *
 * The operator reader intentionally SKIPS re-reading the sealed region on the
 * hot load path (that is the whole F2 fix), so the tamper is invisible to a
 * plain `query()`. The chokepoint is what re-verifies the sealed region and
 * turns the surfaces honest.
 */

import { chmod, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import { migrateFortressAuditStoreSplit, AUDIT_DAEMON_NAMESPACE } from "../../src/operational/audit-store-split.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createAgentNativeCooperativeTools } from "../../src/agent-native/cooperative-surface.js";
import { ApprovalProofStore, fingerprintIdentityId, type SessionBinding } from "../../src/agent-native/safety-base.js";
import { buildAuditDigest } from "../../src/principal-policy/posture.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { ToolDefinition } from "../../src/router.js";

const dirs: string[] = [];

afterEach(async () => {
  for (const d of dirs.splice(0)) {
    await chmod(d, 0o700).catch(() => undefined);
    await chmod(join(d, "state", AUDIT_DAEMON_NAMESPACE), 0o700).catch(() => undefined);
    await rm(d, { recursive: true, force: true }).catch(() => undefined);
  }
});

async function callTool(
  tools: ToolDefinition[],
  name: string,
  args: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`missing tool: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

/**
 * Build a migrated fortress: a sealed prefix (pre-split entries) + an intact
 * post-split suffix, with the full agent cooperative surface wired over the
 * SAME storage. Returns handles plus the on-disk audit dir for tampering.
 */
async function migratedFortressWithSurface() {
  const root = await mkdtemp(join(tmpdir(), "sanctuary-f2-blocker1-"));
  dirs.push(root);
  const statePath = join(root, "state");
  const storage = new FilesystemStorage(statePath);
  const masterKey = generateRandomKey();

  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const approvalProofStore = new ApprovalProofStore();
  let active: SessionBinding | undefined;

  const { tools: l1Tools, identityManager, namespaceRegistry } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog,
    { currentSessionBinding: () => active },
  );
  await identityManager.load();
  const identity = await callTool(l1Tools, "identity_create", { label: "agent-a" });
  const identityId = identity.identity_id as string;
  active = { identity_id: identityId, requester_identity_fingerprint: fingerprintIdentityId(identityId) };

  const { tools: facadeTools } = createAgentNativeCooperativeTools({
    identityManager,
    namespaceRegistry,
    auditLog,
    currentSessionBinding: () => active,
    primitiveTools: l1Tools,
    storage,
    approvalProofStore,
  });

  // Pre-split history (becomes the sealed prefix).
  for (let i = 0; i < 4; i++) {
    await auditLog.appendCritical({
      layer: "l1",
      operation: `pre-split-op-${i}`,
      identity_id: identityId,
      result: "success",
    });
  }
  await auditLog.flush();

  // Seal the prefix behind the boundary.
  await migrateFortressAuditStoreSplit({ storage, masterKey });

  // Intact post-split suffix (writes a suffix head anchor + a searchable row).
  await callTool(facadeTools, "sanctuary_remember", { key: "suffix_key", value: "suffix-value" });
  await auditLog.flush();

  return { root, statePath, storage, masterKey, auditLog, facadeTools, identityId };
}

/** Tamper one sealed prefix entry IN PLACE so its recomputed hash diverges. */
async function tamperSealedEntry(statePath: string): Promise<void> {
  const auditDir = join(statePath, "_audit");
  const files = (await readdir(auditDir)).filter((f) => f.startsWith("entry-")).sort();
  const target = join(auditDir, files[1]!); // a mid-prefix sealed entry
  const raw = JSON.parse(await readFile(target, "utf-8"));
  raw.timestamp = "1999-01-01T00:00:00.000Z"; // covered by the entry hash
  await writeFile(target, JSON.stringify(raw));
}

describe("F2 BLOCKER-1: no clean-claiming surface reports a false green over a tampered sealed entry", () => {
  it("the shared chokepoint flips to `findings` when a sealed entry is tampered in place", async () => {
    const f = await migratedFortressWithSurface();
    // Fresh operator reader: a plain query skips the sealed region and looks clean.
    const before = await new AuditLog(f.storage, f.masterKey).getAuditChainVerdict();
    expect(before.status).toBe("verified");

    await tamperSealedEntry(f.statePath);

    const after = await new AuditLog(f.storage, f.masterKey).getAuditChainVerdict();
    expect(after.status).toBe("findings");
    expect(after.sealed_region.status).toBe("hash_mismatch");
  });

  it("buildAuditDigest reports chain_verified=false / chain_verdict=findings over the tampered sealed prefix", async () => {
    const f = await migratedFortressWithSurface();
    await tamperSealedEntry(f.statePath);

    const digest = await buildAuditDigest({
      auditLog: new AuditLog(f.storage, f.masterKey),
      originMachine: "fortress:test",
      now: Date.now(),
    });
    expect(digest.chain_verified).toBe(false);
    expect(digest.chain_verdict).toBe("findings");
    // Belt-and-suspenders: the digest never emits a "verified"-flavoured claim.
    expect(JSON.stringify(digest)).not.toContain("\"chain_verified\":true");
  });

  it("sanctuary_audit_search denies (never stamps verified_against_audit_chain) over the tampered sealed prefix", async () => {
    const f = await migratedFortressWithSurface();
    await tamperSealedEntry(f.statePath);

    const search = await callTool(f.facadeTools, "sanctuary_audit_search", {
      query: "sanctuary_remember",
      scope: "own_signed",
    });
    expect(search.denied).toBe(true);
    expect(JSON.stringify(search)).not.toContain("verified_against_audit_chain");
  });
});
