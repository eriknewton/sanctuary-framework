/**
 * Wired-consumer + isolation regression tests for the SDW vault tools
 * (IC-15/16, IC-27, IC-28 companion; AGENTS.md assurance rule 4).
 *
 * What the unit-level D2 tests cannot reach:
 *   - that the PRODUCTION composition root (`createSanctuaryServer`) actually
 *     registers `sdw_export` / `sdw_import` on the wire
 *     catalog, and that the built bundle (`dist/index.js`) carries them
 *     (pre-fix they had zero production callers and were tree-shaken out);
 *   - that the multi-agent isolation guard fires from the PRODUCTION-written
 *     identity: `sanctuary wrap` writes `SANCTUARY_AGENT_ID` into the
 *     harness MCP entry, the server resolves it through
 *     `wrappedAgentIdentityFromEnv`, and two distinct ids reaching ONE server
 *     process are separated (memory reads, provenance AND the vault tools).
 *     BOUND: the guard is per process; two harnesses over one fortress run
 *     separate processes and are not separated (IC-16 stays open);
 *   - that on the SHIPPED filesystem backend `sdw_import` fails closed with
 *     `storage_not_transactional` before touching the store (IC-27).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createSanctuaryServer } from "../../src/index.js";
import type { AuditLog as RealAuditLog } from "../../src/operational/audit-log.js";
import { createCognitiveTools } from "../../src/cognitive/tools.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { encrypt } from "../../src/core/encryption.js";
import { stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { derivePurposeKey, IDENTITY_ENCRYPTION_PURPOSE } from "../../src/core/key-derivation.js";
import {
  MEMORY_ADMISSION_SIGNING_DOMAIN_PREFIX,
  MEMORY_ORIGIN_SIGNING_DOMAIN_PREFIX,
  SDW_EXPORT_MANIFEST_SIGNING_DOMAIN,
} from "../../src/core/signing-domains.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { createTempHome } from "../helpers/temp-fortress.js";
import { createIdentity } from "../../src/core/identity.js";
import { fromBase64url } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  SDW_EXPORTABLE_NAMESPACES,
  StorageSnapshotSdwInventorySource,
  buildSignedSdwExportBundle,
  enumerateSdwExportInventory,
  type SdwExportSigningKey,
} from "../../src/sdw/export.js";
import { importSdwExportBundle } from "../../src/sdw/import.js";
import { createSdwTools } from "../../src/sdw/tools.js";
import {
  SDW_MEMORY_MULTI_AGENT_DENIAL_CLASS,
  createSdwMemoryTools,
} from "../../src/sdw/memory-tools.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { TestSdwMemoryBackendAdapter } from "./test-memory-backend.js";
import {
  createMultiAgentIsolationGuard,
  wrappedAgentIdentityFromEnv,
} from "../../src/sdw/memory-isolation.js";
import { createSdwMemoryProvenanceTool } from "../../src/sdw/memory-provenance-tool.js";
import { buildSanctuaryEnv, wrappedAgentId } from "../../src/wrap/cli.js";
import type { AuditLog } from "../../src/operational/audit-log.js";

const SERVER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const VAULT_TOOLS = ["sdw_export", "sdw_import"] as const;

function recordingAudit(): { log: AuditLog; calls: Array<{ operation: string; details: unknown }> } {
  const calls: Array<{ operation: string; details: unknown }> = [];
  const log = {
    async appendCritical(entry: { operation: string; details?: unknown }): Promise<void> {
      calls.push({ operation: entry.operation, details: entry.details });
    },
  } as unknown as AuditLog;
  return { log, calls };
}

function parse(result: { content: Array<{ type: "text"; text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

/** Issue tools/call through the production router (+ gate), exactly as a harness would. */
async function callTool(
  server: Awaited<ReturnType<typeof createSanctuaryServer>>["server"],
  name: string,
  args: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const handler = (
    server as unknown as { _requestHandlers: Map<string, (...a: unknown[]) => unknown> }
  )._requestHandlers.get("tools/call")!;
  const result = (await handler(
    { method: "tools/call" as const, params: { name, arguments: args } },
    {},
  )) as { content: Array<{ type: "text"; text: string }> };
  return parse(result);
}

async function auditOps(log: RealAuditLog, operation: string) {
  await log.flush();
  const { entries } = await log.query({ operation_type: operation, limit: 1000 });
  return entries;
}

/**
 * A hand-authored policy that lets the memory READ tools run unattended so the
 * production-graph tests reach the isolation guard without an approval channel.
 * The vault ops are force-pinned Tier 1 regardless of what this file says.
 */
const READ_TOOLS_TIER3_POLICY = [
  "version: 1",
  "tier1_always_approve: []",
  "tier3_always_allow:",
  "  - memory_count",
  "  - memory_get",
  "  - sdw_memory_provenance",
  "approval_channel:",
  "  type: stderr",
  "  timeout_seconds: 1",
  "",
].join("\n");

function makeSigning(): { signingKey: SdwExportSigningKey; resolvePublicKey: (ref: string) => Uint8Array | null } {
  const keyEncryptionKey = generateRandomKey();
  const { publicIdentity, storedIdentity } = createIdentity("vault-wiring-signer", keyEncryptionKey, "passphrase");
  return {
    signingKey: {
      keyRef: publicIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      encryptionKey: keyEncryptionKey,
    },
    resolvePublicKey: (ref) =>
      ref === publicIdentity.identity_id ? fromBase64url(publicIdentity.public_key) : null,
  };
}

describe("IC-15: the vault tools are reached by the production composition root", () => {
  let home: Awaited<ReturnType<typeof createTempHome>>;
  beforeEach(async () => {
    home = await createTempHome("sanctuary-vault-wiring");
  });
  afterEach(async () => {
    await home.cleanup();
  });

  it("tools/list from createSanctuaryServer carries sdw_export and sdw_import, and NOT sdw_export_delete", async () => {
    const { server, config } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "vault-wiring-deterministic-v1",
    });
    // The operator's machine is not a fixture: this boot resolved its fortress
    // under the temp HOME and never under the account's real home directory
    // (userInfo().homedir reads the passwd entry, not $HOME, so it still names
    // the real one while HOME is redirected).
    expect(config.storage_path.startsWith(home.home)).toBe(true);
    expect(config.storage_path.startsWith(join(userInfo().homedir, ".sanctuary"))).toBe(false);
    const handler = (
      server as unknown as { _requestHandlers: Map<string, (...a: unknown[]) => unknown> }
    )._requestHandlers.get("tools/list")!;
    const listed = (await handler({ method: "tools/list", params: {} }, {})) as {
      tools: Array<{ name: string; description: string }>;
    };
    const byName = new Map(listed.tools.map((t) => [t.name, t]));
    // Asserted as a whole map: a loop that stopped early would pass on the
    // entries it never reached.
    expect(Object.fromEntries(VAULT_TOOLS.map((n) => [n, byName.has(n)]))).toEqual(
      Object.fromEntries(VAULT_TOOLS.map((n) => [n, true])),
    );
    // SUBTRACTED: deletion needs a backend-wide serialization boundary first.
    expect(byName.has("sdw_export_delete")).toBe(false);
    // Product copy for an agent audience states the bound honestly.
    expect(byName.get("sdw_export")!.description).toContain("operator-directed archive");
    expect(byName.get("sdw_export")!.description).toContain("never carried by participant Exit");
    expect(byName.get("sdw_import")!.description).toContain("all-or-nothing");
  });

  // REGRESSION PIN, not a fail-before proof: this already held on origin/main
  // (the names were in DEFAULT_POLICY before the tools were wired). The
  // non-relaxable proof is test/principal-policy/sdw-vault-tier1.test.ts.
  it("both are listed Tier 1 in the default policy (MUST-NEVER #3)", () => {
    expect(Object.fromEntries(VAULT_TOOLS.map((n) => [n, DEFAULT_POLICY.tier1_always_approve.includes(n)]))).toEqual(
      Object.fromEntries(VAULT_TOOLS.map((n) => [n, true])),
    );
  });

  it("the built bundle carries the tool surface (no longer tree-shaken out of dist)", () => {
    // `npm test` runs `pretest: npm run build`, so dist is the artifact of THIS
    // source tree. A missing dist is a failure, never a skip: absent must not
    // read as passing.
    const distIndex = join(SERVER_DIR, "dist", "index.js");
    expect(existsSync(distIndex)).toBe(true);
    const built = readFileSync(distIndex, "utf8");
    expect(built).toContain("Export the Sovereign Data Warehouse");
    expect(built).toContain("Import a signed SDW export bundle");
  });
});

describe("IC-16: the isolation guard fires from the production-written SANCTUARY_AGENT_ID", () => {
  const savedAgentId = process.env.SANCTUARY_AGENT_ID;
  let home: Awaited<ReturnType<typeof createTempHome>>;
  beforeEach(async () => {
    home = await createTempHome("sanctuary-isolation");
    await mkdir(home.defaultFortressPath, { recursive: true, mode: 0o700 });
    await writeFile(join(home.defaultFortressPath, "principal-policy.yaml"), READ_TOOLS_TIER3_POLICY, { mode: 0o600 });
  });
  afterEach(async () => {
    if (savedAgentId === undefined) delete process.env.SANCTUARY_AGENT_ID;
    else process.env.SANCTUARY_AGENT_ID = savedAgentId;
    await home.cleanup();
  });

  it("sanctuary wrap writes SANCTUARY_AGENT_ID into the MCP entry env, distinct per harness and per fortress", () => {
    const envA = buildSanctuaryEnv({} as never, { platform: "claude-code", storagePath: "/srv/fortress-a" });
    const envB = buildSanctuaryEnv({} as never, { platform: "cursor", storagePath: "/srv/fortress-a" });
    const envC = buildSanctuaryEnv({} as never, { platform: "claude-code", storagePath: "/srv/fortress-c" });
    expect(envA.SANCTUARY_AGENT_ID).toBe(wrappedAgentId("claude-code", "/srv/fortress-a"));
    expect(new Set([envA.SANCTUARY_AGENT_ID, envB.SANCTUARY_AGENT_ID, envC.SANCTUARY_AGENT_ID]).size).toBe(3);
    // Same harness over the same fortress is the same agent (stable across restarts).
    expect(buildSanctuaryEnv({} as never, { platform: "claude-code", storagePath: "/srv/fortress-a" }).SANCTUARY_AGENT_ID)
      .toBe(envA.SANCTUARY_AGENT_ID);
  });

  it("MEDIUM-4/C5/C7: through the production router + gate, ONE guard instance covers memory, provenance AND vault tools", async () => {
    const agentA = wrappedAgentId("claude-code", home.defaultFortressPath);
    const agentB = wrappedAgentId("cursor", home.defaultFortressPath);
    process.env.SANCTUARY_AGENT_ID = agentA;
    const { server, auditLog } = await createSanctuaryServer({
      storage: new MemoryStorage(),
      passphrase: "isolation-one-graph-v1",
    });
    // A touches the scope first through a memory tool.
    expect((await callTool(server, "memory_count")).count).toBe(0);

    process.env.SANCTUARY_AGENT_ID = agentB;
    // B is refused by the vault export at GATE time: the denial comes back
    // from the router's approvalTargetArgs path (no enumeration, no Tier-1
    // prompt) and the REAL audit log carries the isolation denial.
    const exportByB = await callTool(server, "sdw_export", { export_name: "steal" });
    expect(exportByB.denied).toBe(true);
    expect(exportByB.exported).toBeUndefined();
    expect((await auditOps(auditLog, "sdw_export_denied")).map((e) => e.details?.denial_class))
      .toEqual([SDW_MEMORY_MULTI_AGENT_DENIAL_CLASS]);
    // No export scope was ever frozen for B (gate refused before enumeration).
    expect(await auditOps(auditLog, "sdw_export_scope_approved")).toEqual([]);
    // Same instance: provenance is refused for B too.
    const provenanceByB = await callTool(server, "sdw_memory_provenance", { passage_id: "anything" });
    expect(provenanceByB.denied).toBe(true);
    expect((await auditOps(auditLog, "sdw_memory_provenance_denied")).map((e) => e.details?.denial_class))
      .toEqual([SDW_MEMORY_MULTI_AGENT_DENIAL_CLASS]);
    // And the import/delete gates refuse B the same way.
    expect((await callTool(server, "sdw_import", { bundle: "AAAA", source_key_ref: "this-fortress" })).denied).toBe(true);
    expect((await auditOps(auditLog, "sdw_import_denied")).map((e) => e.details?.denial_class))
      .toEqual([SDW_MEMORY_MULTI_AGENT_DENIAL_CLASS]);
  });

  it("provenance: the gate-time projection refuses a foreign identity before the approval gate, and the handler rechecks", async () => {
    const adapter = new TestSdwMemoryBackendAdapter({
      storage: new MemoryStorage(),
      masterKey: new Uint8Array(32).fill(3),
      fortressId: "fortress:prov-gate",
      ownerRef: "fleet-self",
    });
    const { log, calls } = recordingAudit();
    const guard = createMultiAgentIsolationGuard(wrappedAgentIdentityFromEnv);
    const tool = createSdwMemoryProvenanceTool({ adapter, auditLog: log, isolationGuard: guard });
    process.env.SANCTUARY_AGENT_ID = "a";
    expect(await tool.approvalTargetArgs!({ passage_id: "p" })).toEqual({ passage_id: "p" });
    process.env.SANCTUARY_AGENT_ID = "b";
    await expect(Promise.resolve(tool.approvalTargetArgs!({ passage_id: "p" }))).rejects.toMatchObject({
      category: "owner_scope_conflict",
    });
    expect(parse(await tool.handler({ passage_id: "p" })).denied).toBe(true);
    expect(calls.filter((c) => c.operation === "sdw_memory_provenance_denied")).toHaveLength(2);
  });

  it("two ids reaching one guard instance: the second cannot read the first's passages", async () => {
    const adapter = new TestSdwMemoryBackendAdapter({
      storage: new MemoryStorage(),
      masterKey: new Uint8Array(32).fill(3),
      fortressId: "fortress:shared-host",
      ownerRef: "fleet-self",
    });
    const { log } = recordingAudit();
    const guard = createMultiAgentIsolationGuard(wrappedAgentIdentityFromEnv);
    const memoryTools = new Map(
      createSdwMemoryTools({ adapter, auditLog: log, isolationGuard: guard }).map((t) => [t.name, t]),
    );
    process.env.SANCTUARY_AGENT_ID = "a";
    await adapter.insertPassage({ passage_id: "owned-by-a", text: "agent A's private passage" }, "user_content");
    expect(parse(await memoryTools.get("memory_get")!.handler({ passage_id: "owned-by-a" })).found).toBe(true);
    process.env.SANCTUARY_AGENT_ID = "b";
    const readByB = parse(await memoryTools.get("memory_get")!.handler({ passage_id: "owned-by-a" }));
    expect(readByB.denied).toBe(true);
    expect(JSON.stringify(readByB)).not.toContain("agent A's private passage");
  });
});

describe("LOW-N4: sdw_import refuses at gate time on the shipped filesystem backend, before any prompt", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-vault-import-gate-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("the gate throws storage_not_transactional without parsing the bundle", async () => {
    const { log, calls } = recordingAudit();
    const signing = makeSigning();
    const tools = new Map(
      createSdwTools({
        storage: new FilesystemStorage(join(dir, "state")),
        inventory: { listNamespaceSync: () => [] },
        auditLog: log,
        fortressId: "fortress:fs",
        exportDir: join(dir, "sdw-exports"),
        signingKey: signing.signingKey,
        resolvePublicKey: signing.resolvePublicKey,
        resolveSourceMasterKey: () => null,
        targetMasterKey: new Uint8Array(32).fill(9),
      }).map((t) => [t.name, t]),
    );
    const imp = tools.get("sdw_import")!;
    await expect(Promise.resolve(imp.approvalTargetArgs!({ bundle: "not-even-parsed", source_key_ref: "this-fortress" })))
      .rejects.toMatchObject({ category: "storage_not_transactional" });
    expect(calls.map((c) => [c.operation, (c.details as { denial_class?: string }).denial_class]))
      .toEqual([["sdw_import_denied", "storage_not_transactional"]]);
  });
});

describe("MEDIUM-C6: the export archive cannot be redirected outside the fortress by a symlink", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-vault-symlink-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  function exportToolOver(
    fortress: string,
    log: AuditLog,
    hooks: { beforeOpen?: () => Promise<void>; afterRename?: () => Promise<void> } = {},
  ) {
    const signing = makeSigning();
    return createSdwTools({
      storage: new MemoryStorage(),
      inventory: { listNamespaceSync: () => [] },
      auditLog: log,
      fortressId: "fortress:sym",
      exportDir: join(fortress, "sdw-exports"),
      fortressRoot: fortress,
      signingKey: signing.signingKey,
      resolvePublicKey: signing.resolvePublicKey,
      resolveSourceMasterKey: () => null,
      targetMasterKey: new Uint8Array(32).fill(4),
      ...(hooks.beforeOpen ? { __afterExportDirPrepared: hooks.beforeOpen } : {}),
      ...(hooks.afterRename ? { __afterExportRenamed: hooks.afterRename } : {}),
    }).find((t) => t.name === "sdw_export")!;
  }

  /** The attacker's move: replace the validated directory with a link to the outside, carrying the fresh dir's name across. */
  async function swapToOutside(fortress: string, outside: string): Promise<void> {
    const exportsDir = join(fortress, "sdw-exports");
    const fresh = (await readdir(exportsDir))[0];
    await rm(exportsDir, { recursive: true, force: true });
    await symlink(outside, exportsDir);
    if (fresh) await mkdir(join(outside, fresh), { recursive: true, mode: 0o700 });
  }

  async function nothingOutside(outside: string): Promise<void> {
    for (const entry of await readdir(outside)) expect(await readdir(join(outside, entry))).toEqual([]);
  }

  it("swap BEFORE the open (after validation): the pre-open recheck refuses; nothing lands outside", async () => {
    const fortress = join(dir, "fortress-swap-open");
    const outside = join(dir, "outside-swap-open");
    await mkdir(fortress, { recursive: true, mode: 0o700 });
    await mkdir(outside, { recursive: true, mode: 0o700 });
    const { log, calls } = recordingAudit();
    const exportTool = exportToolOver(fortress, log, { beforeOpen: () => swapToOutside(fortress, outside) });
    const args: Record<string, unknown> = { export_name: "swapped" };
    await exportTool.approvalTargetArgs!(args);
    const out = parse(await exportTool.handler(args));
    expect(out.denied).toBe(true);
    await nothingOutside(outside);
    expect(calls.filter((c) => c.operation === "sdw_export_failed").map((c) => (c.details as { category: string }).category))
      .toEqual(["write_failed"]);
  });

  it("swap AFTER the rename: the post-rename recheck refuses and unlinks what was written", async () => {
    const fortress = join(dir, "fortress-swap-rename");
    const outside = join(dir, "outside-swap-rename");
    await mkdir(fortress, { recursive: true, mode: 0o700 });
    await mkdir(outside, { recursive: true, mode: 0o700 });
    const { log, calls } = recordingAudit();
    const exportTool = exportToolOver(fortress, log, { afterRename: () => swapToOutside(fortress, outside) });
    const args: Record<string, unknown> = { export_name: "swapped" };
    await exportTool.approvalTargetArgs!(args);
    const out = parse(await exportTool.handler(args));
    expect(out.denied).toBe(true);
    await nothingOutside(outside);
    expect(calls.filter((c) => c.operation === "sdw_export_failed").map((c) => (c.details as { category: string }).category))
      .toEqual(["write_failed"]);
  });

  it("a successful export lands inside a fresh per-export directory under the fortress", async () => {
    const fortress = join(dir, "fortress-ok");
    await mkdir(fortress, { recursive: true, mode: 0o700 });
    const { log } = recordingAudit();
    const exportTool = exportToolOver(fortress, log);
    const args: Record<string, unknown> = { export_name: "fine" };
    await exportTool.approvalTargetArgs!(args);
    const out = parse(await exportTool.handler(args));
    expect(out.exported).toBe(true);
    const destination = out.destination_path as string;
    expect(destination.startsWith(join(fortress, "sdw-exports") + "/fine.")).toBe(true);
    expect(existsSync(destination)).toBe(true);
  });

  it("a planted sdw-exports symlink fails the export closed and nothing lands outside", async () => {
    const fortress = join(dir, "fortress");
    const outside = join(dir, "outside");
    await mkdir(fortress, { recursive: true, mode: 0o700 });
    await mkdir(outside, { recursive: true, mode: 0o700 });
    await symlink(outside, join(fortress, "sdw-exports"));
    const { log, calls } = recordingAudit();
    const exportTool = exportToolOver(fortress, log);
    const args: Record<string, unknown> = { export_name: "redirected" };
    await exportTool.approvalTargetArgs!(args);
    const out = parse(await exportTool.handler(args));
    expect(out.denied).toBe(true);
    expect(out.exported).toBeUndefined();
    expect(await readdir(outside)).toEqual([]);
    const failed = calls.filter((c) => c.operation === "sdw_export_failed");
    expect(failed.map((c) => (c.details as { category: string }).category)).toEqual(["write_failed"]);
  });
});

describe("MEDIUM-2: the raw identity_sign surface cannot mint an internal artifact", () => {
  it("refuses a payload that begins with an internal signing domain, and signs ordinary bytes", async () => {
    const storage = new MemoryStorage();
    const masterKey = new Uint8Array(32).fill(11);
    const auditLog = new (await import("../../src/operational/audit-log.js")).AuditLog(new MemoryStorage(), generateRandomKey());
    const identityEncKey = derivePurposeKey(masterKey, IDENTITY_ENCRYPTION_PURPOSE);
    const { storedIdentity } = createIdentity("raw-signer", identityEncKey, "passphrase");
    await storage.write(
      "_identities",
      storedIdentity.identity_id,
      stringToBytes(JSON.stringify(encrypt(stringToBytes(JSON.stringify(storedIdentity)), identityEncKey))),
    );
    const { tools, identityManager } = createCognitiveTools(
      new StateStore(storage, masterKey),
      storage,
      masterKey,
      "passphrase",
      auditLog,
    );
    await identityManager.load();
    const sign = tools.find((t) => t.name === "identity_sign")!;
    const forged = parse(
      await sign.handler({
        identity_id: storedIdentity.identity_id,
        payload: toBase64url(stringToBytes(`${SDW_EXPORT_MANIFEST_SIGNING_DOMAIN}{"body":"hand-built manifest"}`)),
      }),
    );
    expect(forged.denied).toBe(true);
    expect(forged.signature).toBeUndefined();
    for (const prefix of ["sanctuary.state-envelope.v2\n", "sanctuary.audit.v1", "sanctuary.receipt.v1"]) {
      const out = parse(
        await sign.handler({ identity_id: storedIdentity.identity_id, payload: toBase64url(stringToBytes(`${prefix}forged`)) }),
      );
      expect(out.denied, prefix).toBe(true);
    }
    for (const domain of [
      MEMORY_ORIGIN_SIGNING_DOMAIN_PREFIX,
      MEMORY_ADMISSION_SIGNING_DOMAIN_PREFIX,
    ]) {
      const out = parse(
        await sign.handler({
          identity_id: storedIdentity.identity_id,
          payload: toBase64url(stringToBytes(`${domain}{"forged":true}`)),
        }),
      );
      expect(out.denied, domain).toBe(true);
      expect(out.signature).toBeUndefined();
    }
    const plain = parse(
      await sign.handler({ identity_id: storedIdentity.identity_id, payload: toBase64url(stringToBytes("an ordinary commitment")) }),
    );
    expect(typeof plain.signature).toBe("string");
  });

  it("export.ts declares no signing domain of its own (single source in core/signing-domains.ts)", () => {
    const exportSource = readFileSync(join(SERVER_DIR, "src", "sdw", "export.ts"), "utf8");
    expect(exportSource.match(/"sanctuary\.[a-z0-9.-]+\\n"/g) ?? []).toEqual([]);
    expect(exportSource).toContain('from "../core/signing-domains.js"');
  });
});

describe("IC-27: import is all-or-nothing on the shipped backend", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-vault-import-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  // REGRESSION PIN for the import module (the transactional-or-refuse check
  // predates this change, #449); the fail-before witness for THIS change is the
  // delete refusal test below.
  it("FilesystemStorage has no transaction primitive, so a verified bundle is refused before any write", async () => {
    const signing = makeSigning();
    const emptySource = { listNamespaceSync: () => [] };
    const inventory = enumerateSdwExportInventory(emptySource);
    const { bundle } = buildSignedSdwExportBundle({
      inventory,
      source: emptySource,
      fortressId: "fortress:source",
      exportAuditEventId: "sdw-export:1:wiring",
      signingKey: signing.signingKey,
    });
    const storage = new FilesystemStorage(join(dir, "state"));
    await expect(
      importSdwExportBundle({
        bundle,
        storage,
        resolvePublicKey: signing.resolvePublicKey,
        sourceMasterKey: new Uint8Array(32).fill(5),
        targetMasterKey: new Uint8Array(32).fill(6),
        targetFortressId: "fortress:target",
      }),
    ).rejects.toMatchObject({ category: "storage_not_transactional" });
    // Nothing was applied: every exportable namespace is still empty.
    const after = Object.fromEntries(
      await Promise.all(
        SDW_EXPORTABLE_NAMESPACES.map(async (ns) => [ns, (await storage.list(ns)).length] as const),
      ),
    );
    expect(after).toEqual(Object.fromEntries(SDW_EXPORTABLE_NAMESPACES.map((ns) => [ns, 0])));
  });
});

describe("StorageSnapshotSdwInventorySource (the production inventory over an async store)", () => {
  it("fails closed before refresh and serves the live store after it", async () => {
    const entries = new Map<string, Uint8Array>();
    const storage = {
      async list(namespace: string) {
        return [...entries.keys()]
          .filter((k) => k.startsWith(`${namespace}\0`))
          .map((k) => ({ key: k.slice(namespace.length + 1) }));
      },
      async read(namespace: string, key: string) {
        return entries.get(`${namespace}\0${key}`) ?? null;
      },
    };
    const source = new StorageSnapshotSdwInventorySource(storage);
    expect(() => source.listNamespaceSync("_sdw_working_state")).toThrow(/before refresh/);

    entries.set("_sdw_working_state\0k1", new Uint8Array([1]));
    await source.refresh();
    expect(source.listNamespaceSync("_sdw_working_state").map((e) => e.key)).toEqual(["k1"]);

    // A later write is invisible until the next refresh (the tool layer
    // refreshes before every enumeration), then visible.
    entries.set("_sdw_working_state\0k2", new Uint8Array([2]));
    expect(source.listNamespaceSync("_sdw_working_state").map((e) => e.key)).toEqual(["k1"]);
    await source.refresh();
    expect(source.listNamespaceSync("_sdw_working_state").map((e) => e.key).sort()).toEqual(["k1", "k2"]);
  });
});
