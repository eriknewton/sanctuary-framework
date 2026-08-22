/**
 * Wired-consumer + isolation regression tests for the SDW vault tools
 * (IC-15/16, IC-27, IC-28 companion; AGENTS.md assurance rule 4).
 *
 * What the unit-level D2 tests cannot reach:
 *   - that the PRODUCTION composition root (`createSanctuaryServer`) actually
 *     registers `sdw_export` / `sdw_import` / `sdw_export_delete` on the wire
 *     catalog, and that the built bundle (`dist/index.js`) carries them
 *     (pre-fix they had zero production callers and were tree-shaken out);
 *   - that the multi-agent isolation guard fires from the PRODUCTION-written
 *     identity: `sanctuary wrap` writes `SANCTUARY_AGENT_ID` into the
 *     harness MCP entry, the server resolves it through
 *     `wrappedAgentIdentityFromEnv`, and two wrapped agents on one host
 *     resolve two distinct ids so the second is refused (memory reads AND the
 *     vault export);
 *   - that on the SHIPPED filesystem backend `sdw_import` fails closed with
 *     `storage_not_transactional` before touching the store (IC-27).
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createSanctuaryServer } from "../../src/index.js";
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
import { createSdwMemoryTools } from "../../src/sdw/memory-tools.js";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import {
  createMultiAgentIsolationGuard,
  wrappedAgentIdentityFromEnv,
} from "../../src/sdw/memory-isolation.js";
import { buildSanctuaryEnv, wrappedAgentId } from "../../src/wrap/cli.js";
import type { AuditLog } from "../../src/operational/audit-log.js";

const SERVER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const VAULT_TOOLS = ["sdw_export", "sdw_import", "sdw_export_delete"] as const;

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

  it("tools/list from createSanctuaryServer carries sdw_export, sdw_import and sdw_export_delete", async () => {
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
    // Product copy for an agent audience states the bound honestly.
    expect(byName.get("sdw_export")!.description).toContain("operator-directed archive");
    expect(byName.get("sdw_export")!.description).toContain("never carried by participant Exit");
    expect(byName.get("sdw_import")!.description).toContain("all-or-nothing");
  });

  it("all three are force-pinned Tier 1 in the default policy (MUST-NEVER #3)", () => {
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
    expect(built).toContain("Post-export local-state delete");
    expect(built).toContain("Import a signed SDW export bundle");
  });
});

describe("IC-16: the isolation guard fires from the production-written SANCTUARY_AGENT_ID", () => {
  const savedAgentId = process.env.SANCTUARY_AGENT_ID;
  afterEach(() => {
    if (savedAgentId === undefined) delete process.env.SANCTUARY_AGENT_ID;
    else process.env.SANCTUARY_AGENT_ID = savedAgentId;
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

  it("two wrapped agents on one host: the second cannot read the first's passages, through the production resolver", async () => {
    const agentA = wrappedAgentId("claude-code", "/srv/shared-host-fortress");
    const agentB = wrappedAgentId("cursor", "/srv/shared-host-fortress");
    expect(agentA).not.toBe(agentB);

    const adapter = new SdwMemoryBackendAdapter({
      storage: new MemoryStorage(),
      masterKey: new Uint8Array(32).fill(3),
      fortressId: "fortress:shared-host",
      ownerRef: "fleet-self",
    });
    const { log, calls } = recordingAudit();
    // Exactly the index.ts wiring: the production resolver and ONE guard
    // instance shared by every family over the scope.
    const guard = createMultiAgentIsolationGuard(wrappedAgentIdentityFromEnv);
    const memoryTools = new Map(
      createSdwMemoryTools({ adapter, auditLog: log, isolationGuard: guard }).map((t) => [t.name, t]),
    );
    const vaultTools = new Map(
      createSdwTools({
        storage: new MemoryStorage(),
        inventory: { listNamespaceSync: () => [] },
        auditLog: log,
        fortressId: "fortress:shared-host",
        exportDir: tmpdir(),
        signingKey: () => null,
        resolvePublicKey: () => null,
        resolveSourceMasterKey: () => null,
        targetMasterKey: new Uint8Array(32).fill(3),
        isolationGuard: guard,
      }).map((t) => [t.name, t]),
    );

    process.env.SANCTUARY_AGENT_ID = agentA;
    await adapter.insertPassage({ passage_id: "owned-by-a", text: "agent A's private passage" }, "user_content");
    const readByA = parse(await memoryTools.get("memory_get")!.handler({ passage_id: "owned-by-a" }));
    expect(readByA.found).toBe(true);

    process.env.SANCTUARY_AGENT_ID = agentB;
    const readByB = parse(await memoryTools.get("memory_get")!.handler({ passage_id: "owned-by-a" }));
    expect(readByB.denied).toBe(true);
    expect(JSON.stringify(readByB)).not.toContain("agent A's private passage");
    // The vault export sits behind the SAME pin: B cannot move the corpus
    // out either, and the refusal is audited with the isolation class.
    const exportByB = parse(await vaultTools.get("sdw_export")!.handler({ export_name: "steal" }));
    expect(exportByB.denied).toBe(true);
    expect(exportByB.exported).toBeUndefined();
    expect(
      calls.filter((c) => c.operation === "sdw_export_denied").map((c) => (c.details as { denial_class: string }).denial_class),
    ).toEqual(["multi_agent_isolation"]);

    // The pin never advances: A still reads after B was refused.
    process.env.SANCTUARY_AGENT_ID = agentA;
    expect(parse(await memoryTools.get("memory_get")!.handler({ passage_id: "owned-by-a" })).found).toBe(true);
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
