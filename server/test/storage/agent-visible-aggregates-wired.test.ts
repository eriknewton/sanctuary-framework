import { cp, mkdir, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { expect, it, vi } from "vitest";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateDefaultPolicyYaml } from "../../src/principal-policy/loader.js";
import { createTempFortress, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

it("health and export bytes agree across fortresses with different local stores and operator audit rows", async () => {
  // The wired path is the built server (npm test builds dist first); it is loaded by URL so the
  // tests typecheck does not need a dist that exists only after a build. Types come from src.
  const { createSanctuaryServer } = (await import(
    new URL("../../dist/index.js", import.meta.url).href
  )) as typeof import("../../src/index.js");
  const fortress = await createTempFortress("aggregate-wired");
  const oldAgent = process.env.SANCTUARY_AGENT_ID;
  const oldIdentity = process.env.SANCTUARY_SESSION_IDENTITY_ID;
  delete process.env.SANCTUARY_AGENT_ID;
  delete process.env.SANCTUARY_SESSION_IDENTITY_ID;
  // A fixed Date supplies identical export timestamps without replacing I/O or deadline timers.
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-11-22T00:00:00.000Z"));
  const a = join(fortress.home, "a");
  const b = join(fortress.home, "b");
  async function boot(root: string) {
    // Both storage worlds use the same operator configuration and wall evidence source.
    process.env.SANCTUARY_STORAGE_PATH = a;
    const storage = new FilesystemStorage(join(root, "state"));
    const runtime = await createSanctuaryServer({ storage, passphrase: TEST_PASSPHRASE,
      approvalCallback: async () => ({ decision: "approve", decided_at: new Date().toISOString(), decided_by: "human" }),
    });
    const client = new Client({ name: "aggregate-witness", version: "1.0.0" });
    try {
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      await runtime.server.connect(serverTransport);
      await client.connect(clientTransport);
    } catch (error) {
      await client.close(); await runtime.cleanup(); await runtime.server.close(); throw error;
    }
    return { storage, runtime, client, close: async () => {
      try { await client.close(); } finally { try { await runtime.cleanup(); } finally { await runtime.server.close(); } }
    } };
  }
  type Fixture = Awaited<ReturnType<typeof boot>>;
  async function call(f: Fixture, name: string, args = {}) {
    const response = await f.client.callTool({ name, arguments: args });
    expect(response.isError).not.toBe(true);
    const content = response.content as Array<{ type: string; text: string }>;
    const body = JSON.parse(content[0]!.text);
    expect(body).not.toHaveProperty("error");
    return { response, body };
  }
  try {
    await mkdir(a, { recursive: true, mode: 0o700 }); // Owner-only fortress directory.
    await writeFile(join(a, "principal-policy.yaml"), generateDefaultPolicyYaml().replace(
      /approval_channel:\n  type: \w+/, "approval_channel:\n  type: callback"), { mode: 0o600 }); // Owner-only policy.
    const seed = await boot(a);
    try {
      await call(seed, "identity_create", { label: "ordinary" });
      // One ordinary record, so the continuing path carries real agent-visible bytes and an export entry.
      await call(seed, "state_write", { namespace: "notes", key: "one", value: "ordinary fixture" });
    } finally { await seed.close(); }
    // The ordinary namespace's on-disk bytes, measured directly rather than through the method under test.
    const notesDir = join(a, "state", "notes");
    let ordinaryBytes = 0;
    for (const file of await readdir(notesDir)) ordinaryBytes += (await stat(join(notesDir, file))).size;
    expect(ordinaryBytes).toBeGreaterThan(0);
    // The custody envelope and identity ciphertext are identical before either measured boot.
    await cp(a, b, { recursive: true });
    async function observe(root: string, localRows: boolean) {
      const f = await boot(root);
      try {
        if (localRows) {
          await f.storage.write("_local_results", "one", new TextEncoder().encode("operator result"));
          await f.storage.write("_local_oplog", "one", new TextEncoder().encode("operator log"));
          await f.runtime.auditLog.append("l1", "operator_render", "operator-fixture", { request_id: "fixture" });
        }
        // Optional spies let the base reach its real aggregate comparison before the new-method assertions.
        const sizeSpy = typeof f.storage.totalSizeOfNonReservedNamespaces === "function" && vi.spyOn(f.storage, "totalSizeOfNonReservedNamespaces");
        const discoverySpy = typeof f.storage.listNamespacesForAgentDiscovery === "function" && vi.spyOn(f.storage, "listNamespacesForAgentDiscovery");
        const health = await call(f, "monitor_health");
        const exported = await call(f, "state_export");
        // The health response carries these live clock fields.
        delete health.body.checked_at;
        delete health.body.castle_wall_liveness.evaluated_at;
        delete health.body.castle_wall_liveness.served_age_ms;
        Object.defineProperty(f.storage, "totalSizeOfNonReservedNamespaces", { value: undefined });
        const missingSize = await f.client.callTool({ name: "monitor_health", arguments: {} });
        return { missingSizeError: missingSize.isError, storageBytes: health.body.storage_bytes, health: JSON.stringify(health.body), exported: JSON.stringify(exported.response), sizeCalls: sizeSpy ? sizeSpy.mock.calls.length : 0,
          discoveryCalls: discoverySpy ? discoverySpy.mock.calls.length : 0 };
      } finally { await f.close(); }
    }
    const before = await observe(a, false);
    const after = await observe(b, true);
    expect(after.storageBytes).toBe(before.storageBytes);
    expect(after.health).toBe(before.health);
    // Both fixtures hold the same ordinary record beside their reserved namespaces; the expected
    // value is the ordinary directory's measured size, independent of new source exports.
    const expectedStorageBytes = ordinaryBytes;
    expect(before.storageBytes).toBe(expectedStorageBytes);
    expect(after.storageBytes).toBe(expectedStorageBytes);
    expect(JSON.parse(before.exported).content[0].text).toContain("notes");
    expect(after.exported).toBe(before.exported);
    expect(before.missingSizeError).toBe(true);
    expect(after.missingSizeError).toBe(true);
    expect(before.sizeCalls).toBeGreaterThan(0);
    expect(after.sizeCalls).toBeGreaterThan(0);
    expect(before.discoveryCalls).toBeGreaterThan(0);
    expect(after.discoveryCalls).toBeGreaterThan(0);
  } finally {
    vi.restoreAllMocks(); vi.useRealTimers();
    if (oldAgent === undefined) delete process.env.SANCTUARY_AGENT_ID; else process.env.SANCTUARY_AGENT_ID = oldAgent;
    if (oldIdentity === undefined) delete process.env.SANCTUARY_SESSION_IDENTITY_ID; else process.env.SANCTUARY_SESSION_IDENTITY_ID = oldIdentity;
    await fortress.cleanup();
  }
});
