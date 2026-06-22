/**
 * Integration Test — Multi-Instance Isolation (v0.10.0 WP1)
 *
 * Proves two parallel Sanctuary instances on one host with distinct
 * `SANCTUARY_STORAGE_PATH` + `SANCTUARY_DASHBOARD_PORT` +
 * `SANCTUARY_WEBHOOK_CALLBACK_PORT` produce clean separation:
 *
 *   1. Storage path isolation — audit logs, identities, state, and principal
 *      policies written to one instance are invisible to the other.
 *   2. Dashboard port isolation — two wraps pick distinct dashboard start ports
 *      from environment without colliding.
 *   3. Webhook callback port isolation — two webhook approval channels bind
 *      distinct ports simultaneously.
 *   4. Config loading — `loadConfig()` honours distinct env overrides so each
 *      instance sees its own per-tenant settings.
 *
 * This is the minimum end-to-end guarantee that the multi-tenancy audit
 * (Review/Multi_Tenancy_Audit_v0.9.0_2026-04-17.md) promises.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { loadConfig } from "../../src/config.js";
import { WebhookApprovalChannel } from "../../src/principal-policy/webhook.js";
import { resolveStoragePath, resolveDashboardPort } from "../../src/paths.js";

type ToolHandler = {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: string; text: string }>;
  }>;
};

async function callTool(
  tools: ToolHandler[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

interface TenantHandle {
  storagePath: string;
  tools: ToolHandler[];
  storage: FilesystemStorage;
  auditLog: AuditLog;
}

async function createTenant(rootDir: string, name: string): Promise<TenantHandle> {
  const storagePath = join(rootDir, name);
  const storage = new FilesystemStorage(storagePath);
  // Each tenant holds its own master key — in production this is derived from
  // a per-tenant Keychain item (see keychainServiceFor in passphrase.ts).
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const { tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  await identityManager.load();
  return { storagePath, tools, storage, auditLog };
}

describe("Multi-Instance Isolation (WP1)", () => {
  let rootDir: string;

  beforeEach(async () => {
    rootDir = await mkdtemp(join(tmpdir(), "sanctuary-multi-instance-"));
  });

  afterEach(async () => {
    // Tenant instances can still flush writes (_meta, audit) while the
    // recursive walk deletes, racing to ENOTEMPTY under parallel-suite load.
    await rm(rootDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  it("identities created in tenant A are invisible to tenant B", async () => {
    const a = await createTenant(rootDir, "tenant-a");
    const b = await createTenant(rootDir, "tenant-b");

    const aliceA = await callTool(a.tools, "identity_create", {
      label: "alice@tenant-a",
    });
    const aliceB = await callTool(b.tools, "identity_create", {
      label: "alice@tenant-b",
    });

    // Distinct key material despite the shared "alice" label — different
    // master keys + different storage backends.
    expect(aliceA.public_key).not.toBe(aliceB.public_key);
    expect(aliceA.did).not.toBe(aliceB.did);

    // Tenant B's identity list does NOT contain tenant A's identity.
    const listB = (await callTool(b.tools, "identity_list", {})) as {
      identities: Array<{ identity_id: string }>;
    };
    const bIds = listB.identities.map((i) => i.identity_id);
    expect(bIds).toContain(aliceB.identity_id);
    expect(bIds).not.toContain(aliceA.identity_id);
  });

  it("state written by tenant A is unreadable from tenant B", async () => {
    const a = await createTenant(rootDir, "tenant-a");
    const b = await createTenant(rootDir, "tenant-b");

    const identA = await callTool(a.tools, "identity_create", { label: "a" });
    await callTool(a.tools, "state_write", {
      namespace: "secrets",
      key: "api-token",
      value: "tenant-a-only",
      identity_id: identA.identity_id,
    });

    // Tenant B, reading its own namespace, finds nothing — the file exists on
    // disk but sits in a different storage root with a different master key.
    const readB = (await callTool(b.tools, "state_read", {
      namespace: "secrets",
      key: "api-token",
    })) as { found?: boolean; value?: string };
    expect(readB.found).not.toBe(true);
    expect(readB.value).toBeUndefined();
  });

  it("audit log entries from tenant A do not leak into tenant B's audit log", async () => {
    const a = await createTenant(rootDir, "tenant-a");
    const b = await createTenant(rootDir, "tenant-b");

    await callTool(a.tools, "identity_create", { label: "a-trigger" });
    await callTool(b.tools, "identity_create", { label: "b-trigger" });

    // Flush any fire-and-forget persistence before reading.
    await new Promise((r) => setTimeout(r, 20));

    const auditA = await a.auditLog.query({ limit: 100 });
    const auditB = await b.auditLog.query({ limit: 100 });

    const serializedA = JSON.stringify(auditA.entries);
    const serializedB = JSON.stringify(auditB.entries);

    expect(serializedA).toContain("a-trigger");
    expect(serializedA).not.toContain("b-trigger");
    expect(serializedB).toContain("b-trigger");
    expect(serializedB).not.toContain("a-trigger");
  });

  it("loadConfig honours distinct SANCTUARY_STORAGE_PATH values per tenant", async () => {
    const savedStorage = process.env.SANCTUARY_STORAGE_PATH;
    const savedDashPort = process.env.SANCTUARY_DASHBOARD_PORT;
    const savedCbPort = process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT;

    try {
      process.env.SANCTUARY_STORAGE_PATH = join(rootDir, "tenant-a");
      process.env.SANCTUARY_DASHBOARD_PORT = "3501";
      process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT = "3511";
      const configA = await loadConfig();

      process.env.SANCTUARY_STORAGE_PATH = join(rootDir, "tenant-b");
      process.env.SANCTUARY_DASHBOARD_PORT = "3502";
      process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT = "3512";
      const configB = await loadConfig();

      expect(configA.storage_path).toBe(join(rootDir, "tenant-a"));
      expect(configB.storage_path).toBe(join(rootDir, "tenant-b"));
      expect(configA.storage_path).not.toBe(configB.storage_path);

      expect(configA.dashboard.port).toBe(3501);
      expect(configB.dashboard.port).toBe(3502);

      expect(configA.webhook.callback_port).toBe(3511);
      expect(configB.webhook.callback_port).toBe(3512);
    } finally {
      if (savedStorage === undefined) delete process.env.SANCTUARY_STORAGE_PATH;
      else process.env.SANCTUARY_STORAGE_PATH = savedStorage;
      if (savedDashPort === undefined) delete process.env.SANCTUARY_DASHBOARD_PORT;
      else process.env.SANCTUARY_DASHBOARD_PORT = savedDashPort;
      if (savedCbPort === undefined) delete process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT;
      else process.env.SANCTUARY_WEBHOOK_CALLBACK_PORT = savedCbPort;
    }
  });

  it("two webhook callback servers bind distinct ports simultaneously", async () => {
    // Pick two high ports unlikely to collide on a dev machine. Both channels
    // must be able to listen at the same time without port conflict.
    const portA = 38501;
    const portB = 38502;

    const channelA = new WebhookApprovalChannel({
      webhook_url: "http://127.0.0.1:1/webhook-a",
      webhook_secret: "secret-a",
      callback_port: portA,
      callback_host: "127.0.0.1",
      timeout_seconds: 1,
    });
    const channelB = new WebhookApprovalChannel({
      webhook_url: "http://127.0.0.1:1/webhook-b",
      webhook_secret: "secret-b",
      callback_port: portB,
      callback_host: "127.0.0.1",
      timeout_seconds: 1,
    });

    try {
      await channelA.start();
      await channelB.start();
      // If either .start() resolves without throwing and the other also
      // resolves, the kernel has bound two distinct sockets.
      expect(true).toBe(true);
    } finally {
      await channelA.stop();
      await channelB.stop();
    }
  });

  it("resolveStoragePath + resolveDashboardPort pick per-tenant values from env", () => {
    const storageA = resolveStoragePath(
      { SANCTUARY_STORAGE_PATH: join(rootDir, "tenant-a") },
      "/unused"
    );
    const storageB = resolveStoragePath(
      { SANCTUARY_STORAGE_PATH: join(rootDir, "tenant-b") },
      "/unused"
    );
    expect(storageA).not.toBe(storageB);

    const portA = resolveDashboardPort(undefined, {
      SANCTUARY_DASHBOARD_PORT: "3501",
    });
    const portB = resolveDashboardPort(undefined, {
      SANCTUARY_DASHBOARD_PORT: "3502",
    });
    expect(portA).toBe(3501);
    expect(portB).toBe(3502);
    expect(portA).not.toBe(portB);
  });
});
