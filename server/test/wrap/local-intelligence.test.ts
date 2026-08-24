import { describe, expect, it, vi } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { INTEL_OPS } from "../../src/intelligence/audit-events.js";
import { runLocalIntelligenceSetup } from "../../src/wrap/local-intelligence.js";
import type { OllamaClient } from "../../src/intelligence/substrates/local.js";

function fixture() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const client = {
    pull: vi.fn(),
    show: vi.fn(),
  } as unknown as OllamaClient;
  return { storage, masterKey, auditLog, client };
}

describe("shared protect/init local-intelligence adapter", () => {
  it("keeps production inert and audits manifest-unavailable without model mutation", async () => {
    const { storage, masterKey, auditLog, client } = fixture();
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "test-fortress",
      isTty: true,
      print: vi.fn(),
    }, { client, confirm: vi.fn() })).resolves.toEqual({
      kind: "refused",
      reason: "manifest_unavailable",
    });
    expect(client.pull).not.toHaveBeenCalled();
    expect(client.show).not.toHaveBeenCalled();
    const events = await auditLog.query({
      operation_type: INTEL_OPS.MODEL_PROVISION_REFUSED,
    });
    expect(events.entries.at(-1)?.details).toMatchObject({
      reason: "manifest_unavailable",
    });
  });

  it("skips the future manifest loader on non-TTY even with a positive flag", async () => {
    const { storage, masterKey, auditLog, client } = fixture();
    const loadManifest = vi.fn(async () => "must not load");
    await expect(runLocalIntelligenceSetup({
      storage,
      masterKey,
      auditLog,
      identityId: "test-fortress",
      isTty: false,
      preAnswered: true,
      print: vi.fn(),
    }, { client, loadManifest, confirm: vi.fn() })).resolves.toEqual({
      kind: "refused",
      reason: "non_tty",
    });
    expect(loadManifest).not.toHaveBeenCalled();
    expect(client.pull).not.toHaveBeenCalled();
  });
});
