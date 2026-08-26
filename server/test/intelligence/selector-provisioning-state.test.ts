import { describe, expect, it } from "vitest";
import { generateRandomKey } from "../../src/core/random.js";
import { SubstrateSelector } from "../../src/intelligence/selector.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";

function buildSelector(storage = new MemoryStorage(), masterKey = generateRandomKey()) {
  const auditLog = new AuditLog(storage, masterKey);
  const fetchImpl = (async () => new Response(JSON.stringify({ models: [] }), {
    status: 200,
    headers: { "content-type": "application/json" },
  })) as typeof fetch;
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: "provisioning-test",
    fetchImpl,
  });
  return { selector, storage, masterKey, auditLog, fetchImpl };
}

describe("selector provisioning state", () => {
  it("persists refusals into operator-visible DEGRADED status", async () => {
    const { selector, storage, masterKey, auditLog, fetchImpl } = buildSelector();
    await selector.load();
    await selector.recordLocalProvisioningFailure(
      ["concierge"],
      "substrate_misconfigured",
      "signed manifest unavailable",
    );
    const reloaded = new SubstrateSelector({
      storage,
      masterKey,
      auditLog,
      identityId: "provisioning-test",
      fetchImpl,
    });
    await reloaded.load();
    const status = await reloaded.getOperatorVisibleStatus();
    const concierge = status.surfaces.find((surface) => surface.surface === "concierge");
    expect(concierge?.health).toBe("degraded");
    expect(concierge?.recentFailures.at(-1)?.snippet).toBe("signed manifest unavailable");
    expect(reloaded.getConfig().perSurface.concierge).toBe("local");
  });
});
