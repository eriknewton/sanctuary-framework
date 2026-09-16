/**
 * OperatorChatService.sendConcierge — request-scoped local-only constraint
 * (2026-09-15 slice), wired against the REAL `SubstrateSelector`.
 *
 * Unlike most `operator-chat-service.test.ts` cases, which pass a literal
 * stub implementing the selector's narrow method surface, this file
 * constructs the real production `SubstrateSelector` (the one class every
 * consumer routes through) so the assertions prove the `localOnly` flag
 * actually reaches that class's `invoke()` chokepoint from the operator
 * chat's "final answer" call site, not merely that a stub recorded the
 * right argument.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/intelligence/substrates/venice.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/intelligence/substrates/venice.js")>();
  return { ...actual, VeniceClient: vi.fn(actual.VeniceClient) };
});

const { MemoryStorage } = await import("../../src/storage/memory.js");
const { generateRandomKey } = await import("../../src/core/random.js");
const { AuditLog } = await import("../../src/operational/audit-log.js");
const { OperatorChatService, OperatorChatStore } = await import("../../src/chat/operator-chat-index.js");
const { SubstrateSelector } = await import("../../src/intelligence/selector.js");
const { VeniceClient } = await import("../../src/intelligence/substrates/venice.js");
const { INTEL_OPS } = await import("../../src/intelligence/audit-events.js");

const TEST_IDENTITY = "test-operator";

async function buildRealService(opts: { fetchImpl?: typeof fetch } = {}) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new OperatorChatStore(storage, masterKey);
  const substrateSelector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: TEST_IDENTITY,
    fetchImpl: opts.fetchImpl,
  });
  await substrateSelector.load();
  const service = new OperatorChatService({
    store,
    auditLog,
    identityId: TEST_IDENTITY,
    substrateSelector,
  });
  return { service, substrateSelector, auditLog };
}

beforeEach(() => {
  vi.mocked(VeniceClient).mockClear();
});

afterEach(() => {
  vi.mocked(VeniceClient).mockClear();
});

describe("OperatorChatService.sendConcierge — local-only, real SubstrateSelector", () => {
  it("refuses (never constructing VeniceClient) when concierge is bound to venice", async () => {
    const { service, substrateSelector, auditLog } = await buildRealService();
    await substrateSelector.setPerSurfaceChoice("concierge", "venice");
    await substrateSelector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    const response = await service.sendConcierge("what is pending?", { localOnly: true });

    expect(response.outcome).toBe("substrate_disabled");
    expect(response.message.body).toContain("Local-only was requested");
    expect(VeniceClient).not.toHaveBeenCalled();

    const failures = await auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_FAILURE });
    expect(
      failures.entries.some(
        (e) => (e.details as { failure_class?: string }).failure_class === "local_only_violation",
      ),
    ).toBe(true);
  });

  it("positive control: without localOnly, the same venice-bound fortress DOES construct VeniceClient", async () => {
    const { service, substrateSelector } = await buildRealService();
    await substrateSelector.setPerSurfaceChoice("concierge", "venice");
    await substrateSelector.setVeniceApiKey("test-venice-key");
    vi.mocked(VeniceClient).mockClear();

    await service.sendConcierge("what is pending?");

    expect(VeniceClient).toHaveBeenCalledOnce();
  });

  it("succeeds and answers when concierge is (default) local, with localOnly set", async () => {
    const fetchImpl = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = input instanceof Request ? input.url : String(input);
      if (new URL(url, "http://localhost").pathname === "/api/generate") {
        return new Response(JSON.stringify({ response: "local-only operator answer" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("", { status: 404 });
    }) as unknown as typeof fetch;
    const { service } = await buildRealService({ fetchImpl });

    const response = await service.sendConcierge("what is pending?", { localOnly: true });

    expect(response.outcome).toBe("ok");
    expect(response.message.body).toBe("local-only operator answer");
    expect(response.served_by).toBe("local");
    expect(VeniceClient).not.toHaveBeenCalled();
  });
});
