import { describe, expect, it, vi } from "vitest";
import { randomBytes } from "node:crypto";

import { buildV11Bindings } from "../../src/dashboard/v1_1/wiring.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { SubstrateSelector } from "../../src/intelligence/index.js";
import type {
  SubstrateHandle,
  SubstrateResponse,
  SummarizeRequest,
} from "../../src/intelligence/types.js";

function makeCapturingSelector(): {
  selector: SubstrateSelector;
  captured: { context: string | null };
} {
  const captured = { context: null as string | null };
  const handle: SubstrateHandle = {
    surface: "concierge",
    substrate: "local",
    badge: {
      surface: "concierge",
      substrate: "local",
      labelKey: "test",
      tradeoffKey: "test",
      status: "green",
    },
    capability: { summarize: true, classify: false, redact: false },
    displayLabel: "Test Local",
  };
  const selector = {
    getSubstrate: vi.fn().mockResolvedValue(handle),
    invokeSummarize: vi.fn(
      async (
        _surface: string,
        req: SummarizeRequest,
      ): Promise<SubstrateResponse> => {
        captured.context = req.context;
        return {
          servedBy: "local",
          failureClass: null,
          body: { kind: "summarize" as const, text: "ok" },
          completedAt: new Date().toISOString(),
          latencyMs: 1,
        };
      },
    ),
  } as unknown as SubstrateSelector;
  return { selector, captured };
}

describe("v1.1 dashboard wiring Castle Wall attribution", () => {
  it("does not attribute forged unsigned Castle Wall activity to a victim in concierge context", async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const auditLog = new AuditLog(storage, masterKey);
    const identityId = "operator-dashboard-attribution";
    await auditLog.append(
      "l1",
      "egress_blocked",
      identityId,
      {
        agent_id: "victim-agent-b",
        dest_host: "evil.example",
        dest_ip: "203.0.113.91",
        dest_port: 443,
        dest_protocol: "tcp",
      },
      "success",
    );
    await auditLog.flush();

    const { selector, captured } = makeCapturingSelector();
    const bindings = buildV11Bindings({
      identityId,
      fortressId: "fortress-dashboard-attribution",
      auditLog,
      storage,
      masterKey,
      intelligenceSelector: selector,
    });

    await bindings.operatorChatService!.sendConcierge(
      "show recent activity for victim-agent-b",
    );

    expect(captured.context).toContain("agent=_fortress");
    expect(captured.context).not.toContain("victim-agent-b");
    expect(captured.context).not.toContain("verified");
  });
});
