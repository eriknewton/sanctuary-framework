import { describe, expect, it, vi } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { buildV11Bindings } from "../../src/dashboard/v1_1/wiring.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../../src/castle-wall/constants.js";
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

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const producerPriv = ed25519.utils.randomPrivateKey();
const producerPubB64 = toBase64url(ed25519.getPublicKey(producerPriv));
const SIGNED_AT_MS = 1_777_777_777_777;

function withProducerSignature(
  entry: AuditEntry,
  identityId: string,
): AuditEntry {
  const seq = typeof entry.details?.seq === "number" ? entry.details.seq : 91;
  const body = JSON.stringify({
    timestamp: entry.timestamp,
    layer: entry.layer,
    operation: entry.operation,
    identity_id: identityId,
    result: entry.result,
    details: entry.details ?? {},
  });
  const sig = ed25519.sign(
    producerSigningBytes(body, SIGNED_AT_MS, seq),
    producerPriv,
  );
  return {
    ...entry,
    identity_id: identityId,
    details: {
      ...(entry.details ?? {}),
      seq,
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]:
        CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT_MS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    },
  };
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

  it("threads the producer key so legitimate signed Castle Wall activity remains attributable", async () => {
    const storage = new MemoryStorage();
    const masterKey = randomBytes(32);
    const auditLog = new AuditLog(storage, masterKey);
    const identityId = "op-1";
    const signed = withProducerSignature(
      {
        timestamp: "2026-07-20T10:10:00.000Z",
        layer: "l1",
        operation: "egress_blocked",
        identity_id: identityId,
        result: "success",
        details: {
          agent_id: identityId,
          agent_template: "claude-code",
          dest_host: "legitimate.example.com",
          dest_ip: "198.51.100.10",
          dest_port: 443,
          dest_protocol: "tcp",
        },
      },
      identityId,
    );
    await auditLog.appendCritical(signed);
    await auditLog.flush();

    const { selector, captured } = makeCapturingSelector();
    const bindings = buildV11Bindings({
      identityId,
      fortressId: "fortress-dashboard-attribution",
      auditLog,
      storage,
      masterKey,
      intelligenceSelector: selector,
      pinnedProducerKeyB64url: producerPubB64,
    });

    const activity = await bindings.hubService.listActivity({
      agent_id: identityId,
      limit: 10,
    });
    expect(activity).toHaveLength(1);
    expect(activity[0]!.agent_id).toBe(identityId);
    expect(activity[0]!.attestation!.state).toBe("verified");

    await bindings.operatorChatService!.sendConcierge("show recent activity");

    expect(captured.context).toContain(`agent=${identityId}`);
    expect(captured.context).not.toContain("agent=_fortress");
  });
});
