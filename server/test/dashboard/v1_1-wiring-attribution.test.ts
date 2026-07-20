import { describe, expect, it, vi } from "vitest";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import { buildV11Bindings } from "../../src/dashboard/v1_1/wiring.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import { canonicalize } from "../../src/mesh/canonical-json.js";
import { writePersistedLocalAgents } from "../../src/hub/agent-registry-persistence.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import { protectionSubjectForUid } from "../../src/castle-wall/subject-binding.js";
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

function auditTokenForRuid(uid: number): string {
  const vals = [
    0xffffffff,
    uid,
    uid,
    uid,
    uid,
    0x00000269,
    0x000186ae,
    0x00000566,
  ];
  return vals
    .map((value) => {
      const bytes = new Uint8Array(4);
      new DataView(bytes.buffer).setUint32(0, value >>> 0, true);
      return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    })
    .join("");
}

function subjectForUid(fortressId: string, uid: number): string {
  const subject = protectionSubjectForUid(fortressId, uid);
  if (subject === null) throw new Error("test subject could not be derived");
  return subject;
}

function makeLocalAgent(
  overrides: Partial<LocalAgentRecord> = {},
): LocalAgentRecord {
  const base: LocalAgentRecord = {
    version: "1.1",
    agent_id: "agent-macos-prod",
    identity_id: "operator-macos-prod",
    harness: "claude_code",
    harness_version: "1.0.0",
    model_provider: {
      vendor: "anthropic",
      model_id: "claude-opus-4-7",
      runs_locally: false,
    },
    policy_id: "policy-default",
    channel_template_id: "request-approve-act",
    status: "active",
    budget_summary: {
      daily: { unit: "tokens", cap: 100_000, used: 0 },
      last_refreshed_at: "2026-07-20T00:00:00.000Z",
    },
    last_activity_at: "2026-07-20T10:00:00.000Z",
    wrapped_at: "2026-07-20T00:00:00.000Z",
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: true,
      can_change_template: true,
    },
  };
  return { ...base, ...overrides };
}

async function withTmpFortress<T>(
  fn: (storagePath: string) => Promise<T>,
): Promise<T> {
  const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-hub-macos-"));
  try {
    return await fn(storagePath);
  } finally {
    await rm(storagePath, { recursive: true, force: true });
  }
}

function withProducerSignature(
  entry: AuditEntry,
  identityId: string,
): AuditEntry {
  const seq = typeof entry.details?.seq === "number" ? entry.details.seq : 91;
  const body = canonicalize({
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

function signedMacOSEgressEntry(args: {
  fortressId: string;
  uid: number;
  timestamp?: string;
}): AuditEntry {
  const subject = subjectForUid(args.fortressId, args.uid);
  return withProducerSignature(
    {
      timestamp: args.timestamp ?? "2026-07-20T10:20:00.000Z",
      layer: "l1",
      operation: "egress_blocked",
      identity_id: subject,
      result: "success",
      details: {
        agent_id: auditTokenForRuid(args.uid),
        agent_template: "claude-code",
        dest_host: "legitimate.example.com",
        dest_ip: "198.51.100.10",
        dest_port: 443,
        dest_protocol: "tcp",
        source: "macos_extension",
      },
    },
    subject,
  );
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

  it("resolves macOS signed protection subjects to the wrapped id for activity and inspect", async () => {
    await withTmpFortress(async (storagePath) => {
      const storage = new MemoryStorage();
      const masterKey = randomBytes(32);
      const auditLog = new AuditLog(storage, masterKey);
      const fortressId = "fortress:test";
      const identityId = "operator-macos-prod";
      const protectionSubject = subjectForUid(fortressId, 503);
      const record = makeLocalAgent({
        agent_id: "agent-macos-prod",
        identity_id: identityId,
        protection_subject: protectionSubject,
      });
      writePersistedLocalAgents(storagePath, [record]);

      const signed = signedMacOSEgressEntry({ fortressId, uid: 503 });
      await auditLog.appendCritical(signed);
      await auditLog.flush();

      const bindings = buildV11Bindings({
        identityId,
        fortressId,
        storagePath,
        auditLog,
        storage,
        masterKey,
        pinnedProducerKeyB64url: producerPubB64,
      });

      const activity = await bindings.hubService.listActivity({ limit: 10 });
      expect(activity).toHaveLength(1);
      expect(activity[0]!.agent_id).toBe("agent-macos-prod");
      expect(activity[0]!.display_template_args).toContainEqual({
        kind: "agent_id",
        value: "agent-macos-prod",
      });

      const filteredByWrappedId = await bindings.hubService.listActivity({
        agent_id: "agent-macos-prod",
        limit: 10,
      });
      expect(filteredByWrappedId).toHaveLength(1);
      expect(filteredByWrappedId[0]!.agent_id).toBe("agent-macos-prod");

      const filteredBySubject = await bindings.hubService.listActivity({
        agent_id: protectionSubject,
        limit: 10,
      });
      expect(filteredBySubject).toHaveLength(0);

      const panel =
        await bindings.hubService.openAgentInspectPanel("agent-macos-prod");
      expect(panel.recent_activity).toHaveLength(1);
      expect(panel.recent_activity[0]!.agent_id).toBe("agent-macos-prod");
    });
  });

  it("resolves macOS signed protection subjects to the wrapped id in concierge recent-activity lines", async () => {
    await withTmpFortress(async (storagePath) => {
      const storage = new MemoryStorage();
      const masterKey = randomBytes(32);
      const auditLog = new AuditLog(storage, masterKey);
      const fortressId = "fortress:test";
      const identityId = "operator-macos-prod";
      const protectionSubject = subjectForUid(fortressId, 503);
      const record = makeLocalAgent({
        agent_id: "agent-macos-prod",
        identity_id: identityId,
        protection_subject: protectionSubject,
      });
      writePersistedLocalAgents(storagePath, [record]);

      const signed = signedMacOSEgressEntry({ fortressId, uid: 503 });
      await auditLog.appendCritical(signed);
      await auditLog.flush();

      const { selector, captured } = makeCapturingSelector();
      const bindings = buildV11Bindings({
        identityId,
        fortressId,
        storagePath,
        auditLog,
        storage,
        masterKey,
        intelligenceSelector: selector,
        pinnedProducerKeyB64url: producerPubB64,
      });

      await bindings.operatorChatService!.sendConcierge("show recent activity");

      expect(captured.context).toContain(
        "2026-07-20T10:20:00.000Z  l1.egress_blocked  agent=agent-macos-prod  result=success",
      );
      expect(captured.context).not.toContain(`agent=${protectionSubject}`);
    });
  });

  it("does not invent a wrapped id for unmatched macOS signed protection subjects", async () => {
    await withTmpFortress(async (storagePath) => {
      const storage = new MemoryStorage();
      const masterKey = randomBytes(32);
      const auditLog = new AuditLog(storage, masterKey);
      const fortressId = "fortress:test";
      const identityId = "operator-macos-prod";
      const protectionSubject = subjectForUid(fortressId, 503);
      const unrelatedRecord = makeLocalAgent({
        agent_id: "agent-forged-label",
        identity_id: identityId,
        protection_subject: subjectForUid(fortressId, 777),
      });
      writePersistedLocalAgents(storagePath, [unrelatedRecord]);

      const signed = signedMacOSEgressEntry({ fortressId, uid: 503 });
      await auditLog.appendCritical(signed);
      await auditLog.flush();

      const bindings = buildV11Bindings({
        identityId,
        fortressId,
        storagePath,
        auditLog,
        storage,
        masterKey,
        pinnedProducerKeyB64url: producerPubB64,
      });

      const activity = await bindings.hubService.listActivity({ limit: 10 });
      expect(activity).toHaveLength(1);
      expect(activity[0]!.agent_id).toBe(protectionSubject);
      expect(activity[0]!.agent_id).not.toBe("agent-forged-label");

      const filteredByUnmatchedWrappedId =
        await bindings.hubService.listActivity({
          agent_id: "agent-forged-label",
          limit: 10,
        });
      expect(filteredByUnmatchedWrappedId).toHaveLength(0);
    });
  });

  it("renders unmatched macOS signed protection subjects raw in concierge recent-activity lines", async () => {
    await withTmpFortress(async (storagePath) => {
      const storage = new MemoryStorage();
      const masterKey = randomBytes(32);
      const auditLog = new AuditLog(storage, masterKey);
      const fortressId = "fortress:test";
      const protectionSubject = subjectForUid(fortressId, 503);
      const identityId = protectionSubject;
      const unrelatedRecord = makeLocalAgent({
        agent_id: "agent-forged-label",
        identity_id: identityId,
        protection_subject: subjectForUid(fortressId, 777),
      });
      writePersistedLocalAgents(storagePath, [unrelatedRecord]);

      const signed = signedMacOSEgressEntry({ fortressId, uid: 503 });
      await auditLog.appendCritical(signed);
      await auditLog.flush();

      const { selector, captured } = makeCapturingSelector();
      const bindings = buildV11Bindings({
        identityId,
        fortressId,
        storagePath,
        auditLog,
        storage,
        masterKey,
        intelligenceSelector: selector,
        pinnedProducerKeyB64url: producerPubB64,
      });

      await bindings.operatorChatService!.sendConcierge("show recent activity");
      expect(captured.context).toContain(
        `2026-07-20T10:20:00.000Z  l1.egress_blocked  agent=${protectionSubject}  result=success`,
      );
      expect(captured.context).not.toContain("agent=agent-forged-label");
    });
  });
});
