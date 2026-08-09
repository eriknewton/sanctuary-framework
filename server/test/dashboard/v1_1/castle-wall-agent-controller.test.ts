import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MemoryStorage } from "../../../src/storage/memory.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import type { LocalAgentRecord } from "../../../src/contracts/v1.1/local-agent-records.js";
import type { HubAgentControlAction } from "../../../src/hub/constants.js";
import { HubCapabilityError } from "../../../src/hub/errors.js";
import { writePersistedLocalAgents } from "../../../src/hub/agent-registry-persistence.js";
import { protectionSubjectForUid } from "../../../src/castle-wall/subject-binding.js";
import {
  AgentEgressStopError,
  type StopAgentEgressInput,
  type StopAgentEgressObservation,
} from "../../../src/castle-wall/provision/agent-stop.js";
import {
  buildV11Bindings,
  fortressIdFromStoragePath,
} from "../../../src/dashboard/v1_1/wiring.js";
import { CastleWallAgentController } from "../../../src/dashboard/v1_1/castle-wall-agent-controller.js";

async function withTmpFortress<T>(
  fn: (storagePath: string) => Promise<T>,
): Promise<T> {
  const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-nf07-controller-"));
  try {
    return await fn(storagePath);
  } finally {
    await rm(storagePath, { recursive: true, force: true });
  }
}

function makeRecord(
  overrides: Partial<LocalAgentRecord> = {},
): LocalAgentRecord {
  const fortressId = overrides.identity_id ?? "operator-nf07";
  return {
    version: "1.1",
    agent_id: "agent-nf07",
    identity_id: "operator-nf07",
    harness: "claude_code",
    model_provider: { provider: "anthropic", model: "claude" } as never,
    policy_id: "policy-1",
    status: "active",
    budget_summary: {} as never,
    protection_subject: subjectForUid(fortressId, 503),
    last_activity_at: "2026-08-08T00:00:00.000Z",
    wrapped_at: "2026-08-08T00:00:00.000Z",
    capabilities: {
      can_pause: false,
      can_resume: false,
      can_restart: false,
      can_unwrap: false,
      can_lockdown: true,
      can_chat: false,
      can_change_template: false,
    },
    ...overrides,
  };
}

function subjectForUid(fortressId: string, uid: number): string {
  const subject = protectionSubjectForUid(fortressId, uid);
  if (subject === null) throw new Error("test subject must resolve");
  return subject;
}

function engagedObservation(
  storagePath: string,
): StopAgentEgressObservation {
  return {
    outcome: "engaged",
    agent_uid: 503,
    revoked_rule_ids: ["provisioned-harness-allow"],
    residual_allow_count: 0,
    reload_confirmed: true,
    snapshot_path: join(storagePath, "state", "_hub", "stop-snapshots", "agent.json"),
  };
}

function makeAuditLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), randomBytes(32));
}

async function listSourceFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) return listSourceFiles(path);
      return path.endsWith(".ts") ? [path] : [];
    }),
  );
  return nested.flat();
}

describe("CastleWallAgentController", () => {
  it("refuses unsupported process actions with stable NF07 reason codes", async () => {
    const record = makeRecord();
    const controller = new CastleWallAgentController({
      storagePath: "/tmp/sanctuary-nf07",
      fortressPath: "/tmp/sanctuary-nf07",
      fortressId: "operator-nf07",
      auditLog: makeAuditLog(),
      now: () => new Date("2026-08-08T00:00:00.000Z"),
      getAgentRecord: (agentId) => (agentId === record.agent_id ? record : null),
      stopAgentEgress: async () => engagedObservation("/tmp/sanctuary-nf07"),
    });

    const cases: Array<[HubAgentControlAction, () => Promise<unknown>, string]> = [
      [
        "pause",
        () => controller.pause(record.agent_id),
        "agent_control_pause_unsupported_no_process_handle",
      ],
      [
        "resume",
        () => controller.resume(record.agent_id),
        "agent_control_resume_unsupported_no_process_handle",
      ],
      [
        "restart",
        () => controller.restart(record.agent_id),
        "agent_control_restart_unsupported_no_process_handle",
      ],
      [
        "unwrap",
        () => controller.unwrap(record.agent_id),
        "agent_control_unwrap_unsupported_operator_decision_pending",
      ],
    ];

    for (const [action, call, reasonCode] of cases) {
      expect(controller.supports(action, record.agent_id)).toBe(false);
      await expect(call()).rejects.toMatchObject({ reasonCode });
    }
  });

  it("converts stop refusals into HubCapabilityError reason codes", async () => {
    const record = makeRecord();
    const controller = new CastleWallAgentController({
      storagePath: "/tmp/sanctuary-nf07",
      fortressPath: "/tmp/sanctuary-nf07",
      fortressId: "operator-nf07",
      auditLog: makeAuditLog(),
      now: () => new Date("2026-08-08T00:00:00.000Z"),
      getAgentRecord: (agentId) => (agentId === record.agent_id ? record : null),
      stopAgentEgress: async () => {
        throw new AgentEgressStopError("stop_enforcement_not_verified");
      },
    });

    await expect(controller.lockdown(record.agent_id)).rejects.toMatchObject({
      reasonCode: "stop_enforcement_not_verified",
    });
  });

  it("production v1.1 wiring installs the Castle Wall controller and reaches the stop chokepoint", async () => {
    await withTmpFortress(async (storagePath) => {
      const fortressId = fortressIdFromStoragePath(storagePath);
      const identityId = "operator-nf07";
      const record = makeRecord({
        identity_id: identityId,
        protection_subject: subjectForUid(fortressId, 503),
      });
      writePersistedLocalAgents(storagePath, [record]);

      let captured: StopAgentEgressInput | null = null;
      const { hubService } = buildV11Bindings({
        identityId,
        fortressId,
        storagePath,
        auditLog: makeAuditLog(),
        stopAgentEgress: async (input) => {
          captured = input;
          return engagedObservation(storagePath);
        },
      });
      const controller = (
        hubService as unknown as {
          deps: { agentController: unknown };
        }
      ).deps.agentController;
      expect(controller).toBeInstanceOf(CastleWallAgentController);

      const enqueued = await hubService.controlAgent(record.agent_id, "lockdown");
      expect("inbox_item_id" in enqueued).toBe(true);
      const itemId = "inbox_item_id" in enqueued ? enqueued.inbox_item_id : "";
      const resolved = await hubService.resolveInboxItem(itemId, "approve");

      expect(captured).toMatchObject({
        agentId: record.agent_id,
        protectionSubject: record.protection_subject,
        fortressId,
        fortressPath: storagePath,
        storagePath,
      });
      expect(resolved.kind).toBe("approval_pending");
      if (resolved.kind === "approval_pending") {
        expect(resolved.resolution_payload).toMatchObject({
          outcome: "engaged",
          agent_uid: 503,
          revoked_rule_ids: ["provisioned-harness-allow"],
          residual_allow_count: 0,
          reload_confirmed: true,
        });
      }
    });
  });

  it("does not leave the old placeholder controller in the shipped source tree", async () => {
    const srcFiles = await listSourceFiles(join(process.cwd(), "src"));
    const matches: string[] = [];
    for (const file of srcFiles) {
      const source = await readFile(file, "utf8");
      if (source.includes("CapabilityErrorAgentController")) {
        matches.push(file);
      }
    }
    expect(matches).toEqual([]);
  });
});
