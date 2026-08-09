import { afterEach, describe, expect, it } from "vitest";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";
import {
  AgentEgressStopError,
  liftAgentEgressStop,
  stopAgentEgress,
} from "../../../src/castle-wall/provision/agent-stop.js";
import {
  egressRulesDir,
} from "../../../src/castle-wall/provision/egress.js";
import { egressPolicyWriterLock } from "../../../src/castle-wall/provision/lockfile.js";
import { countAgentMatchableAllowRules } from "../../../src/cli/castle-wall.js";
import { listAgentMatchableAllowRuleFiles } from "../../../src/castle-wall/allowlist/agent-matchable.js";
import { HABEAS_RULE_ID_PREFIX } from "../../../src/castle-wall/allowlist/habeas-port.js";
import type { AllowlistRule } from "../../../src/castle-wall/allowlist/schema.js";
import type { ResolvedEnforcementAvailability } from "../../../src/castle-wall/runtime/enforcement-availability.js";

const AGENT_ID = "agent-hermes";
const FORTRESS_ID = "fortress-test";
const AGENT_UID = 501;
const GATE_UID = 502;
const NOW = "2026-08-08T00:00:00.000Z";

const tempDirs: string[] = [];

afterEach(async () => {
  for (const dir of tempDirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

async function makeFortress(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "sanctuary-agent-stop-"));
  tempDirs.push(dir);
  await mkdir(egressRulesDir(dir), { recursive: true });
  await writeJson(join(dir, "policy", "egress", "exclusive-routing.json"), {
    version: 1,
    mode: "exclusive",
    agent_uid: AGENT_UID,
    gate_uid: GATE_UID,
    agent_id: AGENT_ID,
    agent_template: "hermes",
  });
  await writeJson(join(dir, "policy", "egress", "agent-origin.json"), {
    mode: "uid",
    agent_uid: AGENT_UID,
    gate_uid: GATE_UID,
    system_uid_allow_ceiling: 500,
  });
  return dir;
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

function allowRule(id: string, host = "api.example.test"): AllowlistRule {
  return {
    id,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: NOW,
    match: { host: [host], port: [443], protocol: "tcp" },
    scope: { uids: [AGENT_UID] },
    disposition: "allow",
  };
}

function denyRule(id: string): AllowlistRule {
  return {
    ...allowRule(id, "deny.example.test"),
    disposition: "deny",
  };
}

async function writeRule(fortress: string, rule: AllowlistRule): Promise<void> {
  await writeJson(join(egressRulesDir(fortress), `${rule.id}.json`), rule);
}

async function readRuleBytes(fortress: string): Promise<Record<string, string>> {
  const dir = egressRulesDir(fortress);
  const out: Record<string, string> = {};
  for (const filename of (await readdir(dir)).sort()) {
    out[filename] = await readFile(join(dir, filename), "utf8");
  }
  return out;
}

const liveAvailability: ResolvedEnforcementAvailability = {
  status: "live",
  reason: "green",
  observed_at: NOW,
  freshness_window_ms: 30_000,
  active_connection_count: 1,
};

function stopInput(fortress: string) {
  return {
    agentId: AGENT_ID,
    protectionSubject: `${FORTRESS_ID}/uid-${AGENT_UID}`,
    fortressId: FORTRESS_ID,
    fortressPath: fortress,
    storagePath: fortress,
    platform: "darwin" as const,
    now: () => new Date(NOW),
    queryEnforcement: async () => liveAvailability,
    reloadPolicy: async () => ({ ok: true }),
  };
}

async function expectStopReason(
  promise: Promise<unknown>,
  reasonCode: string,
): Promise<void> {
  try {
    await promise;
    throw new Error("stop unexpectedly succeeded");
  } catch (err) {
    expect(err).toBeInstanceOf(AgentEgressStopError);
    expect((err as AgentEgressStopError).reasonCode).toBe(reasonCode);
  }
}

describe("agent-matchable allow predicate", () => {
  it("selects the same full set the arm guard counts and treats malformed JSON as false", async () => {
    const fortress = await makeFortress();
    await writeRule(fortress, allowRule("agent-allow"));
    await writeRule(fortress, denyRule("agent-deny"));
    await writeRule(fortress, { ...allowRule("agent-prompt"), disposition: "prompt" });
    await writeRule(fortress, allowRule(`${HABEAS_RULE_ID_PREFIX}local`));
    await writeFile(join(egressRulesDir(fortress), "bad.json"), "{not json");

    const filenames = await readdir(egressRulesDir(fortress));
    const selected = await listAgentMatchableAllowRuleFiles(
      egressRulesDir(fortress),
      filenames,
    );

    expect(selected).toEqual(["agent-allow.json"]);
    expect(await countAgentMatchableAllowRules(fortress)).toBe(selected.length);
  });
});

describe("stopAgentEgress", () => {
  it("revokes agent-matchable allows, preserves habeas and operator rules, and lift restores bytes", async () => {
    const fortress = await makeFortress();
    await writeRule(fortress, allowRule("agent-allow-a"));
    await writeRule(fortress, allowRule("agent-allow-b", "api2.example.test"));
    await writeRule(fortress, allowRule(`${HABEAS_RULE_ID_PREFIX}local`));
    await writeRule(fortress, denyRule("operator-deny-marker"));
    const before = await readRuleBytes(fortress);

    const stopped = await stopAgentEgress(stopInput(fortress));

    expect(stopped).toMatchObject({
      outcome: "engaged",
      agent_uid: AGENT_UID,
      residual_allow_count: 0,
      reload_confirmed: true,
    });
    expect(stopped.revoked_rule_ids.sort()).toEqual([
      "agent-allow-a",
      "agent-allow-b",
    ]);
    const afterStop = await readRuleBytes(fortress);
    expect(Object.keys(afterStop).sort()).toEqual([
      "operator-deny-marker.json",
      `${HABEAS_RULE_ID_PREFIX}local.json`,
    ]);

    const lifted = await liftAgentEgressStop({
      agentId: AGENT_ID,
      fortressPath: fortress,
      storagePath: fortress,
      reloadPolicy: async () => ({ ok: true }),
    });

    expect(lifted.reload_confirmed).toBe(true);
    expect(await readRuleBytes(fortress)).toEqual(before);
  });

  it("refuses unsupported platform before removing files", async () => {
    const fortress = await makeFortress();
    await writeRule(fortress, allowRule("agent-allow"));
    await expectStopReason(
      stopAgentEgress({ ...stopInput(fortress), platform: "linux" }),
      "stop_unsupported_platform",
    );
    expect(await countAgentMatchableAllowRules(fortress)).toBe(1);
  });

  it("refuses when routing marker is absent", async () => {
    const fortress = await makeFortress();
    await rm(join(fortress, "policy", "egress", "exclusive-routing.json"));
    await writeRule(fortress, allowRule("agent-allow"));
    await expectStopReason(
      stopAgentEgress(stopInput(fortress)),
      "stop_agent_not_confined",
    );
    expect(await countAgentMatchableAllowRules(fortress)).toBe(1);
  });

  it("refuses when agent-origin is absent", async () => {
    const fortress = await makeFortress();
    await rm(join(fortress, "policy", "egress", "agent-origin.json"));
    await writeRule(fortress, allowRule("agent-allow"));
    await expectStopReason(
      stopAgentEgress(stopInput(fortress)),
      "stop_agent_not_confined",
    );
    expect(await countAgentMatchableAllowRules(fortress)).toBe(1);
  });

  it("refuses when agent-origin is not uid mode", async () => {
    const fortress = await makeFortress();
    await writeJson(join(fortress, "policy", "egress", "agent-origin.json"), {
      mode: "nat",
      egress_helper_signing_id: "helper",
      system_uid_allow_ceiling: 500,
    });
    await writeRule(fortress, allowRule("agent-allow"));
    await expectStopReason(
      stopAgentEgress(stopInput(fortress)),
      "stop_agent_not_confined",
    );
    expect(await countAgentMatchableAllowRules(fortress)).toBe(1);
  });

  it("refuses when the routing marker uid disagrees with agent-origin", async () => {
    const fortress = await makeFortress();
    await writeJson(join(fortress, "policy", "egress", "exclusive-routing.json"), {
      version: 1,
      mode: "exclusive",
      agent_uid: 599,
      gate_uid: GATE_UID,
      agent_id: AGENT_ID,
      agent_template: "hermes",
    });
    await writeRule(fortress, allowRule("agent-allow"));
    await expectStopReason(
      stopAgentEgress(stopInput(fortress)),
      "stop_uid_binding_mismatch",
    );
    expect(await countAgentMatchableAllowRules(fortress)).toBe(1);
  });

  it("refuses when protection_subject does not match the confined uid", async () => {
    const fortress = await makeFortress();
    await writeRule(fortress, allowRule("agent-allow"));
    await expectStopReason(
      stopAgentEgress({
        ...stopInput(fortress),
        protectionSubject: `${FORTRESS_ID}/uid-999`,
      }),
      "stop_uid_binding_mismatch",
    );
    expect(await countAgentMatchableAllowRules(fortress)).toBe(1);
  });

  it("refuses non-green enforcement without removing files", async () => {
    const fortress = await makeFortress();
    await writeRule(fortress, allowRule("agent-allow-non-green"));
    await expectStopReason(
      stopAgentEgress({
        ...stopInput(fortress),
        queryEnforcement: async () => ({
          ...liveAvailability,
          status: "non_green",
          reason: "manifest_absent",
        }),
      }),
      "stop_enforcement_not_verified",
    );
    expect(await countAgentMatchableAllowRules(fortress)).toBe(1);
  });

  it("refuses indeterminate enforcement without removing files", async () => {
    const fortress = await makeFortress();
    await writeRule(fortress, allowRule("agent-allow-indeterminate"));
    await expectStopReason(
      stopAgentEgress({
        ...stopInput(fortress),
        queryEnforcement: async () => ({
          ...liveAvailability,
          status: "undetermined",
          reason: "no_report",
        }),
      }),
      "stop_enforcement_not_verified",
    );
    expect(await countAgentMatchableAllowRules(fortress)).toBe(1);
  });

  it("refuses when the egress writer lock is already held", async () => {
    const fortress = await makeFortress();
    await writeRule(fortress, allowRule("agent-allow"));
    const release = await egressPolicyWriterLock(fortress).acquire();
    expect(release).not.toBeNull();
    try {
      await expectStopReason(
        stopAgentEgress(stopInput(fortress)),
        "stop_policy_writer_busy",
      );
      expect(await countAgentMatchableAllowRules(fortress)).toBe(1);
    } finally {
      await release!();
    }
  });

  it("restores the snapshot and reports failure when residual agent-matchable reachability survives", async () => {
    const fortress = await makeFortress();
    await writeRule(fortress, allowRule("agent-allow"));
    const before = await readRuleBytes(fortress);

    await expectStopReason(
      stopAgentEgress({
        ...stopInput(fortress),
        afterScrub: async () => {
          await writeRule(fortress, allowRule("agent-residual"));
        },
      }),
      "stop_residual_allow_rules",
    );

    expect(await readRuleBytes(fortress)).toEqual(before);
  });

  it("reports partial on unconfirmed reload and leaves files revoked", async () => {
    const fortress = await makeFortress();
    await writeRule(fortress, allowRule("agent-allow"));

    const result = await stopAgentEgress({
      ...stopInput(fortress),
      reloadPolicy: async () => ({ ok: false, error: "daemon unreachable" }),
    });

    expect(result).toMatchObject({
      outcome: "partial",
      residual_allow_count: 0,
      reload_confirmed: false,
      reason_code: "stop_reload_unconfirmed",
    });
    expect(await countAgentMatchableAllowRules(fortress)).toBe(0);
  });
});
