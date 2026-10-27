import * as fs from "node:fs/promises";
import { join } from "node:path";
import { vi } from "vitest";
import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../../src/castle-wall/constants.js";
import { stopAgentEgress } from "../../../src/castle-wall/provision/agent-stop.js";
import { egressRulesDir } from "../../../src/castle-wall/provision/egress.js";

// Snapshot restoration preserves file-specific refusal reasons. IC-11.
export async function stoppedAgentFixture(fortressPath: string, agentId: string) {
  const agentUid = 501; // First uid above the fixture's system uid ceiling.
  const gateUid = agentUid + 1;
  const fortressId = "fixture-fortress";
  const now = "2026-10-27T00:00:00.000Z";
  const rulesDir = egressRulesDir(fortressPath);
  await fs.mkdir(rulesDir, { recursive: true });
  await fs.writeFile(join(fortressPath, "policy", "egress", "exclusive-routing.json"), JSON.stringify({
    version: 1, mode: "exclusive", agent_uid: agentUid, gate_uid: gateUid,
    agent_id: agentId, agent_template: "hermes",
  }));
  await fs.writeFile(join(fortressPath, "policy", "egress", "agent-origin.json"), JSON.stringify({
    mode: "uid", agent_uid: agentUid, gate_uid: gateUid, system_uid_allow_ceiling: agentUid - 1,
  }));
  const rulePath = join(rulesDir, "agent-allow.json");
  await fs.writeFile(rulePath, JSON.stringify({
    id: "agent-allow", schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: now, match: { host: ["api.example.test"], port: [443], protocol: "tcp" }, // HTTPS port.
    scope: { uids: [agentUid] }, disposition: "allow",
  }));
  const stopped = await stopAgentEgress({
    agentId, fortressId, fortressPath, storagePath: fortressPath,
    protectionSubject: `${fortressId}/uid-${agentUid}`, platform: "darwin",
    now: () => new Date(now),
    queryEnforcement: async () => ({
      status: "live", reason: "green", observed_at: now,
      freshness_window_ms: 30_000, // Thirty-second fixture probe window.
      active_connection_count: 0,
    }),
    reloadPolicy: async () => ({ ok: true }),
  });
  return { stopped, rulesDir, rulePath };
}

export function removeRulesBeforeRestoreWrite(rulesDir: string, rulePath: string): void {
  const writeFile = fs.writeFile;
  vi.spyOn(fs, "writeFile").mockImplementation(async (path, data, options) => {
    // Restore recreates an absent directory; schedule its loss immediately before the real write.
    if (path === rulePath) await fs.rm(rulesDir, { recursive: true, force: true });
    return writeFile(path, data, options);
  });
}
