// fail-before-exempt: the code under test is server/scripts/demo, which the server/src revert leaves in place; the test fails without that code (the PR records the witness).
import { lstat, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { seedDemoFortress } from "../../scripts/demo/seed-fortress-lib.js";
import { getFreePort } from "../helpers/free-port.js";

const PASSPHRASE = "demo fixture passphrase with enough entropy for tests";

async function mtimeMs(path: string): Promise<number | null> {
  try {
    return (await lstat(path)).mtimeMs;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

async function getJson(baseUrl: string, path: string, token: string): Promise<unknown> {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(response.status, `${path} status`).toBe(200);
  return response.json();
}

function dataRecord(payload: unknown): Record<string, unknown> {
  expect(payload).toBeTruthy();
  expect(typeof payload).toBe("object");
  return payload as Record<string, unknown>;
}

describe("seedDemoFortress", () => {
  it("seeds a temp-only demo fortress through server read paths", async () => {
    const realHome = process.env.HOME;
    const realSanctuaryPath = realHome ? join(realHome, ".sanctuary") : null;
    const realSanctuaryBefore = realSanctuaryPath
      ? await mtimeMs(realSanctuaryPath)
      : null;
    const home = await mkdtemp(join(tmpdir(), "sanctuary-demo-fortress-"));
    const port = await getFreePort();
    const seeded = await seedDemoFortress({
      home,
      passphrase: PASSPHRASE,
      port,
      startDashboard: true,
      removeOnStop: true,
      now: () => new Date("2026-10-14T12:00:00.000Z"),
    });

    try {
      for (const touched of seeded.touchedPaths) {
        const root = resolve(home);
        const candidate = resolve(touched);
        expect(candidate === root || candidate.startsWith(`${root}/`)).toBe(true);
      }

      const agentsPayload = dataRecord(
        await getJson(seeded.apiBaseUrl, "/api/hub/agents?limit=10", seeded.authToken),
      );
      const agentsData = dataRecord(agentsPayload.data);
      const agents = agentsData.agents as Array<Record<string, unknown>>;
      expect(agents.map((agent) => agent.agent_id).sort()).toEqual(
        seeded.agentIds.slice().sort(),
      );

      const pending = (await getJson(
        seeded.apiBaseUrl,
        "/api/pending",
        seeded.authToken,
      )) as Array<Record<string, unknown>>;
      expect(pending).toHaveLength(2);
      expect(pending.map((item) => item.operation).sort()).toEqual([
        "demo_agent_unwrap_request",
        "demo_policy_template_change",
      ]);

      const findingsPayload = dataRecord(
        await getJson(
          seeded.apiBaseUrl,
          "/api/sentinels/findings?limit=10",
          seeded.authToken,
        ),
      );
      const findingsData = dataRecord(findingsPayload.data);
      const findings = findingsData.findings as Array<Record<string, unknown>>;
      expect(findings).toHaveLength(1);
      expect(findings[0]?.finding_id).toBe(seeded.findingId);

      const auditPayload = dataRecord(
        await getJson(seeded.apiBaseUrl, "/api/audit-log?limit=100", seeded.authToken),
      );
      const entries = auditPayload.entries as Array<Record<string, unknown>>;
      expect(entries.some((entry) => entry.operation === "demo_agent_registered")).toBe(true);
      expect(
        entries.some((entry) => entry.operation === "sentinel_finding_emitted"),
      ).toBe(true);
      expect(
        entries.some((entry) => entry.operation === "demo_audit_chain_verified"),
      ).toBe(true);

      const snapshot = dataRecord(
        await getJson(seeded.apiBaseUrl, "/api/snapshot", seeded.authToken),
      );
      expect(String(dataRecord(snapshot.agent).display_name)).toContain("demo");
      expect((snapshot.pending_approvals as unknown[]).length).toBe(2);
    } finally {
      await seeded.stop();
    }

    expect(process.env.HOME).toBe(realHome);
    const realSanctuaryAfter = realSanctuaryPath
      ? await mtimeMs(realSanctuaryPath)
      : null;
    expect(realSanctuaryAfter).toBe(realSanctuaryBefore);
  });
});
