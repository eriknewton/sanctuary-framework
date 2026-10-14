// fail-before-exempt: the code under test is menubar/src/api/client.ts, outside server/src; the test fails against main's menubar client (the PR records the witness).
import { beforeEach, describe, expect, it, vi } from "vitest";

const fetchMock = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/plugin-http", () => ({
  fetch: fetchMock,
}));

function jsonResponse(payload: unknown, ok = true): { ok: boolean; json: () => Promise<unknown> } {
  return {
    ok,
    json: async () => payload,
  };
}

async function loadClient(): Promise<any> {
  return import(new URL("../../../menubar/src/api/client.ts", import.meta.url).href);
}

describe("menubar FortressClient routes", () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  it("counts pending approvals from the dashboard /api/pending route", async () => {
    const { FortressClient } = await loadClient();
    fetchMock.mockResolvedValueOnce(
      jsonResponse([
        { id: "a", operation: "op-a", tier: 1 },
        { id: "b", operation: "op-b", tier: 1 },
      ]),
    );

    const client = new FortressClient({
      fortressEndpoint: "http://127.0.0.1:3517",
      authToken: "token",
    });

    await expect(client.fetchPendingTier1Count()).resolves.toBe(2);
    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:3517/api/pending",
      expect.objectContaining({
        method: "GET",
        headers: expect.objectContaining({ Authorization: "Bearer token" }),
      }),
    );
  });

  it("builds a fleet snapshot from served dashboard endpoints", async () => {
    const { FortressClient } = await loadClient();
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse([
          {
            id: "hold-1",
            operation: "state_export",
            tier: 1,
            reason: "Needs operator approval",
            context: { agent_id: "agent-1" },
            created_at: "2026-10-14T12:00:00.000Z",
          },
        ]),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          entries: [
            {
              timestamp: "2026-10-14T12:00:01.000Z",
              layer: "l2",
              operation: "sentinel_finding_emitted",
              identity_id: "operator-1",
              result: "success",
              details: { agent_id: "agent-1" },
            },
          ],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          generated_at: "2026-10-14T12:00:02.000Z",
          overall: { status: "healthy" },
          agent: {
            display_name: "demo fortress",
            primary_identity_id: "operator-1",
            identity_count: 1,
          },
        }),
      );

    const client = new FortressClient({
      fortressEndpoint: "http://127.0.0.1:3517",
    });
    const snapshot = await client.fetchFleetSnapshot();

    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
      "http://127.0.0.1:3517/api/pending",
      "http://127.0.0.1:3517/api/audit-log?limit=10",
      "http://127.0.0.1:3517/api/snapshot",
    ]);
    expect(snapshot.connection_status).toBe("connected");
    expect(snapshot.pending_tier1).toEqual([
      expect.objectContaining({
        audit_id: "hold-1",
        agent_id: "agent-1",
        tool: "state_export",
      }),
    ]);
    expect(snapshot.recent_events).toEqual([
      expect.objectContaining({
        agent_id: "agent-1",
        tier: 2,
        decision: "approved",
      }),
    ]);
    expect(snapshot.agents).toEqual([
      expect.objectContaining({
        agent_id: "operator-1",
        tier: "A",
        status: "online",
      }),
    ]);
  });
});
