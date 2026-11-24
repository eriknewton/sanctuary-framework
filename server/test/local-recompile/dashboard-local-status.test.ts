// The operator status route reports the local task ready only when a valid job could be granted now.
import type { IncomingMessage, ServerResponse } from "node:http";
import { describe, expect, it } from "vitest";
import { handleLocalRoute, type LocalDashboardSurface } from "../../src/local-recompile/dashboard-routes.js";

// Must match LOCAL_AUTHORITY_NOTICE in src/local-recompile/dashboard-routes.ts.
const AUTHORITY_NOTICE =
  "Local tasks are not ready: the local model binding did not verify. A binding set up or changed after the server started needs a server restart.";

async function status(authorityCause: string | null, armed = true): Promise<Record<string, unknown>> {
  const surface: LocalDashboardSurface = {
    status: { armed, cause: armed ? null : "worker_unavailable", authorityCause: () => authorityCause, workerPid: () => undefined, queueDepth: () => 0 },
    modelTag: () => null,
    stores: null,
  };
  let body = "";
  let code = 0;
  const res = {
    writeHead: (statusCode: number) => {
      code = statusCode;
      return res;
    },
    end: (text: string) => {
      body = text;
    },
  } as unknown as ServerResponse;
  const req = { method: "GET", url: "/api/local/status" } as IncomingMessage;
  expect(await handleLocalRoute(surface, req, res)).toBe(true);
  expect(code).toBe(200);
  return JSON.parse(body) as Record<string, unknown>;
}

describe("local task status", () => {
  it.each([["unarmed"], ["binding_absent"], ["epoch_changed"]])("an armed tool whose authority refuses as %s is not ready and names the cause", async (cause) => {
    expect(await status(cause)).toMatchObject({ armed: true, ready: false, authority_cause: cause, notice: AUTHORITY_NOTICE });
  });

  it("an armed tool whose authority would grant is ready, with no notice", async () => {
    const body = await status(null);
    expect(body).toMatchObject({ armed: true, ready: true, authority_cause: null });
    expect(body).not.toHaveProperty("notice");
  });

  it("a disarmed tool is not ready", async () => {
    expect(await status(null, false)).toMatchObject({ armed: false, ready: false, cause: "worker_unavailable" });
  });
});
