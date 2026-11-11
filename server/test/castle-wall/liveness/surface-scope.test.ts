// fail-before-exempt: public status scope already excludes liveness at base
import { expect, it, vi } from "vitest";
import { Writable } from "node:stream";
import { startRig } from "../../v1/rig.js";
import { handleRequest } from "../../../src/dashboard/api.js";
import { getSanctuaryVersion } from "../../../src/version.js";
import * as sessions from "../../../src/cli/v1-session.js";
import * as dashboardRequests from "../../../src/cli/dashboard-request.js";
import { runStatusCommand } from "../../../src/cli/status.js";
import { createDashboardReadFlightMap } from "../../../src/dashboard/read-response.js";
import { createPosturePanelStore } from "../../../src/principal-policy/panel-producer.js";
import type { IncomingMessage, ServerResponse } from "node:http";

it("keeps public status byte-identical and component-free", async () => {
  const rig = await startRig();
  try {
    const response = await fetch(rig.baseUrl + "/v1/status");
    expect(await response.text()).toBe(JSON.stringify({ ok: true, version: getSanctuaryVersion() }));
  } finally { await rig.stop(); }
});

it("keeps health and readiness payloads component-free", async () => {
  const deps = { sources: { mode: "co-located" as const, server_version: "fixture" }, authToken: "fixture",
    readFlightMap: createDashboardReadFlightMap(), panelStore: createPosturePanelStore() };
  for (const path of ["/api/health", "/api/readiness"]) {
    let body = "";
    const res = { writeHead() {}, end(s: string) { body = s; } } as unknown as ServerResponse;
    await handleRequest(deps, { url: path, method: "GET", headers: { authorization: "Bearer fixture" } } as unknown as IncomingMessage, res);
    const value = JSON.parse(body);
    expect(value).not.toHaveProperty("castle_wall_liveness");
    expect(Object.keys(value).sort()).toEqual(path === "/api/health" ? ["instance", "mode", "ok", "since"] : ["ready", "supervisor"]);
  }
});

it("keeps the status command successful when the authenticated response has wall DOWN", async () => {
  let text = "";
  const out = new Writable({ write(chunk, _encoding, done) { text += chunk; done(); } });
  const session = vi.spyOn(sessions, "openV1Session").mockResolvedValue({ token: "fixture" } as never);
  const spy = vi.spyOn(dashboardRequests, "dashboardRequest").mockResolvedValue({ ok: true,
    castle_wall_liveness: { wall: { state: "wall_DOWN" }, exit_code: 1 } } as never);
  try {
    const code = await runStatusCommand({ argv: ["--output", "json"], out });
    expect(code).toBe(0); expect(JSON.parse(text).castle_wall_liveness.wall.state).toBe("wall_DOWN");
  } finally { spy.mockRestore(); session.mockRestore(); }
});
