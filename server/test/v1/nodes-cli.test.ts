import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";

import { DashboardRequestError } from "../../src/cli/dashboard-request.js";
import { runNodesCommand } from "../../src/cli/nodes.js";

function capture() {
  let text = "";
  const stream = new Writable({
    write(chunk, _enc, cb) {
      text += chunk.toString();
      cb();
    },
  });
  return { stream, get: () => text };
}

describe("sanctuary nodes list", () => {
  it("requires a v1 session token", async () => {
    const err = capture();
    const code = await runNodesCommand({
      argv: ["list"],
      env: {},
      out: capture().stream,
      err: err.stream,
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/SANCTUARY_V1_SESSION_TOKEN/);
  });

  it("prints JSON from GET /v1/nodes", async () => {
    const out = capture();
    const code = await runNodesCommand({
      argv: ["list", "--session-token", "session", "--output", "json"],
      env: {},
      out: out.stream,
      err: capture().stream,
      request: async (path, _init, ctx) => {
        expect(path).toBe("/v1/nodes");
        expect(ctx?.authToken).toBe("session");
        return {
          nodes: [
            {
              node_id: "linux-1",
              attestation_status: "verified",
              last_sync: { received_at: "2026-06-10T00:00:00.000Z" },
            },
          ],
          total: 1,
        };
      },
    });
    expect(code).toBe(0);
    expect(JSON.parse(out.get()).nodes[0].node_id).toBe("linux-1");
  });

  it("accepts equals-form value flags", async () => {
    const out = capture();
    const code = await runNodesCommand({
      argv: [
        "list",
        "--session-token=session",
        "--output=json",
        "--dashboard-url=http://127.0.0.1:4500",
      ],
      env: {},
      out: out.stream,
      err: capture().stream,
      request: async (path, _init, ctx) => {
        expect(path).toBe("/v1/nodes");
        expect(ctx?.authToken).toBe("session");
        expect(ctx?.dashboardUrl).toBe("http://127.0.0.1:4500");
        return { nodes: [], total: 0 };
      },
    });

    expect(code).toBe(0);
    expect(JSON.parse(out.get()).total).toBe(0);
  });

  it("prints node mode and trust-boundary label in table output", async () => {
    const out = capture();
    const code = await runNodesCommand({
      argv: ["list", "--session-token", "session"],
      env: {},
      out: out.stream,
      err: capture().stream,
      request: async () => ({
        nodes: [
          {
            node_id: "cloud-1",
            node_mode: "operator_cloud",
            attestation_status: "verified",
            trust_boundary: { label: "provider in trust boundary, not TEE" },
            last_sync: { received_at: "2026-06-10T00:00:00.000Z" },
          },
        ],
        total: 1,
      }),
    });
    expect(code).toBe(0);
    expect(out.get()).toContain("MODE");
    expect(out.get()).toContain("TRUST BOUNDARY");
    expect(out.get()).toContain("operator_cloud");
    expect(out.get()).toContain("provider in trust boundary, not TEE");
  });

  it("maps auth failures to exit code 3", async () => {
    const err = capture();
    const code = await runNodesCommand({
      argv: ["list", "--session-token", "bad"],
      env: {},
      out: capture().stream,
      err: err.stream,
      request: async () => {
        throw new DashboardRequestError("denied", "auth", 401);
      },
    });
    expect(code).toBe(3);
    expect(err.get()).toMatch(/denied/);
  });
});
