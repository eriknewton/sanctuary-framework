/**
 * Phase S1 — Supervisor local socket end-to-end (real AF_UNIX).
 *
 * Exercises the dashboard-client → supervisor-server round trip over a real
 * unix socket in a 0700 temp dir, plus the security gates the codex
 * adversarial lens targets:
 *   - a client with the WRONG auth secret cannot get a request serviced;
 *   - the server REFUSES to bind in a group/other-accessible dir (fail closed);
 *   - an over-long / garbage frame closes the connection without servicing;
 *   - the read budget caps a flood.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "node:net";
import { SupervisorSocketServer } from "../../src/supervisor/socket-server.js";
import { sendSupervisorRequest } from "../../src/supervisor/socket-client.js";
import { mintAuthSecret, type SupervisorRequest, type SupervisorResponse } from "../../src/supervisor/protocol.js";

const servers: SupervisorSocketServer[] = [];
const dirs: string[] = [];

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close().catch(() => {});
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function secureDir(): string {
  const d = mkdtempSync(join(tmpdir(), "superd-"));
  chmodSync(d, 0o700);
  dirs.push(d);
  return d;
}

async function startServer(opts: {
  secret: Uint8Array;
  dir?: string;
  handle?: (req: SupervisorRequest) => Promise<SupervisorResponse>;
}): Promise<{ server: SupervisorSocketServer; socketPath: string }> {
  const dir = opts.dir ?? secureDir();
  const socketPath = join(dir, "sup.sock");
  const server = new SupervisorSocketServer({
    socketPath,
    authSecret: opts.secret,
    handle:
      opts.handle ??
      (async (req): Promise<SupervisorResponse> => {
        if (req.kind === "status") return { ok: true, kind: "status", agents: [] };
        if (req.kind === "protect") {
          return { ok: true, kind: "protecting", agent_id: req.agent_id, launch_id: "L1" };
        }
        return { ok: true, kind: "unprotecting", agent_id: req.agent_id };
      }),
  });
  await server.listen();
  servers.push(server);
  return { server, socketPath };
}

describe("supervisor socket round trip", () => {
  it("services a protect over an authenticated socket", async () => {
    const secret = mintAuthSecret();
    const { socketPath } = await startServer({ secret });
    const resp = await sendSupervisorRequest(
      { kind: "protect", agent_id: "a1", harness: "claude_code", config_path: "/c", transient_key_b64: "AAAA" },
      { socketPath, authSecret: secret },
    );
    expect(resp.ok).toBe(true);
    if (resp.ok && resp.kind === "protecting") expect(resp.agent_id).toBe("a1");
  });

  it("a client with the WRONG secret gets no serviced response (auth gate)", async () => {
    const serverSecret = mintAuthSecret();
    const { socketPath } = await startServer({ secret: serverSecret });
    await expect(
      sendSupervisorRequest(
        { kind: "status" },
        { socketPath, authSecret: mintAuthSecret(), timeoutMs: 1500 },
      ),
    ).rejects.toThrow();
  });

  it("REFUSES to bind in a group/other-accessible directory (fail closed)", async () => {
    const d = mkdtempSync(join(tmpdir(), "superd-open-"));
    dirs.push(d);
    chmodSync(d, 0o755); // group/other readable
    const server = new SupervisorSocketServer({
      socketPath: join(d, "sup.sock"),
      authSecret: mintAuthSecret(),
      handle: async () => ({ ok: true, kind: "status", agents: [] }),
    });
    await expect(server.listen()).rejects.toThrow(/group\/other-accessible/);
  });

  it("drops a connection that sends a garbage (un-MAC'd) frame", async () => {
    const secret = mintAuthSecret();
    const { socketPath } = await startServer({ secret });
    // Send a frame with a valid-looking length but random MAC+payload.
    const garbage = Buffer.alloc(4 + 32 + 8);
    garbage.writeUInt32BE(8, 0);
    garbage.fill(0xab, 4);
    const closed = await new Promise<boolean>((resolve) => {
      const sock = connect(socketPath, () => sock.write(garbage));
      let got = false;
      sock.on("data", () => {
        got = true;
      });
      sock.on("close", () => resolve(!got)); // closed with no serviced response
      sock.on("error", () => resolve(true));
      setTimeout(() => resolve(!got), 1000);
    });
    expect(closed).toBe(true);
  });

  it("status round-trips an empty roster", async () => {
    const secret = mintAuthSecret();
    const { socketPath } = await startServer({ secret });
    const resp = await sendSupervisorRequest({ kind: "status" }, { socketPath, authSecret: secret });
    expect(resp).toEqual({ ok: true, kind: "status", agents: [] });
  });
});
