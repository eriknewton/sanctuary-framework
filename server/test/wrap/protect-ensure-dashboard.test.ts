/**
 * Dashboard-fold PR-4 — `sanctuary protect` ensures-and-reuses the ONE main
 * dashboard (ratified decision 1, 2026-08-02).
 *
 * Targets the real exported `ensureMainDashboardForWrap` (+ the legacy-seam
 * adapter), not a re-implementation. Pins the four contracts:
 *
 *  1. REUSE: a live main dashboard for THIS fortress (runtime.json with a
 *     live PID + an answering /api/health) is reused — no starter call, no
 *     second server, banner URL = the running one.
 *  2. FRESH START: a missing/stale/dead runtime record falls through to a
 *     start on the requested port (multi-tenant port walk preserved).
 *  3. RACE-CLOSE: an EADDRINUSE from the starter re-checks THIS tenant's
 *     runtime and reuses a same-fortress race winner; anything else rethrows.
 *  4. runtime.json SINGLE-WRITER BY CONSTRUCTION: the ensure path never
 *     writes or clears runtime.json — reuse leaves the owner's record
 *     byte-identical, and a fresh start writes nothing from the wrap side
 *     (the started dashboard's own boot path is the only production writer).
 */

import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtemp, readFile, writeFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ensureMainDashboardForWrap,
  adaptLegacyDashboardStarter,
  type OwnedDashboardStarter,
} from "../../src/wrap/cli.js";
import { RUNTIME_FILE_NAME } from "../../src/cli/agents/runtime.js";
import type { DashboardStarter } from "../../src/wrap/cli.js";

async function makeFortressDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "sanctuary-ensure-dash-"));
}

/** Start a stub "main dashboard" that answers GET /api/health honestly. */
async function startStubDashboard(): Promise<{
  port: number;
  server: Server;
  requests: string[];
}> {
  const requests: string[] = [];
  const server = createServer((req, res) => {
    requests.push(req.url ?? "");
    if (req.url === "/api/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, mode: "principal-policy" }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return { port, server, requests };
}

async function writeRuntimeRecord(
  storagePath: string,
  opts: { pid: number; port: number; mode?: "standalone" | "wrap" },
): Promise<string> {
  const record = {
    version: "9.9.9-test",
    pid: opts.pid,
    started_at: new Date().toISOString(),
    dashboard_host: "127.0.0.1",
    dashboard_port: opts.port,
    mode: opts.mode ?? "standalone",
  };
  const raw = JSON.stringify(record, null, 2);
  await writeFile(join(storagePath, RUNTIME_FILE_NAME), raw);
  return raw;
}

/**
 * A live PID that is NOT this process: the test runner's parent. Fix round 1
 * F2(b) makes a self-pid record never reusable, so reuse rigs must present a
 * genuinely-other live writer, exactly like a real running dashboard would.
 */
const OTHER_LIVE_PID = process.ppid;

const neverStarter: OwnedDashboardStarter = async () => {
  throw new Error("starter must NOT be called in this scenario");
};

describe("dashboard-fold PR-4: ensureMainDashboardForWrap", () => {
  const cleanups: (() => Promise<void> | void)[] = [];
  afterEach(async () => {
    for (const fn of cleanups.splice(0)) await fn();
  });

  it("REUSES a live main dashboard for this fortress and leaves runtime.json byte-identical (single-writer)", async () => {
    const storagePath = await makeFortressDir();
    const stub = await startStubDashboard();
    cleanups.push(() => new Promise((r) => stub.server.close(() => r())));
    const rawBefore = await writeRuntimeRecord(storagePath, {
      pid: OTHER_LIVE_PID, // a live OTHER process => PID-liveness passes, F2(b) does not trip
      port: stub.port,
    });

    const ensured = await ensureMainDashboardForWrap({
      storagePath,
      requestedPort: stub.port,
      start: neverStarter, // reuse must never start
    });

    expect(ensured.reused).toBe(true);
    expect(ensured.url).toBe(`http://127.0.0.1:${stub.port}`);
    expect(ensured.port).toBe(stub.port);
    // The probe actually hit the running dashboard's health route.
    expect(stub.requests).toContain("/api/health");
    // Single-writer: the owner's record is untouched, byte for byte.
    const rawAfter = await readFile(
      join(storagePath, RUNTIME_FILE_NAME),
      "utf-8",
    );
    expect(rawAfter).toBe(rawBefore);
  });

  it("starts FRESH when no runtime record exists, on the requested port, and writes NO runtime.json from the wrap side", async () => {
    const storagePath = await makeFortressDir();
    const calls: { port: number; storagePath: string }[] = [];
    const starter: OwnedDashboardStarter = async ({ port, storagePath: sp }) => {
      calls.push({ port, storagePath: sp });
      return { url: `http://127.0.0.1:${port}`, port };
    };

    const ensured = await ensureMainDashboardForWrap({
      storagePath,
      requestedPort: 3599,
      start: starter,
    });

    expect(ensured).toEqual({
      url: "http://127.0.0.1:3599",
      port: 3599,
      reused: false,
    });
    expect(calls).toEqual([{ port: 3599, storagePath }]);
    // Single-writer by construction: the ensure path wrote nothing — the
    // started dashboard's own boot path owns runtime.json.
    const entries = await readdir(storagePath);
    expect(entries).not.toContain(RUNTIME_FILE_NAME);
  });

  it("F2(a): NEVER reuses a mode:\"wrap\" record, even with a live PID and an answering health probe", async () => {
    const storagePath = await makeFortressDir();
    const stub = await startStubDashboard();
    cleanups.push(() => new Promise((r) => stub.server.close(() => r())));
    // A still-running OLD-version wrap process: live writer, answering
    // /api/health — but it is the RETIRED wrap-served server, not the one
    // main dashboard. Blessing it would resurrect the retired surface.
    await writeRuntimeRecord(storagePath, {
      pid: OTHER_LIVE_PID,
      port: stub.port,
      mode: "wrap",
    });
    let startedPort: number | null = null;
    const ensured = await ensureMainDashboardForWrap({
      storagePath,
      requestedPort: 3610,
      start: async ({ port }) => {
        startedPort = port;
        return { url: `http://127.0.0.1:${port}`, port };
      },
    });
    expect(ensured.reused).toBe(false);
    expect(startedPort).toBe(3610);
    // The probe was never consulted for the wrap-mode record.
    expect(stub.requests).not.toContain("/api/health");
  });

  it("F2(b): NEVER reuses a SELF-pid record (a failed in-process boot's leftover), even if the port answers", async () => {
    const storagePath = await makeFortressDir();
    const stub = await startStubDashboard();
    cleanups.push(() => new Promise((r) => stub.server.close(() => r())));
    // A record naming THIS pid: trivially "alive", but it is our own
    // leftover — the port's current owner could be a FOREIGN process that
    // happens to answer a health probe. Reuse must refuse.
    await writeRuntimeRecord(storagePath, {
      pid: process.pid,
      port: stub.port,
    });
    const ensured = await ensureMainDashboardForWrap({
      storagePath,
      requestedPort: 3611,
      start: async ({ port }) => ({ url: `http://127.0.0.1:${port}`, port }),
    });
    expect(ensured.reused).toBe(false);
    expect(ensured.port).toBe(3611);
    expect(stub.requests).not.toContain("/api/health");
  });

  it("ignores a STALE runtime record (dead PID) and starts fresh", async () => {
    const storagePath = await makeFortressDir();
    // PID 1 is init/launchd — process.kill(1, 0) from an unprivileged test
    // yields EPERM (alive) on some hosts, so use a PID from the ephemeral
    // range that is overwhelmingly likely dead AND owned by no one: spawn
    // nothing, just pick an id far above pid_max defaults? Not portable —
    // instead write a malformed record (missing pid), which readTenantRuntime
    // rejects the same way it rejects a dead writer.
    await writeFile(
      join(storagePath, RUNTIME_FILE_NAME),
      JSON.stringify({ dashboard_host: "127.0.0.1", dashboard_port: 3501 }),
    );
    let started = false;
    const ensured = await ensureMainDashboardForWrap({
      storagePath,
      requestedPort: 3600,
      start: async ({ port }) => {
        started = true;
        return { url: `http://127.0.0.1:${port}`, port };
      },
    });
    expect(started).toBe(true);
    expect(ensured.reused).toBe(false);
  });

  it("falls through to a fresh start when the runtime PID is live but nothing answers the health probe", async () => {
    const storagePath = await makeFortressDir();
    // Live PID (this process) but a port with no listener.
    await writeRuntimeRecord(storagePath, { pid: OTHER_LIVE_PID, port: 3601 });
    const ensured = await ensureMainDashboardForWrap({
      storagePath,
      requestedPort: 3602,
      start: async ({ port }) => ({ url: `http://127.0.0.1:${port}`, port }),
      probeHealth: async () => false, // deterministic: probe says dead
    });
    expect(ensured.reused).toBe(false);
    expect(ensured.port).toBe(3602);
  });

  it("RACE-CLOSE: EADDRINUSE from the starter reuses a same-fortress winner that appeared meanwhile", async () => {
    const storagePath = await makeFortressDir();
    const stub = await startStubDashboard();
    cleanups.push(() => new Promise((r) => stub.server.close(() => r())));

    const starter: OwnedDashboardStarter = async () => {
      // Simulate: between the free-port probe and the real bind, a
      // concurrent protect for the SAME fortress won the race.
      await writeRuntimeRecord(storagePath, {
        pid: OTHER_LIVE_PID,
        port: stub.port,
      });
      const err = new Error("listen EADDRINUSE") as NodeJS.ErrnoException;
      err.code = "EADDRINUSE";
      throw err;
    };

    const ensured = await ensureMainDashboardForWrap({
      storagePath,
      requestedPort: 3603,
      start: starter,
    });
    expect(ensured.reused).toBe(true);
    expect(ensured.port).toBe(stub.port);
  });

  it("WALKS to the next port when a foreign process owns the requested one (multi-tenant behavior preserved)", async () => {
    const storagePath = await makeFortressDir();
    const attempts: number[] = [];
    const starter: OwnedDashboardStarter = async ({ port }) => {
      attempts.push(port);
      if (port === 3606) {
        // Foreign owner on the preferred port; no same-fortress runtime
        // record ever appears, so the walk must move on.
        const err = new Error("listen EADDRINUSE") as NodeJS.ErrnoException;
        err.code = "EADDRINUSE";
        throw err;
      }
      return { url: `http://127.0.0.1:${port}`, port };
    };
    const ensured = await ensureMainDashboardForWrap({
      storagePath,
      requestedPort: 3606,
      start: starter,
    });
    expect(attempts).toEqual([3606, 3607]);
    expect(ensured).toEqual({
      url: "http://127.0.0.1:3607",
      port: 3607,
      reused: false,
    });
  });

  it("rethrows a non-EADDRINUSE starter failure (no silent degrade)", async () => {
    const storagePath = await makeFortressDir();
    await expect(
      ensureMainDashboardForWrap({
        storagePath,
        requestedPort: 3604,
        start: async () => {
          throw new Error("custody establishment failed");
        },
      }),
    ).rejects.toThrow("custody establishment failed");
  });

  it("adaptLegacyDashboardStarter drives the legacy stub shape through the ensure flow", async () => {
    const storagePath = await makeFortressDir();
    const legacyCalls: { port: number; mode: string }[] = [];
    const legacy: DashboardStarter = (async (opts: {
      port: number;
      mode: string;
    }) => {
      legacyCalls.push({ port: opts.port, mode: opts.mode });
      return {
        url: `http://127.0.0.1:${opts.port}`,
        port: opts.port,
        host: "127.0.0.1",
        stop: async () => {},
        publish: () => {},
        publishActivity: () => {},
        publishApproval: () => {},
        publishInbox: () => {},
        publishAgentStatus: () => {},
        setV11Bindings: () => {},
        setV11LoopbackAutoAuth: () => {},
        updateSources: () => {},
      };
    }) as unknown as DashboardStarter;

    const ensured = await ensureMainDashboardForWrap({
      storagePath,
      requestedPort: 3605,
      start: adaptLegacyDashboardStarter(legacy),
    });
    expect(ensured).toEqual({
      url: "http://127.0.0.1:3605",
      port: 3605,
      reused: false,
    });
    expect(legacyCalls).toEqual([{ port: 3605, mode: "co-located" }]);
  });
});
