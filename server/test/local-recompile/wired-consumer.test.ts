/**
 * The production graph, built by createSanctuaryServer with only the local
 * task seams the server honours under Vitest: the tool is listed, a call
 * reaches the worker process, the worker reaches the model only through the
 * loopback generation client, the operator log records the job, the
 * operator dashboard reports the tool armed, and cleanup leaves no process.
 */
import { fork } from "node:child_process";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OllamaClient } from "../../src/intelligence/substrates/local.js";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { isAlive, localTaskPid } from "./helpers/local-task-server.js";
import { openWorld, waitForJobEnds, type World } from "./helpers/armed-world.js";

vi.mock("../../src/intelligence/model-manifest.js", async (original) => {
  // Must match Q5E_PRIVATE_KEY in test/intelligence/q5e-fixtures.ts, which imports this module and so cannot be imported here.
  const { ed25519 } = await import("@noble/curves/ed25519");
  const key = ed25519.getPublicKey(new Uint8Array(32).fill(41));
  return { ...await original<typeof import("../../src/intelligence/model-manifest.js")>(), loadPinnedModelManifestKey: () => Uint8Array.from(key) };
});

const PRELOAD = fileURLToPath(new URL("./__fixtures__/worker-spy-preload.ts", import.meta.url));
// Must match `file` in __fixtures__/worker-spy-preload.ts: the worker's parent is this process.
const spyFile = join(tmpdir(), `lr1b-worker-spy-${process.pid}.log`);
const EPHEMERAL_PORT = 0;
const TOOL = "sanctuary_local_task";
const RECORD = { namespace: "notes", key: "one", value: "short note about the plan" };
const VALID = { kind: "summarize", sources: { refs: [{ namespace: "notes", key: "one" }] }, instruction: "Summarize the main points." };
// Boots twice, one job, one dashboard read.
const WIRED_TIMEOUT_MS = 180_000;

const env = { ...process.env };
let world: World | undefined;
afterEach(async () => {
  try {
    const workerPid = world ? localTaskPid(world.server.runtime) : undefined;
    const fakePid = world?.fake.pid;
    await world?.close();
    world = undefined;
    // Cleanup leaves no worker or fake model process alive.
    expect(isAlive(workerPid)).toBe(false);
    expect(isAlive(fakePid)).toBe(false);
  } finally {
    vi.restoreAllMocks();
    process.env = { ...env };
    await rm(spyFile, { force: true });
  }
});

describe("the local task in the production graph", () => {
  it("is listed, runs in the worker through the loopback client, and is reported to the operator", async () => {
    await rm(spyFile, { force: true });
    delete process.env.SANCTUARY_DASHBOARD_PORT;
    process.env.SANCTUARY_DASHBOARD_HOST = "127.0.0.1";
    // The local routes admit only an operator credential, so the operator configures a token.
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = `wired-${process.pid}-${Date.now()}`;
    const dashboards: DashboardApprovalChannel[] = [];
    const start = DashboardApprovalChannel.prototype.start;
    vi.spyOn(DashboardApprovalChannel.prototype, "start").mockImplementation(function (this: DashboardApprovalChannel, ...args) {
      (this as unknown as { config: { port: number } }).config.port = EPHEMERAL_PORT;
      dashboards.push(this);
      return start.apply(this, args);
    });
    const serverGenerate = vi.spyOn(OllamaClient.prototype, "generate");

    world = await openWorld({
      records: [RECORD],
      policy: (text) => text.replace("type: callback", "type: dashboard"),
      // The fork seam, with one extra preload that records network calls inside the worker.
      seams: { spawnWorker: (modulePath, args, options) => fork(modulePath, args, { ...options, execArgv: [...(options.execArgv ?? []), "--import", PRELOAD] }) },
    });
    const server = world.server;

    const listed = await server.client.listTools();
    expect(listed.tools.map((tool) => tool.name)).toContain(TOOL);

    const pid = server.runtime.localTask.workerPid();
    expect(pid).toBeDefined();
    expect(pid).not.toBe(process.pid);
    expect(isAlive(pid)).toBe(true);

    await server.runtime.auditLog.flush();
    const before = (await server.runtime.auditLog.query({ limit: 1_000 })).entries.length;
    const response = await server.call(VALID);
    expect(response.text).toMatch(/^\{"status":"submitted","request_id":"[0-9a-f]{32}"/);
    await server.runtime.auditLog.flush();
    const added = (await server.runtime.auditLog.query({ limit: 1_000 })).entries.slice(before).map((entry) => entry.operation);
    expect(added.sort()).toEqual(["gate_allow:sanctuary_local_task", "local_request_submitted"]);

    const rows = await waitForJobEnds(world, 1);
    expect(rows.map((row) => row.kind)).toEqual(expect.arrayContaining(["job_queued", "job_started", "job_call", "job_committed"]));
    expect(world.fake.requests.map((request) => request.path)).toEqual(expect.arrayContaining(["/api/tags", "/api/generate"]));

    // The preload ran in the worker, and the worker made no fetch and no OllamaClient call; nor did the server.
    const spy = (await readFile(spyFile, "utf8")).trim().split("\n");
    expect(spy[0]).toBe(`loaded ${pid}`);
    expect(spy.slice(1)).toEqual([]);
    expect(serverGenerate).not.toHaveBeenCalled();

    const sized = vi.spyOn(FilesystemStorage.prototype, "totalSizeOfNonReservedNamespaces");
    await server.callTool("monitor_health", {});
    expect(sized).toHaveBeenCalled();

    const dashboard = dashboards.at(-1)!;
    const internals = dashboard as unknown as { httpServer: { address(): { port: number } } | null; authToken?: string };
    const port = internals.httpServer!.address().port;
    const status = await fetch(`http://127.0.0.1:${port}/api/local/status`, {
      headers: internals.authToken ? { Authorization: `Bearer ${internals.authToken}` } : {},
    });
    expect(status.status).toBe(200);
    expect(internals.authToken).toBeDefined();
    expect((await fetch(`http://127.0.0.1:${port}/api/local/status`)).status).toBe(401);
    expect(await status.json()).toMatchObject({ armed: true, cause: null, worker_alive: true, model_tag: "qwen2.5:1.5b" });
  }, WIRED_TIMEOUT_MS);
});
