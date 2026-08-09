import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Writable } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runTaskCommand } from "../../src/cli/task.js";
import type { Task } from "../../src/operational/task-coordination/index.js";
import { writeLockdownStatus } from "../../src/lockdown/status.js";
import { writeTenantRuntime } from "../../src/cli/agents/runtime.js";

class StringWritable extends Writable {
  chunks: string[] = [];

  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void,
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }

  get text(): string {
    return this.chunks.join("");
  }
}

function okJson(payload: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  } as Response;
}

const task = (id: string, overrides: Partial<Task> = {}): Task => ({
  id,
  fortress_id: "fortress-a",
  title: "Coordinate review",
  creator: "operator-test",
  assignee: "agent-a",
  status: "pending",
  created_at: "2026-05-16T12:00:00.000Z",
  updated_at: "2026-05-16T12:00:00.000Z",
  schema_version: 1,
  ...overrides,
});

async function run(argv: string[]): Promise<{
  code: number;
  out: StringWritable;
  err: StringWritable;
}> {
  const out = new StringWritable();
  const err = new StringWritable();
  const code = await runTaskCommand({ argv, out, err });
  return { code, out, err };
}

describe("sanctuary task CLI", () => {
  let originalFetch: typeof globalThis.fetch;
  let originalDashboardUrl: string | undefined;
  let originalOperatorId: string | undefined;
  let originalStoragePath: string | undefined;
  let fortressPath: string;
  let tasks: Task[];

  beforeEach(async () => {
    originalFetch = globalThis.fetch;
    originalDashboardUrl = process.env.SANCTUARY_DASHBOARD_URL;
    originalOperatorId = process.env.SANCTUARY_OPERATOR_ID;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-task-lockdown-"));
    process.env.SANCTUARY_DASHBOARD_URL = "http://127.0.0.1:3919";
    process.env.SANCTUARY_OPERATOR_ID = "operator-test";
    process.env.SANCTUARY_STORAGE_PATH = fortressPath;
    tasks = [task("task-1")];
  });

  afterEach(async () => {
    globalThis.fetch = originalFetch;
    if (originalDashboardUrl === undefined) {
      delete process.env.SANCTUARY_DASHBOARD_URL;
    } else {
      process.env.SANCTUARY_DASHBOARD_URL = originalDashboardUrl;
    }
    if (originalOperatorId === undefined) {
      delete process.env.SANCTUARY_OPERATOR_ID;
    } else {
      process.env.SANCTUARY_OPERATOR_ID = originalOperatorId;
    }
    if (originalStoragePath === undefined) {
      delete process.env.SANCTUARY_STORAGE_PATH;
    } else {
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    }
    await rm(fortressPath, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  function installTaskFetch(): ReturnType<typeof vi.fn> {
    const fetchSpy = vi.fn(async (url: string | URL, init?: RequestInit) => {
      const target = String(url);
      if (target === "http://127.0.0.1:3919/api/hub/tasks" && init?.method === "POST") {
        const body = JSON.parse(String(init.body));
        const created = task("task-2", {
          title: body.title,
          description: body.description,
          assignee: body.assignee,
          parent_task_id: body.parent_task_id,
        });
        tasks.push(created);
        return okJson({ ok: true, data: { task: created } }, 201);
      }
      if (target.startsWith("http://127.0.0.1:3919/api/hub/tasks?")) {
        return okJson({ ok: true, data: { tasks } });
      }
      if (target === "http://127.0.0.1:3919/api/hub/tasks") {
        return okJson({ ok: true, data: { tasks } });
      }
      const show = /^http:\/\/127\.0\.0\.1:3919\/api\/hub\/tasks\/([^/]+)$/.exec(target);
      if (show && !init?.method) {
        const found = tasks.find((entry) => entry.id === decodeURIComponent(show[1]!));
        return found
          ? okJson({ ok: true, data: { task: found } })
          : okJson({ ok: false, detail: "task not found" }, 404);
      }
      if (show && init?.method === "PATCH") {
        const found = tasks.find((entry) => entry.id === decodeURIComponent(show[1]!));
        if (!found) return okJson({ ok: false, detail: "task not found" }, 404);
        const body = JSON.parse(String(init.body));
        found.status = body.status;
        return okJson({ ok: true, data: { task: found } });
      }
      const assign = /^http:\/\/127\.0\.0\.1:3919\/api\/hub\/tasks\/([^/]+)\/assign$/.exec(target);
      if (assign && init?.method === "POST") {
        const found = tasks.find((entry) => entry.id === decodeURIComponent(assign[1]!));
        if (!found) return okJson({ ok: false, detail: "task not found" }, 404);
        const body = JSON.parse(String(init.body));
        found.assignee = body.assignee;
        return okJson({ ok: true, data: { task: found } });
      }
      const cancel = /^http:\/\/127\.0\.0\.1:3919\/api\/hub\/tasks\/([^/]+)\/cancel$/.exec(target);
      if (cancel && init?.method === "POST") {
        const found = tasks.find((entry) => entry.id === decodeURIComponent(cancel[1]!));
        if (!found) return okJson({ ok: false, detail: "task not found" }, 404);
        found.status = "cancelled";
        return okJson({ ok: true, data: { task: found } });
      }
      return okJson({ ok: false, detail: "unexpected route" }, 500);
    });
    globalThis.fetch = fetchSpy as unknown as typeof globalThis.fetch;
    return fetchSpy;
  }

  it("creates tasks and supports --json", async () => {
    const fetchSpy = installTaskFetch();

    const { code, out, err } = await run([
      "create",
      "--title",
      "Coordinate review",
      "--description",
      "Check it",
      "--assignee",
      "agent-a",
      "--parent",
      "parent-1",
      "--json",
    ]);

    expect(code).toBe(0);
    expect(err.text).toBe("");
    expect(JSON.parse(out.text)).toMatchObject({
      id: "task-2",
      title: "Coordinate review",
      assignee: "agent-a",
      parent_task_id: "parent-1",
    });
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:3919/api/hub/tasks",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("lists, shows, updates, assigns, and cancels through hub routes", async () => {
    const fetchSpy = installTaskFetch();

    expect((await run(["list", "--status", "pending"])).out.text).toContain("task-1");
    expect((await run(["show", "task-1", "--json"])).out.text).toContain("Coordinate review");
    expect((await run(["update", "task-1", "--status", "in_progress"])).out.text).toContain("updated");
    expect((await run(["assign", "task-1", "--assignee", "agent-b"])).out.text).toContain("assigned");
    expect((await run(["cancel", "task-1", "--reason", "done"])).out.text).toContain("cancelled");

    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:3919/api/hub/tasks/task-1",
      expect.objectContaining({ method: "PATCH" }),
    );
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:3919/api/hub/tasks/task-1/assign",
      expect.objectContaining({ method: "POST" }),
    );
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://127.0.0.1:3919/api/hub/tasks/task-1/cancel",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("routes --fortress=<path> through that fortress runtime", async () => {
    const scopedFortress = await mkdtemp(join(tmpdir(), "sanctuary-task-scoped-"));
    try {
      await writeTenantRuntime(scopedFortress, {
        version: "test",
        pid: process.pid,
        started_at: new Date().toISOString(),
        dashboard_host: "127.0.0.1",
        dashboard_port: 3920,
        mode: "standalone",
      });
      const fetchSpy = vi.fn(async (url: string | URL) => {
        expect(String(url)).toBe("http://127.0.0.1:3920/api/hub/tasks");
        return okJson({ ok: true, data: { tasks } });
      });
      globalThis.fetch = fetchSpy as unknown as typeof globalThis.fetch;

      const { code, err } = await run(["list", "--json", `--fortress=${scopedFortress}`]);

      expect(code).toBe(0);
      expect(err.text).toBe("");
      expect(fetchSpy).toHaveBeenCalledOnce();
    } finally {
      await rm(scopedFortress, { recursive: true, force: true });
    }
  });

  it("prints a lockdown banner for task list reads", async () => {
    installTaskFetch();
    await writeLockdownStatus(fortressPath, {
      active: true,
      activated_at: "2026-05-19T12:00:00.000Z",
      reason: "operator_lockdown",
    });

    const listed = await run(["list"]);

    expect(listed.code).toBe(0);
    expect(listed.out.text).toContain(
      "Fortress lockdown status is ACTIVE (since 2026-05-19T12:00:00.000Z). CLI status only; writes are not blocked by this flag.",
    );
    expect(listed.out.text).toContain("task-1");
  });

  it("YYYYY regression: task create succeeds without SANCTUARY_DASHBOARD_AUTH_TOKEN when dashboard is loopback (co-resolved by WWWWW #321)", async () => {
    // YYYYY (2026-05-19 drill): `sanctuary task create` returned
    // "sanctuary task: unauthorized" on a wrap+identity-bootstrapped
    // fortress. The root cause was WWWWW (broken wrap-time identity
    // bootstrap) which prevented the dashboard from launching with
    // loopback auto-auth. With WWWWW fixed (#321), the dashboard
    // starts correctly, loopback auto-auth is enabled, and the task
    // CLI's request to 127.0.0.1 passes auth without a token.
    //
    // This test verifies that task create sends no Authorization
    // header when SANCTUARY_DASHBOARD_AUTH_TOKEN is unset, which is
    // the code path that relies on the dashboard's loopback auto-auth.
    const origToken = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;

    let capturedHeaders: Headers | undefined;
    const fetchSpy = vi.fn(async (_url: string | URL, init?: RequestInit) => {
      capturedHeaders = new Headers(init?.headers);
      const body = JSON.parse(String(init?.body ?? "{}"));
      return okJson({
        ok: true,
        data: { task: task("task-yyyyy", { title: body.title }) },
      }, 201);
    });
    globalThis.fetch = fetchSpy as unknown as typeof globalThis.fetch;

    const { code, err } = await run([
      "create",
      "--title",
      "yyyyy verification",
    ]);

    expect(code).toBe(0);
    expect(err.text).toBe("");
    // Verify no Authorization header was sent (loopback auto-auth path)
    expect(capturedHeaders?.get("Authorization")).toBeNull();
    expect(fetchSpy).toHaveBeenCalledOnce();

    if (origToken !== undefined) {
      process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = origToken;
    }
  });

  it("task create names network/connection failures with a remediation hint", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new TypeError("fetch failed", { cause: new Error("ECONNREFUSED") });
    }) as unknown as typeof globalThis.fetch;

    const { code, out, err } = await run([
      "create",
      "--title",
      "Classify failure",
    ]);

    expect(code).toBe(1);
    expect(out.text).toBe("");
    expect(err.text).toContain("sanctuary task: network/connection failure: fetch failed");
    expect(err.text).toContain("ECONNREFUSED");
    expect(err.text).toContain("Hint: start the Sanctuary dashboard");
  });

  it.each([
    [
      "404",
      404,
      { ok: false, detail: "route missing" },
      "endpoint not implemented in this build (HTTP 404): route missing",
      "verify the dashboard exposes /api/hub/tasks",
    ],
    [
      "401",
      401,
      { ok: false, detail: "unauthorized" },
      "auth/policy denied (HTTP 401): unauthorized",
      "check SANCTUARY_DASHBOARD_AUTH_TOKEN",
    ],
    [
      "403",
      403,
      { ok: false, detail: "policy denied" },
      "auth/policy denied (HTTP 403): policy denied",
      "operator authorization",
    ],
    [
      "503",
      503,
      { ok: false, detail: "unavailable" },
      "server error (HTTP 503): unavailable",
      "inspect the dashboard logs",
    ],
  ])(
    "task create names HTTP %s failure class",
    async (_label, status, payload, expectedClass, expectedHint) => {
      globalThis.fetch = vi.fn(async () => okJson(payload, status)) as unknown as typeof globalThis.fetch;

      const { code, out, err } = await run([
        "create",
        "--title",
        "Classify failure",
      ]);

      expect(code).toBe(1);
      expect(out.text).toBe("");
      expect(err.text).toContain(`sanctuary task: ${expectedClass}`);
      expect(err.text).toContain(expectedHint);
    },
  );

  it("validates required arguments and documents the surface", async () => {
    const help = await run(["--help"]);
    const missingTitle = await run(["create"]);
    const badStatus = await run(["update", "task-1", "--status", "bogus"]);

    expect(help.code).toBe(0);
    expect(help.out.text).toContain("create --title <s>");
    expect(missingTitle.code).toBe(2);
    expect(missingTitle.err.text).toContain("task create requires --title <s>");
    expect(badStatus.code).toBe(2);
    expect(badStatus.err.text).toContain("task update --status must be one of");
  });
});
