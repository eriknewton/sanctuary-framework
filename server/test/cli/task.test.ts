import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Writable } from "node:stream";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runTaskCommand } from "../../src/cli/task.js";
import type { Task } from "../../src/l2-operational/task-coordination/index.js";
import { writeLockdownStatus } from "../../src/lockdown/status.js";

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
      "Fortress is LOCKED (since 2026-05-19T12:00:00.000Z). Reads permitted; writes blocked.",
    );
    expect(listed.out.text).toContain("task-1");
  });

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
