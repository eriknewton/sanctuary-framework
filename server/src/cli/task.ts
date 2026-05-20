import { readTenantRuntime } from "./agents/runtime.js";
import {
  TASK_STATUSES,
  type Task,
} from "../l2-operational/task-coordination/index.js";
import { lockdownBanner, readLockdownStatus } from "../lockdown/status.js";

export interface TaskCliArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
}

interface TaskCliContext {
  argv: string[];
  dashboardUrl?: string;
  fortressPath?: string;
}

const DEFAULT_DASHBOARD_URL = "http://127.0.0.1:3502";

export async function runTaskCommand(args: TaskCliArgs): Promise<number> {
  const out = args.out ?? process.stdout;
  const err = args.err ?? process.stderr;

  try {
    const ctx = await resolveContext(args.argv, err);
    if (!ctx) return 2;
    const [sub, ...rest] = ctx.argv;

    if (!sub || sub === "--help" || sub === "-h") {
      printUsage(out);
      return 0;
    }

    switch (sub) {
      case "create":
        return await create(rest, out, err, ctx);
      case "list":
        return await list(rest, out, err, ctx);
      case "show":
        return await show(rest, out, err, ctx);
      case "update":
        return await update(rest, out, err, ctx);
      case "assign":
        return await assign(rest, out, err, ctx);
      case "cancel":
        return await cancel(rest, out, err, ctx);
      default:
        err.write(`Unknown task subcommand: ${sub}\n`);
        printUsage(err);
        return 2;
    }
  } catch (cause) {
    err.write(`sanctuary task: ${cause instanceof Error ? cause.message : String(cause)}\n`);
    return 1;
  }
}

function printUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary task <command> [args]

  create --title <s> [--description <s>] [--assignee <agent-id>] [--parent <task-id>] [--json]
  list [--status <status>] [--assignee <agent-id>] [--creator <agent-id>] [--json]
  show <id> [--json]
  update <id> --status <new-status> [--json]
  assign <id> --assignee <agent-id> [--json]
  cancel <id> [--reason <s>] [--json]

Options:
  --fortress <path>   Use the dashboard runtime recorded for this fortress.

Statuses: ${TASK_STATUSES.join(", ")}
Env: SANCTUARY_DASHBOARD_URL, SANCTUARY_DASHBOARD_AUTH_TOKEN, SANCTUARY_OPERATOR_ID
`);
}

async function create(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: TaskCliContext,
): Promise<number> {
  const title = flagValue(argv, "--title");
  if (!title) {
    err.write("task create requires --title <s>\n");
    return 2;
  }
  const json = hasFlag(argv, "--json");
  const body = await request("/api/hub/tasks", {
    method: "POST",
    body: JSON.stringify({
      title,
      description: flagValue(argv, "--description") ?? undefined,
      assignee: flagValue(argv, "--assignee") ?? undefined,
      parent_task_id: flagValue(argv, "--parent") ?? undefined,
      creator: operatorLabel(),
    }),
  }, ctx);
  const task = body.data?.task ?? body;
  writeTask(out, task, json, "created");
  return 0;
}

async function list(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: TaskCliContext,
): Promise<number> {
  const status = flagValue(argv, "--status");
  if (status && !TASK_STATUSES.includes(status as any)) {
    err.write(`task list --status must be one of: ${TASK_STATUSES.join(", ")}\n`);
    return 2;
  }
  const json = hasFlag(argv, "--json");
  const qs = new URLSearchParams();
  setFlag(qs, "status", argv, "--status");
  setFlag(qs, "assignee", argv, "--assignee");
  setFlag(qs, "creator", argv, "--creator");
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  const body = await request(`/api/hub/tasks${suffix}`, undefined, ctx);
  const tasks = body.data?.tasks ?? [];
  const lockdown_status = await readLockdownStatus(ctx.fortressPath);
  if (json) {
    out.write(JSON.stringify({ lockdown_status, tasks }, null, 2) + "\n");
    return 0;
  }
  out.write(lockdownBanner(lockdown_status));
  writeTaskTable(out, tasks);
  return 0;
}

async function show(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: TaskCliContext,
): Promise<number> {
  const id = argv[0];
  if (!id || id.startsWith("--")) {
    err.write("task show requires <id>\n");
    return 2;
  }
  const json = hasFlag(argv, "--json");
  const body = await request(`/api/hub/tasks/${encodeURIComponent(id)}`, undefined, ctx);
  const task = body.data?.task ?? body;
  if (json) {
    out.write(JSON.stringify(task, null, 2) + "\n");
  } else {
    writeTaskDetail(out, task);
  }
  return 0;
}

async function update(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: TaskCliContext,
): Promise<number> {
  const id = argv[0];
  const status = flagValue(argv, "--status");
  if (!id || id.startsWith("--") || !status) {
    err.write("task update requires <id> --status <new-status>\n");
    return 2;
  }
  if (!TASK_STATUSES.includes(status as any)) {
    err.write(`task update --status must be one of: ${TASK_STATUSES.join(", ")}\n`);
    return 2;
  }
  const json = hasFlag(argv, "--json");
  const body = await request(`/api/hub/tasks/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify({ status, actor: operatorLabel() }),
  }, ctx);
  writeTask(out, body.data?.task ?? body, json, "updated");
  return 0;
}

async function assign(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: TaskCliContext,
): Promise<number> {
  const id = argv[0];
  const assignee = flagValue(argv, "--assignee");
  if (!id || id.startsWith("--") || !assignee) {
    err.write("task assign requires <id> --assignee <agent-id>\n");
    return 2;
  }
  const json = hasFlag(argv, "--json");
  const body = await request(`/api/hub/tasks/${encodeURIComponent(id)}/assign`, {
    method: "POST",
    body: JSON.stringify({ assignee, actor: operatorLabel() }),
  }, ctx);
  writeTask(out, body.data?.task ?? body, json, "assigned");
  return 0;
}

async function cancel(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: TaskCliContext,
): Promise<number> {
  const id = argv[0];
  if (!id || id.startsWith("--")) {
    err.write("task cancel requires <id>\n");
    return 2;
  }
  const json = hasFlag(argv, "--json");
  const body = await request(`/api/hub/tasks/${encodeURIComponent(id)}/cancel`, {
    method: "POST",
    body: JSON.stringify({ reason: flagValue(argv, "--reason") ?? undefined, actor: operatorLabel() }),
  }, ctx);
  writeTask(out, body.data?.task ?? body, json, "cancelled");
  return 0;
}

async function request(
  path: string,
  init?: RequestInit,
  ctx?: TaskCliContext,
): Promise<any> {
  const base = (ctx?.dashboardUrl ?? process.env.SANCTUARY_DASHBOARD_URL ?? DEFAULT_DASHBOARD_URL).replace(/\/$/, "");
  const token = process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN ?? "";
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(`${base}${path}`, { ...init, headers });
  const body = (await res.json().catch(() => ({}))) as {
    ok?: boolean;
    error?: unknown;
    detail?: unknown;
  };
  if (!res.ok || body.ok === false) {
    throw new Error(
      body.detail ? String(body.detail) : body.error ? String(body.error) : `HTTP ${res.status}`,
    );
  }
  return body;
}

async function resolveContext(
  argv: string[],
  err: NodeJS.WritableStream,
): Promise<TaskCliContext | null> {
  const fortressIdx = argv.indexOf("--fortress");
  if (fortressIdx < 0) {
    return {
      argv,
      fortressPath:
        process.env.SANCTUARY_STORAGE_PATH ?? process.env.SANCTUARY_FORTRESS_PATH,
    };
  }
  const fortress = argv[fortressIdx + 1];
  if (!fortress) {
    err.write("task --fortress requires a path\n");
    return null;
  }
  const filtered = [...argv];
  filtered.splice(fortressIdx, 2);
  const runtime = await readTenantRuntime(fortress);
  if (!runtime) {
    throw new Error(`no readable runtime.json for fortress ${fortress}`);
  }
  return {
    argv: filtered,
    dashboardUrl: `http://${runtime.dashboard_host}:${runtime.dashboard_port}`,
    fortressPath: fortress,
  };
}

function writeTask(
  out: NodeJS.WritableStream,
  task: Task,
  json: boolean,
  verb: string,
): void {
  if (json) {
    out.write(JSON.stringify(task, null, 2) + "\n");
    return;
  }
  out.write(`task: ${task.id} ${verb} ${task.status}\n`);
}

function writeTaskTable(out: NodeJS.WritableStream, tasks: Task[]): void {
  const rows = tasks.map((task) => [
    task.id,
    task.status,
    task.assignee ?? "-",
    task.creator,
    task.title,
  ]);
  const table = [["ID", "STATUS", "ASSIGNEE", "CREATOR", "TITLE"], ...rows];
  const widths = table[0]!.map((_, idx) =>
    Math.max(...table.map((row) => String(row[idx] ?? "").length)),
  );
  for (const row of table) {
    out.write(
      row
        .map((cell, idx) => String(cell ?? "").padEnd(widths[idx]!))
        .join("  ")
        .trimEnd() + "\n",
    );
  }
}

function writeTaskDetail(out: NodeJS.WritableStream, task: Task): void {
  out.write(`id: ${task.id}\n`);
  out.write(`status: ${task.status}\n`);
  out.write(`title: ${task.title}\n`);
  out.write(`creator: ${task.creator}\n`);
  out.write(`assignee: ${task.assignee ?? "-"}\n`);
  if (task.description) out.write(`description: ${task.description}\n`);
  if (task.parent_task_id) out.write(`parent: ${task.parent_task_id}\n`);
  if (task.approval_request_id) {
    out.write(`approval_request_id: ${task.approval_request_id}\n`);
  }
}

function setFlag(
  qs: URLSearchParams,
  key: string,
  argv: string[],
  flag: string,
): void {
  const value = flagValue(argv, flag);
  if (value) qs.set(key, value);
}

function hasFlag(argv: string[], flag: string): boolean {
  return argv.includes(flag);
}

function flagValue(argv: string[], flag: string): string | null {
  const idx = argv.indexOf(flag);
  if (idx < 0 || idx + 1 >= argv.length) return null;
  return argv[idx + 1] ?? null;
}

function operatorLabel(): string {
  return process.env.SANCTUARY_OPERATOR_ID ?? process.env.USER ?? "operator";
}
