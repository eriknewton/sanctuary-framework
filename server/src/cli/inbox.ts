import { readTenantRuntime } from "./agents/runtime.js";
import { dashboardRequest } from "./dashboard-request.js";
import { lockdownBanner, readLockdownStatus } from "../lockdown/status.js";
import { consumeFlagValue, flagValue, unknownFlagWithPrefix } from "./argv.js";

export interface InboxCliArgs {
  argv: string[];
  out?: NodeJS.WritableStream;
  err?: NodeJS.WritableStream;
}

interface InboxCliContext {
  argv: string[];
  dashboardUrl?: string;
  fortressPath?: string;
}

export async function runInboxCommand(args: InboxCliArgs): Promise<number> {
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
      case "list":
        return await list(rest, out, ctx);
      case "show":
        return await show(rest, out, err, ctx);
      case "archive":
      case "dismiss":
        return await batch(sub, rest, out, err, ctx);
      case "snooze":
        return await snooze(rest, out, err, ctx);
      case "retention":
        return await retention(rest, out, err, ctx);
      case "approvals":
        return await approvals(rest, out, err, ctx);
      default:
        err.write(`Unknown inbox subcommand: ${sub}\n`);
        printUsage(err);
        return 2;
    }
  } catch (cause) {
    err.write(`sanctuary inbox: ${cause instanceof Error ? cause.message : String(cause)}\n`);
    return 1;
  }
}

function printUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary inbox <command> [args]

  list [--source-class X] [--severity Y] [--agent Z] [--state active|archived|snoozed|dismissed]
  show <entry_id>
  archive <entry_id> [<entry_id>...]
  dismiss <entry_id> [<entry_id>...]
  snooze <entry_id> --until <ISO8601>
  approvals list [--json]
  approvals approve <entry_id> [--json]
  retention show
  retention set --source-class blocked_egress --state archived --days 30

Options:
  --fortress <path>   Use the dashboard runtime recorded for this fortress.

Env: SANCTUARY_DASHBOARD_URL, SANCTUARY_DASHBOARD_AUTH_TOKEN
`);
}

async function list(
  argv: string[],
  out: NodeJS.WritableStream,
  ctx: InboxCliContext,
): Promise<number> {
  const qs = new URLSearchParams();
  setFlag(qs, "source_class", argv, "--source-class");
  setFlag(qs, "severity", argv, "--severity");
  setFlag(qs, "agent_id", argv, "--agent");
  setFlag(qs, "state", argv, "--state");
  const body = await request(`/api/inbox/unified?${qs.toString()}`, undefined, ctx);
  const entries = body.data?.entries ?? [];
  for (const entry of entries) {
    out.write(`${entry.inbox_id} ${entry.state ?? "active"} ${entry.severity} ${entry.source_class} ${entry.agent_id ?? "-"} ${entry.summary}\n`);
  }
  return 0;
}

async function show(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: InboxCliContext,
): Promise<number> {
  const id = argv[0];
  if (!id) {
    err.write("inbox show requires an entry_id\n");
    return 2;
  }
  const body = await request(`/api/inbox/unified/${encodeURIComponent(id)}`, undefined, ctx);
  out.write(JSON.stringify(body.data?.entry ?? body, null, 2) + "\n");
  return 0;
}

async function batch(
  action: "archive" | "dismiss",
  ids: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: InboxCliContext,
): Promise<number> {
  if (ids.length === 0) {
    err.write(`inbox ${action} requires at least one entry_id\n`);
    return 2;
  }
  const body = await request("/api/inbox/unified/batch", {
    method: "POST",
    body: JSON.stringify({ action, entry_ids: ids }),
  }, ctx);
  out.write(JSON.stringify(body.data?.result ?? body, null, 2) + "\n");
  return 0;
}

async function snooze(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: InboxCliContext,
): Promise<number> {
  const id = argv[0];
  const until = flagValue(argv, "--until");
  if (!id || !until) {
    err.write("inbox snooze requires <entry_id> --until <ISO8601>\n");
    return 2;
  }
  const body = await request("/api/inbox/unified/batch", {
    method: "POST",
    body: JSON.stringify({ action: "snooze", entry_ids: [id], until }),
  }, ctx);
  out.write(JSON.stringify(body.data?.result ?? body, null, 2) + "\n");
  return 0;
}

async function retention(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: InboxCliContext,
): Promise<number> {
  const sub = argv[0];
  if (sub === "show") {
    const body = await request("/api/inbox/retention", undefined, ctx);
    out.write(JSON.stringify(body.data ?? body, null, 2) + "\n");
    return 0;
  }
  if (sub === "set") {
    const sourceClass = flagValue(argv, "--source-class");
    const state = flagValue(argv, "--state");
    const days = flagValue(argv, "--days");
    if (!sourceClass || !state || !days) {
      err.write("retention set requires --source-class, --state, and --days\n");
      return 2;
    }
    const body = await request(
      `/api/inbox/retention/${encodeURIComponent(sourceClass)}/${encodeURIComponent(state)}`,
      {
        method: "PATCH",
        body: JSON.stringify({ retain_for_days: Number(days) }),
      },
      ctx,
    );
    out.write(JSON.stringify(body.data?.policy ?? body, null, 2) + "\n");
    return 0;
  }
  err.write("Unknown retention subcommand\n");
  return 2;
}

async function approvals(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: InboxCliContext,
): Promise<number> {
  const [sub, ...rest] = argv;
  switch (sub) {
    case "list":
      return await approvalsList(rest, out, ctx);
    case "approve":
      return await approvalsApprove(rest, out, err, ctx);
    case "--help":
    case "-h":
    case undefined:
      printApprovalsUsage(out);
      return 0;
    default:
      err.write(`Unknown inbox approvals subcommand: ${sub}\n`);
      printApprovalsUsage(err);
      return 2;
  }
}

function printApprovalsUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary inbox approvals <command> [args]

  list [--json]                         List pending approval inbox items.
  approve <entry_id> [--json]           Approve a pending approval inbox item.
  approve --id <entry_id> [--json]      Alias for approve <entry_id>.

Options:
  --fortress <path>   Use the dashboard runtime recorded for this fortress.
`);
}

function printApprovalsListUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary inbox approvals list [--json] [--fortress <path>]

List pending approval inbox items.
`);
}

function printApprovalsApproveUsage(s: NodeJS.WritableStream): void {
  s.write(`Usage: sanctuary inbox approvals approve <entry_id> [--json] [--fortress <path>]
       sanctuary inbox approvals approve --id <entry_id> [--json] [--fortress <path>]

Approve a pending approval inbox item.
`);
}

async function approvalsList(
  argv: string[],
  out: NodeJS.WritableStream,
  ctx: InboxCliContext,
): Promise<number> {
  if (hasFlag(argv, "--help") || hasFlag(argv, "-h")) {
    printApprovalsListUsage(out);
    return 0;
  }
  const json = hasFlag(argv, "--json");
  const body = await request("/api/hub/inbox", undefined, ctx);
  if (body.data?.pending_approvals_redacted === true) {
    const pendingCount = body.data?.pending_approvals_count ?? 0;
    if (json) {
      out.write(
        JSON.stringify(
          {
            locked: true,
            pending_approvals_redacted: true,
            pending_approvals_count: pendingCount,
            items: [],
          },
          null,
          2,
        ) + "\n",
      );
    } else {
      out.write(
        `Approvals are hidden, not empty. Pending count: ${pendingCount}. Provide SANCTUARY_DASHBOARD_AUTH_TOKEN to list and decide them.\n`,
      );
    }
    return 1;
  }
  const items = (body.data?.items ?? []).filter(isPendingApproval);
  const lockdown_status = await readLockdownStatus(ctx.fortressPath);
  if (json) {
    out.write(JSON.stringify({ lockdown_status, items }, null, 2) + "\n");
    return 0;
  }
  out.write(lockdownBanner(lockdown_status));
  writeApprovalTable(out, items);
  return 0;
}

async function approvalsApprove(
  argv: string[],
  out: NodeJS.WritableStream,
  err: NodeJS.WritableStream,
  ctx: InboxCliContext,
): Promise<number> {
  if (hasFlag(argv, "--help") || hasFlag(argv, "-h")) {
    printApprovalsApproveUsage(out);
    return 0;
  }
  const id = argv[0] && !argv[0].startsWith("--") ? argv[0] : flagValue(argv, "--id");
  const json = hasFlag(argv, "--json");
  if (!id) {
    err.write("inbox approvals approve requires <entry_id>\n");
    return 2;
  }
  const body = await request(
    `/api/hub/inbox/${encodeURIComponent(id)}/approve`,
    { method: "POST", body: JSON.stringify({}) },
    ctx,
  );
  const item = body.data?.item ?? body;
  if (json) {
    out.write(
      JSON.stringify(
        {
          approval_id: id,
          status: "approved",
          operator: operatorLabel(),
          item,
        },
        null,
        2,
      ) + "\n",
    );
    return 0;
  }
  out.write(`approval: ${id} approved by ${operatorLabel()}\n`);
  return 0;
}

const request = dashboardRequest;

async function resolveContext(
  argv: string[],
  err: NodeJS.WritableStream,
): Promise<InboxCliContext | null> {
  const unknownFortressFlag = unknownFlagWithPrefix(argv, "--fortress");
  if (unknownFortressFlag) {
    err.write(`inbox unknown fortress flag ${unknownFortressFlag}\n`);
    return null;
  }
  const parsed = consumeFlagValue(argv, "--fortress");
  if (parsed.error) {
    err.write(`inbox ${parsed.error}\n`);
    return null;
  }
  if (parsed.value === undefined) {
    return {
      argv: parsed.argv,
      fortressPath:
        process.env.SANCTUARY_STORAGE_PATH ?? process.env.SANCTUARY_FORTRESS_PATH,
    };
  }
  const fortress = parsed.value;
  const runtime = await readTenantRuntime(fortress);
  if (!runtime) {
    throw new Error(`no readable runtime.json for fortress ${fortress}`);
  }
  return {
    argv: parsed.argv,
    dashboardUrl: `http://${runtime.dashboard_host}:${runtime.dashboard_port}`,
    fortressPath: fortress,
  };
}

/**
 * Hub inbox item fields consumed by the approvals table. The payload shape
 * is hub-defined; every field is optional and rendering falls back to "-".
 */
interface ApprovalInboxItem {
  kind?: string;
  resolved?: boolean;
  item_id?: string;
  requester_id?: string;
  identity_id?: string;
  target_id?: string;
  agent_id?: string;
  operation_category?: string;
  display_template_id?: string;
  display_template_args?: ApprovalTemplateArg[];
  created_at?: string;
}

interface ApprovalTemplateArg {
  kind?: string;
  value?: unknown;
}

function isPendingApproval(item: ApprovalInboxItem): boolean {
  return item?.kind === "approval_pending" && item?.resolved !== true;
}

function writeApprovalTable(out: NodeJS.WritableStream, items: ApprovalInboxItem[]): void {
  const rows = items.map((item) => [
    item.item_id ?? "-",
    requesterLabel(item),
    targetLabel(item),
    item.operation_category ?? actionFromTemplate(item.display_template_id),
    ageLabel(item.created_at),
  ]);
  const table = [["ID", "REQUESTER", "TARGET", "ACTION", "AGE"], ...rows];
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

function requesterLabel(item: ApprovalInboxItem): string {
  return item.requester_id ?? argValue(item, "identity_id") ?? item.identity_id ?? "-";
}

function targetLabel(item: ApprovalInboxItem): string {
  return item.target_id ?? item.agent_id ?? argValue(item, "agent_id") ?? "fortress";
}

function argValue(item: ApprovalInboxItem, kind: string): string | null {
  const args = Array.isArray(item?.display_template_args)
    ? item.display_template_args
    : [];
  const found = args.find(
    (arg): arg is ApprovalTemplateArg & { value: string } =>
      arg?.kind === kind && typeof arg.value === "string",
  );
  return found?.value ?? null;
}

function actionFromTemplate(templateId: unknown): string {
  if (typeof templateId !== "string" || templateId.length === 0) return "-";
  const parts = templateId.split(".");
  return parts[parts.length - 1] || "-";
}

function ageLabel(createdAt: unknown): string {
  if (typeof createdAt !== "string") return "-";
  const then = new Date(createdAt).getTime();
  if (Number.isNaN(then)) return "-";
  const diffSec = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (diffSec < 60) return `${diffSec}s`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h`;
  return `${Math.floor(diffHr / 24)}d`;
}

function operatorLabel(): string {
  return process.env.SANCTUARY_OPERATOR_ID ?? process.env.USER ?? "operator";
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
